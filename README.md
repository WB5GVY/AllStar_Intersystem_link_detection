# AllStar Intersystem Link Detector

Automated detection and response system for unauthorized inter-system bridging on AllStarLink repeater networks.

> **Status note (2026-06-30): the bubble-map image-analysis / "hidden-path" layer is known to produce false positives and has been disabled in the maintainer's deployment.**
> Investigation of the data source showed the server-rendered bubble map is generated from the same registration data the AllStarLink stats API already exposes, so a bridge "visible only on the map" does not arise in practice — across the full production history, every hidden-path alert was a computer-vision misread of a benign (within-policy) topology. **The API-based topology detector — the primary detection path — is unaffected and remains reliable.** A revision that removes the image-analysis layer is in progress. If you are evaluating this project, rely on the API detector and treat the image/hidden-path code as deprecated.

## Background

AllStarLink linkage between repeater systems is at the discretion of each system's Trustee (owner/operator). Different systems have different policies:

- Some systems **liberally allow** linkage with other systems.
- Some systems **selectively allow** linkage on special occasions (e.g., for particular nets).
- Some systems **discourage all linkage** with other systems.

This monitoring system is intended for the last of these — systems that do not permit unauthorized inter-system bridging.

Furthermore, a given repeater system may want to designate particular nodes as AllStar or EchoLink gateways, hubs, or bridges, where personal nodes are encouraged to connect so as to avoid undue loading of key infrastructure nodes. This monitoring system recognizes each such designated gateway/hub/bridge. Guest nodes are welcome to connect to any gateway/hub/bridge so long as they are not simultaneously connected to other nodes. Guest nodes that *are* connected to other nodes are detected by the monitoring system, and various preconfigured actions are taken, including:

- **Notification to system administrators** (email alerts with full connection path details)
- **Notification to operators of offending nodes** (courtesy email via QRZ.com callsign lookup)
- **Selective auto-disconnect** of offending nodes from managed gateways/hubs/bridges

## The Problem

AllStarLink allows amateur radio operators to connect their nodes to any other node. When a guest connects to your repeater system while also connected to another network, they create an unauthorized *bridge* — routing audio between systems without the repeater trustee's knowledge or consent. This can cause confusion, echo, and unwanted cross-traffic.

Detecting these bridges manually is impractical. The AllStarLink bubble map shows the current topology, but you'd have to watch it continuously. This tool automates the monitoring.

## How It Works

The detector uses a **two-screen topology model** based on how repeater systems are typically organized:

```
                    ┌──────────┐
          ┌────────>│ Guest A  │   (hop 2 via bridge — PERMITTED)
          │         └──────────┘
    ┌─────┴────┐
    │  Bridge   │    (hop 1 — designated bridge node)
    │  YYYYY    │
    └─────┬────┘
          │
    ┌─────┴────┐    ┌──────────┐
    │  Focus   │───>│ Regular  │   (hop 1 — must be leaf endpoint)
    │  XXXXX   │    │  Node    │
    └─────┬────┘    └────┬─────┘
          │              │
    ┌─────┴────┐    ┌────┴─────┐
    │  Bridge   │    │ Node X   │   (hop 2 via non-bridge — VIOLATION!)
    │  ZZZZZ    │    └──────────┘
    └─────┬────┘
          │
    ┌─────┴────┐
    │ Guest B  │    (hop 2 via bridge — PERMITTED)
    └─────┬────┘
          │
    ┌─────┴────┐
    │ Node Y   │    (hop 3 via bridge — VIOLATION!)
    └──────────┘
```

### Detection Rules

**Screen 1** (simple, no node identification needed):
- Any node ≥3 hops from the focus node is ALWAYS problematic.

**Screen 2** (refined, uses bridge node identification):
- A non-bridge hop-1 node must be a leaf endpoint. Any connection beyond it is unauthorized.
- A bridge node is allowed exactly one additional hop (one guest). Any connection beyond the guest is unauthorized.
- External connections (RepeaterPhone, EchoLink) on non-bridge nodes are unauthorized bridging.

**Same-instant coherence** (2026-10-12): a guest's outside link is taken from the guest's *own*
stats record, while "the guest is attached to us" comes from the bridge's record — two records
from two clocks. After a *disconnect before connect* switch the stats API can serve the guest's
pre-join record (naming the old network, not the bridge) for a minute or more, which looks like a
simultaneous link but is not. So the outside link counts only when the guest's own record **also
names the node it is attached to**. Otherwise the guest is `unconfirmed` (shown in `/status`, the
log and the daily digest): no event, no cut, no email, and one delayed re-scan per episode after its
next post. A record that stays incoherent past `coherence.max_unconfirmed_seconds` while the guest
stays attached is flagged `past_grace` (one warning, `/status`; the digest lists it among the pre-join records) but is *still* not
enforced: there is no automatic cut on a record that never names its attach node, and the link-state
watchdog and tripwire remain the backstop for a real foreign mesh. The re-verify before a cut applies the same rule,
prefers the vantage's live AMI link list for the bridge side (falling back to the stats record when
the two disagree), never cuts on an unreadable or empty guest record, and (with `live_mesh_veto`)
refuses to cut when the live mesh shows the guest but none of its outside nodes.

### Dual Detection: API + Image Analysis

The system uses two independent detection methods:

1. **API-based analysis** (`graph_analyzer.py`): Queries the AllStarLink Stats API for each node's connection list. Walks the graph outward from the focus node, applying detection rules at each hop. Provides exact node IDs, callsigns, and connection details.

2. **Bubble map image analysis** (`bubble_analyzer.py`) — *deprecated, see Status note above*: Fetches the AllStarLink-generated network topology image (Graphviz bubble chart) and uses computer vision (OpenCV) to detect nodes, connections, and graph distances. Originally intended to catch bridging through non-reporting nodes. In practice the map carries no connectivity the API lacks, and the pixel-based edge tracer produced false positives; this layer is being removed.

3. **Cross-checker** (`cross_checker.py`) — *deprecated, see Status note above*: Compares both results. If the image showed deeper topology than the API detected, it flagged a possible hidden-path event. This proved to be false-positive-only and its email alerts are disabled.

### SSH Vantage Reader & Link-Count Tripwire

Alongside the stats-API walk, the detector can read link state directly from
a vantage node you administer (`rpt_reader.py`): one SSH round trip runs
`rpt xnode` and parses the full mesh list app_rpt itself sees — including
nodes the stats API cannot (unregistered nodes, EchoLink endpoints, named
IAX2 leaf clients). The mesh link count is recorded with every scan, and a
background thread (`link_watch.py`) polls it *between* scans as a
**tripwire**: a count rising faster than a configured rate, or above a
rolling-median baseline plus margin, requests an immediate out-of-cycle full
scan. The tripwire never detects or alerts by itself — it only collapses the
polling latency when something is happening. The reader is read-only by
construction (whitelisted commands only) and fail-safe: any SSH or parse
error is logged and the scan proceeds without it.

Optionally, an **AMI push listener** (`ami_listener.py`) collapses the
tripwire's polling latency further: it keeps a persistent Asterisk Manager
Interface session to the vantage node through an SSH tunnel (AMI stays
bound to localhost on the node — no node-side changes) and, whenever
app_rpt fires a link-change event, wakes the watch thread for an immediate
sample — seconds instead of the polling interval. Enforcement never runs
from the listener thread; a dead tunnel or AMI session simply falls back
to polling, reconnecting with capped backoff. A hard floor between samples
caps the SSH rate to the vantage node no matter how fast events arrive.

### Response Pipeline

When unauthorized bridging is detected:

1. **Email alert** to system operators with full path details, detection rule,
   and the vantage node's link count captured at detection time (before the
   disconnect, so it still includes the offender)
2. **QRZ.com lookup** of the offending operator's callsign → sends courtesy email asking them to "disconnect before connect"
3. **Auto-disconnect** (for managed nodes): Waits 15 seconds, re-verifies the bridge still exists (DNS check + fresh API query), then SSH into the managed AllStar node to force-disconnect the offender via Asterisk CLI
4. **Watch mode** (repeat-offender handling): the offender is fast-polled via
   the vantage reader for a configurable window. A reappearance is re-kicked
   through the full re-verify chain; only a *verified* re-bridge counts as a
   strike (an innocent reconnect never does). At the strike threshold, one
   escalation email per offender per window goes out — this REPEAT_OFFENDER
   alert bypasses quiet hours by policy, because a node that persistently
   re-bridges after disconnects is misconfigured or deliberate.

All actions are rate-limited, respect quiet hours (except where noted), and
are logged. As an outermost fail-safe, no recipient address ever receives
more than a configurable absolute maximum of emails per rolling window
(default 18 per 6 hours) across **all** categories, with the final allowed
email carrying a rate-limit notice.

### Analytics & Daily Digest

An isolated observation store (`analytics_db.py`, separate SQLite file)
records per-scan presence transitions, guest/external sessions, the vantage
mesh count, and every violation detection. A standalone reporter
(`analytics_report.py`, run daily via launchd/cron) emails a digest with
per-node availability, bridge presence sessions, guest activity, external
leaf clients, and an **Unauthorized bridging** section — violations are
clustered into episodes, flagged on the offending guest's row, and episodes
that began during quiet hours are annotated as held-overnight (since
2026-10-12 the real-time alert is queued and delivered when quiet hours end;
the morning digest is where the episode also surfaces). Analytics never affects detection:
all writes are fail-safe and the recorder is bypassed entirely on error.

**Three-state node health** (`node_health.py`, 2026-10-18). "Online" means three
different things, and they disagree in practice: a node can hold a live audio link
to the hub for days after its AllStar registration lapsed, and the hub can list a
node it is only *dialing*. Per monitored node the daemon now tracks, independently,
**registered** (checked in with AllStar within 90 min), **posting** (sent its own
stats post within 10 min) and the **link letter its expected parent reports for it**
(T live · R rx-only · L local monitor · C dialing, no audio · — not listed ·
? parent data unavailable); *linked* = T/R/L. All three come from records the scan
already fetched (zero extra requests; a node its parent does not list is fetched at
most once per 5 min, never in the top-of-hour burst). Shown live in `/status`
(`node_health`, plus `node_counts.registered/linked/posting`), recorded as debounced
transitions (two consecutive scans) with restart baselines in `analytics.db`, and
summarised in the digest's **Registration & link state** section (linked %, time the
parent was dialing, registered %, posting %, state at period end, transitions). The
same change adds a validity gate: when the hub's record cannot be fetched at all the
scan records nothing (previously it wrote a mass "disappeared" and an outage for every
core node); a hub that is fetched but silent is a real state, not a gate.

## Quick Start

### Prerequisites

- Python 3.10+ (tested with 3.13)
- A Gmail account with an [App Password](https://support.google.com/accounts/answer/185833) for sending notifications
- Optional: [QRZ.com XML subscription](https://www.qrz.com/page/xml_data.html) for offender email lookup
- Optional: SSH access to managed AllStar nodes for auto-disconnect

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/AllStar_Intersystem_link_detection.git
cd AllStar_Intersystem_link_detection
pip install -r requirements.txt
```

### Configuration

1. Copy the example config files:
   ```bash
   cp config.yaml.example config.yaml
   mkdir -p ~/.config/asl_link_detector
   cp secrets.yaml.example ~/.config/asl_link_detector/secrets.yaml
   chmod 600 ~/.config/asl_link_detector/secrets.yaml
   ```

2. Edit `config.yaml`:
   - Set `focus_node` to your central hub node number
   - List your `bridge_nodes` (nodes permitted to have one guest connection)
   - Configure `auto_disconnect` with SSH details for any nodes you admin
   - Adjust `rate_limits`, `quiet_hours`, and `poll_interval_seconds` as needed

3. Edit `~/.config/asl_link_detector/secrets.yaml`:
   - Add your Gmail address and App Password
   - Add QRZ.com credentials if using offender notification

4. Customize `offender_email_draft.txt` with your system's callsign, trustee info, and admin contact links. This template is sent to offending operators when QRZ email lookup is enabled.

### Test Your Setup

```bash
# Verify email configuration
python3 asl_link_detector.py --test-email

# Run a single scan (no notifications sent)
python3 asl_link_detector.py --dry-run

# Run a single scan with notifications
python3 asl_link_detector.py --once

# Run a single scan without bubble map image check
python3 asl_link_detector.py --once --no-image
```

### Continuous Monitoring

```bash
# Run as a foreground process (polls every 5 minutes by default)
python3 asl_link_detector.py
```

For persistent monitoring, set up as a system service:

**macOS (launchd)**:

The service plist is at `~/Library/LaunchAgents/com.example.asl-link-detector.plist`.

```bash
# Start the service
launchctl load ~/Library/LaunchAgents/com.example.asl-link-detector.plist

# Stop the service
launchctl unload ~/Library/LaunchAgents/com.example.asl-link-detector.plist
```

The service starts on login (`RunAtLoad`) and restarts automatically on crash (`KeepAlive`).

**Linux (systemd)**:
Create a standard systemd user service unit pointing to the script.

## Operational Scripts

Scripts for controlling auto-disconnect from the monitoring host. All take effect on the next scan cycle without requiring a service restart.

| Script | Usage | Description |
|--------|-------|-------------|
| `autodisconnect-off` | `./autodisconnect-off <NODE_ID>` | Disable auto-disconnect for a node (creates local override file) |
| `autodisconnect-on` | `./autodisconnect-on <NODE_ID>` | Re-enable auto-disconnect for a node (removes local override file) |
| `autodisconnect-status` | `./autodisconnect-status` | Show config and override status for all managed nodes |
| `autodisconnect-reconfig` | `./autodisconnect-reconfig` | Send SIGHUP to reload config.yaml without restarting the service |

### Two-Layer Disable Mechanism

Auto-disconnect for a managed node requires **both**:
1. `enabled: true` in `config.yaml` (persistent across host reboots)
2. No local override file at `/tmp/autodisconnect_disabled_<NODE_ID>` (cleared on host reboot)

Either layer can independently disable auto-disconnect for a node. The `enabled` field is for persistent configuration changes (edit config.yaml, then run `autodisconnect-reconfig`). The local override files are for quick toggling without editing config files.

### Remote Flag File (Node-Side Disable)

Nodes with `flag_file_check` configured in config.yaml have an additional layer: the monitoring system SSHes into the node before each disconnect attempt and checks for a flag file. If present, the disconnect is skipped (fail-closed). This lets the node's trustee disable auto-disconnect via DTMF without access to the monitoring system.

## Architecture

```
asl_link_detector.py     Main entry point, CLI, polling loop
├── asl_api.py           AllStarLink Stats API client (rate-limited)
├── graph_analyzer.py    Two-screen topology detection model
├── bubble_analyzer.py   Bubble map image analysis (OpenCV; deprecated)
├── cross_checker.py     API vs. image cross-check logic (deprecated)
├── dns_checker.py       DNS TXT record lookup (node online check)
├── rpt_reader.py        Read-only SSH vantage reader (rpt xnode parser)
├── link_watch.py        Between-scan link-count tripwire + watch mode
├── ami_listener.py      AMI push listener (SSH tunnel; wakes link_watch)
├── bubble_map_gen.py    Local Graphviz bubble-map renderer (/bubble.png)
├── notifier.py          Email alerts, rate limiting, quiet hours,
│                        absolute per-recipient volume fail-safe
├── qrz_lookup.py        QRZ.com XML API callsign/email lookup
├── auto_disconnect.py   SSH-based force disconnect for managed nodes
├── analytics_db.py      Observation store (presence/sessions/violations)
├── analytics_report.py  Standalone daily/weekly digest generator
├── status_server.py     HTTP status endpoint for dashboards (HA etc.)
├── config.yaml          Your local configuration (not committed)
└── secrets.yaml         Credentials file (stored outside project dir)
```

### Key Design Decisions

- **Split-secrets architecture**: Credentials (`secrets.yaml`) are stored outside the project directory at `~/.config/asl_link_detector/secrets.yaml` with `chmod 600`. The project directory can safely live in Dropbox or version control.

- **DNS-first liveness check**: Before flagging a node or attempting disconnect, the system checks AllStarLink DNS TXT records (`<node>.nodes.allstarlink.org`). DNS records update within ~60 seconds of registration changes, making them far more reliable than the stats API's `regseconds` field (which can lag ~60 minutes).

- **Path-based rate limiting**: Notification cooldown is keyed on the full violation *path* (e.g., `XXXXX → YYYYY → 67890 → 12345`), not just the offending node. This ensures that different violation paths through the same node are independently reported.

- **Re-verification before disconnect**: Auto-disconnect waits a configurable delay (default 15 seconds), then re-queries the API and DNS to confirm the bridge still exists before acting. This prevents disconnecting nodes that resolved the issue on their own.

- **Bridge node exemption for external connections**: Designated bridge nodes (e.g., EchoLink gateways) are not flagged for having external connections (RepeaterPhone, EchoLink), since that is their normal function.

## Configuration Reference

### `config.yaml`

| Field | Description | Default |
|-------|-------------|---------|
| `focus_node` | Your central hub node number | (required) |
| `bridge_nodes` | List of nodes allowed one guest hop | `[]` |
| `allowlist` | Nodes exempt from detection rules | `[]` |
| `poll_interval_seconds` | Seconds between scan cycles | `300` |
| `stale_threshold_minutes` | Ignore links older than this | `120` |
| `secrets_file` | Path to credentials file | `~/.config/asl_link_detector/secrets.yaml` |
| `coherence.enabled` | Guest outside links count only when the guest's own record names its attach node | `true` |
| `coherence.relook_delay_seconds` | Delay of the one re-scan after an unconfirmed (pre-join) record | `100` |
| `coherence.relook_node_cooldown_seconds` / `relook_global_min_seconds` | Re-look budget per node / between any two re-looks | `300` / `60` |
| `coherence.max_unconfirmed_seconds` | Still incoherent and attached after this: flagged `past_grace` (one warning, `/status`); still not enforced | `240` |
| `coherence.live_mesh_veto` | The re-verify refuses a cut when the trusted vantage mesh shows the guest but none of its outside nodes | `true` |

### Rate Limits

| Field | Description | Default |
|-------|-------------|---------|
| `max_per_window` | Max notifications per time window | `2` |
| `window_minutes` | Time window in minutes | `15` |
| `max_per_day` | Max notifications per day | `24` |
| `cooldown_per_path_minutes` | Per-path cooldown | `15` |
| `absolute_recipient_max_per_window` | Hard cap on emails to any single address per rolling window, all categories, no bypass | `18` |
| `absolute_recipient_window_hours` | Rolling window for the absolute cap | `6` |

### Vantage Reader & Link Watch

| Field | Description | Default |
|-------|-------------|---------|
| `rpt_reader.enabled` | Enable the SSH vantage reader | `false` |
| `rpt_reader.vantage_node` | Node to read from (must match an `auto_disconnect.nodes` entry — SSH creds are reused) | (required) |
| `rpt_reader.timeout_seconds` | SSH read timeout | `15` |
| `link_watch.enabled` | Enable the tripwire/watch thread (requires `rpt_reader`) | `false` |
| `link_watch.poll_interval_seconds` | Tripwire sampling cadence | `60` |
| `link_watch.count_margin` | Trip at count ≥ rolling baseline + margin | `5` |
| `link_watch.rate_per_minute` | Trip when the count rises this fast | `5` |
| `link_watch.watch_window_minutes` | Post-violation watch duration per offender | `45` |
| `link_watch.watch_poll_interval_seconds` | Fast poll while any watch is active | `15` |
| `link_watch.strike_threshold` | Verified re-offenses before the REPEAT_OFFENDER escalation | `3` |
| `link_watch.scan_on_mesh_change` | Mesh membership change requests one out-of-cycle full scan (fast map confirmation of joins) | `true` |
| `link_watch.mesh_change_scan_cooldown_seconds` | API-load bound for the above | `180` |
| `ami_listener.enabled` | Enable the AMI push listener (requires `link_watch`; AMI credentials go in `secrets.yaml` under `ami:`) | `false` |
| `ami_listener.vantage_node` | Node whose AMI to listen to | `rpt_reader.vantage_node` |
| `ami_listener.local_port` / `remote_port` | SSH tunnel endpoints | `61220` / `5038` |
| `ami_listener.qso_hold_seconds` | Unkeyed gap that ends a "QSO" for the activity indicator | `120` |
| `bubble_map.enabled` | Render local Graphviz bubble maps each update, served at `/bubble.png` and `/bubble_wide.png` (requires graphviz installed) | `false` |
| `bubble_map.engine` | Graphviz layout engine (`neato` recommended: compact spring layout with `overlap=vpsc` packing) | `neato` |
| `bubble_map.qrz_names` | Annotate guests with cached QRZ operator names | `false` |
| `bubble_map.qrz_lookups_per_scan` | QRZ cache-miss budget per scan | `3` |
| `bubble_map.output` / `landscape_output` | Render output paths — point OUTSIDE any cloud-synced folder (File Provider sync can stall renders) | see example |
| `bubble_map.landscape_enabled` / `landscape_ratio` | Also render a wide variant for landscape displays | `true` / `0.45` |
| `bubble_map.spread_enabled` | Also render airy prism-layout variants, selected with `?layout=spread` on either endpoint | `true` |
| `bubble_map.refresh_on_link_change` / `refresh_min_interval_seconds` | Render-only refresh when the watcher sees the mesh change | `true` / `10` |
| `bubble_map.echolink_host` | EchoLink gateway node: unconfirmed EchoLink mesh entries attach here speculatively | unset |
| `bubble_map.node_info_ttl_days` | Disk cache of node callsign/freq/tone/coords (also feeds the digest's callsign columns) | `30` |
| `bubble_map.render_timeout_seconds` | Render subprocess cap (companions capped lower internally) | `30` |

The local bubble maps are rendered from each scan's own topology (role-colored
with an on-image legend; violations red; external leaves dashed; nodes
invisible to the stats API dotted, courtesy of the vantage reader; superset of
the official map's per-node info incl. frequency/CTCSS/coordinates and cached
QRZ operator names). Both orientations re-render within seconds of a mesh
change, and the caption carries a network QSO-activity indicator ("ACTIVE /
inactive since ...") derived from the vantage's AMI keyed events, also exposed
as a `qso` block in `/status` alongside the `guest_arrivals` feed. Endpoints
support HEAD/Last-Modified for cache revalidation.

### Analytics

| Field | Description | Default |
|-------|-------------|---------|
| `analytics.enabled` | Enable the observation recorder | `false` |
| `analytics.db_path` | Analytics SQLite file | `analytics.db` |
| `analytics.system_name` | Name shown in digest titles | `""` |
| `analytics.core_nodes` / `analytics.bridge_nodes` | Role sets for the digest | derived |
| `analytics.timezone` | Digest display timezone | quiet-hours zone, else UTC |

### Node health

| Field | Description | Default |
|-------|-------------|---------|
| `node_health.enabled` | Track registered / posting / parent-letter per node (`/status`, analytics, digest) | `false` |
| `node_health.nodes` | `node: expected parent` map (`self` for the hub); a node behind a bridge lists that bridge | hub + analytics core/bridges under the hub |
| `node_health.registered_max_age_seconds` | Registration age that still counts as registered | `5400` |
| `node_health.posting_max_age_seconds` | Stats-post age that still counts as posting (also the parent-record freshness for the letter) | `600` |
| `node_health.confirm_scans` | Consecutive scans before a change is recorded | `2` |
| `node_health.extra_fetch_interval_seconds` / `extra_fetch_max_per_scan` | Own-record fetches for nodes the scan did not reach | `300` / `8` |
| `node_health.dns_lookups` | Per scan, look up both registration DNS names (`<n>.nodes.allstarlink.org` A+TXT, `<n>.asl.hamvoip.org` TXT) and cross-check them against each other and the node's stats record (`/status … nodes.<n>.dns`: record sets, `issues`, `consistent`) | `true` |
| `node_health.hamvoip_nodes` | Nodes that register with HamVoIP, so their `<n>.asl.hamvoip.org` record must exist; every other node's HamVoIP record is informational (registering with HamVoIP is optional) | none |

### Team status page feed (`public_export`)

After every scan the daemon can render one small JSON document (`public_export/status.json`, schema 1: per node the registered / link / posting facts, the DNS block, and the record facts — callsign, frequency, tone, location, uptime, key-ups, link tokens) and push it to a single Azure blob with a **write-only** SAS read from the login keychain (item `ASL_TEAM_STATUS_SAS`; never in `config.yaml`, the log or `/status`). Push-only, worker thread, at most one PUT per `min_interval_seconds`; a failure is a counter and a type-only `last_error` under `/status … public_export`. `python3 public_export.py --once [--push]` renders (and pushes) by hand; `--selftest` runs the unit tests. Side effect: the exporter pins the `urllib3`/`requests` loggers to WARNING for the whole process (so a `logging.level: DEBUG` can never write a request line carrying the SAS), which also hides the stats-API request lines at DEBUG. The login-protected page that shows it lives on Azure Static Web Apps (invited users) and is documented in `Claude-shared/2026-10-20_1716_team_status_page_exporter_PLAN_v1.md`.

| Key | Meaning | Default |
|---|---|---|
| `public_export.enabled` | Turn the feed on | `false` |
| `public_export.dir` | Local output directory (gitignored) | `public_export` |
| `public_export.blob_url` | The blob's https URL **without** a query string; absent = render locally only | none |
| `public_export.sas_keychain_item` | Keychain generic-password service name holding the SAS | `ASL_TEAM_STATUS_SAS` |
| `public_export.min_interval_seconds` | Minimum spacing between pushes | `60` |
| `public_export.timeout_seconds` | Per-PUT timeout (one retry after 5 s) | `10` |
| `public_export.stale_after_seconds` | Advisory for the page's stale banner | `900` |
| `public_export.groups` | Ordered display groups: `name`, `icon`, `nodes` (ints or `{node, description}`) | one group of all node_health nodes |

Digest tables carry callsign columns (sourced read-only from the bubble-map
node-info cache — no API/QRZ lookups at report time). Guest activity is split
into guests via designated bridges vs. directly to the hub, and UNWITTING
guests (foreign-mesh nodes dragged in by a violation, identified by their
attachment through a guest chain) get their own table. The violation-alert
email reports the action actually taken (auto-disconnect / self-cleared /
failed) rather than a generic recommendation.

### Auto-Disconnect

Each entry in `auto_disconnect.nodes`:

| Field | Description |
|-------|-------------|
| `node_id` | AllStar node number you admin |
| `ssh_host` | IP address of the node's server |
| `ssh_user` | SSH username |
| `ssh_key` | Path to SSH private key |
| `ssh_port` | SSH port (default 22) |
| `enabled` | Set `true` to activate |
| `flag_file_check` | Remote file path to check before disconnecting. If file exists on the node, disconnect is skipped. Optional. |

The disconnect command issued is: `asterisk -rx "rpt fun <node_id> *1<target_node>"`

## For System Administrators

### Adding Your Node for Auto-Disconnect

If you admin an AllStar node in the monitored system, you can enable auto-disconnect:

1. Ensure SSH key-based authentication is set up from the monitoring machine to your node
2. Test SSH access: `ssh -p <port> -i <key_path> <user>@<host> 'asterisk -rx "rpt showvars <node_id>"'`
3. Add your node to the `auto_disconnect.nodes` list in `config.yaml`
4. Set `enabled: true` after testing

### Adding a Bridge Node

If a new bridge/gateway node is added to the system:

1. Add its node number to the `bridge_nodes` list in `config.yaml`
2. Restart the detector service

### Offender Courtesy Email

When QRZ lookup is enabled, detected offenders receive a courtesy email (template in `offender_email_draft.txt`) asking them to "disconnect before connect." The email is sent from the configured SMTP account with a BCC to the operators. Edit `offender_email_draft.txt` to customize the wording, contact links, and node numbers for your system.

## Dependencies

- `requests` — HTTP client for AllStarLink Stats API and QRZ API
- `PyYAML` — Configuration file parsing
- `dnspython` — DNS TXT record lookup for node liveness checks
- `opencv-python-headless` — Bubble map image analysis
- `numpy` — Required by OpenCV

All other modules (`smtplib`, `sqlite3`, `subprocess`, `xml.etree`) are Python standard library.

## License

This project is provided as-is for use by amateur radio operators managing AllStarLink repeater systems. Use responsibly and in accordance with FCC Part 97 regulations and your repeater trustee's policies.
