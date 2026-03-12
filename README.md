# AllStar Intersystem Link Detector

Automated detection and response system for unauthorized inter-system bridging on AllStarLink repeater networks.

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

### Dual Detection: API + Image Analysis

The system uses two independent detection methods:

1. **API-based analysis** (`graph_analyzer.py`): Queries the AllStarLink Stats API for each node's connection list. Walks the graph outward from the focus node, applying detection rules at each hop. Provides exact node IDs, callsigns, and connection details.

2. **Bubble map image analysis** (`bubble_analyzer.py`): Fetches the AllStarLink-generated network topology image (Graphviz bubble chart) and uses computer vision (OpenCV) to detect nodes, connections, and graph distances. Catches bridging through non-reporting nodes whose connection lists are not visible to the API.

3. **Cross-checker** (`cross_checker.py`): Compares both results. If the image shows deeper topology than the API detected, it flags a possible hidden-path bridging event through non-reporting nodes.

### Response Pipeline

When unauthorized bridging is detected:

1. **Email alert** to system operators with full path details and detection rule
2. **QRZ.com lookup** of the offending operator's callsign → sends courtesy email asking them to "disconnect before connect"
3. **Auto-disconnect** (for managed nodes): Waits 15 seconds, re-verifies the bridge still exists (DNS check + fresh API query), then SSH into the managed AllStar node to force-disconnect the offender via Asterisk CLI

All actions are rate-limited, respect quiet hours, and are logged.

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
Create a launch agent plist in `~/Library/LaunchAgents/` with `RunAtLoad`, `KeepAlive`, and `WorkingDirectory` pointing to the project directory. Use the full path to your Python interpreter (e.g., from pyenv).

**Linux (systemd)**:
Create a standard systemd user service unit pointing to the script.

## Architecture

```
asl_link_detector.py     Main entry point, CLI, polling loop
├── asl_api.py           AllStarLink Stats API client (rate-limited)
├── graph_analyzer.py    Two-screen topology detection model
├── bubble_analyzer.py   Bubble map image analysis (OpenCV)
├── cross_checker.py     API vs. image cross-check logic
├── dns_checker.py       DNS TXT record lookup (node online check)
├── notifier.py          Email alerts, rate limiting, quiet hours
├── qrz_lookup.py        QRZ.com XML API callsign/email lookup
├── auto_disconnect.py   SSH-based force disconnect for managed nodes
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

### Rate Limits

| Field | Description | Default |
|-------|-------------|---------|
| `max_per_window` | Max notifications per time window | `2` |
| `window_minutes` | Time window in minutes | `15` |
| `max_per_day` | Max notifications per day | `24` |
| `cooldown_per_path_minutes` | Per-path cooldown | `15` |

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
