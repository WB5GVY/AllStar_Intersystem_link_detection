"""Topology analysis for AllStarLink node connection graphs.

Detection model (matching the repeater operator's mental model):

The system has one focus hub node and one or more bridge nodes.
All other nodes connect as guests.

Permitted topology:
  - focus → regular_node          (1 hop: leaf endpoint, nothing beyond)
  - focus → bridge_node → guest   (2 hops via bridge: one guest per bridge)
  - focus ↔ bridge_node           (hub-to-bridge link)

Detection rules:
  Screen 1 (simple, no node identification needed):
    Any node ≥3 hops from the focus node is ALWAYS problematic.
    The node at hop 3 is the offending node.

  Screen 2 (refined, requires identifying bridge nodes):
    A 1-hop node that is NOT a bridge node should be a leaf endpoint.
    Any node at hop 2 through a non-bridge node is problematic.
    The node at hop 2 is the offending node.

    A bridge node is allowed exactly one additional hop.
    Any node at hop 3 through a bridge node is problematic.
    The node at hop 3 is the offending node.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from asl_api import ASLApiClient, parse_link_modes
from dns_checker import check_node_dns

logger = logging.getLogger(__name__)


def _display_fields(info: dict) -> dict:
    """Display-only fields carried into topology entries for the bubble-map
    renderer (2026-07-04). Detection logic never reads these."""
    return {
        "frequency": info.get("frequency", ""),
        "tone": info.get("tone", ""),
        "owner": info.get("owner", ""),
        "lat": info.get("lat"),
        "lon": info.get("lon"),
    }


@dataclass
class BridgingEvent:
    """Represents a detected unauthorized bridging event."""
    offending_node: int           # The node at the boundary (the offender)
    offending_callsign: str
    offending_location: str
    path: list[int]               # Full path from focus node to offending node
    path_description: str         # Human-readable path description
    depth: int                    # Hops from focus node
    rule: str                     # Which screen/rule triggered this
    # Human-readable link-mode summary (T/R/L/C as each node self-reports to
    # AllStarLink stats) for the offender's links. Informational only —
    # detection ignores mode. Last, with a default, so existing constructors
    # and duck-typed consumers are untouched.
    link_modes: str = ""
    # time.monotonic() when the OFFENDER's stats record was fetched — the
    # age of the evidence behind this event. One scan emits one event per
    # outside target from ONE fetch, minutes apart (2026-09-07 23:42: the
    # 2nd-4th events of a scan re-used a record fetched before the cut and
    # counted a strike). link_watch compares this with the moment it saw
    # the offender absent; older evidence is never a re-offense.
    observed_at: float = 0.0
    # Coherence (2026-10-12): the evidence behind the offender's outside link
    # is its OWN stats record. These carry that record's freshness so the
    # email / log / re-verify can judge it: age of the post at fetch time,
    # the post's epoch time (logged by the re-verify when it re-reads the
    # SAME post), the raw `nodes` string, whether the analyzer judged the
    # record coherent (it named the attach node, or another system node
    # whose record lists it). incoherent_for_seconds is kept for consumers
    # but is always None in v1 (no event is emitted for an incoherent record).
    guest_post_age_seconds: Optional[float] = None
    guest_post_time: Optional[int] = None
    guest_raw_nodes: str = ""
    incoherent_for_seconds: Optional[float] = None
    guest_record_coherent: bool = False

    def __str__(self):
        return (
            f"BRIDGING DETECTED: Node {self.offending_node} "
            f"({self.offending_callsign}, {self.offending_location}) "
            f"at depth {self.depth}. Path: {self.path_description}. "
            f"Rule: {self.rule}"
        )


def record_addr(data) -> tuple:
    """(ipaddr, port) from a node's own stats record (`node.ipaddr` /
    `node.port`), each None when absent or unusable. Shared by the walk and
    the node-health extra fetch (DNS cross-check, 2026-10-19)."""
    try:
        node = (data or {}).get("node") or {}
        ip = node.get("ipaddr")
        ip = str(ip).strip()[:45] if isinstance(ip, str) and ip.strip() else None
        try:
            port = int(node.get("port"))          # OverflowError: a JSON 1e999 (audit pass 4)
            port = port if 0 < port < 65536 else None
        except (TypeError, ValueError, OverflowError):
            port = None
        return (ip, port)
    except (AttributeError, TypeError):
        return (None, None)


def record_version(data):
    """`stats.data.apprptvers` of a node's own record (capped), or None."""
    try:
        v = (((data or {}).get("stats") or {}).get("data") or {}).get("apprptvers")
        v = str(v).strip()[:40] if v not in (None, "") else None
        return v or None
    except AttributeError:
        return None


_PUBLIC_LINK_TOKEN = re.compile(r"^[A-Z]?[0-9A-Za-z]{1,12}$")


def _public_text(v, cap: int):
    """A registry text field made safe for display: str, stripped, control
    characters removed, capped; None when absent/blank/not scalar."""
    if v is None or isinstance(v, (bool, list, dict, tuple, set)):
        return None
    try:
        s = str(v)
    except Exception:
        return None
    s = "".join(ch for ch in s if ch.isprintable()).strip()[:cap]
    return s or None


def _public_int(v, lo: int = 0, hi: int = 10**10):
    """int(v) within [lo, hi], else None (OverflowError-safe)."""
    if v is None or isinstance(v, bool):
        return None
    try:
        n = int(float(v)) if isinstance(v, str) else int(v)
    except (TypeError, ValueError, OverflowError):
        return None
    return n if lo <= n <= hi else None


def record_public(data) -> dict:
    """The display-only facts of a node's own stats record that the team
    status page shows (2026-10-20): callsign, status, frequency, tone, site
    location, portal udpport / proxy_ip, uptime, key-ups, keyed, keytime
    (2026-10-22: seconds since the node's own receiver last keyed, at post
    time — app_rpt `keytime`), txtime_s (app_rpt `totaltxtime`: total
    transmitter-on seconds since start), and the raw link tokens of `stats.data.nodes`
    ("T1000", "C2000", …). Every key is always present (None / [] when absent
    or unusable); strings are capped and stripped of control characters;
    never raises."""
    out = {"callsign": None, "status": None, "frequency": None, "tone": None,
           "location": None, "site": None, "udpport": None, "proxy_ip": None,
           "uptime_s": None, "keyups": None, "keyed": None, "keytime_s": None, "txtime_s": None, "links": []}
    try:
        node = (data or {}).get("node") or {}
        if not isinstance(node, dict):
            node = {}
        server = node.get("server") or {}
        if not isinstance(server, dict):
            server = {}
        sd = (((data or {}).get("stats") or {}).get("data") or {})
        if not isinstance(sd, dict):
            sd = {}
        out["callsign"] = _public_text(node.get("callsign"), 12)
        out["status"] = _public_text(node.get("Status"), 16)
        out["frequency"] = _public_text(node.get("node_frequency"), 16)
        out["tone"] = _public_text(node.get("node_tone"), 16)
        out["location"] = _public_text(server.get("Location"), 60)
        out["site"] = _public_text(server.get("SiteName"), 60)
        out["udpport"] = _public_int(server.get("udpport"), 1, 65535)
        out["proxy_ip"] = _public_text(server.get("proxy_ip"), 45)
        out["uptime_s"] = _public_int(sd.get("apprptuptime"))
        out["keyups"] = _public_int(sd.get("totalkeyups"))
        out["keytime_s"] = _public_int(sd.get("keytime"))
        out["txtime_s"] = _public_int(sd.get("totaltxtime"))
        keyed = sd.get("keyed")
        if isinstance(keyed, bool):
            out["keyed"] = keyed
        elif isinstance(keyed, int) and keyed in (0, 1):            # a key post may send 0/1
            out["keyed"] = bool(keyed)
        elif isinstance(keyed, str) and keyed.strip().lower() in ("true", "false", "1", "0"):
            out["keyed"] = keyed.strip().lower() in ("true", "1")
        raw = sd.get("nodes")
        if isinstance(raw, str):
            toks = [t.strip() for t in raw.split(",")]
            out["links"] = [t for t in toks if _PUBLIC_LINK_TOKEN.match(t)][:64]
    except Exception:                            # noqa: BLE001 — runs on the enforcement walk: never raise
        pass
    return out


@dataclass
class ScanResult:
    """Result of a topology scan."""
    timestamp: str
    focus_node: int
    bridge_nodes: list[int]
    bridging_events: list[BridgingEvent]
    topology: dict[int, dict]        # node_id -> {depth, parent, role, ...}
    errors: list[str] = field(default_factory=list)
    # Undirected union of every reported numeric link seen during the walk,
    # as frozenset({a, b}) pairs. Unlike `topology` (a directed tree rooted at
    # the focus), this preserves cross-links — letting cross_checker compute
    # EXACT BFS distances and detect bridges through non-reporting nodes from
    # structured data, replacing the error-prone bubble-map CV (Item B,
    # 2026-06-11). Shadow-mode only for now; not yet an alerting source.
    edges: set = field(default_factory=set)
    # True when API shows at least one triangle through the focus
    # (focus↔A, focus↔B, A↔B all present). Bubble-map images of triangles
    # are unreliable for distance-based hidden-path detection because the
    # image-processor's straight-line edge tracer drops one of the routed-
    # around edges. Used by cross_checker to suppress hidden-path alerts.
    has_focus_triangle: bool = False
    # Link mode letters as self-reported to AllStarLink stats, keyed
    # (observer, peer) as strings -> "T"/"R"/"L"/"C". Both directions of a
    # link are recorded when both ends were queried. Only the node that
    # INITIATED a monitor link ever reports R; the receiving end always
    # records T (app_rpt creates incoming links in transceive mode), so a
    # T here never contradicts an R from the other end. Display-only.
    link_modes: dict = field(default_factory=dict)
    # Phase 2: permitted "listener" nodes found this scan — nodes whose EVERY
    # AllStar link is monitor-only by their own report. Each entry:
    # {node, callsign, attached_to, attachment ("bridge"|"hub"), monitored:
    # [outside node ids recorded as monitored_by_guest], summary}. Empty
    # unless GraphAnalyzer(permit_listeners=True).
    listeners: list = field(default_factory=list)
    # Nodes the walk tried to query but got NO LINK LIST from this scan (API
    # error, or an empty stats record — whether never posted, stale, or a
    # fresh post reporting no links; `linkless` nodes are in here too). A
    # previously known listener in this set was merely unobserved, not gone
    # — the daemon keeps its listener registration rather than clearing it
    # (an empty list never proves a listener's links are gone: the attach
    # node's own record is what says whether it left). A system node in
    # this set degrades the scan.
    unobserved: set = field(default_factory=set)
    # Step 2b (2026-09-07): "dark" guests — online (registered in DNS) but
    # posting nothing to stats, so their outside links are invisible to
    # this walk. [{node, attached_to, attachment}] for the daemon's
    # DarkGuestTracker, which corroborates against the bridge's own
    # `rpt nodes` union and the vantage keyed feed.
    dark_guests: list = field(default_factory=list)
    # Change 1 (2026-09-08, the <guest> case): guests in DNS that POSTED within
    # linkless_fresh_seconds a record naming NO links at all (empty
    # linkedNodes AND empty `nodes` string) while the attach node still
    # lists them — typically the attach-side link stuck re-dialing after the
    # guest's address changed, no audio path. Listed here INSTEAD of
    # dark_guests (the guest is provably reporting; its report is just
    # empty); still in `unobserved`. Same shape as dark_guests plus
    # post_age_seconds. Shown in /status `linkless`; change 2: daily digest.
    linkless: list = field(default_factory=list)
    # node -> age in seconds of its stats POST (`stats.data.time`), None when
    # the record carries no usable time (not posting / far-future). Every
    # fetched node.
    post_age: dict = field(default_factory=dict)
    # Nodes whose record's `nodes` mode string named at least one link this
    # scan (even if linkedNodes was empty — the two fields can disagree;
    # audit 2026-09-08 S1). Such a node is never `linkless`.
    names_links: set = field(default_factory=set)
    # Numeric nodes whose stats record was fetched NON-EMPTY this scan (the
    # dark-guest tracker's "seen posting" set; audit 2 advisory). `linkless`
    # nodes are deliberately NOT in here (round-2 audit C1).
    posting: set = field(default_factory=set)
    # Change 3 (2026-09-08): links a guest / non-bridge hop-1 node reports in
    # state C (CONNECTING — dialled, not yet answered; no audio path). Such
    # a link is "not a link yet": it neither disqualifies the node as a
    # listener nor counts as bridging until it settles to T (violation) or
    # R/L (listener branch). [{node, target, attached_to, attachment}]; the
    # daemon asks for one quick re-scan per new pair. Live 15:58 case: a
    # guest dialling a slow far end was cut on the C alone.
    connecting: list = field(default_factory=list)
    # Coherence (2026-10-12): guests / non-bridge hop-1 nodes whose OWN stats
    # record names an outside node but does NOT name the system node they
    # are attached to (per the attach node's record). Two records from two
    # clocks: the guest's is a pre-join (or post-leave) post, so its outside
    # links are equally old — not evidence of a simultaneous link. All three
    # real cuts to date (09-10, 09-28, 10-11) had exactly this shape. No
    # event, no walk, no topology entry (CONNECTING precedent); the daemon
    # asks for one delayed re-look. [{node, callsign, attached_to,
    # attachment, outside, co_adjacent, post_age_seconds, post_time,
    # raw_nodes, age_seconds, state ("unconfirmed" | "past_grace")}]
    unconfirmed: list = field(default_factory=list)
    # node -> the raw `nodes` string of its record (capped), and node -> the
    # record's `stats.data.time` epoch (None when unusable). Evidence only.
    raw_nodes: dict = field(default_factory=dict)
    post_time: dict = field(default_factory=dict)
    # Node health (2026-10-18): which nodes' records the walk OBTAINED this
    # scan (`fetched`, any content) and which fetches FAILED outright (API
    # error / 429 / timeout — `fetch_failed`). The two sets are disjoint. A
    # failed fetch of a node's expected parent gates health recording for
    # its children; a failed hub fetch also gates presence recording.
    fetched: set = field(default_factory=set)
    fetch_failed: set = field(default_factory=set)
    # node -> its own record's `node.regseconds` (registry registration
    # epoch; None when absent), for every fetched node; and node -> the
    # `regseconds` copy carried in ANOTHER node's linkedNodes entry (same
    # registry column) for every peer listed by a fetched node.
    regseconds: dict = field(default_factory=dict)
    peer_regseconds: dict = field(default_factory=dict)
    # DNS cross-check (2026-10-19): node -> (ipaddr, port) from its own
    # record's `node.ipaddr` / `node.port` (the registry's view of where the
    # node is — `node.port` is the port the registry OBSERVED, not necessarily
    # the node's IAX port), and node -> `stats.data.apprptvers` (software
    # version, display only; it implies nothing about HamVoIP registration).
    # Both None/absent when the record lacks them. Display/analytics only.
    node_addr: dict = field(default_factory=dict)
    node_version: dict = field(default_factory=dict)
    # node -> record_public(data): display-only facts for the team status
    # page (callsign, frequency, location, uptime, key-ups, link tokens…).
    node_public: dict = field(default_factory=dict)

    @property
    def has_problems(self) -> bool:
        return len(self.bridging_events) > 0


def event_has_monitor_link(result: "ScanResult", event: "BridgingEvent") -> bool:
    """True when a DRAWN edge touching the offender — its link to its parent,
    or a child's link to it — is monitor-only (R) or local-monitor (L) from
    either end's report. Uses the per-entry keys the map renderer styles, so
    the cover email never promises a dashed arrow the attached render does
    not show. Presentation only; never detection."""
    def listens(info: dict) -> bool:
        return (info.get("link_mode_to_parent") in ("R", "L")
                or info.get("link_mode_from_parent") in ("R", "L"))
    o = str(event.offending_node)
    for nid, info in result.topology.items():
        if str(nid) == o or str(info.get("parent")) == o:
            if listens(info):
                return True
    return False


class GraphAnalyzer:
    """Analyzes AllStarLink node topology for unauthorized bridging.

    Uses the two-screen detection model described in the module docstring.
    """

    DEFAULT_STALE_THRESHOLD_MINUTES = 120

    DEFAULT_MAX_DRAGGED_IN = 30  # cap on informational deep-walk cataloging

    # Change 1: how recent a post must be for an EMPTY record to read as
    # "reporting no links" (linkless) rather than dark. Sized to the stats
    # post cadence (live 2026-09-08 04:1x: post ages 5-25 s on three nodes),
    # NOT to stale_threshold_minutes (120 min, an evidence-INCLUSION window
    # for far-end attribution — the opposite safety direction; audit S2).
    # If the stats server keeps serving a node's last record after it stops
    # posting, this is also the longest a node whose last post named no
    # links can go truly dark before dark tracking starts; confirmation then
    # takes confirm_scans more scans (audit C1). Linkless nodes earn no
    # posting-hiccup grace, so nothing compounds this. 0 disables the
    # classification (every empty record is dark, as before change 1).
    DEFAULT_LINKLESS_FRESH_SECONDS = 600
    # Coherence (2026-10-12): a guest whose own record keeps NOT naming the
    # node it is attached to, for longer than this while still attached, is
    # either posting a stuck record or suppressing it. Past this grace the
    # node is flagged `past_grace` (one WARNING, /status, daily digest) but
    # STILL not judged — never cut, never emailed (v1; see _coherence_gate).
    # ~2 x the 60 s post cadence + the measured API lag, rounded up.
    DEFAULT_MAX_UNCONFIRMED_SECONDS = 240

    def __init__(self, api_client: ASLApiClient, focus_node: int,
                 bridge_nodes: list[int],
                 allowlist: Optional[list[int]] = None,
                 stale_threshold_minutes: float = DEFAULT_STALE_THRESHOLD_MINUTES,
                 max_dragged_in_nodes: int = DEFAULT_MAX_DRAGGED_IN,
                 permit_listeners: bool = False,
                 linkless_fresh_seconds: float = DEFAULT_LINKLESS_FRESH_SECONDS,
                 coherence_enabled: bool = True,
                 max_unconfirmed_seconds: float = DEFAULT_MAX_UNCONFIRMED_SECONDS):
        self.api = api_client
        self.focus_node = focus_node
        self.bridge_nodes = set(bridge_nodes)
        self.allowlist = set(allowlist or [])
        self.stale_threshold_minutes = stale_threshold_minutes
        try:
            self.linkless_fresh_seconds = max(0.0, float(linkless_fresh_seconds))
        except (TypeError, ValueError):
            logger.warning("linkless_fresh_seconds=%r is not a number — using the "
                           "default %s", linkless_fresh_seconds,
                           self.DEFAULT_LINKLESS_FRESH_SECONDS)
            self.linkless_fresh_seconds = float(self.DEFAULT_LINKLESS_FRESH_SECONDS)
        # Coherence (2026-10-12): see ScanResult.unconfirmed. With the toggle
        # off, the gate is skipped and today's verdicts return.
        self.coherence_enabled = bool(coherence_enabled)
        try:
            # Floor 30 s: the prune window is 2x this, and a grace shorter
            # than one scan interval can never be reached (audit A3).
            self.max_unconfirmed_seconds = max(30.0, float(max_unconfirmed_seconds))
        except (TypeError, ValueError):
            logger.warning("max_unconfirmed_seconds=%r is not a number — using the "
                           "default %s", max_unconfirmed_seconds,
                           self.DEFAULT_MAX_UNCONFIRMED_SECONDS)
            self.max_unconfirmed_seconds = float(self.DEFAULT_MAX_UNCONFIRMED_SECONDS)
        # node -> (first_seen, last_seen) monotonic times of an INCOHERENT
        # record while the node stayed attached. Persists across scans; the
        # daemon carries it over a SIGHUP rebuild (like _connecting_first_seen).
        self._unconfirmed_first_seen: dict = {}
        self._incoherent_warned: set = set()   # nodes warned once past the grace
        # Phase 2 (2026-09-07, trustee decision pending — default OFF): a
        # node whose EVERY AllStar link is monitor-only by its own stats
        # report is a permitted "listener": its outside links move no audio
        # across the system boundary in either direction. Any transceive
        # (or unreported) link anywhere keeps today's verdict. With the
        # toggle off, nothing below changes behavior.
        self.permit_listeners = bool(permit_listeners)
        # Step 2 trigger B (2026-09-07): node id -> reason. A node here is
        # refused listener status regardless of its self-report — the daemon
        # fills it when the vantage saw the node KEYED toward us over a link
        # it reports as monitor-only (a true monitor link never keys toward
        # the monitored node). The daemon expires entries; the reason lands
        # in the violation email's REPORTED LINK MODES line.
        self.listener_veto: dict[int, str] = {}
        self.listener_veto_seen: set = set()   # ids whose veto a scan consulted
        # Cap on the depth>=4 "drag-in" catalog walk. The walk adds NO detection
        # (the offender is already identified at depth 2-3) — it only logs the
        # extent of the foreign mesh. On a huge event that walk fetched 264
        # nodes (~13 min, each rate-limited), which delayed the end-of-scan image
        # AND the auto-disconnect phase until long after the link self-resolved.
        # Capping it keeps scans short so action stays timely.
        self.max_dragged_in_nodes = max_dragged_in_nodes
        # Optional callback fired exactly once per scan, the instant the FIRST
        # bridging event is detected — used to trigger immediate bubble-map
        # evidence capture before the deep drag-in walk finishes and before the
        # offending link can self-resolve. Receives the in-progress ScanResult.
        # Exceptions are swallowed so a capture failure can never abort a scan.
        self.on_first_detection: Optional[Callable[["ScanResult"], None]] = None
        # Optional callback fired (synchronously, on the scan thread) for EACH
        # bridging event the instant it is recorded — used to attempt auto-
        # disconnect AT DETECTION TIME rather than after the walk. Receives the
        # BridgingEvent. Exceptions are swallowed so a disconnect failure can
        # never abort a scan.
        self.on_violation: Optional[Callable[["BridgingEvent"], None]] = None
        self._detection_fired = False
        self._fetch_mono: dict = {}      # node -> monotonic time of its last fetch
        self._dragged_in_count = 0
        self._cap_logged = False
        # Change 3: (node, target) -> (first_seen, last_seen) monotonic times
        # of a CONNECTING pair. Persists across scans and is carried over a
        # SIGHUP rebuild by the daemon; entries not re-seen within the grace
        # are pruned.
        self._connecting_first_seen: dict = {}

    def _fetch_details(self, node_id: int, result: "ScanResult"):
        """Fetch a node's linked-node details AND record its numeric links into
        the undirected edge union (result.edges).

        Thin wrapper around the API call: return value is unchanged (None on
        API error, [] for a non-reporting node), so all existing control flow
        is untouched. The only side effect is populating result.edges for the
        structured hidden-path analysis (Item B). External (RepeaterPhone /
        WebTransceiver / EchoLink) pseudo-links and node_id 0 are excluded —
        they are leaf transports, not graph edges.
        """
        # Stamp BEFORE the call: the earliest the record could describe
        # (conservative for link_watch's stale-evidence gate).
        self._fetch_mono[node_id] = time.monotonic()
        # One HTTP fetch: the raw record gives both the link list and the
        # post age (change 1 — "posts nothing" vs "posts no links").
        data = self.api.get_node_stats(node_id)
        details = (None if data is None
                   else self.api.get_linked_node_details(node_id, data=data))
        result.post_age[node_id] = ASLApiClient.post_age_seconds(data)
        # Node health (2026-10-18): fetched / failed bookkeeping + the
        # record's own registration epoch. Display/analytics only.
        if data is None:
            result.fetch_failed.add(node_id)
        else:
            result.fetched.add(node_id)
            try:
                rs = (data.get("node") or {}).get("regseconds")
                result.regseconds[node_id] = int(rs) if rs is not None else None
            except (TypeError, ValueError, AttributeError, OverflowError):
                result.regseconds[node_id] = None
            result.node_addr[node_id] = record_addr(data)
            result.node_version[node_id] = record_version(data)
            result.node_public[node_id] = record_public(data)
        # Audit S1/round-2 #2: any RAW token in the `nodes` string counts as
        # a named link (parse_link_modes drops conflicting/unknown letters —
        # not a safe gate). Fails CLOSED: junk shapes count as naming links.
        try:
            stats_data = (((data or {}).get("stats") or {}).get("data") or {})
            raw_nodes = stats_data.get("nodes")
            # Coherence evidence: keep the raw string and the post's epoch.
            if isinstance(raw_nodes, str):
                result.raw_nodes[node_id] = raw_nodes[:2000]
            elif raw_nodes is not None:
                result.raw_nodes[node_id] = repr(raw_nodes)[:2000]
            try:
                pt = int(stats_data.get("time"))
                result.post_time[node_id] = pt if pt > 0 else None
            except (TypeError, ValueError):
                result.post_time[node_id] = None
            if raw_nodes is None or raw_nodes == "":
                pass
            elif isinstance(raw_nodes, str):
                if any(tok.strip() for tok in raw_nodes.split(",")):
                    result.names_links.add(node_id)
            else:
                result.names_links.add(node_id)
        except Exception:
            result.names_links.add(node_id)
        if details:
            result.posting.add(node_id)
            for d in details:
                nid = d.get("node_id", 0)
                is_ext = d.get("is_external", False)
                # Skip node_id 0, external pseudo-links, and any self-loop
                # (a 1-element frozenset would break the BFS edge unpack).
                if nid and nid != node_id and not is_ext:
                    result.edges.add(frozenset((node_id, nid)))
                if nid and not is_ext:
                    # The peer's registry regseconds ride in this entry.
                    try:
                        rs = int(d.get("regseconds") or 0)
                        if rs > 0:
                            result.peer_regseconds[nid] = rs
                    except (TypeError, ValueError):
                        pass
                # Link mode from this node's own report (see ScanResult).
                mode = d.get("link_mode")
                if mode:
                    peer = d.get("external_name") if is_ext else (str(nid) if nid else None)
                    if peer:
                        result.link_modes[(str(node_id), str(peer))] = mode
        return details

    def _fresh_linkless(self, node_id: int, result: "ScanResult") -> bool:
        """True when the node's EMPTY link list came from a post within
        linkless_fresh_seconds AND the record's `nodes` string names no link
        either: the node is reporting, and reports nothing linked. Change 1
        (2026-09-08). None/stale/far-future post time, or a `nodes` string
        that names a link -> False (dark path, as before). The caller still
        requires DNS registration."""
        if self.linkless_fresh_seconds <= 0:     # 0 disables the classification
            return False
        if node_id in result.names_links:
            return False
        age = result.post_age.get(node_id)
        if age is None:
            return False
        try:
            return float(age) <= self.linkless_fresh_seconds
        except (TypeError, ValueError):
            return False

    def _record_linkless(self, node_id: int, attached_to: int, attachment: str,
                         callsign: str, co_adjacent: list, result: "ScanResult") -> None:
        age = result.post_age.get(node_id)
        age_txt = f"{age:.0f} s" if isinstance(age, (int, float)) else "?"
        logger.info(
            f"  Node {node_id} is posting (post age {age_txt}) but reports "
            f"no links while {attached_to} still lists it — linkless, not "
            f"dark (typically the attach-side link stuck, no audio path).")
        # NOT added to result.posting (round-2 audit C1): the posting-hiccup
        # grace forgives a node KNOWN to report its links; an empty record
        # proves nothing about links, and crediting it would let a node that
        # posts one empty record per grace period never be confirmed.
        result.linkless.append({
            "node": node_id, "attached_to": attached_to,
            "attachment": attachment, "callsign": callsign,
            "co_adjacent": co_adjacent, "post_age_seconds": age})

    @staticmethod
    def _peer_name(nid, info: dict) -> str:
        """Raw API-facing name of a topology entry: the node number, or the
        external's display name (stored as callsign at both ext_* sites)."""
        if isinstance(nid, str) and nid.startswith("ext_"):
            return str(info.get("callsign", nid))
        return str(nid)

    def _apply_link_modes(self, result: "ScanResult") -> None:
        """Post-pass: stamp each child entry with both ends' view of its link
        to its parent, for the map renderer. None when a side never reported."""
        modes = result.link_modes
        for nid, info in result.topology.items():
            parent = info.get("parent")
            if parent is None:
                continue
            child = self._peer_name(nid, info)
            p = str(parent)
            info["link_mode_from_parent"] = modes.get((p, child))
            info["link_mode_to_parent"] = modes.get((child, p))

    def _link_mode_summary(self, result: "ScanResult", offender: int,
                           parent: int, outside: list[int]) -> str:
        """One-line T/R/L/C summary for an offender: its link to the system
        node it hangs off (both views) and its links beyond (its own view)."""
        modes = result.link_modes
        o, p = str(offender), str(parent)
        own = modes.get((o, p)) or "?"
        theirs = modes.get((p, o)) or "?"
        parts = [f"to {parent}: {own} ({offender} view) / {theirs} ({parent} view)"]
        if outside:
            # Capped like every other section of the violation email — a
            # mass-bridge offender must not grow the line without bound.
            shown = outside[:20]
            beyond = ", ".join(f"{n} {modes.get((o, str(n))) or '?'}" for n in shown)
            if len(outside) > len(shown):
                beyond += f" (+{len(outside) - len(shown)} more)"
            parts.append(f"beyond: {beyond} ({offender} view)")
        veto = self.listener_veto.get(int(offender)) if str(offender).isdigit() else None
        if veto:
            parts.append(f"LISTENER STATUS REFUSED: {veto}")
        return "; ".join(parts)

    # ---- Phase 2: permitted listeners -------------------------------------

    _LISTEN = ("R", "L")

    def _is_listener(self, result: "ScanResult", node: int, attach: int,
                     raw_links: list[int]) -> bool:
        """Listener test on the node's OWN report: its link to `attach` (the
        system node it hangs off) AND every other AllStar link it has —
        the RAW list, before any bridge/allowlist/liveness filtering, so a
        transceive link to an allowlisted peer, a second bridge or the hub
        disqualifies — must be R or L. A missing letter fails the test."""
        if not self.permit_listeners:
            return False
        veto = self.listener_veto.get(int(node))
        if veto:
            self.listener_veto_seen.add(int(node))
            logger.warning(f"  Node {node}: listener status REFUSED — {veto}")
            return False
        modes = result.link_modes
        n = str(node)
        if modes.get((n, str(attach))) not in self._LISTEN:
            return False
        others = [p for p in raw_links if p != attach and p != node]
        return all(modes.get((n, str(p))) in self._LISTEN for p in others)

    # Change 3: how long a link may stay CONNECTING (C) before it is judged
    # as an established link again (today's rule). A real dial settles in
    # seconds; a link still C after this is either stuck (no audio, and a
    # cut is harmless) or a report we should not keep trusting (audit C1).
    CONNECTING_GRACE_SECONDS = 600

    def _split_connecting(self, result: "ScanResult", node: int, attach: int,
                          attachment: str, links: list[int]) -> list[int]:
        """Change 3: remove the node's CONNECTING (C) links to OUTSIDE nodes
        from `links` — for at most CONNECTING_GRACE_SECONDS per (node,
        target) pair — record them on result.connecting, and return the
        established links. Only the node's OWN report can say C
        (result.link_modes is keyed by observer). Never split out: the link
        back to `attach`, the hub, or any designated bridge (a C toward a
        system node keeps disqualifying the listener, as before)."""
        modes = result.link_modes
        n = str(node)
        now = time.monotonic()
        grace = self.CONNECTING_GRACE_SECONDS
        # Prune: an entry not re-seen within a grace period is a finished
        # dial (or a node that left) — it must not cancel the grace of a
        # later dial to the same target (round-2 audit S4). Bounded size.
        for key in [k for k, (first, last) in self._connecting_first_seen.items()
                    if now - last > grace]:
            self._connecting_first_seen.pop(key, None)
        kept: list[int] = []
        for p in links:
            is_c = (p != attach and p != node and p != self.focus_node
                    and p not in self.bridge_nodes
                    and modes.get((n, str(p))) == "C")
            if not is_c:
                kept.append(p)
                continue
            first, _last = self._connecting_first_seen.get((node, p), (now, now))
            self._connecting_first_seen[(node, p)] = (first, now)
            age = now - first
            if age > self.CONNECTING_GRACE_SECONDS:
                logger.warning(
                    f"  Node {node} has reported {p} as CONNECTING for {age:.0f} s "
                    f"(> {self.CONNECTING_GRACE_SECONDS} s grace) — treated as an "
                    f"established link again.")
                kept.append(p)
                continue
            result.connecting.append({"node": node, "target": p,
                                      "attached_to": attach,
                                      "attachment": attachment,
                                      "age_seconds": int(age)})
            result.edges.discard(frozenset((node, p)))   # not an audio path
            logger.info(
                f"  Node {node} reports {p} as CONNECTING (dialled, not yet "
                f"answered; {age:.0f} s) — not a link yet: ignored for the "
                f"listener test and for bridging until it settles or the "
                f"{self.CONNECTING_GRACE_SECONDS} s grace ends.")
        # forget this node's pairs no longer reported as C (a later dial
        # starts fresh); pairs of nodes not walked this scan age out above.
        live = {(node, p) for p in links
                if modes.get((n, str(p))) == "C"}
        for key in [k for k in self._connecting_first_seen
                    if k[0] == node and k not in live]:
            self._connecting_first_seen.pop(key, None)
        return kept

    # ---- Coherence gate (2026-10-12) ----------------------------------------

    def _coherence_gate(self, result: "ScanResult", node: int, attach: int,
                        attachment: str, raw_links: list[int],
                        co_adjacent: list, detail_map: dict,
                        exclude: Optional[list[int]] = None) -> bool:
        """Same-instant test on a guest's (or non-bridge hop-1 node's) OWN
        stats record BEFORE any Screen-2 judgement.

        The attach node's record says the node is attached; the node's own
        record is what names its outside links. Those are two records from
        two clocks. When the node's record does NOT name `attach` at all it
        was posted before the join (or after a leave) — the stats API served
        a record 45 s+ stale on every real cut to date — so its outside
        links are equally old and prove nothing about a simultaneous link.

        Returns True when the caller must STOP (the node is recorded in
        result.unconfirmed: no event, no listener verdict, no walk, no
        topology entry; its node->outside edges are dropped from the union).
        Returns False when the record is coherent (names `attach`, or any
        system node whose record lists it), names no live outside node, or
        the gate is disabled — the caller then proceeds exactly as before.
        Past max_unconfirmed_seconds the node is marked `past_grace` and
        warned about once; it is still never cut or emailed (v1)."""
        if not self.coherence_enabled:
            self._unconfirmed_first_seen.clear()      # a SIGHUP that turned it off
            self._incoherent_warned.clear()
            return False
        n = str(node)
        modes = result.link_modes
        # Coherent = the node's OWN record names the node it is attached to:
        # in linkedNodes, as a mode letter, or as a raw `nodes` token (audit
        # A2 — the two fields can disagree). Also coherent when it names ANY
        # system node (hub/bridge) whose own record lists it — a guest on two
        # system nodes is judged on whichever record is fresh (audit A1).
        system_nodes = {self.focus_node, *self.bridge_nodes}
        raw_tokens = set(re.findall(r"\d+", result.raw_nodes.get(node) or ""))
        def _names(peer: int) -> bool:
            return (peer in raw_links or modes.get((n, str(peer))) is not None
                    or str(peer) in raw_tokens)
        coherent = _names(attach) or any(
            _names(s) and modes.get((str(s), n)) is not None
            for s in system_nodes if s != attach)
        if coherent:
            self._unconfirmed_first_seen.pop(node, None)
            self._incoherent_warned.discard(node)
            return False
        # Only now (the record is incoherent) the outside filter — the same
        # one the Screen-2 path applies before it would fire, DNS lookups
        # included: a dead (DNS-unregistered) outside peer never produced an
        # event, so it must not make a record "unconfirmed" either. Cheap for
        # the common coherent case (audit S7: no lookups above this line).
        excl = set(exclude or [])
        outside = [p for p in raw_links
                   if p not in (attach, self.focus_node, node)
                   and p not in self.bridge_nodes
                   and p not in self.allowlist
                   and p not in excl
                   and self._is_node_alive(p, (detail_map or {}).get(p, {}))]
        if not outside:
            self._unconfirmed_first_seen.pop(node, None)
            self._incoherent_warned.discard(node)
            return False
        now = time.monotonic()
        max_s = self.max_unconfirmed_seconds
        # Prune: a node not re-seen incoherent within 2 x the grace starts fresh.
        for key in [k for k, (_f, last) in self._unconfirmed_first_seen.items()
                    if now - last > 2 * max_s]:
            self._unconfirmed_first_seen.pop(key, None)
            self._incoherent_warned.discard(key)
        first, _last = self._unconfirmed_first_seen.get(node, (now, now))
        self._unconfirmed_first_seen[node] = (first, now)
        age = now - first
        pa = result.post_age.get(node)
        pa_txt = f"{pa:.0f} s" if isinstance(pa, (int, float)) else "?"
        state = "unconfirmed"
        if age > max_s:
            # Past the grace the node is STILL not judged (v1, 2026-10-13):
            # three audit rounds showed that enforcing on "the live mesh
            # shows the guest and a claimed outside node" cannot be made safe
            # without tying the release to the exact evidence (walk order,
            # non-foreign nodes beyond the walk cap, flags outliving their
            # decision). A stuck record is surfaced — one WARNING, /status,
            # the daily digest — and the link-state watchdog / tripwire
            # remain the backstop for a real foreign mesh behind it.
            state = "past_grace"
            if node not in self._incoherent_warned:
                self._incoherent_warned.add(node)
                logger.warning(
                    f"  Node {node}: record persistently INCOHERENT ({age:.0f} s > "
                    f"{max_s:.0f} s; never named {attach}; post age {pa_txt}; "
                    f"claims {outside[:20]}) — NOT enforced (no automatic "
                    f"enforcement on a record that never names its attach node); "
                    f"see /status unconfirmed and the daily digest.")
        for p in outside:
            result.edges.discard(frozenset((node, p)))    # not a proven audio path
        # Not judged this scan: no "seen posting" credit for the dark-guest
        # tracker (audit S1 — a stale record is not a live report, same as
        # linkless), and unobserved so a known listener keeps its
        # registration / the watcher does not treat it as gone (audit A5).
        result.posting.discard(node)
        if state != "past_grace":
            # Inside the grace: unobserved, so a known listener keeps its
            # registration across a transient stale record. PAST the grace
            # it is dropped from unobserved on purpose (round-4 audit S1):
            # a listener whose record no longer names the bridge for minutes
            # must lose its registration and its watchdog allowance.
            result.unobserved.add(node)
        callsign = result.topology.get(node, {}).get("callsign", "Unknown")
        result.unconfirmed.append({
            "node": node, "callsign": callsign,
            "attached_to": attach, "attachment": attachment,
            "outside": outside[:50],
            "co_adjacent": [x for x in (co_adjacent or []) if x],
            "post_age_seconds": pa,
            "post_time": result.post_time.get(node),
            "raw_nodes": (result.raw_nodes.get(node) or "")[:200],
            "age_seconds": int(age),
            "state": state,
        })
        logger.info(
            f"  Node {node} ({callsign}) via {attachment} {attach}: own record does "
            f"NOT name {attach} (post age {pa_txt}; raw nodes "
            f"'{(result.raw_nodes.get(node) or '')[:80]}') but claims "
            f"{outside[:20]} — a pre-join/post-leave record, not evidence of a "
            f"simultaneous link: UNCONFIRMED ({age:.0f} s), no event; re-look "
            f"requested by the daemon.")
        return True

    def _record_listener(self, result: "ScanResult", node: int, attach: int,
                         attachment: str, outside: list[int], detail_map: dict,
                         depth: int) -> None:
        """Record a permitted listener: its live outside nodes become
        `monitored_by_guest` entries (no event, no walk beyond), their edges
        leave `result.edges` (not audio paths), and the listener is listed on
        the result for /status, link_watch and the notice email."""
        recorded: list[int] = []
        for n in outside:
            if n in result.topology:
                continue  # never overwrite an entry another path owns
            info = detail_map.get(n, {})
            if not self._is_node_alive(n, info):
                continue  # stale/offline link — keep it out of the roster
            result.topology[n] = {
                "depth": depth, "parent": node, "role": "monitored_by_guest",
                "client_type": "allstar",
                "callsign": info.get("callsign", "Unknown"),
                "location": info.get("location", "Unknown"),
                **_display_fields(info),
            }
            result.edges.discard(frozenset((node, n)))
            recorded.append(n)
        summary = self._link_mode_summary(result, node, attach, outside)
        node_info = result.topology.get(node, {})
        result.listeners.append({
            "node": node,
            "callsign": node_info.get("callsign", "Unknown"),
            "attached_to": attach,
            "attachment": attachment,
            "monitored": recorded,
            "summary": summary,
        })
        logger.info(
            f"  Node {node} ({node_info.get('callsign', '?')}) is a permitted "
            f"LISTENER (every link monitor-only by its own report) via "
            f"{attachment} {attach}; monitored outside nodes: "
            f"{recorded or '(none live)'}. Modes: {summary}")

    def _record_evidence(self, result: "ScanResult", node: int) -> dict:
        """Coherence evidence fields for a BridgingEvent about `node`."""
        clock = self._unconfirmed_first_seen.get(node)
        return {
            "guest_post_age_seconds": result.post_age.get(node),
            "guest_post_time": result.post_time.get(node),
            "guest_raw_nodes": (result.raw_nodes.get(node) or "")[:2000],
            # v1: no event is ever emitted for an incoherent record (the
            # past-grace enforcement path was withdrawn after audit); kept
            # for the email/consumers, always None.
            "incoherent_for_seconds": None,
            # With the gate on, an event is emitted only for a record the
            # gate judged coherent (clock popped).
            "guest_record_coherent": bool(self.coherence_enabled and clock is None),
        }

    def _emit_event(self, result: "ScanResult", event: "BridgingEvent") -> None:
        """Record a bridging event and fire the first-detection callback once.

        Centralizes event recording so immediate evidence capture is triggered
        the moment the FIRST violation is seen in a scan, rather than after the
        full topology walk completes (which can take minutes and outlast a
        transient offending link).
        """
        if not getattr(event, "observed_at", 0):
            try:
                event.observed_at = self._fetch_mono.get(
                    event.offending_node,
                    getattr(self, "_scan_started_mono", 0.0))
            except Exception:
                pass
        result.bridging_events.append(event)
        logger.warning(str(event))
        if event.link_modes:
            logger.info(f"  Link modes (self-reported to ASL stats; T transceive, "
                        f"R monitor, L local monitor, C connecting) for "
                        f"{event.offending_node}: {event.link_modes}")
        pa = getattr(event, "guest_post_age_seconds", None)
        logger.info(f"  Offender record evidence for {event.offending_node}: post age "
                    f"{(f'{pa:.0f} s' if isinstance(pa, (int, float)) else '?')}, "
                    f"post time {getattr(event, 'guest_post_time', None)}, raw nodes "
                    f"'{(getattr(event, 'guest_raw_nodes', '') or '')[:200]}'")
        if not self._detection_fired:
            self._detection_fired = True
            cb = self.on_first_detection
            if cb is not None:
                try:
                    cb(result)
                except Exception as e:  # never let capture abort a scan
                    logger.error(f"on_first_detection callback failed: {e}")
        # Per-event action hook (auto-disconnect at detection time). Fires for
        # EVERY event, AFTER on_first_detection so the evidence image is captured
        # before any disconnect changes the topology. Errors are swallowed.
        if self.on_violation is not None:
            try:
                self.on_violation(event)
            except Exception as e:  # never let a disconnect abort a scan
                logger.error(f"on_violation callback failed: {e}")

    def scan(self) -> ScanResult:
        """Perform a full topology scan from the focus node.

        Walks outward from the focus node, applying the two-screen
        detection rules at each hop.
        """
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        result = ScanResult(
            timestamp=timestamp,
            focus_node=self.focus_node,
            bridge_nodes=list(self.bridge_nodes),
            bridging_events=[],
            topology={},
        )
        # Reset per-scan latches/counters.
        self._detection_fired = False
        self._fetch_mono = {}
        self._scan_started_mono = time.monotonic()
        self._dragged_in_count = 0
        self._cap_logged = False

        # === HOP 0: Query the focus node ===
        logger.info(f"Querying focus node {self.focus_node}...")
        focus_details = self._fetch_details(self.focus_node, result)
        if focus_details is None:
            msg = f"Failed to query focus node {self.focus_node}"
            logger.error(msg)
            result.errors.append(msg)
            return result
        if len(focus_details) == 0:
            # An EMPTY hub record is a degraded scan, not an empty system
            # (audit 2026-09-08 A2): every downstream consumer would otherwise
            # see a one-node roster and purge its state.
            msg = f"Focus node {self.focus_node} returned an empty record (not posting?)"
            logger.error(msg)
            result.errors.append(msg)
            result.unobserved.add(self.focus_node)

        hop0_links = [d["node_id"] for d in focus_details if d["node_id"] != 0]
        detail_map_focus = {d["node_id"]: d for d in focus_details}

        result.topology[self.focus_node] = {
            "depth": 0, "parent": None, "role": "focus",
            "client_type": "allstar",
            "callsign": "Focus", "location": "Hub",
            **_display_fields({}),
        }
        logger.info(f"Focus node {self.focus_node}: {len(hop0_links)} direct links: {hop0_links}")

        # === HOP 1: Classify each direct connection ===
        for node_id in hop0_links:
            info = detail_map_focus.get(node_id, {})
            callsign = info.get("callsign", "Unknown")
            location = info.get("location", "Unknown")

            if node_id in self.bridge_nodes:
                role = "bridge"
                logger.info(f"  Hop 1: Node {node_id} ({callsign}) — BRIDGE node")
            else:
                role = "regular"
                logger.info(f"  Hop 1: Node {node_id} ({callsign}) — regular 1-hop node")

            result.topology[node_id] = {
                "depth": 1, "parent": self.focus_node, "role": role,
                "client_type": "allstar",
                "callsign": callsign, "location": location,
                **_display_fields(info),
            }

        # === HOP 2+: Walk outward from each 1-hop node ===
        for hop1_node in hop0_links:
            hop1_info = result.topology[hop1_node]
            is_bridge = hop1_info["role"] == "bridge"

            logger.info(f"Checking hop-1 node {hop1_node} ({hop1_info['callsign']})...")

            # Query this node's connections
            hop1_details = self._fetch_details(hop1_node, result)
            if hop1_details is None:
                logger.warning(f"API error querying node {hop1_node}")
                result.unobserved.add(hop1_node)
                continue
            if len(hop1_details) == 0:
                result.unobserved.add(hop1_node)
                # Non-reporting node — DNS check for visibility
                dns_info = check_node_dns(hop1_node)
                if dns_info.is_registered and self._fresh_linkless(hop1_node, result):
                    # Change 1: in DNS AND posted recently, empty link list
                    # -> linkless, not dark. (A retained record with a
                    # recent time but no DNS entry falls through to the
                    # offline branch below, as before; audit S3.) Bridges /
                    # allowlisted nodes are listed in neither.
                    if not is_bridge and hop1_node not in self.allowlist:
                        self._record_linkless(
                            hop1_node, self.focus_node, "hub",
                            hop1_info.get("callsign", "Unknown"),
                            [n for n in hop0_links if n and n != hop1_node],
                            result)
                    else:
                        logger.info(f"  Node {hop1_node} is posting but reports "
                                    f"no links (system/allowlisted node).")
                    continue
                if dns_info.is_registered:
                    logger.info(
                        f"  Node {hop1_node} has no stats but IS registered "
                        f"in DNS ({dns_info.ip_address}:{dns_info.port}) — "
                        f"online but link list not visible (non-reporting)."
                    )
                    if not is_bridge and hop1_node not in self.allowlist:
                        # co_adjacent: every numeric node the attach node
                        # itself reports as linked (allowlisted peers and
                        # other bridges included) — the tracker's
                        # ambiguity test must see ALL of them (audit C5).
                        result.dark_guests.append({
                            "node": hop1_node, "attached_to": self.focus_node,
                            "attachment": "hub",
                            "callsign": hop1_info.get("callsign", "Unknown"),
                            "co_adjacent": [n for n in hop0_links
                                            if n and n != hop1_node]})
                else:
                    logger.info(
                        f"  Node {hop1_node} has no stats and NOT in DNS — "
                        f"likely offline. Link may be stale."
                    )
                continue

            # External connections (RepeaterPhone / WebTransceiver / EchoLink) on a
            # hop-1 node are PERMITTED regardless of whether the hop-1 is a designated
            # bridge. These transports are inherently single-user "intimate" leaf
            # endpoints: the AllStarLink protocol treats them as local to the node
            # they attach to, and a node can only carry one of each transport type
            # at a time. They cannot themselves bridge into another network, so
            # tolerating them does not expose the focus system to foreign AllStar
            # traffic. Recorded in topology with role=permitted_external for
            # visibility, but no BridgingEvent is fired.
            external_connections = [d for d in hop1_details if d.get("is_external", False)]
            for ext in external_connections:
                ext_name = ext.get("external_name", "Unknown")
                result.topology[f"ext_{hop1_node}_{ext_name}"] = {
                    "depth": 2, "parent": hop1_node, "role": "permitted_external",
                    "client_type": ext.get("client_type", "webtransceiver_type"),
                    "callsign": ext_name, "location": "External Connection",
                    **_display_fields(ext),
                }
                logger.info(
                    f"  Hop-1 node {hop1_node} ({hop1_info['callsign']}) has "
                    f"external connection '{ext_name}' — permitted (transceive-like leaf)"
                )

            hop1_links = [d["node_id"] for d in hop1_details
                          if not d.get("is_external", False) and d["node_id"] != 0]
            detail_map_hop1 = {d["node_id"]: d for d in hop1_details
                               if not d.get("is_external", False)}

            # Focus enrichment (display-only, 2026-07-04): the focus node
            # appears as a full linkedNodes record in each hop-1 node's stats,
            # so its real callsign/location/frequency ride along for free —
            # no extra API call. Replaces the "Focus"/"Hub" placeholders.
            focus_rec = detail_map_hop1.get(self.focus_node)
            if focus_rec and result.topology[self.focus_node]["callsign"] == "Focus":
                result.topology[self.focus_node].update({
                    "callsign": focus_rec.get("callsign", "Focus"),
                    "location": focus_rec.get("location", "Hub"),
                    **_display_fields(focus_rec),
                })

            # Change 3: a non-bridge hop-1 node's CONNECTING links are not
            # links yet — neither listener-disqualifying nor bridging.
            hop1_links_raw = list(hop1_links)   # incl. CONNECTING peers, for the summary
            # Coherence (2026-10-12): judged FIRST, on the raw list — nothing
            # below may run on a record that predates the attachment.
            if (not is_bridge
                    and self._coherence_gate(
                        result, hop1_node, self.focus_node, "hub", hop1_links,
                        [n for n in hop0_links if n != hop1_node], detail_map_hop1,
                        exclude=[n for n in hop0_links if n != hop1_node])):
                continue
            if not is_bridge:
                hop1_links = self._split_connecting(
                    result, hop1_node, self.focus_node, "hub", hop1_links)

            # Phase 2: a NON-bridge hop-1 node whose every link (to the hub
            # and beyond) is monitor-only is a permitted listener attached
            # at the hub. Decided once, on the raw link list, before any
            # per-hop2 skip rule can hide a transceive link.
            if (not is_bridge
                    and self._is_listener(result, hop1_node, self.focus_node,
                                          hop1_links)):
                self._record_listener(
                    result, hop1_node, self.focus_node, "hub",
                    [n for n in hop1_links if n != self.focus_node],
                    detail_map_hop1, depth=2)
                continue

            for hop2_node in hop1_links:
                # Skip links back to focus or to other known system nodes
                if hop2_node == self.focus_node:
                    continue
                if hop2_node in self.bridge_nodes:
                    # Bridge-to-bridge link — also forms a triangle through the
                    # focus (focus↔hop1, focus↔hop2, hop1↔hop2). The bubble-map
                    # image-processor drops one of the routed-around edges of
                    # such triangles, producing false hidden-path alerts; flag
                    # so cross_checker can suppress.
                    result.has_focus_triangle = True
                    continue
                if hop2_node in [n for n in hop0_links if n != hop1_node]:
                    # Two non-bridge 1-hop nodes that are also linked to each
                    # other — same triangle structure.
                    result.has_focus_triangle = True
                    continue
                if hop2_node in self.allowlist:
                    continue
                if hop2_node in result.topology:
                    continue  # Already seen at a closer distance

                hop2_info = detail_map_hop1.get(hop2_node, {})
                hop2_callsign = hop2_info.get("callsign", "Unknown")
                hop2_location = hop2_info.get("location", "Unknown")

                result.topology[hop2_node] = {
                    "depth": 2, "parent": hop1_node, "role": "guest" if is_bridge else "unauthorized",
                    "client_type": "allstar",
                    "callsign": hop2_callsign, "location": hop2_location,
                    **_display_fields(hop2_info),
                }

                if not is_bridge:
                    # SCREEN 2: Regular node has something beyond it — NOT allowed
                    if not self._is_node_alive(hop2_node, hop2_info):
                        continue

                    path = [self.focus_node, hop1_node, hop2_node]
                    # Offender is the boundary node (hop1) — it owns the connection
                    # to focus AND the connection beyond. hop2 is just on the receiving end.
                    event = BridgingEvent(
                        offending_node=hop1_node,
                        offending_callsign=hop1_info["callsign"],
                        offending_location=hop1_info.get("location", "Unknown"),
                        path=path,
                        path_description=f"{self.focus_node} → {hop1_node} → {hop2_node}",
                        depth=1,
                        rule=f"Screen 2: non-bridge node {hop1_node} has connection to {hop2_node}",
                        link_modes=self._link_mode_summary(
                            result, hop1_node, self.focus_node,
                            [n for n in hop1_links_raw
                             if n != self.focus_node and n not in self.bridge_nodes]),
                        **self._record_evidence(result, hop1_node),
                    )
                    self._emit_event(result, event)

                    # Also investigate what's beyond this unauthorized node
                    self._walk_beyond(hop2_node, [self.focus_node, hop1_node, hop2_node],
                                      result, depth=3)
                else:
                    # Bridge node — this hop 2 guest is allowed.
                    # But now check if the GUEST has further connections (hop 3).
                    logger.info(f"  Bridge {hop1_node} → guest {hop2_node} ({hop2_callsign}) — permitted")
                    self._check_beyond_guest(
                        hop2_node, hop1_node, detail_map_hop1,
                        [self.focus_node, hop1_node, hop2_node], result
                    )

        self._apply_link_modes(result)
        return result

    def _check_beyond_guest(self, guest_node: int, bridge_node: int,
                            bridge_detail_map: dict,
                            path_so_far: list[int], result: ScanResult):
        """Check if a guest node (hop 2 via bridge) has further connections.

        Any connection beyond the guest = problem (hop 3 via bridge).
        """
        guest_details = self._fetch_details(guest_node, result)
        if guest_details is None:
            logger.warning(f"API error querying guest node {guest_node}")
            result.unobserved.add(guest_node)
            return
        if len(guest_details) == 0:
            result.unobserved.add(guest_node)
            dns_info = check_node_dns(guest_node)
            if dns_info.is_registered and self._fresh_linkless(guest_node, result):
                # Change 1: in DNS and posted recently, empty link list ->
                # linkless, not dark (see the hop-1 twin above).
                if guest_node not in self.allowlist:
                    self._record_linkless(
                        guest_node, bridge_node, "bridge",
                        result.topology.get(guest_node, {}).get("callsign", "Unknown"),
                        [n for n in bridge_detail_map if n and n != guest_node],
                        result)
                else:
                    logger.info(f"  Guest {guest_node} is posting but reports "
                                f"no links (allowlisted).")
                return
            if dns_info.is_registered:
                logger.info(
                    f"  Guest {guest_node} has no stats but IS in DNS — "
                    f"online but link list not visible (non-reporting)."
                )
                if guest_node not in self.allowlist:
                    result.dark_guests.append({
                        "node": guest_node, "attached_to": bridge_node,
                        "attachment": "bridge",
                        "callsign": result.topology.get(guest_node, {}).get(
                            "callsign", "Unknown"),
                        "co_adjacent": [n for n in bridge_detail_map
                                        if n and n != guest_node]})
            else:
                logger.info(f"  Guest {guest_node} not in DNS — likely offline/stale.")
            return

        # Separate external (RepeaterPhone/EchoLink) and numeric node connections
        external_connections = [d for d in guest_details if d.get("is_external", False)]
        guest_links = [d["node_id"] for d in guest_details
                       if not d.get("is_external", False) and d["node_id"] != 0]
        detail_map_guest = {d["node_id"]: d for d in guest_details
                            if not d.get("is_external", False)}

        # External connections on a guest node are PERMITTED — the operator-owned
        # personal-hotspot pattern. See the matching block on the hop-1 path for
        # the rationale. Recorded in topology with role=permitted_external for
        # visibility; no BridgingEvent is fired. The numeric-AllStar-guest branch
        # below still flags real foreign bridging.
        for ext in external_connections:
            ext_name = ext.get("external_name", "Unknown")
            result.topology[f"ext_{ext_name}"] = {
                "depth": 3, "parent": guest_node, "role": "permitted_external",
                "client_type": ext.get("client_type", "webtransceiver_type"),
                "callsign": ext_name, "location": "External Connection",
                **_display_fields(ext),
            }
            guest_call = result.topology.get(guest_node, {}).get("callsign", "Unknown")
            logger.info(
                f"  Guest {guest_node} ({guest_call}) has external "
                f"connection '{ext_name}' — permitted (transceive-like leaf)"
            )

        # Coherence (2026-10-12): judged FIRST, on the raw list — nothing
        # below may run on a record that predates the attachment.
        if self._coherence_gate(
                result, guest_node, bridge_node, "bridge", guest_links,
                [n for n in bridge_detail_map if n and n != guest_node],
                detail_map_guest):
            return

        # Change 3: CONNECTING links are not links yet (see _split_connecting).
        guest_links_raw = list(guest_links)     # incl. CONNECTING peers, for the summary
        guest_links = self._split_connecting(
            result, guest_node, bridge_node, "bridge", guest_links)

        # Phase 2: a guest whose every AllStar link is monitor-only (to the
        # bridge AND beyond) is a permitted listener — outside nodes are
        # recorded as monitored_by_guest, no event, no walk beyond.
        if self._is_listener(result, guest_node, bridge_node, guest_links):
            self._record_listener(
                result, guest_node, bridge_node, "bridge",
                [n for n in guest_links if n != bridge_node],
                detail_map_guest, depth=3)
            return

        # Numeric node connections beyond the guest
        for hop3_node in guest_links:
            if hop3_node == bridge_node:
                continue  # Link back to bridge is expected
            if hop3_node == self.focus_node:
                continue
            if hop3_node in self.bridge_nodes:
                continue
            if hop3_node in self.allowlist:
                continue

            hop3_info = detail_map_guest.get(hop3_node, {})
            hop3_callsign = hop3_info.get("callsign", "Unknown")
            hop3_location = hop3_info.get("location", "Unknown")

            if not self._is_node_alive(hop3_node, hop3_info):
                continue

            path = path_so_far + [hop3_node]
            result.topology[hop3_node] = {
                "depth": 3, "parent": guest_node, "role": "unauthorized",
                "client_type": "allstar",
                "callsign": hop3_callsign, "location": hop3_location,
                **_display_fields(hop3_info),
            }

            # Offender is the boundary node (the guest) — it owns the connection
            # to the bridge AND the unauthorized connection beyond. hop3 is on
            # the receiving end.
            guest_info = result.topology.get(guest_node, {})
            event = BridgingEvent(
                offending_node=guest_node,
                offending_callsign=guest_info.get("callsign", "Unknown"),
                offending_location=guest_info.get("location", "Unknown"),
                path=path,
                path_description=" → ".join(str(n) for n in path),
                depth=2,
                rule=(f"Screen 2: guest {guest_node} (via bridge {bridge_node}) "
                      f"has unauthorized connection to {hop3_node}"),
                link_modes=self._link_mode_summary(
                    result, guest_node, bridge_node,
                    [n for n in guest_links_raw
                     if n not in (bridge_node, self.focus_node)
                     and n not in self.bridge_nodes]),
                **self._record_evidence(result, guest_node),
            )
            self._emit_event(result, event)

            # Walk further to catalog the full extent of the problem
            self._walk_beyond(hop3_node, path, result, depth=4)

    def _walk_beyond(self, node_id: int, path_so_far: list[int],
                     result: ScanResult, depth: int, max_depth: int = 8):
        """Walk beyond an unauthorized node to catalog all dragged-in nodes.

        This doesn't create new BridgingEvents — the offending node is already
        identified. This just logs the extent of the damage.
        """
        if depth > max_depth:
            logger.info(f"  Max depth {max_depth} reached, stopping walk.")
            return
        # Global drag-in budget: this catalog walk creates no detection, so
        # bound it so a huge foreign mesh can't stretch the scan (and thus the
        # auto-disconnect/image) by many minutes. Logged once when first hit.
        if self._dragged_in_count >= self.max_dragged_in_nodes:
            if not self._cap_logged:
                self._cap_logged = True
                logger.info(
                    f"  Drag-in catalog cap reached "
                    f"({self.max_dragged_in_nodes} nodes) — not walking the full "
                    f"extent (the mesh is larger). Detection is already complete; "
                    f"this only bounds informational cataloging.")
            return

        details = self._fetch_details(node_id, result)
        if details is None or len(details) == 0:
            return

        for d in details:
            nid = d["node_id"]
            if nid == 0 or nid in result.topology:
                continue
            if nid == self.focus_node or nid in self.bridge_nodes:
                continue

            callsign = d.get("callsign", "Unknown")
            location = d.get("location", "Unknown")
            result.topology[nid] = {
                "depth": depth, "parent": node_id, "role": "dragged_in",
                "client_type": "allstar",
                "callsign": callsign, "location": location,
                **_display_fields(d),
            }
            self._dragged_in_count += 1
            logger.info(f"  {'  ' * depth}Depth {depth}: node {nid} ({callsign}) dragged in")

            self._walk_beyond(nid, path_so_far + [nid], result, depth + 1, max_depth)
            # Stop cataloging sibling branches too once the budget is exhausted.
            if self._dragged_in_count >= self.max_dragged_in_nodes:
                break

    def _is_node_alive(self, node_id: int, api_info: dict) -> bool:
        """Check if a node is alive using DNS (primary) and regseconds (secondary).

        Returns False if the node is definitely offline (stale link).
        Returns True if online or if status is uncertain.
        """
        dns_info = check_node_dns(node_id)
        if not dns_info.is_registered:
            regsec = api_info.get("regseconds", 0)
            age = ASLApiClient.node_age_minutes(regsec)
            age_str = f"{age:.0f}min ago" if age is not None else "unknown"
            logger.info(
                f"  Node {node_id} NOT in DNS (regseconds: {age_str}) — "
                f"offline, stale link. Skipping."
            )
            return False

        logger.info(
            f"  Node {node_id} confirmed ONLINE via DNS "
            f"({dns_info.ip_address}:{dns_info.port})"
        )
        return True


def _selftest() -> int:
    """Offline end-to-end scan on a synthetic mesh (no network, DNS stubbed):
    focus 1000 -> bridge 2000 -> guest 4000, where 4000 MONITORS 2000 (R from
    4000's view, T from 2000's — the receiving end always records T) and has
    two outside links, 5000 (T) and 6000 (R), plus one softclient."""
    import types

    def rec(name, allstar=True):
        d = {"name": name}
        if allstar:
            d.update({"Node_ID": 1, "callsign": f"C{name}", "server": {"Location": "X"},
                      "regseconds": 1})
        return d

    payloads = {
        1000: ("T2000,T3000", [rec(2000), rec(3000)]),
        2000: ("T1000,T4000", [rec(1000), rec(4000)]),
        3000: ("T1000", [rec(1000)]),
        4000: ("R2000,T5000,R6000,TQQ0QQQ",
               [rec(2000), rec(5000), rec(6000), rec("QQ0QQQ", allstar=False)]),
        5000: ("", []),   # non-reporting: stops the drag-in walk
        6000: ("", []),
    }
    def run(pl, permit=False, allowlist=None, veto=None, post_time=None,
            dns_unregistered=(), fresh_seconds=600, connecting_seed=None,
            coherence=True, max_unconfirmed=240, unconfirmed_seed=None,
            ga_out=None, dns_calls=None):
        client = ASLApiClient()
        post_time = post_time or {}      # node -> stats.data.time (epoch)
        def stats(n):
            d = {"nodes": pl.get(n, ("", []))[0],
                 "linkedNodes": pl.get(n, ("", []))[1]}
            if n in post_time:
                d["time"] = post_time[n]
            return {"stats": {"data": d}}
        client.get_node_stats = stats  # type: ignore[assignment]
        global check_node_dns
        saved_dns = check_node_dns
        def _dns(n):
            if dns_calls is not None:
                dns_calls.append(n)
            return types.SimpleNamespace(
                is_registered=(n not in dns_unregistered), ip_address="192.0.2.1", port=4569)
        check_node_dns = _dns
        try:
            ga = GraphAnalyzer(client, focus_node=1000, bridge_nodes=[2000],
                               allowlist=allowlist, permit_listeners=permit,
                               linkless_fresh_seconds=fresh_seconds,
                               coherence_enabled=coherence,
                               max_unconfirmed_seconds=max_unconfirmed)
            if veto:
                ga.listener_veto.update(veto)
            if connecting_seed:
                ga._connecting_first_seen.update(connecting_seed)
            if unconfirmed_seed:
                ga._unconfirmed_first_seen.update(unconfirmed_seed)
            if ga_out is not None:
                ga_out.append(ga)
            return ga.scan()
        finally:
            check_node_dns = saved_dns

    res = run(payloads)
    t = res.topology
    ev = res.bridging_events

    # --- Phase 2 fixtures --------------------------------------------------
    # All-monitor guest: R to the bridge, R and L outside.
    pl_listener = dict(payloads)
    pl_listener[4000] = ("R2000,R5000,L6000,TQQ0QQQ",
                         [rec(2000), rec(5000), rec(6000), rec("QQ0QQQ", allstar=False)])
    r_on = run(pl_listener, permit=True)
    r_off = run(pl_listener, permit=False)
    # Step 2 trigger B: the same all-monitor guest, but the vantage saw it
    # keyed toward us -> listener status refused -> today's violation path.
    r_veto = run(pl_listener, permit=True,
                 veto={4000: "keyed toward vantage 2000 at 12:00:00 despite "
                             "monitor-only self-report"})
    r_mixed_on = run(payloads, permit=True)            # 5000 is T -> still a violation
    # Hop-1 (hub-attached) listener: 3000 is a non-bridge hop-1 node that
    # monitors the hub and one outside node.
    pl_hub = dict(pl_listener)
    pl_hub[3000] = ("R1000,R7000", [rec(1000), rec(7000)])
    pl_hub[7000] = ("", [])
    h_on = run(pl_hub, permit=True)
    h_off = run(pl_hub, permit=False)
    # Transceive to an ALLOWLISTED peer must disqualify (raw-list test).
    pl_allow = dict(payloads)
    pl_allow[4000] = ("R2000,T8000", [rec(2000), rec(8000)])
    pl_allow[8000] = ("", [])
    a_on = run(pl_allow, permit=True, allowlist=[8000])
    # Conflicting duplicate letters for an outside peer -> unknown -> violation.
    pl_dup = dict(payloads)
    pl_dup[4000] = ("R2000,T5000,R5000", [rec(2000), rec(5000)])
    d_on = run(pl_dup, permit=True)
    # Non-reporting guest can never be a listener.
    pl_silent = dict(payloads)
    pl_silent[4000] = ("", [])
    s_on = run(pl_silent, permit=True)
    # Change 1 (the <guest> case): the guest POSTS a fresh record with an empty
    # link list while the bridge still lists it -> linkless, not dark.
    now = int(time.time())
    lk_fresh = run(pl_silent, permit=True, post_time={4000: now - 4})
    lk_stale = run(pl_silent, permit=True, post_time={4000: now - 3 * 3600})
    lk_allow = run(pl_silent, permit=True, allowlist=[4000], post_time={4000: now})
    # Same for a hub-attached (hop-1) node: 3000 posts fresh, reports nothing.
    pl_hub_silent = dict(payloads)
    pl_hub_silent[3000] = ("", [])
    hk_fresh = run(pl_hub_silent, post_time={3000: now - 10})
    hk_dark = run(pl_hub_silent)
    # A bridge that posts fresh but reports nothing is neither.
    pl_bridge_silent = dict(payloads)
    pl_bridge_silent[2000] = ("", [])
    bk_fresh = run(pl_bridge_silent, post_time={2000: now})
    # Audit 2026-09-08: C2 future-dated post; S1 `nodes` names a link while
    # linkedNodes is empty; S3 fresh but NOT in DNS; S6 window boundary.
    lk_future = run(pl_silent, permit=True, post_time={4000: now + 24 * 3600})
    pl_mismatch = dict(payloads)
    pl_mismatch[4000] = ("T2000,T700001", [])
    lk_mismatch = run(pl_mismatch, permit=True, post_time={4000: now})
    lk_nodns = run(pl_silent, permit=True, post_time={4000: now}, dns_unregistered={4000})
    # (age is measured a fraction of a second after `now`, so 598 s lands
    # inside a 600 s window and 601 s outside it)
    lk_edge_in = run(pl_silent, permit=True, post_time={4000: now - 598}, fresh_seconds=600)
    lk_edge_out = run(pl_silent, permit=True, post_time={4000: now - 601}, fresh_seconds=600)
    # Round-2 audit #2: conflicting letters parse to {} but still NAME a link.
    pl_conflict = dict(payloads)
    pl_conflict[4000] = ("T700001,R700001", [])
    lk_conflict = run(pl_conflict, permit=True, post_time={4000: now})
    lk_zero = run(pl_silent, permit=True, post_time={4000: now}, fresh_seconds=0)
    # Change 3: CONNECTING (C) links are not links yet.
    pl_c1 = dict(payloads); pl_c1[4000] = ("R2000,C9000", [rec(2000), rec(9000)])
    c1_on, c1_off = run(pl_c1, permit=True), run(pl_c1, permit=False)
    pl_c2 = dict(payloads); pl_c2[4000] = ("T2000,C9000", [rec(2000), rec(9000)])
    c2_off = run(pl_c2, permit=False)
    pl_c3 = dict(payloads); pl_c3[4000] = ("R2000,T5000,C9000", [rec(2000), rec(5000), rec(9000)])
    c3_on = run(pl_c3, permit=True)
    pl_c4 = dict(payloads); pl_c4[3000] = ("T1000,C7000", [rec(1000), rec(7000)])
    c4_off = run(pl_c4, permit=False)
    pl_c5 = dict(payloads); pl_c5[4000] = ("C2000,T5000", [rec(2000), rec(5000)])
    c5_off = run(pl_c5, permit=False)
    # grace expired: the C link counts as established again (round-2 audit C1)
    _t = time.monotonic()
    c6_old = run(pl_c1, permit=False,
                 connecting_seed={(4000, 9000): (_t - 601, _t - 1)})
    c6_young = run(pl_c1, permit=False,
                   connecting_seed={(4000, 9000): (_t - 300, _t - 1)})
    # a stale entry (last seen long ago) is pruned, so the new dial starts fresh
    c6_stale = run(pl_c1, permit=False,
                   connecting_seed={(4000, 9000): (_t - 86400, _t - 700)})
    # C toward the HUB is never split out (still disqualifies a listener)
    pl_c7 = dict(payloads); pl_c7[4000] = ("R2000,C1000", [rec(2000), rec(1000)])
    c7_on = run(pl_c7, permit=True)
    # ---- Coherence gate (2026-10-12) ----
    # Replay shape of every real cut to date (2026-09-10, 09-28, 10-11): the
    # bridge's record lists the guest (T), the guest's OWN record names only
    # the far node and never the bridge — a pre-join post served stale.
    pl_u1 = dict(payloads); pl_u1[4000] = ("T5000", [rec(5000)])
    u1_on, u1_off = run(pl_u1, permit=True), run(pl_u1, permit=False)
    u1_ev = [u1_on.unconfirmed[0]] if u1_on.unconfirmed else []
    u1_raw = run(pl_u1, permit=False, coherence=False)      # toggle off -> today's verdict
    # coherent record (names the bridge) -> today's event, now with evidence
    pl_u2 = dict(payloads); pl_u2[4000] = ("T2000,T5000", [rec(2000), rec(5000)])
    u2 = run(pl_u2, permit=False, post_time={4000: now - 7})
    # hop-1 twin: a non-bridge hub node whose record names only the far node
    pl_u3 = dict(payloads); pl_u3[3000] = ("T7000", [rec(7000)]); pl_u3[7000] = ("", [])
    u3 = run(pl_u3, permit=False)
    # all-monitor record that does not name the bridge: unconfirmed, NOT a
    # listener (the record predates the attachment, so it cannot be judged)
    pl_u4 = dict(payloads); pl_u4[4000] = ("R5000,L6000", [rec(5000), rec(6000)])
    u4_on, u4_off = run(pl_u4, permit=True), run(pl_u4, permit=False)
    # C outside on an incoherent record: unconfirmed, no CONNECTING entry
    pl_u5 = dict(payloads); pl_u5[4000] = ("C9000", [rec(9000)])
    u5 = run(pl_u5, permit=False)
    # dead outside peer on an incoherent record: no event today -> not unconfirmed either
    u6 = run(pl_u1, permit=False, dns_unregistered={5000})
    # past the grace: STILL not enforced (v1) — flagged past_grace, warned once
    _u = time.monotonic()
    seed_old = {4000: (_u - 300, _u - 1)}
    _g7: list = []
    u7_old = run(pl_u1, permit=False, unconfirmed_seed=dict(seed_old), ga_out=_g7)
    u7_young = run(pl_u1, permit=False, unconfirmed_seed={4000: (_u - 100, _u - 1)})
    # audit S1/A5: an unconfirmed node is neither "posting" nor observed
    # audit S7: a coherent record costs no DNS lookups inside the gate
    _dns_coh: list = []
    u11 = run(pl_u2, permit=False, dns_calls=_dns_coh)
    # audit A2: attach present only as a raw token (conflicting letters drop
    # it from the parsed modes) -> still coherent
    pl_u12 = dict(payloads); pl_u12[4000] = ("T2000,R2000,T5000", [rec(5000)])
    u12 = run(pl_u12, permit=False)
    # a coherent scan pops the clock; a stale clock (last seen long ago) is pruned
    _ga8: list = []
    u8 = run(pl_u2, permit=False, unconfirmed_seed=dict(seed_old), ga_out=_ga8)
    _ga9: list = []
    u9 = run(pl_u1, permit=False, unconfirmed_seed={4000: (_u - 86400, _u - 700)}, ga_out=_ga9)
    # carry-over: a seeded first-seen keeps counting (SIGHUP rebuild path)
    u10 = run(pl_u1, permit=False, unconfirmed_seed={4000: (_u - 50, _u - 1)})

    checks = [
        # ---- coherence gate ----
        ("coherence: stale guest record -> no event, unconfirmed, no topology entry, edge dropped",
         not u1_on.bridging_events and not u1_off.bridging_events
         and len(u1_on.unconfirmed) == 1 and len(u1_off.unconfirmed) == 1
         and u1_ev and u1_ev[0]["node"] == 4000 and u1_ev[0]["attached_to"] == 2000
         and u1_ev[0]["attachment"] == "bridge" and u1_ev[0]["outside"] == [5000]
         and u1_ev[0]["raw_nodes"] == "T5000" and u1_ev[0]["state"] == "unconfirmed"
         and 5000 not in u1_on.topology and frozenset((4000, 5000)) not in u1_on.edges
         and u1_on.raw_nodes[4000] == "T5000" and not u1_on.listeners),
        ("coherence: toggle off -> today's verdict (event on the stale record)",
         len(u1_raw.bridging_events) == 1 and not u1_raw.unconfirmed),
        ("coherence: coherent record -> event with evidence fields",
         len(u2.bridging_events) == 1 and not u2.unconfirmed
         and u2.bridging_events[0].guest_raw_nodes == "T2000,T5000"
         and u2.bridging_events[0].guest_post_time == now - 7
         and isinstance(u2.bridging_events[0].guest_post_age_seconds, float)
         and 6 <= u2.bridging_events[0].guest_post_age_seconds <= 10
         and u2.bridging_events[0].incoherent_for_seconds is None),
        ("coherence: hop-1 twin -> unconfirmed via hub, no event for 3000",
         all(e.offending_node == 4000 for e in u3.bridging_events) and len(u3.unconfirmed) == 1
         and u3.unconfirmed[0]["node"] == 3000 and u3.unconfirmed[0]["attachment"] == "hub"
         and u3.unconfirmed[0]["attached_to"] == 1000 and u3.unconfirmed[0]["outside"] == [7000]
         and 7000 not in u3.topology),
        ("coherence: all-R/L record not naming the bridge -> unconfirmed, not a listener (permit on/off)",
         not u4_on.bridging_events and not u4_off.bridging_events
         and not u4_on.listeners and len(u4_on.unconfirmed) == 1 and len(u4_off.unconfirmed) == 1),
        ("coherence: C outside on an incoherent record -> unconfirmed, no CONNECTING entry",
         not u5.bridging_events and len(u5.unconfirmed) == 1 and u5.connecting == []),
        ("coherence: dead outside peer -> neither event nor unconfirmed",
         not u6.bridging_events and not u6.unconfirmed),
        ("coherence: past the grace -> still unconfirmed, flagged past_grace, warned once, no event",
         not u7_old.bridging_events and len(u7_old.unconfirmed) == 1
         and u7_old.unconfirmed[0]["state"] == "past_grace"
         and u7_old.unconfirmed[0]["age_seconds"] >= 299
         and 4000 in _g7[0]._incoherent_warned),
        ("coherence: inside the grace -> state unconfirmed",
         not u7_young.bridging_events and u7_young.unconfirmed[0]["state"] == "unconfirmed"),
        ("coherence: a coherent scan pops the clock; a stale clock is pruned (fresh count)",
         len(u8.bridging_events) == 1 and 4000 not in _ga8[0]._unconfirmed_first_seen
         and u8.bridging_events[0].incoherent_for_seconds is None
         and len(u9.unconfirmed) == 1 and u9.unconfirmed[0]["age_seconds"] < 5
         and 4000 in _ga9[0]._unconfirmed_first_seen),
        ("coherence: seeded clock carries over (age keeps counting)",
         len(u10.unconfirmed) == 1 and 49 <= u10.unconfirmed[0]["age_seconds"] <= 52),
        ("coherence: unconfirmed node is not 'posting' and is 'unobserved'",
         4000 not in u1_on.posting and 4000 in u1_on.unobserved),
        ("coherence: coherent record -> no DNS lookups inside the gate (exactly the Screen-2 one)",
         len(u11.bridging_events) == 1 and _dns_coh.count(5000) == 1
         and u11.bridging_events[0].guest_record_coherent is True),
        ("coherence: attach named only as a raw token -> coherent (event, not unconfirmed)",
         len(u12.bridging_events) == 1 and not u12.unconfirmed),
        # ---- change 3: connecting links ----
        ("connecting: guest R to bridge + C outside -> listener with no branches, no event",
         not c1_on.bridging_events and len(c1_on.listeners) == 1
         and c1_on.listeners[0]["monitored"] == []
         and [(x["node"], x["target"], x["attached_to"], x["attachment"])
              for x in c1_on.connecting] == [(4000, 9000, 2000, "bridge")]
         and frozenset((4000, 9000)) not in c1_on.edges
         and 9000 not in c1_on.topology),
        ("connecting: same guest, permit off -> still no event (C is not bridging)",
         not c1_off.bridging_events and c1_off.connecting
         and c1_off.connecting[0]["target"] == 9000),
        ("connecting: guest T to bridge + C outside -> no event, not a listener",
         not c2_off.bridging_events and not c2_off.listeners),
        ("connecting: an established T outside link still violates; the C one is set aside",
         [e.offending_node for e in c3_on.bridging_events] == [4000]
         and all("9000" not in e.path_description for e in c3_on.bridging_events)
         and [x["target"] for x in c3_on.connecting] == [9000] and not c3_on.listeners),
        ("connecting: non-bridge hop-1 node with a C link -> no event, recorded as hub attachment",
         not [e for e in c4_off.bridging_events if e.offending_node == 3000]
         and [(x["node"], x["target"], x["attachment"]) for x in c4_off.connecting]
             == [(3000, 7000, "hub")]),
        ("connecting: a C link BACK TO THE BRIDGE is never split out (T outside still violates)",
         not c5_off.connecting and [e.offending_node for e in c5_off.bridging_events] == [4000]),
        ("connecting: baseline scans list none", not res.connecting and not r_on.connecting),
        ("connecting: after the 600 s grace the C link is enforced as established (violation)",
         [e.offending_node for e in c6_old.bridging_events] == [4000] and not c6_old.connecting
         and any("9000" in e.path_description for e in c6_old.bridging_events)),
        ("connecting: inside the grace it is still exempt, age carried on the record",
         not c6_young.bridging_events and c6_young.connecting
         and 295 <= c6_young.connecting[0]["age_seconds"] <= 330),
        ("connecting: a stale clock (not re-seen within the grace) is pruned -> fresh grace",
         not c6_stale.bridging_events and c6_stale.connecting
         and c6_stale.connecting[0]["age_seconds"] <= 30),
        ("connecting: a C toward the hub is not split out -> not a listener",
         not c7_on.listeners and not c7_on.connecting),
        ("connecting: the C peer still appears in the violation's link-mode summary",
         any("9000 C" in e.link_modes for e in c3_on.bridging_events)),
        ("scan clean", not res.errors),
        # ---- change 1: linkless vs dark ----
        ("linkless: fresh empty guest record -> linkless, NOT dark, still unobserved",
         [l["node"] for l in lk_fresh.linkless] == [4000]
         and lk_fresh.linkless[0]["attached_to"] == 2000
         and lk_fresh.linkless[0]["attachment"] == "bridge"
         and lk_fresh.linkless[0]["co_adjacent"] == [1000]
         and 0 <= lk_fresh.linkless[0]["post_age_seconds"] < 120
         and not lk_fresh.dark_guests and 4000 in lk_fresh.unobserved
         and not lk_fresh.listeners and not lk_fresh.bridging_events),
        ("linkless: NOT in the `posting` set (no hiccup grace); post_age recorded per fetch",
         4000 not in lk_fresh.posting and 2000 in lk_fresh.posting
         and 4000 in lk_fresh.post_age
         and lk_fresh.post_age[1000] is None and 4000 not in s_on.posting),
        ("linkless: conflicting mode letters (parse -> {}) still name a link -> dark (round 2 #2)",
         not lk_conflict.linkless and [g["node"] for g in lk_conflict.dark_guests] == [4000]),
        ("linkless: linkless_fresh_seconds 0 disables -> dark",
         not lk_zero.linkless and [g["node"] for g in lk_zero.dark_guests] == [4000]),
        ("linkless: FUTURE-dated post (24 h) -> dark, not linkless (C2)",
         not lk_future.linkless and [g["node"] for g in lk_future.dark_guests] == [4000]
         and lk_future.post_age[4000] is None),
        ("linkless: `nodes` string names links but linkedNodes empty -> dark, not linkless (S1)",
         not lk_mismatch.linkless and [g["node"] for g in lk_mismatch.dark_guests] == [4000]
         and 4000 in lk_mismatch.names_links),
        ("linkless: fresh post but NOT in DNS -> offline branch, neither list (S3)",
         not lk_nodns.linkless and not lk_nodns.dark_guests and 4000 in lk_nodns.unobserved),
        ("linkless: window boundary — age just inside is linkless, just outside is dark",
         [l["node"] for l in lk_edge_in.linkless] == [4000] and not lk_edge_in.dark_guests
         and not lk_edge_out.linkless and [g["node"] for g in lk_edge_out.dark_guests] == [4000]),
        ("linkless: window is its own knob, not stale_threshold_minutes (120 min)",
         GraphAnalyzer(ASLApiClient(), 1, []).linkless_fresh_seconds == 600.0
         and GraphAnalyzer(ASLApiClient(), 1, [], linkless_fresh_seconds="junk")
             .linkless_fresh_seconds == 600.0
         and GraphAnalyzer(ASLApiClient(), 1, [], linkless_fresh_seconds=-5)
             .linkless_fresh_seconds == 0.0),
        ("linkless: STALE post (3 h) -> dark as before",
         not lk_stale.linkless and [g["node"] for g in lk_stale.dark_guests] == [4000]),
        ("linkless: no post time -> dark as before",
         not s_on.linkless and [g["node"] for g in s_on.dark_guests] == [4000]),
        ("linkless: allowlisted guest listed as neither",
         not lk_allow.linkless and not lk_allow.dark_guests),
        ("linkless: hub-attached fresh empty record -> linkless (hub), not dark",
         [l["node"] for l in hk_fresh.linkless] == [3000]
         and hk_fresh.linkless[0]["attachment"] == "hub"
         and hk_fresh.linkless[0]["attached_to"] == 1000
         and hk_fresh.linkless[0]["co_adjacent"] == [2000]
         and not hk_fresh.dark_guests),
        ("linkless: hub-attached, no post time -> dark (hub) as before",
         not hk_dark.linkless and [g["node"] for g in hk_dark.dark_guests] == [3000]),
        ("linkless: a bridge posting nothing is neither linkless nor dark, stays unobserved",
         not bk_fresh.linkless and not bk_fresh.dark_guests and 2000 in bk_fresh.unobserved),
        ("linkless: baseline scan lists none", not res.linkless and not res.dark_guests),
        # ---- phase 2 ----
        ("listener: no events with permit on", not r_on.bridging_events),
        ("listener: outside nodes role monitored_by_guest",
         r_on.topology[5000]["role"] == "monitored_by_guest"
         and r_on.topology[6000]["role"] == "monitored_by_guest"
         and r_on.topology[5000]["parent"] == 4000),
        ("listener: guest stays a guest", r_on.topology[4000]["role"] == "guest"),
        ("veto: keyed listener is NOT a listener", not r_veto.listeners),
        ("veto: violation events fire as with permit off",
         len(r_veto.bridging_events) == len(r_off.bridging_events) > 0),
        ("veto: reason lands in the event's link_modes text",
         any("LISTENER STATUS REFUSED: keyed toward vantage" in e.link_modes
             for e in r_veto.bridging_events)),
        ("veto: unrelated node unaffected by a veto on another id",
         len(run(pl_listener, permit=True, veto={9999: "x"}).listeners) == 1),
        ("listener: listed on the result", len(r_on.listeners) == 1
         and r_on.listeners[0]["node"] == 4000
         and r_on.listeners[0]["attached_to"] == 2000
         and r_on.listeners[0]["attachment"] == "bridge"
         and sorted(r_on.listeners[0]["monitored"]) == [5000, 6000]),
        ("listener: outside edges removed from edge union",
         frozenset((4000, 5000)) not in r_on.edges
         and frozenset((2000, 4000)) in r_on.edges),
        ("listener: modes stamped for the map",
         r_on.topology[5000].get("link_mode_from_parent") == "R"
         and r_on.topology[6000].get("link_mode_from_parent") == "L"),
        ("listener: link_modes keys are strings",
         all(isinstance(k[0], str) and isinstance(k[1], str) for k in r_on.link_modes)),
        ("same payload, permit off -> 2 violations", len(r_off.bridging_events) == 2
         and not r_off.listeners and r_off.topology[5000]["role"] == "unauthorized"),
        ("mixed (one T outside) with permit on -> still 2 violations",
         len(r_mixed_on.bridging_events) == 2 and not r_mixed_on.listeners),
        ("hub listener: no event, outside node depth 2 monitored",
         not [e for e in h_on.bridging_events if e.offending_node == 3000]
         and h_on.topology[7000]["role"] == "monitored_by_guest"
         and h_on.topology[7000]["depth"] == 2
         and any(l["node"] == 3000 and l["attachment"] == "hub" for l in h_on.listeners)),
        ("hub listener, permit off -> violation by 3000",
         any(e.offending_node == 3000 for e in h_off.bridging_events)),
        ("T to an allowlisted peer disqualifies", not a_on.listeners),
        ("conflicting duplicate letters -> not a listener, violation",
         not d_on.listeners and len(d_on.bridging_events) == 1),
        ("non-reporting guest is not a listener", not s_on.listeners),
        # ---- phase 1 (unchanged) ----
        ("guest monitors bridge (own view R)", t[4000].get("link_mode_to_parent") == "R"),
        ("bridge sees guest as T", t[4000].get("link_mode_from_parent") == "T"),
        ("bridge<->focus both T", t[2000].get("link_mode_from_parent") == "T"
         and t[2000].get("link_mode_to_parent") == "T"),
        ("outside 5000 T from guest view", t[5000].get("link_mode_from_parent") == "T"),
        ("outside 6000 R from guest view", t[6000].get("link_mode_from_parent") == "R"),
        ("non-reporting side is None", t[5000].get("link_mode_to_parent") is None),
        ("softclient carries parent view", t["ext_QQ0QQQ"].get("link_mode_from_parent") == "T"),
        ("focus has no mode keys", "link_mode_to_parent" not in t[1000]),
        ("two events", len(ev) == 2),
        ("event summary both views", all(
            "to 2000: R (4000 view) / T (2000 view)" in e.link_modes for e in ev)),
        ("event summary beyond", all(
            "beyond: 5000 T, 6000 R (4000 view)" in e.link_modes for e in ev)),
        ("detection unchanged by mode", {e.offending_node for e in ev} == {4000}
         and t[5000]["role"] == "unauthorized" and t[6000]["role"] == "unauthorized"),
        ("link_modes map populated", res.link_modes.get(("4000", "2000")) == "R"
         and res.link_modes.get(("2000", "4000")) == "T"),
        ("event_has_monitor_link positive", all(event_has_monitor_link(res, e) for e in ev)),
        ("event_has_monitor_link negative (all T)", not event_has_monitor_link(
            ScanResult("t", 1, [], [], {
                9: {"parent": 1, "link_mode_to_parent": "T", "link_mode_from_parent": "T"},
                8: {"parent": 9, "link_mode_to_parent": None, "link_mode_from_parent": "T"}}),
            BridgingEvent(9, "X", "Y", [1, 9], "1 → 9", 1, "r"))),
        ("event_has_monitor_link ignores other nodes' R", not event_has_monitor_link(
            ScanResult("t", 1, [], [], {
                9: {"parent": 1, "link_mode_to_parent": "T", "link_mode_from_parent": "T"},
                7: {"parent": 1, "link_mode_to_parent": "R", "link_mode_from_parent": "T"},
                90: {"parent": 7, "link_mode_to_parent": "R", "link_mode_from_parent": "T"}}),
            BridgingEvent(9, "X", "Y", [1, 9], "1 → 9", 1, "r"))),
        ("event_has_monitor_link via child edge", event_has_monitor_link(
            ScanResult("t", 1, [], [], {
                9: {"parent": 1, "link_mode_to_parent": "T", "link_mode_from_parent": "T"},
                8: {"parent": 9, "link_mode_to_parent": None, "link_mode_from_parent": "R"}}),
            BridgingEvent(9, "X", "Y", [1, 9], "1 → 9", 1, "r"))),
    ]
    # record_public (team status page, 2026-10-20): every key always present, odd payloads safe.
    rp_full = record_public({"node": {"callsign": " N0CALL ", "Status": "Active", "node_frequency": "145.250",
                                      "node_tone": "162.2", "server": {"Location": "Anytown/Texas",
                                      "SiteName": "Site A", "udpport": "4567", "proxy_ip": None}},
                             "stats": {"data": {"apprptuptime": "790167", "totalkeyups": 1223, "keyed": "False",
                                                "keytime": "120", "totaltxtime": "58243",
                                                "nodes": "T2000,C3000, T4000 ,bad token!,T5000"}}})
    rp_odd = record_public({"node": {"callsign": "A\x00B​\tC" * 10, "server": {"udpport": 1e999}},
                            "stats": {"data": {"apprptuptime": "1e999", "totalkeyups": "-5", "keyed": "maybe",
                                               "keytime": "soon", "totaltxtime": "-1", "nodes": ["T1", "T2"]}}})
    rp_keys = ["callsign", "status", "frequency", "tone", "location", "site", "udpport", "proxy_ip",
               "uptime_s", "keyups", "keyed", "keytime_s", "txtime_s", "links"]
    checks += [
        ("record_public: normal record → all facts, link tokens filtered and stripped",
         rp_full["callsign"] == "N0CALL" and rp_full["status"] == "Active" and rp_full["frequency"] == "145.250"
         and rp_full["tone"] == "162.2" and rp_full["location"] == "Anytown/Texas" and rp_full["site"] == "Site A"
         and rp_full["udpport"] == 4567 and rp_full["proxy_ip"] is None and rp_full["uptime_s"] == 790167
         and rp_full["keyups"] == 1223 and rp_full["keyed"] is False and rp_full["keytime_s"] == 120
         and rp_full["txtime_s"] == 58243
         and rp_full["links"] == ["T2000", "C3000", "T4000", "T5000"]),
        ("record_public: odd payload → control chars dropped, caps, overflow/negative/unknown → None, list nodes → []",
         sorted(rp_odd) == sorted(rp_keys) and "\x00" not in rp_odd["callsign"] and "\t" not in rp_odd["callsign"]
         and len(rp_odd["callsign"]) <= 12 and rp_odd["udpport"] is None and rp_odd["uptime_s"] is None
         and rp_odd["keyups"] is None and rp_odd["keyed"] is None and rp_odd["keytime_s"] is None
         and rp_odd["txtime_s"] is None and rp_odd["links"] == []),
        ("record_public: None / {} / wrong shapes never raise and keep every key",
         sorted(record_public(None)) == sorted(rp_keys) and sorted(record_public({})) == sorted(rp_keys)
         and record_public({"node": "x", "stats": 5})["links"] == []
         and record_public({"node": {"server": "x"}, "stats": {"data": "y"}})["location"] is None),
        ("record_public: filled per fetched node on the walk result",
         isinstance(getattr(res, "node_public", None), dict) and len(res.node_public) >= 1
         and all(sorted(v) == sorted(rp_keys) for v in res.node_public.values())),
    ]
    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(f"  [{'OK' if ok else 'FAIL'}] {n}")
    print(f"graph_analyzer selftest: {len(checks) - len(failed)}/{len(checks)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        logging.basicConfig(level=logging.WARNING)
        sys.exit(_selftest())
    print("usage: python3 graph_analyzer.py --selftest")
