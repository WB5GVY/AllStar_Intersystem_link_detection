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
from dataclasses import dataclass, field
from typing import Callable, Optional

from asl_api import ASLApiClient
from dns_checker import check_node_dns

logger = logging.getLogger(__name__)


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

    def __str__(self):
        return (
            f"BRIDGING DETECTED: Node {self.offending_node} "
            f"({self.offending_callsign}, {self.offending_location}) "
            f"at depth {self.depth}. Path: {self.path_description}. "
            f"Rule: {self.rule}"
        )


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

    @property
    def has_problems(self) -> bool:
        return len(self.bridging_events) > 0


class GraphAnalyzer:
    """Analyzes AllStarLink node topology for unauthorized bridging.

    Uses the two-screen detection model described in the module docstring.
    """

    DEFAULT_STALE_THRESHOLD_MINUTES = 120

    DEFAULT_MAX_DRAGGED_IN = 30  # cap on informational deep-walk cataloging

    def __init__(self, api_client: ASLApiClient, focus_node: int,
                 bridge_nodes: list[int],
                 allowlist: Optional[list[int]] = None,
                 stale_threshold_minutes: float = DEFAULT_STALE_THRESHOLD_MINUTES,
                 max_dragged_in_nodes: int = DEFAULT_MAX_DRAGGED_IN):
        self.api = api_client
        self.focus_node = focus_node
        self.bridge_nodes = set(bridge_nodes)
        self.allowlist = set(allowlist or [])
        self.stale_threshold_minutes = stale_threshold_minutes
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
        self._dragged_in_count = 0
        self._cap_logged = False

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
        details = self.api.get_linked_node_details(node_id)
        if details:
            for d in details:
                nid = d.get("node_id", 0)
                # Skip node_id 0, external pseudo-links, and any self-loop
                # (a 1-element frozenset would break the BFS edge unpack).
                if nid and nid != node_id and not d.get("is_external", False):
                    result.edges.add(frozenset((node_id, nid)))
        return details

    def _emit_event(self, result: "ScanResult", event: "BridgingEvent") -> None:
        """Record a bridging event and fire the first-detection callback once.

        Centralizes event recording so immediate evidence capture is triggered
        the moment the FIRST violation is seen in a scan, rather than after the
        full topology walk completes (which can take minutes and outlast a
        transient offending link).
        """
        result.bridging_events.append(event)
        logger.warning(str(event))
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

        hop0_links = [d["node_id"] for d in focus_details if d["node_id"] != 0]
        detail_map_focus = {d["node_id"]: d for d in focus_details}

        result.topology[self.focus_node] = {
            "depth": 0, "parent": None, "role": "focus",
            "client_type": "allstar",
            "callsign": "Focus", "location": "Hub",
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
                continue
            if len(hop1_details) == 0:
                # Non-reporting node — DNS check for visibility
                dns_info = check_node_dns(hop1_node)
                if dns_info.is_registered:
                    logger.info(
                        f"  Node {hop1_node} has no stats but IS registered "
                        f"in DNS ({dns_info.ip_address}:{dns_info.port}) — "
                        f"online but link list not visible (non-reporting)."
                    )
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
                }
                logger.info(
                    f"  Hop-1 node {hop1_node} ({hop1_info['callsign']}) has "
                    f"external connection '{ext_name}' — permitted (transceive-like leaf)"
                )

            hop1_links = [d["node_id"] for d in hop1_details
                          if not d.get("is_external", False) and d["node_id"] != 0]
            detail_map_hop1 = {d["node_id"]: d for d in hop1_details
                               if not d.get("is_external", False)}

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
            return
        if len(guest_details) == 0:
            dns_info = check_node_dns(guest_node)
            if dns_info.is_registered:
                logger.info(
                    f"  Guest {guest_node} has no stats but IS in DNS — "
                    f"online but link list not visible (non-reporting)."
                )
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
            }
            guest_call = result.topology.get(guest_node, {}).get("callsign", "Unknown")
            logger.info(
                f"  Guest {guest_node} ({guest_call}) has external "
                f"connection '{ext_name}' — permitted (transceive-like leaf)"
            )

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
