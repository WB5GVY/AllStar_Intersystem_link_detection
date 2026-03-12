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
from typing import Optional

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

    @property
    def has_problems(self) -> bool:
        return len(self.bridging_events) > 0


class GraphAnalyzer:
    """Analyzes AllStarLink node topology for unauthorized bridging.

    Uses the two-screen detection model described in the module docstring.
    """

    DEFAULT_STALE_THRESHOLD_MINUTES = 120

    def __init__(self, api_client: ASLApiClient, focus_node: int,
                 bridge_nodes: list[int],
                 allowlist: Optional[list[int]] = None,
                 stale_threshold_minutes: float = DEFAULT_STALE_THRESHOLD_MINUTES):
        self.api = api_client
        self.focus_node = focus_node
        self.bridge_nodes = set(bridge_nodes)
        self.allowlist = set(allowlist or [])
        self.stale_threshold_minutes = stale_threshold_minutes

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

        # === HOP 0: Query the focus node ===
        logger.info(f"Querying focus node {self.focus_node}...")
        focus_details = self.api.get_linked_node_details(self.focus_node)
        if focus_details is None:
            msg = f"Failed to query focus node {self.focus_node}"
            logger.error(msg)
            result.errors.append(msg)
            return result

        hop0_links = [d["node_id"] for d in focus_details if d["node_id"] != 0]
        detail_map_focus = {d["node_id"]: d for d in focus_details}

        result.topology[self.focus_node] = {
            "depth": 0, "parent": None, "role": "focus",
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
                "callsign": callsign, "location": location,
            }

        # === HOP 2+: Walk outward from each 1-hop node ===
        for hop1_node in hop0_links:
            hop1_info = result.topology[hop1_node]
            is_bridge = hop1_info["role"] == "bridge"

            logger.info(f"Checking hop-1 node {hop1_node} ({hop1_info['callsign']})...")

            # Query this node's connections
            hop1_details = self.api.get_linked_node_details(hop1_node)
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

            # Check for external connections (RepeaterPhone/EchoLink) on this hop-1 node
            external_connections = [d for d in hop1_details if d.get("is_external", False)]
            if external_connections and not is_bridge:
                # Non-bridge hop-1 node with an external connection = unauthorized bridging
                # Bridge nodes are exempt — external connections (EchoLink, etc.) are their normal operation
                for ext in external_connections:
                    ext_name = ext.get("external_name", "Unknown")
                    path = [self.focus_node, hop1_node]
                    result.topology[f"ext_{hop1_node}_{ext_name}"] = {
                        "depth": 2, "parent": hop1_node, "role": "unauthorized",
                        "callsign": ext_name, "location": "External Connection",
                    }
                    event = BridgingEvent(
                        offending_node=hop1_node,
                        offending_callsign=hop1_info["callsign"],
                        offending_location=hop1_info.get("location", "Unknown"),
                        path=path,
                        path_description=" → ".join(str(n) for n in path) + f" → [{ext_name}]",
                        depth=1,
                        rule=(f"Screen 2: non-bridge node {hop1_node} has external "
                              f"connection '{ext_name}' (RepeaterPhone/EchoLink)"),
                    )
                    result.bridging_events.append(event)
                    logger.warning(str(event))

            hop1_links = [d["node_id"] for d in hop1_details
                          if not d.get("is_external", False) and d["node_id"] != 0]
            detail_map_hop1 = {d["node_id"]: d for d in hop1_details
                               if not d.get("is_external", False)}

            for hop2_node in hop1_links:
                # Skip links back to focus or to other known system nodes
                if hop2_node == self.focus_node:
                    continue
                if hop2_node in self.bridge_nodes:
                    continue  # Bridge-to-bridge or bridge-to-focus is fine
                if hop2_node in [n for n in hop0_links if n != hop1_node]:
                    continue  # Link between two 1-hop nodes is fine
                if hop2_node in self.allowlist:
                    continue
                if hop2_node in result.topology:
                    continue  # Already seen at a closer distance

                hop2_info = detail_map_hop1.get(hop2_node, {})
                hop2_callsign = hop2_info.get("callsign", "Unknown")
                hop2_location = hop2_info.get("location", "Unknown")

                result.topology[hop2_node] = {
                    "depth": 2, "parent": hop1_node, "role": "guest" if is_bridge else "unauthorized",
                    "callsign": hop2_callsign, "location": hop2_location,
                }

                if not is_bridge:
                    # SCREEN 2: Regular node has something beyond it — NOT allowed
                    if not self._is_node_alive(hop2_node, hop2_info):
                        continue

                    path = [self.focus_node, hop1_node, hop2_node]
                    event = BridgingEvent(
                        offending_node=hop2_node,
                        offending_callsign=hop2_callsign,
                        offending_location=hop2_location,
                        path=path,
                        path_description=f"{self.focus_node} → {hop1_node} → {hop2_node}",
                        depth=2,
                        rule=f"Screen 2: non-bridge node {hop1_node} has connection to {hop2_node}",
                    )
                    result.bridging_events.append(event)
                    logger.warning(str(event))

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
        guest_details = self.api.get_linked_node_details(guest_node)
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

        # External connections on a guest node = bridging (e.g., RepeaterPhone)
        for ext in external_connections:
            ext_name = ext.get("external_name", "Unknown")
            path = path_so_far + [ext_name]
            result.topology[f"ext_{ext_name}"] = {
                "depth": 3, "parent": guest_node, "role": "unauthorized",
                "callsign": ext_name, "location": "External Connection",
            }
            event = BridgingEvent(
                offending_node=guest_node,
                offending_callsign=result.topology.get(guest_node, {}).get("callsign", "Unknown"),
                offending_location=result.topology.get(guest_node, {}).get("location", "Unknown"),
                path=path_so_far,
                path_description=" → ".join(str(n) for n in path_so_far) + f" → [{ext_name}]",
                depth=2,
                rule=(f"Screen 2: guest {guest_node} (via bridge {bridge_node}) "
                      f"has external connection '{ext_name}' (RepeaterPhone/EchoLink)"),
            )
            result.bridging_events.append(event)
            logger.warning(str(event))

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
                "callsign": hop3_callsign, "location": hop3_location,
            }

            event = BridgingEvent(
                offending_node=hop3_node,
                offending_callsign=hop3_callsign,
                offending_location=hop3_location,
                path=path,
                path_description=" → ".join(str(n) for n in path),
                depth=3,
                rule=(f"Screen 2: guest {guest_node} (via bridge {bridge_node}) "
                      f"has unauthorized connection to {hop3_node}"),
            )
            result.bridging_events.append(event)
            logger.warning(str(event))

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

        details = self.api.get_linked_node_details(node_id)
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
                "callsign": callsign, "location": location,
            }
            logger.info(f"  {'  ' * depth}Depth {depth}: node {nid} ({callsign}) dragged in")

            self._walk_beyond(nid, path_so_far + [nid], result, depth + 1, max_depth)

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
