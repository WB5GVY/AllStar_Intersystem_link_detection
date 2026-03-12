"""Auto-disconnect module for AllStarLink nodes.

When an unauthorized bridging event is detected through a node we admin,
this module can SSH into that node's Asterisk server and force-disconnect
the offending guest node.

Modular design: each managed node has its own SSH credentials in config.
Adding a new node for auto-disconnect is just a config change.

Safety measures:
  - Configurable per-node enable/disable
  - Re-verification delay (default 15s) with fresh API + DNS check
  - Only acts on nodes in the bridging path through a managed node
  - All actions logged; notification sent before disconnect
"""

import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from asl_api import ASLApiClient
from dns_checker import check_node_dns
from graph_analyzer import BridgingEvent

logger = logging.getLogger(__name__)


@dataclass
class ManagedNode:
    """A node we have admin access to for auto-disconnect."""
    node_id: int
    ssh_host: str
    ssh_user: str
    ssh_key: str
    ssh_port: int = 22
    enabled: bool = False


@dataclass
class DisconnectResult:
    """Result of an auto-disconnect attempt."""
    managed_node: int
    target_node: int
    success: bool
    action: str          # "disconnected", "skipped_reverify", "skipped_disabled", "ssh_failed"
    message: str


class AutoDisconnector:
    """Manages auto-disconnect for nodes we admin."""

    DEFAULT_REVERIFY_DELAY = 15  # seconds

    def __init__(self, config: dict, api_client: ASLApiClient):
        self.api = api_client
        self.managed_nodes: dict[int, ManagedNode] = {}
        self.reverify_delay = config.get("auto_disconnect", {}).get(
            "reverify_delay_seconds", self.DEFAULT_REVERIFY_DELAY
        )

        # Load managed nodes from config
        for node_cfg in config.get("auto_disconnect", {}).get("nodes", []):
            node = ManagedNode(
                node_id=node_cfg["node_id"],
                ssh_host=node_cfg["ssh_host"],
                ssh_user=node_cfg.get("ssh_user", "repeater"),
                ssh_key=node_cfg.get("ssh_key", "~/.ssh/id_rsa"),
                ssh_port=node_cfg.get("ssh_port", 22),
                enabled=node_cfg.get("enabled", False),
            )
            self.managed_nodes[node.node_id] = node
            state = "ENABLED" if node.enabled else "disabled"
            logger.info(
                f"Auto-disconnect: node {node.node_id} at {node.ssh_host} — {state}"
            )

    def can_disconnect(self, event: BridgingEvent) -> Optional[ManagedNode]:
        """Check if we can auto-disconnect for this bridging event.

        Returns the ManagedNode if the offending node's path goes through
        a managed node that has auto-disconnect enabled. Otherwise None.
        """
        # Walk the path to find a managed node that's the direct parent
        # of the offending node (i.e., the node we'd disconnect FROM)
        for i, node_id in enumerate(event.path):
            if node_id in self.managed_nodes:
                managed = self.managed_nodes[node_id]
                if not managed.enabled:
                    return None
                # The offending node must be directly connected to this managed node
                # (i.e., managed node is the parent in the path)
                if i + 1 < len(event.path):
                    next_in_path = event.path[i + 1]
                    # The offending node is at the end of the path, but the
                    # node to disconnect is the one directly after the managed node
                    return managed
        return None

    def target_node_for_disconnect(self, event: BridgingEvent,
                                   managed: ManagedNode) -> Optional[int]:
        """Determine which node to disconnect from the managed node.

        This is the node in the path immediately after the managed node —
        not necessarily the offending node itself, but the guest connected
        to our managed node that is causing the bridge.
        """
        for i, node_id in enumerate(event.path):
            if node_id == managed.node_id and i + 1 < len(event.path):
                return event.path[i + 1]
        return None

    def attempt_disconnect(self, event: BridgingEvent) -> Optional[DisconnectResult]:
        """Attempt auto-disconnect for a bridging event.

        1. Check if path goes through a managed node
        2. Wait reverify_delay seconds
        3. Re-check that the offending node is still connected and alive
        4. SSH into the managed node and force disconnect

        Returns DisconnectResult or None if not applicable.
        """
        managed = self.can_disconnect(event)
        if managed is None:
            return None

        target = self.target_node_for_disconnect(event, managed)
        if target is None:
            return None

        logger.info(
            f"Auto-disconnect candidate: node {target} via managed node "
            f"{managed.node_id}. Waiting {self.reverify_delay}s for re-verification..."
        )

        # === Re-verification delay ===
        time.sleep(self.reverify_delay)

        # === Re-verify: is the target still connected to our managed node? ===
        logger.info(f"Re-verifying node {target} is still connected to {managed.node_id}...")

        linked = self.api.get_linked_node_details(managed.node_id)
        if linked is None:
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=False, action="skipped_reverify",
                message=f"Could not query managed node {managed.node_id} during re-verify"
            )

        connected_ids = [d["node_id"] for d in linked]
        if target not in connected_ids:
            msg = (f"Node {target} is no longer connected to {managed.node_id} "
                   f"(resolved on its own). No action needed.")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_reverify", message=msg
            )

        # === Re-verify: is the target still alive? ===
        dns_info = check_node_dns(target)
        if not dns_info.is_registered:
            msg = (f"Node {target} no longer in DNS during re-verify — "
                   f"likely went offline. Skipping disconnect.")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_reverify", message=msg
            )

        # === Re-verify: does the target still have external connections? ===
        target_details = self.api.get_linked_node_details(target)
        if target_details is not None and len(target_details) > 0:
            # Check for non-numeric external connections (RepeaterPhone, EchoLink)
            has_external_conn = any(
                d.get("is_external", False) for d in target_details
            )
            # Check for numeric node connections outside the monitored system
            target_links = [d["node_id"] for d in target_details
                            if not d.get("is_external", False) and d["node_id"] != 0]
            external_nodes = [n for n in target_links if n != managed.node_id
                              and n not in self.managed_nodes]

            if not has_external_conn and not external_nodes:
                msg = (f"Node {target} no longer has external connections "
                       f"during re-verify. No action needed.")
                logger.info(msg)
                return DisconnectResult(
                    managed_node=managed.node_id, target_node=target,
                    success=True, action="skipped_reverify", message=msg
                )
            if has_external_conn:
                ext_names = [d.get("external_name", "?") for d in target_details
                             if d.get("is_external", False)]
                logger.info(
                    f"Re-verify confirmed: node {target} still has external "
                    f"connection(s): {ext_names}"
                )
            if external_nodes:
                logger.info(
                    f"Re-verify confirmed: node {target} still has external "
                    f"node connection(s): {external_nodes}"
                )

        # === Execute disconnect ===
        logger.warning(
            f"AUTO-DISCONNECT: Disconnecting node {target} from "
            f"managed node {managed.node_id} ({managed.ssh_host})"
        )
        return self._ssh_disconnect(managed, target)

    def _ssh_disconnect(self, managed: ManagedNode, target: int) -> DisconnectResult:
        """SSH into the managed node and force-disconnect the target.

        Uses: asterisk -rx "rpt fun <managed_node> *1<target>"
        """
        asterisk_cmd = f"rpt fun {managed.node_id} *1{target}"
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-p", str(managed.ssh_port),
            "-i", str(Path(managed.ssh_key).expanduser()),
            f"{managed.ssh_user}@{managed.ssh_host}",
            f'asterisk -rx "{asterisk_cmd}"',
        ]

        logger.info(f"SSH command: asterisk -rx \"{asterisk_cmd}\" on {managed.ssh_host}")

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                msg = (f"Successfully disconnected node {target} from "
                       f"{managed.node_id}. Asterisk output: {result.stdout.strip()}")
                logger.warning(msg)
                return DisconnectResult(
                    managed_node=managed.node_id, target_node=target,
                    success=True, action="disconnected", message=msg
                )
            else:
                msg = (f"SSH command returned code {result.returncode}. "
                       f"stdout: {result.stdout.strip()} "
                       f"stderr: {result.stderr.strip()}")
                logger.error(f"Auto-disconnect failed: {msg}")
                return DisconnectResult(
                    managed_node=managed.node_id, target_node=target,
                    success=False, action="ssh_failed", message=msg
                )

        except subprocess.TimeoutExpired:
            msg = f"SSH command timed out connecting to {managed.ssh_host}"
            logger.error(f"Auto-disconnect failed: {msg}")
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=False, action="ssh_failed", message=msg
            )
        except Exception as e:
            msg = f"SSH error: {e}"
            logger.error(f"Auto-disconnect failed: {msg}")
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=False, action="ssh_failed", message=msg
            )
