"""Auto-disconnect module for AllStarLink nodes.

When an unauthorized bridging event is detected through a node we admin,
this module can SSH into that node's Asterisk server and force-disconnect
the offending guest node.

Modular design: each managed node has its own SSH credentials in config.
Adding a new node for auto-disconnect is just a config change.

Safety measures:
  - Configurable per-node enable/disable (config) + local override files
  - Re-verification delay (default 15s) with fresh API + DNS check
  - Remote flag file check (fail-closed) for operator-controlled disable
  - Deepest-managed-node path resolution (never disconnects bridge nodes)
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
    flag_file_check: str = ""


@dataclass
class DisconnectResult:
    """Result of an auto-disconnect attempt."""
    managed_node: int
    target_node: int
    success: bool
    action: str          # "disconnected", "skipped_reverify", "skipped_disabled",
                         # "skipped_flagfile", "skipped_local_override",
                         # "skipped_cooldown", "ssh_failed"
    message: str


class AutoDisconnector:
    """Manages auto-disconnect for nodes we admin."""

    DEFAULT_REVERIFY_DELAY = 15  # seconds
    DEFAULT_COOLDOWN_SECONDS = 120  # min seconds between SUCCESSFUL disconnects
                                    # of the same (managed, target) pair

    def __init__(self, config: dict, api_client: ASLApiClient):
        self.api = api_client
        self.managed_nodes: dict[int, ManagedNode] = {}
        self.bridge_nodes: set[int] = set(config.get("bridge_nodes", []))
        self.reverify_delay = config.get("auto_disconnect", {}).get(
            "reverify_delay_seconds", self.DEFAULT_REVERIFY_DELAY
        )
        self.cooldown_seconds = config.get("auto_disconnect", {}).get(
            "disconnect_cooldown_seconds", self.DEFAULT_COOLDOWN_SECONDS
        )
        # Per-(managed_node, target) last-attempt monotonic timestamps. Prevents
        # an SSH storm now that disconnect fires at detection time on every scan
        # (and that one scan can emit several events for the same target when the
        # focus node is itself managed). Per-instance; resets on config reload.
        self._last_attempt: dict[tuple[int, int], float] = {}

        # Load managed nodes from config
        for node_cfg in config.get("auto_disconnect", {}).get("nodes", []):
            node = ManagedNode(
                node_id=node_cfg["node_id"],
                ssh_host=node_cfg["ssh_host"],
                ssh_user=node_cfg.get("ssh_user", "repeater"),
                ssh_key=node_cfg.get("ssh_key", "~/.ssh/id_rsa"),
                ssh_port=node_cfg.get("ssh_port", 22),
                enabled=node_cfg.get("enabled", False),
                flag_file_check=node_cfg.get("flag_file_check", ""),
            )
            self.managed_nodes[node.node_id] = node
            override_path = Path(f"/tmp/autodisconnect_disabled_{node.node_id}")
            local_override = override_path.exists()
            state = "ENABLED" if node.enabled else "disabled"
            if local_override:
                state += " (LOCAL OVERRIDE — inactive)"
            logger.info(
                f"Auto-disconnect: node {node.node_id} at {node.ssh_host} — {state}"
            )

    def can_disconnect(self, event: BridgingEvent) -> Optional[ManagedNode]:
        """Find the deepest managed node in the path whose next hop is
        a valid disconnect target (not a bridge or managed node).

        This ensures the system SSHes into the node closest to the offending
        guest and disconnects the guest — not an intermediate bridge node.
        """
        best_managed = None
        for i, node_id in enumerate(event.path):
            if node_id in self.managed_nodes:
                managed = self.managed_nodes[node_id]
                if not managed.enabled:
                    continue  # Skip disabled; don't block deeper nodes
                if i + 1 < len(event.path):
                    next_in_path = event.path[i + 1]
                    if next_in_path in self.bridge_nodes or next_in_path in self.managed_nodes:
                        continue  # Never disconnect a bridge/managed node
                    best_managed = managed
        return best_managed

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

        # === Local override check (no network needed) ===
        if self._check_local_override(managed.node_id):
            msg = (f"Auto-disconnect skipped for node {target} — "
                   f"locally disabled for managed node {managed.node_id}")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_local_override", message=msg
            )

        # === Cooldown: don't re-hit the same target too often ===
        # Detection-time firing + short scans mean a persistent relinker could
        # otherwise be disconnected every scan, and a focus-managed multi-guest
        # node can emit several events for the SAME target in one scan. Recorded
        # before the re-verify sleep so repeats skip the expensive path entirely.
        key = (managed.node_id, target)
        now = time.monotonic()
        last = self._last_attempt.get(key)
        if last is not None and (now - last) < self.cooldown_seconds:
            msg = (f"Auto-disconnect for node {target} via {managed.node_id} "
                   f"skipped — within {self.cooldown_seconds}s cooldown "
                   f"({now - last:.0f}s since last successful disconnect).")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_cooldown", message=msg
            )
        # NOTE: the cooldown is armed ONLY on a genuine disconnect (end of this
        # method), never here. Recording before the outcome would let a failed
        # SSH or a transient skipped_reverify burn the window and leave a real
        # bridge up for the full cooldown (audit CRITICAL). Same-scan duplicate
        # events for one target are still deduped: on_violation fires
        # synchronously, so a successful first disconnect arms the cooldown
        # before the next same-target event is processed.

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

        # === Re-verify: does the target still bridge to another AllStar system? ===
        # Per the 2026-05-13 policy update, non-AllStar leaf connections
        # (WebTransceiver / RepeaterPhone / EchoLink-user / softphones) on the
        # target are NOT, by themselves, grounds for disconnect. Those clients
        # are protocol-limited single-hop terminating audio endpoints; they
        # cannot themselves bridge our system to another repeater system. Only
        # an AllStar-to-AllStar link from the target into a node outside our
        # monitored set is a real bridging hazard. (See
        # Intervention_and_Email_Rules.md and the journal entry of 2026-05-13.)
        target_details = self.api.get_linked_node_details(target)
        if target_details is not None and len(target_details) > 0:
            target_links = [d["node_id"] for d in target_details
                            if not d.get("is_external", False) and d["node_id"] != 0]
            external_nodes = [n for n in target_links if n != managed.node_id
                              and n not in self.managed_nodes]
            ext_details = [d for d in target_details if d.get("is_external", False)]

            if not external_nodes:
                # No AllStar bridging hazard remains. If non-AllStar externals
                # are still present, log them in full for the forensic record
                # (defensive addition per 2026-05-13 policy) — we are choosing
                # NOT to disconnect for these.
                if ext_details:
                    skipped_externals = [
                        f"'{d.get('external_name', '?')}' "
                        f"(client_type={d.get('client_type', '?')})"
                        for d in ext_details
                    ]
                    msg = (
                        f"Node {target} has no AllStar links outside the "
                        f"monitored system at re-verify. Non-AllStar externals "
                        f"still present ({', '.join(skipped_externals)}) — "
                        f"these are single-hop leaf endpoints and are not a "
                        f"bridging hazard. No disconnect."
                    )
                else:
                    msg = (
                        f"Node {target} has no remaining bridging-relevant "
                        f"connections at re-verify. No action needed."
                    )
                logger.info(msg)
                return DisconnectResult(
                    managed_node=managed.node_id, target_node=target,
                    success=True, action="skipped_reverify", message=msg
                )
            logger.info(
                f"Re-verify confirmed: node {target} still has AllStar link(s) "
                f"outside the monitored system: {external_nodes}"
            )
            if ext_details:
                # Disconnect IS firing (because of external_nodes). Still log
                # the non-AllStar externals so the alert email has full context.
                ext_summary = [
                    f"'{d.get('external_name', '?')}' "
                    f"(client_type={d.get('client_type', '?')})"
                    for d in ext_details
                ]
                logger.info(
                    f"  Node {target} also carries non-AllStar external(s): "
                    f"{', '.join(ext_summary)} — informational only."
                )

        # === Flag file check: is auto-disconnect disabled by operator? ===
        if self._check_flag_file(managed):
            msg = (f"Auto-disconnect skipped for node {target} — disabled by "
                   f"operator on node {managed.node_id} (flag file present)")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_flagfile", message=msg
            )

        # === Execute disconnect ===
        logger.warning(
            f"AUTO-DISCONNECT: Disconnecting node {target} from "
            f"managed node {managed.node_id} ({managed.ssh_host})"
        )
        result = self._ssh_disconnect(managed, target)
        # Arm the cooldown ONLY on a real disconnect, so a failed/transient
        # attempt retries on the next scan instead of being suppressed.
        if result.action == "disconnected":
            self._last_attempt[key] = time.monotonic()
        return result

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
            f'/usr/sbin/asterisk -rx "{asterisk_cmd}"',
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

    def check_ssh_health(self) -> dict[int, bool]:
        """Test SSH connectivity to all managed nodes.

        Runs a lightweight 'echo ok' on each node with a short timeout.
        Returns {node_id: True if reachable, False if not}.
        No side effects — does not disconnect or modify anything.
        """
        results = {}
        for node_id, managed in self.managed_nodes.items():
            ssh_cmd = [
                "ssh",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=5",
                "-o", "BatchMode=yes",
                "-p", str(managed.ssh_port),
                "-i", str(Path(managed.ssh_key).expanduser()),
                f"{managed.ssh_user}@{managed.ssh_host}",
                "echo ok",
            ]
            try:
                result = subprocess.run(
                    ssh_cmd, capture_output=True, text=True, timeout=10
                )
                healthy = result.returncode == 0
                if not healthy:
                    logger.warning(
                        f"SSH health check failed for node {node_id} "
                        f"({managed.ssh_host}): rc={result.returncode}"
                    )
                results[node_id] = healthy
            except subprocess.TimeoutExpired:
                logger.warning(
                    f"SSH health check timed out for node {node_id} "
                    f"({managed.ssh_host})"
                )
                results[node_id] = False
            except Exception as e:
                logger.warning(
                    f"SSH health check error for node {node_id} "
                    f"({managed.ssh_host}): {e}"
                )
                results[node_id] = False
        return results

    def check_flag_files(self) -> dict[int, bool]:
        """Check flag file status on nodes with flag_file_check configured.

        Returns {node_id: True if disabled (flag exists), False if enabled}.
        Uses the same fail-closed logic as _check_flag_file().
        """
        results = {}
        for node_id, managed in self.managed_nodes.items():
            if managed.flag_file_check:
                results[node_id] = self._check_flag_file(managed)
        return results

    def _check_local_override(self, node_id: int) -> bool:
        """Check if a local override file disables auto-disconnect for this node.

        Returns True if disabled (file exists), False if enabled.
        """
        override_path = Path(f"/tmp/autodisconnect_disabled_{node_id}")
        if override_path.exists():
            logger.info(
                f"Local override file {override_path} present — "
                f"auto-disconnect disabled for node {node_id}"
            )
            return True
        return False

    def _check_flag_file(self, managed: ManagedNode) -> bool:
        """Check if auto-disconnect is disabled on the managed node via flag file.

        Returns True if disabled (flag file exists OR check fails), False if enabled.
        Fail-closed: SSH errors are treated as disabled to prevent disconnecting
        when we cannot confirm the operator's intent.
        """
        if not managed.flag_file_check:
            return False  # No flag file configured — not disabled

        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-p", str(managed.ssh_port),
            "-i", str(Path(managed.ssh_key).expanduser()),
            f"{managed.ssh_user}@{managed.ssh_host}",
            f'test -f "{managed.flag_file_check}" && echo DISABLED || echo ENABLED',
        ]

        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout.strip()
            if output == "DISABLED":
                logger.info(
                    f"Flag file {managed.flag_file_check} present on node "
                    f"{managed.node_id} — auto-disconnect disabled by operator"
                )
                return True
            return False
        except Exception as e:
            logger.warning(
                f"Flag file check failed on node {managed.node_id}: {e}. "
                f"Skipping disconnect (fail-closed). Will retry next scan cycle."
            )
            return True  # Fail-closed: if we can't check, do not disconnect
