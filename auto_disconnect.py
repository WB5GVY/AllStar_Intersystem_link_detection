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
import re
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
    # Coherence (2026-10-12): why a skipped_reverify was skipped, for the
    # email wording — "cleared" (the link is gone), "no_evidence" (the
    # record does not support a cut), "query_failed" (could not look).
    reason: str = ""


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
        # Coherence (2026-10-12): the re-verify's "outside link" filter must
        # match detection's (focus / bridges / allowlist never count), and the
        # live-mesh veto is a config toggle (coherence.live_mesh_veto).
        try:
            self.focus_node = int(config.get("focus_node", 0) or 0)
        except (TypeError, ValueError):
            self.focus_node = 0
        self.allowlist: set[int] = set()
        for a in (config.get("allowlist") or []):
            try:
                self.allowlist.add(int(a))
            except (TypeError, ValueError):
                continue
        _coh = config.get("coherence") or {}
        if not isinstance(_coh, dict):
            _coh = {}
        self.coherence_enabled = _coh.get("enabled", True) is not False
        self.live_mesh_veto = _coh.get("live_mesh_veto", True) is not False
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

    def attempt_disconnect(self, event: BridgingEvent, live_mesh_fn=None,
                           mesh_trusted_fn=None) -> Optional[DisconnectResult]:
        """Attempt auto-disconnect for a bridging event.

        1. Check if path goes through a managed node
        2. Wait reverify_delay seconds
        3. Re-check that the offending node is still connected and alive
        4. SSH into the managed node and force disconnect

        Coherence (2026-10-12): step 3 is a decision matrix, not a re-read.
        The bridge side prefers the vantage's LIVE AMI link list; the guest's
        own record must be non-empty and must NAME the managed node (else it
        predates the join and its outside links are equally old; re-reading
        the SAME 60 s post is logged, not refused — a coherent record is
        post-join evidence either way); the live vantage mesh
        (`live_mesh_fn` -> RptSnapshot or None, consulted only when
        `mesh_trusted_fn()` is true) can VETO a cut on a coherent record
        (guest present, none of its claimed outside nodes present); an
        incoherent record is never grounds for a cut (v1). The three real
        cuts to date (records naming only the old network) are refused here.

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

        # Coherence: the vantage's LIVE AMI link list beats the stats API's
        # bridge record (which was >= 21 s stale on 2026-10-11 and said T
        # for a guest that had already left). API only when no feed exists
        # for this managed node (the hub itself has none).
        live = self._live_alinks(managed.node_id)
        live_absent = False
        if live is not None:
            live_nodes, live_age, _ = live
            if target not in live_nodes:
                # A frozen frame on a half-dead session (noticed only after
                # the idle ping, ~105 s worst case) could also read "absent"
                # (audit S9): take it as decisive only when the API bridge
                # record agrees; otherwise log the conflict and continue —
                # the guest-record rules below still apply.
                live_absent = True
                linked = self.api.get_linked_node_details(managed.node_id)
                api_lists = (linked is not None
                             and target in [d["node_id"] for d in linked])
                if not api_lists:
                    msg = (f"Node {target} is not attached to {managed.node_id} per the "
                           f"live AMI link list (RPT_ALINKS age {live_age:.0f} s)"
                           f"{' and the API record agrees' if linked is not None else ' (API record unreadable)'}"
                           f" — resolved on its own or never settled. No action needed.")
                    logger.info(msg)
                    return DisconnectResult(
                        managed_node=managed.node_id, target_node=target,
                        success=True, action="skipped_reverify", message=msg,
                        reason="cleared")
                logger.warning(
                    f"  Node {target}: live AMI (RPT_ALINKS age {live_age:.0f} s) says "
                    f"NOT attached to {managed.node_id} but the API record lists it — "
                    f"possible frozen AMI frame; continuing on the record rules.")
            else:
                logger.info(f"  Node {target} attached to {managed.node_id} per live AMI "
                            f"(RPT_ALINKS age {live_age:.0f} s)")
        if live is None:
            linked = self.api.get_linked_node_details(managed.node_id)
            if linked is None:
                return DisconnectResult(
                    managed_node=managed.node_id, target_node=target,
                    success=False, action="skipped_reverify",
                    message=f"Could not query managed node {managed.node_id} during re-verify",
                    reason="query_failed"
                )

            connected_ids = [d["node_id"] for d in linked]
            if target not in connected_ids:
                msg = (f"Node {target} is no longer connected to {managed.node_id} "
                       f"(resolved on its own). No action needed.")
                logger.info(msg)
                return DisconnectResult(
                    managed_node=managed.node_id, target_node=target,
                    success=True, action="skipped_reverify", message=msg,
                    reason="cleared"
                )

        # === Re-verify: is the target still alive? ===
        dns_info = check_node_dns(target)
        if not dns_info.is_registered:
            msg = (f"Node {target} no longer in DNS during re-verify — "
                   f"likely went offline. Skipping disconnect.")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_reverify", message=msg,
                reason="cleared"
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
        def _skip(msg: str, ok: bool = True, reason: str = "no_evidence") -> DisconnectResult:
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=ok, action="skipped_reverify", message=msg, reason=reason)

        data = self.api.get_node_stats(target)
        target_details = (None if data is None
                          else self.api.get_linked_node_details(target, data=data))
        if target_details is None:
            # Coherence: no record = no evidence. Never fall through to a cut.
            return _skip(f"Node {target}'s own record is unreadable at re-verify — "
                         f"no evidence of an outside link, no cut.", ok=False,
                         reason="query_failed")
        if len(target_details) == 0:
            return _skip(f"Node {target}'s own record is EMPTY at re-verify (not "
                         f"posting / posting no links) — the dark-guest and "
                         f"linkless paths own this case; no cut here.")

        post_age = ASLApiClient.post_age_seconds(data)
        try:
            post_time = int(((data or {}).get("stats") or {}).get("data", {}).get("time"))
        except (TypeError, ValueError, AttributeError):
            post_time = None
        det_post_time = getattr(event, "guest_post_time", None)
        target_links = [d["node_id"] for d in target_details
                        if not d.get("is_external", False) and d["node_id"] != 0]
        # Like detection: focus / bridges / allowlist / our managed nodes
        # never count as "outside", and a CONNECTING (C) link is not a link
        # yet (change 3).
        external_nodes = [
            d["node_id"] for d in target_details
            if not d.get("is_external", False) and d["node_id"] != 0
            and d["node_id"] != managed.node_id
            and d["node_id"] not in self.managed_nodes
            and d["node_id"] not in self.bridge_nodes
            and d["node_id"] != self.focus_node
            and d["node_id"] not in self.allowlist
            and (d.get("link_mode") or "") != "C"]
        ext_details = [d for d in target_details if d.get("is_external", False)]
        # Same predicate as the analyzer's gate (round-2 audit S4): the record
        # names the managed node in linkedNodes OR as a raw `nodes` token; or
        # the analyzer judged it coherent via another system node's record.
        try:
            raw_tokens = set(re.findall(
                r"\d+", str(((data or {}).get("stats") or {}).get("data", {}).get("nodes") or "")))
        except Exception:
            raw_tokens = set()
        try:
            post_time_now = int(((data or {}).get("stats") or {}).get("data", {}).get("time"))
        except (TypeError, ValueError, AttributeError):
            post_time_now = None
        det_pt = getattr(event, "guest_post_time", None)
        same_post_now = (post_time_now is not None and det_pt is not None
                         and post_time_now == det_pt)
        # The analyzer's coherence verdict (which may rest on ANOTHER system
        # node's record — A1) is honoured only for the SAME post it judged;
        # a newer post must name the managed node itself (round-3 audit N-2:
        # a post-leave record must never ride on the old verdict).
        coherent_by_record = (managed.node_id in target_links
                              or str(managed.node_id) in raw_tokens)
        coherent_by_verdict = (same_post_now and target == event.offending_node
                               and bool(getattr(event, "guest_record_coherent", False)))
        if coherent_by_verdict and not coherent_by_record and live is not None:
            # The verdict path is the one route a frozen "present" AMI frame
            # could ride (round-4 audit A1): require the API bridge record
            # to agree that the guest is attached before honouring it.
            linked_chk = self.api.get_linked_node_details(managed.node_id)
            if linked_chk is None or target not in [d["node_id"] for d in linked_chk]:
                return _skip(f"Node {target}: the analyzer's coherence verdict would apply "
                             f"(same post), but the API bridge record "
                             f"{'is unreadable' if linked_chk is None else 'no longer lists it'}"
                             f" — not honoured. No cut.", reason="cleared")
        coherent = coherent_by_record or coherent_by_verdict
        pa_txt = f"{post_age:.0f} s" if isinstance(post_age, (int, float)) else "?"

        same_post = (post_time is not None and det_post_time is not None
                     and post_time == det_post_time)
        # NOTE (audit C1): a 15 s re-verify usually re-reads the SAME 60 s
        # post. That is not grounds to refuse a COHERENT record (it names the
        # managed node, so it is post-join evidence either way); it is logged
        # and, for an incoherent record, the coherence rule below already
        # refuses the cut.
        # NOTE: the "outside" filter here (managed / bridges / focus /
        # allowlist / C) is narrower than detection's, which also drops
        # DNS-dead peers and hub-triangle peers; a cut still needs the
        # analyzer to have fired on a live, non-triangle peer first.

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
                return _skip(
                    f"Node {target} has no AllStar links outside the "
                    f"monitored system at re-verify. Non-AllStar externals "
                    f"still present ({', '.join(skipped_externals)}) — "
                    f"these are single-hop leaf endpoints and are not a "
                    f"bridging hazard. No disconnect.", reason="cleared")
            return _skip(f"Node {target} has no remaining bridging-relevant "
                         f"connections at re-verify. No action needed.", reason="cleared")

        # Live-mesh view: "corroborates" (guest + >= 1 claimed outside node
        # present — informational only in v1), "contradicts" (guest present,
        # none of them — vetoes a cut on a coherent record), else
        # "unavailable" (no source / untrusted / unusable / guest not in the
        # mesh / RPT_LINKS near its 5120-char cap, where absence proves nothing).
        mesh_state = "unavailable"
        mesh_note = ""
        if (self.coherence_enabled and self.live_mesh_veto
                and live_mesh_fn is not None and mesh_trusted_fn is not None):
            trusted = False
            try:
                trusted = bool(mesh_trusted_fn())
            except Exception as e:
                logger.error("re-verify: mesh trust check failed (non-fatal): %s", e)
            snap = None
            if trusted:
                try:
                    snap = live_mesh_fn()
                except Exception as e:
                    logger.error("re-verify: live-mesh read failed (non-fatal): %s", e)
            if not trusted:
                mesh_note = "vantage not trusted"
            elif snap is None or not getattr(snap, "ok", False):
                mesh_note = "no usable vantage snapshot"
            else:
                mesh = {str(x) for x in (getattr(snap, "mesh_nodes", None) or [])}
                raw_links = str((getattr(snap, "variables", None) or {}).get("RPT_LINKS", ""))
                if len(raw_links) >= 4500:
                    mesh_note = f"RPT_LINKS near cap ({len(raw_links)} chars)"
                elif str(target) not in mesh:
                    mesh_note = "guest not in vantage mesh"
                else:
                    seen = [n for n in external_nodes if str(n) in mesh]
                    mesh_state = "corroborates" if seen else "contradicts"
                    mesh_note = (f"vantage {getattr(snap, 'vantage_node', '?')} mesh "
                                 f"{len(mesh)} nodes, outside nodes present: {seen}")
        logger.info(
            f"  Re-verify evidence for {target}: record names {managed.node_id}: "
            f"{coherent}; post age {pa_txt}; post time {post_time}"
            f"{' (same post as detection)' if same_post else ''}; outside "
            f"{external_nodes}; live AMI absent: {live_absent}; live mesh "
            f"{mesh_state} ({mesh_note or 'not consulted'})")

        if self.coherence_enabled:
            if coherent and mesh_state == "contradicts":
                return _skip(f"Node {target}'s record names {managed.node_id} and "
                             f"{external_nodes}, but the live mesh ({mesh_note}) shows "
                             f"{target} and NONE of them — not corroborated. No cut.")
            # v1: an INCOHERENT record is never grounds for a cut (the
            # "licence on live-mesh corroboration" path was withdrawn after
            # three audit rounds — see graph_analyzer._coherence_gate).
            if not coherent:
                return _skip(f"Node {target}'s record does NOT name {managed.node_id} "
                             f"(post age {pa_txt}; raw link list "
                             f"{sorted(target_links)[:20]}) — a pre-join/post-leave "
                             f"record; its outside links {external_nodes} are equally "
                             f"old (live mesh: {mesh_state}, {mesh_note or 'not consulted'}). "
                             f"No cut.")
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

    @staticmethod
    def _live_alinks(vantage_node: int):
        """ami_listener.live_alinks, or None when the module/feed is absent."""
        try:
            from ami_listener import live_alinks
        except Exception:
            return None
        try:
            return live_alinks(vantage_node)
        except Exception as e:
            logger.error("live AMI link lookup failed (non-fatal): %s", e)
            return None

    def read_bridge_union(self, bridge_node_id: int,
                          timeout_s: int = 15) -> Optional[list]:
        """Read a managed bridge's learned-node union (`rpt nodes <id>`) over
        the node's configured SSH. Returns deduped node tokens with the
        app_rpt mode prefix (T/R/C) stripped, [] for an empty union, or None
        on any failure (fail-safe: callers must treat None as "could not
        see", never as "empty"). Read-only: the only remote command this
        method can issue is the fixed `rpt nodes` form."""
        managed = self.managed_nodes.get(bridge_node_id)
        if managed is None:
            return None
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-p", str(managed.ssh_port),
            "-i", str(Path(managed.ssh_key).expanduser()),
            f"{managed.ssh_user}@{managed.ssh_host}",
            f'/usr/sbin/asterisk -rx "rpt nodes {int(bridge_node_id)}"',
        ]
        try:
            proc = subprocess.run(ssh_cmd, capture_output=True, text=True,
                                  timeout=timeout_s)
        except Exception as e:
            logger.warning("read_bridge_union(%s): ssh failed: %s",
                           bridge_node_id, e)
            return None
        if proc.returncode != 0:
            logger.warning("read_bridge_union(%s): rc=%d stderr=%s",
                           bridge_node_id, proc.returncode,
                           (proc.stderr or "")[:200])
            return None
        out = []
        # Skip the banner line entirely ("*** CONNECTED NODES ***") — its
        # words would otherwise survive tokenization as phantom entries.
        body = "\n".join(ln for ln in proc.stdout.splitlines()
                         if "CONNECTED NODES" not in ln)
        for raw in body.replace(",", " ").split():
            tok = raw.strip()
            if not tok or tok.startswith("*") or tok == "<NONE>":
                continue
            # Same mode-prefix rule as rpt_reader (_MODE_CHARS = "TRC").
            if tok[0] in "TRC" and len(tok) > 1:
                tok = tok[1:]
            # Mesh identifiers are uppercase alnum (node numbers, callsigns,
            # EchoLink wire forms). Anything else is CLI furniture — dropping
            # it keeps phantom tokens out of an ENFORCEMENT count (audit A2).
            if tok and re.fullmatch(r"[A-Z0-9]+", tok) and tok not in out:
                out.append(tok)
        return out

    def watchdog_disconnect(self, bridge_node_id: int, target: int,
                            reverify, reason: str) -> Optional[DisconnectResult]:
        """Link-state-watchdog enforcement (2026-07-21, Bennett's max-prefix
        design): disconnect `target` from a managed bridge on the strength of
        SUSTAINED excess link-state advertisement. attempt_disconnect's
        API-bridging re-verify is replaced by the caller's `reverify`
        callable (a fresh vantage/union read) because this path exists
        precisely for offenses the stats API cannot see (wedged gossip,
        flapping records). Every operator safety rail is retained: enabled
        flag, local override, per-pair cooldown, still-connected check, flag
        file. Returns None when not applicable, else a DisconnectResult."""
        managed = self.managed_nodes.get(bridge_node_id)
        if managed is None or not managed.enabled:
            return None
        if target in self.managed_nodes or target in self.bridge_nodes:
            logger.error("watchdog_disconnect: refusing to target "
                         "managed/bridge node %s", target)
            return None
        if self._check_local_override(managed.node_id):
            msg = (f"Watchdog disconnect skipped for node {target} — locally "
                   f"disabled for managed node {managed.node_id}")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_local_override", message=msg)
        key = (managed.node_id, target)
        now = time.monotonic()
        last = self._last_attempt.get(key)
        if last is not None and (now - last) < self.cooldown_seconds:
            msg = (f"Watchdog disconnect for node {target} via "
                   f"{managed.node_id} skipped — within "
                   f"{self.cooldown_seconds}s cooldown")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_cooldown", message=msg)
        logger.info("Watchdog disconnect candidate: node %s via %s (%s). "
                    "Waiting %ds for re-verification...",
                    target, managed.node_id, reason, self.reverify_delay)
        time.sleep(self.reverify_delay)
        # Still connected to the bridge per the bridge's own stats record?
        # (Fail-safe: unqueryable => skip; a wedge source that already left
        # needs no kick.)
        linked = self.api.get_linked_node_details(managed.node_id)
        if linked is None:
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=False, action="skipped_reverify",
                message=f"Could not query managed node {managed.node_id} "
                        "during watchdog re-verify")
        if target not in [d["node_id"] for d in linked]:
            msg = (f"Node {target} no longer connected to {managed.node_id} "
                   "at watchdog re-verify. No action needed.")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_reverify", message=msg)
        # The watchdog's own offense re-check (fresh link-state reading).
        try:
            still_excess = bool(reverify())
        except Exception as e:
            logger.error("watchdog_disconnect: reverify callable failed: %s", e)
            still_excess = False
        if not still_excess:
            msg = (f"Link-state excess no longer present at re-verify — "
                   f"no disconnect of {target} (self-resolved or transient)")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_reverify", message=msg)
        if self._check_flag_file(managed):
            msg = (f"Watchdog disconnect skipped for node {target} — disabled "
                   f"by operator on node {managed.node_id} (flag file)")
            logger.info(msg)
            return DisconnectResult(
                managed_node=managed.node_id, target_node=target,
                success=True, action="skipped_flagfile", message=msg)
        logger.warning("LINK-STATE WATCHDOG DISCONNECT: node %s from managed "
                       "node %s (%s)", target, managed.node_id, reason)
        result = self._ssh_disconnect(managed, target)
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
            if result.returncode != 0 or output != "ENABLED":
                # Audit 2026-09-08 S-D: an SSH that connects but does not
                # answer the question (rc != 0, empty/foreign output) is
                # NOT "operator has not disabled us" — fail closed.
                logger.warning(
                    f"Flag file check on node {managed.node_id} inconclusive "
                    f"(rc={result.returncode}, stdout={output[:40]!r}, "
                    f"stderr={(result.stderr or '')[:80]!r}). Skipping disconnect "
                    f"(fail-closed). Will retry next scan cycle.")
                return True
            return False
        except Exception as e:
            logger.warning(
                f"Flag file check failed on node {managed.node_id}: {e}. "
                f"Skipping disconnect (fail-closed). Will retry next scan cycle."
            )
            return True  # Fail-closed: if we can't check, do not disconnect


# ---------------------------------------------------------------------------
# Self-test (2026-10-12, coherence): offline, no SSH, no DNS, no network.
# ---------------------------------------------------------------------------

def _selftest() -> int:            # pragma: no cover - developer tool
    """Re-verify decision matrix on a synthetic mesh: focus 1000 -> managed
    bridge 2000 -> guest 4000 -> outside 5000. Fake stats API, stubbed DNS,
    recorded SSH, a fake AMI registry entry for vantage 2000."""
    import time as _time
    import types
    import ami_listener as _ami

    def rec(name):
        return {"name": name, "Node_ID": 1, "callsign": f"C{name}",
                "server": {"Location": "X"}, "regseconds": 1}

    def mk_api(records: dict, calls: list):
        client = ASLApiClient()
        def stats(n):
            calls.append(n)
            r = records.get(n, "absent")
            if r is None:
                return None
            if r == "absent":
                return {"stats": {"data": {"nodes": "", "linkedNodes": []}}}
            nodes, linked, t = r
            d = {"nodes": nodes, "linkedNodes": linked}
            if t is not None:
                d["time"] = t
            return {"stats": {"data": d}}
        client.get_node_stats = stats  # type: ignore[assignment]
        return client

    def mk_event(post_time=100, incoherent_for=None):
        return BridgingEvent(
            offending_node=4000, offending_callsign="C4000", offending_location="X",
            path=[1000, 2000, 4000, 5000], path_description="1000 → 2000 → 4000 → 5000",
            depth=2, rule="Screen 2: guest 4000 (via bridge 2000) has unauthorized connection to 5000",
            guest_post_time=post_time, incoherent_for_seconds=incoherent_for)

    def mesh(nodes, raw_len=10, ok=True):
        return types.SimpleNamespace(ok=ok, mesh_nodes=[str(n) for n in nodes],
                                     variables={"RPT_LINKS": "x" * raw_len}, vantage_node=3000)

    base_cfg = {"focus_node": 1000, "bridge_nodes": [2000], "allowlist": [8000],
                "auto_disconnect": {"reverify_delay_seconds": 0,
                                    "nodes": [{"node_id": 2000, "ssh_host": "h", "enabled": True}]},
                "coherence": {"live_mesh_veto": True}}
    bridge_rec = ("T1000,T4000", [rec(1000), rec(4000)], 50)

    global check_node_dns
    saved_dns = check_node_dns
    check_node_dns = lambda n: types.SimpleNamespace(is_registered=True, ip_address="192.0.2.1", port=4569)  # noqa: E731
    saved_reg = dict(_ami._REGISTRY)
    checks: list = []

    def run(guest, ami="present", mesh_snap=None, trusted=True, cfg=None,
            bridge=bridge_rec, event=None):
        calls: list = []
        ssh: list = []
        api = mk_api({2000: bridge, 4000: guest}, calls)
        d = AutoDisconnector(cfg or base_cfg, api)
        d._check_local_override = lambda nid: False          # type: ignore[assignment]
        d._check_flag_file = lambda m: False                  # type: ignore[assignment]
        def fake_ssh(managed, target):
            ssh.append(target)
            return DisconnectResult(managed_node=managed.node_id, target_node=target,
                                    success=True, action="disconnected", message="fake")
        d._ssh_disconnect = fake_ssh                          # type: ignore[assignment]
        _ami._REGISTRY.clear()
        if ami == "present":
            _ami._REGISTRY[2000] = types.SimpleNamespace(
                connected=True, _alinks_snap=("2,4000TU,1000TU", _time.monotonic(), 1), _session_no=1)
        elif ami == "absent":
            _ami._REGISTRY[2000] = types.SimpleNamespace(
                connected=True, _alinks_snap=("1,1000TU", _time.monotonic(), 1), _session_no=1)
        elif ami == "stale_session":
            _ami._REGISTRY[2000] = types.SimpleNamespace(
                connected=True, _alinks_snap=("2,4000TU,1000TU", _time.monotonic(), 1), _session_no=2)
        res = d.attempt_disconnect(
            event or mk_event(),
            live_mesh_fn=(lambda: mesh_snap) if mesh_snap is not None else None,
            mesh_trusted_fn=(lambda: trusted))
        return res, calls, ssh

    try:
        incoh = ("T5000", [rec(5000)], 200)
        coh = ("T2000,T5000", [rec(2000), rec(5000)], 200)
        a, _, a_ssh = run(None)
        b, _, b_ssh = run("absent")
        c, _, c_ssh = run(("T2000,T5000", [rec(2000), rec(5000)], 100))      # same post as detection
        d_, _, d_ssh = run(incoh)
        ev_past = mk_event(incoherent_for=300.0)
        e, _, e_ssh = run(incoh, mesh_snap=mesh([1000, 2000, 4000, 5000]), event=ev_past)
        e0, _, e0_ssh = run(incoh, mesh_snap=mesh([1000, 2000, 4000, 5000]))
        e2, _, e2_ssh = run(incoh, mesh_snap=mesh([1000, 2000, 4000]), event=ev_past)
        cfg_dis = dict(base_cfg); cfg_dis["coherence"] = {"enabled": False}
        e3, _, e3_ssh = run(incoh, cfg=cfg_dis)                                 # gate off -> today's cut
        e4, _, e4_ssh = run(coh, ami="absent")                                   # live absent, API lists -> continue
        f, _, f_ssh = run(coh, mesh_snap=mesh([1000, 2000, 4000]))
        g, _, g_ssh = run(coh, mesh_snap=mesh([1000, 2000, 4000]), trusted=False)
        h, _, h_ssh = run(coh, mesh_snap=mesh([1000, 2000, 4000], raw_len=4600))
        h2, _, h2_ssh = run(coh, mesh_snap=mesh([1000, 2000], ))                 # guest not in mesh
        h3, _, h3_ssh = run(coh, mesh_snap=mesh([1000, 2000, 4000], ok=False))
        i, i_calls, i_ssh = run(coh, ami="absent", bridge=("T1000", [rec(1000)], 50))
        i2, _, i2_ssh = run(coh, ami="stale_session", bridge=("T1000", [rec(1000)], 50))
        j, j_calls, j_ssh = run(coh, ami="none")
        j2, _, j2_ssh = run(coh, ami="none", bridge=("T1000", [rec(1000)], 50))
        k, _, k_ssh = run(("T2000,C5000,T8000,T1000", [rec(2000), rec(5000), rec(8000), rec(1000)], 200))
        cfg_off = dict(base_cfg); cfg_off["coherence"] = {"live_mesh_veto": False}
        l, _, l_ssh = run(coh, mesh_snap=mesh([1000, 2000, 4000]), cfg=cfg_off)
        m, _, m_ssh = run(coh, mesh_snap=mesh([1000, 2000, 4000, 5000]))
        n, _, n_ssh = run(coh)                                                  # no mesh source at all
        # round-2 audit S4: the same coherence predicate as the analyzer
        o, _, o_ssh = run(("T2000,R2000,T5000", [rec(5000)], 200))             # attach only as a raw token
        ev_coh = mk_event(post_time=200); ev_coh.guest_record_coherent = True
        p, _, p_ssh = run(incoh, event=ev_coh)                 # analyzer judged coherent (A1), SAME post
        ev_coh2 = mk_event(post_time=100); ev_coh2.guest_record_coherent = True
        p2, _, p2_ssh = run(incoh, event=ev_coh2)              # a NEWER post that lacks the managed node
        ev_coh3 = mk_event(post_time=None); ev_coh3.guest_record_coherent = True
        p3, _, p3_ssh = run(incoh, event=ev_coh3)              # no post time on the event -> no verdict reuse
        p4, _, p4_ssh = run(incoh, event=ev_coh, bridge=("T1000", [rec(1000)], 50))   # verdict path but API bridge record lacks the guest (A1)
        checks = [
            ("verdict reuse needs a post time on the event (None -> skipped)",
             p3.action == "skipped_reverify" and not p3_ssh),
            ("verdict reuse with live AMI 'present' but the API bridge record lacking the guest -> skipped (A1)",
             p4.action == "skipped_reverify" and p4.reason == "cleared" and not p4_ssh),
            ("analyzer verdict honoured only for the SAME post: newer post lacking the managed node -> skipped (N-2)",
             p2.action == "skipped_reverify" and not p2_ssh),
            ("reason codes: unreadable -> query_failed, empty -> no_evidence, incoherent -> no_evidence, "
             "live-absent -> cleared, no outside -> cleared",
             a.reason == "query_failed" and b.reason == "no_evidence" and d_.reason == "no_evidence"
             and i.reason == "cleared" and k.reason == "cleared"),
            ("attach named only as a raw `nodes` token -> coherent -> disconnected",
             o.action == "disconnected" and o_ssh == [4000]),
            ("event marked coherent by the analyzer (via another system node) -> disconnected",
             p.action == "disconnected" and p_ssh == [4000]),
            ("unreadable guest record -> skipped, success False, no SSH",
             a.action == "skipped_reverify" and a.success is False and not a_ssh),
            ("empty guest record -> skipped, no SSH",
             b.action == "skipped_reverify" and "EMPTY" in b.message and not b_ssh),
            ("coherent record, SAME post as detection -> still a cut (audit C1)",
             c.action == "disconnected" and c_ssh == [4000]),
            ("incoherent record, no mesh -> skipped ('does NOT name')",
             d_.action == "skipped_reverify" and "does NOT name 2000" in d_.message and not d_ssh),
            ("incoherent record + corroborating mesh -> STILL skipped (v1: no licence path), with or "
             "without a past-grace mark on the event",
             e.action == "skipped_reverify" and not e_ssh
             and e0.action == "skipped_reverify" and not e0_ssh),
            ("incoherent record + trusted mesh lacking far node -> skipped",
             e2.action == "skipped_reverify" and not e2_ssh),
            ("coherence.enabled false -> incoherent record cuts as before (audit S4)",
             e3.action == "disconnected" and e3_ssh == [4000]),
            ("live AMI absent but API bridge record lists the guest -> continue on record rules (audit S9)",
             e4.action == "disconnected" and e4_ssh == [4000]),
            ("coherent record + trusted mesh lacking far node -> skipped (not corroborated)",
             f.action == "skipped_reverify" and "not corroborated" in f.message and not f_ssh),
            ("coherent record + untrusted mesh -> disconnected on record evidence",
             g.action == "disconnected" and g_ssh == [4000]),
            ("coherent record + RPT_LINKS near cap -> no veto -> disconnected",
             h.action == "disconnected" and h_ssh == [4000]),
            ("coherent record, guest not in mesh / unusable snapshot -> no veto -> disconnected",
             h2.action == "disconnected" and h3.action == "disconnected"),
            ("live AMI says guest absent and the API bridge record agrees -> skipped, no guest read",
             i.action == "skipped_reverify" and "live AMI" in i.message and not i_ssh
             and 4000 not in i_calls),
            ("stale AMI session -> API fallback (bridge record without guest -> skipped)",
             i2.action == "skipped_reverify" and "no longer connected" in i2.message and not i2_ssh),
            ("no AMI feed -> API fallback (bridge lists guest -> proceeds -> disconnected)",
             j.action == "disconnected" and 2000 in j_calls and j_ssh == [4000]),
            ("no AMI feed, bridge record lacks guest -> skipped",
             j2.action == "skipped_reverify" and not j2_ssh),
            ("C / allowlist / focus / managed links are not outside links -> skipped",
             k.action == "skipped_reverify" and "no remaining" in k.message and not k_ssh),
            ("live_mesh_veto off -> contradicting mesh ignored -> disconnected",
             l.action == "disconnected" and l_ssh == [4000]),
            ("coherent record + corroborating mesh -> disconnected",
             m.action == "disconnected" and m_ssh == [4000]),
            ("coherent record, no mesh source -> disconnected (today's path)",
             n.action == "disconnected" and n_ssh == [4000]),
        ]
    finally:
        check_node_dns = saved_dns
        _ami._REGISTRY.clear()
        _ami._REGISTRY.update(saved_reg)
    failed = 0
    for name, ok in checks:
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
        failed += 0 if ok else 1
    print(f"auto_disconnect selftest: {len(checks) - failed}/{len(checks)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        logging.basicConfig(level=logging.WARNING)
        sys.exit(_selftest())
    print("usage: python3 -m auto_disconnect --selftest")
