"""AMI push listener — asynchronous link-change wake source (phase 2).

app_rpt's `rpt_update_links` fires Asterisk Manager Interface (AMI) events
(RPT_ALINKS / RPT_NUMALINKS / RPT_LINKS / RPT_NUMLINKS, each carrying the
node and an EventValue) every time the vantage node's link set changes. This
module maintains a persistent AMI session to the vantage node and, on a
link-change event, WAKES the LinkWatcher for an immediate tick.

It deliberately does NOT act on events itself: enforcement (tripwire
evaluation, watch-mode re-kicks) stays single-threaded inside LinkWatcher,
which re-reads the mesh over SSH on wake. AMI only collapses the watcher's
poll latency (~60s) to a couple of seconds. If AMI is down, nothing is lost
— the watcher's polling continues as before.

Transport: the vantage node's AMI binds to 127.0.0.1 only (HamVoIP default),
so the listener owns an `ssh -N -L` tunnel subprocess (same SSH credentials
as auto_disconnect / rpt_reader; zero changes on the node) and speaks the
line-based AMI protocol through it. Credentials come from secrets.yaml's
`ami:` block — never from the repo config.

Wire-format note (app_rpt 0.327 `rpt_manager_trigger`): the event includes
LastKeyedTime/LastTxKeyedTime rendered with ctime(), whose value embeds a
raw newline. The parser therefore treats any blank line as end-of-block and
ignores fragment blocks with no Event: header — the fields we need (Event,
Node, EventValue) always precede the damaged ones.

Fail-safe: every failure path logs and retries with capped backoff; nothing
here may crash the daemon or block its shutdown (daemon thread + stop()).
"""

from __future__ import annotations

import inspect
import logging
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Events that indicate the link set changed. Keyed-state events (RPT_RXKEYED
# etc.) arrive on the same channel; since 2026-07-06 they feed the QSO
# activity tracker (they still never wake the watcher).
_LINK_EVENTS = ("RPT_ALINKS", "RPT_NUMALINKS", "RPT_LINKS", "RPT_NUMLINKS")
_KEYED_EVENTS = ("RPT_TXKEYED", "RPT_RXKEYED", "RPT_ETXKEYED")

_BACKOFF_START_S = 5
_BACKOFF_MAX_S = 300
_SOCKET_IDLE_TIMEOUT_S = 60          # send an AMI Ping if quiet this long
_MIN_WAKE_INTERVAL_S = 2             # debounce bursts of link events
_DEFAULT_QSO_HOLD_S = 120            # unkeyed gap that ends a "QSO"
_LISTENER_KEYED_DEBOUNCE_S = 30      # per-node: one keyed report per window

# Coherence (2026-10-12): started listeners register here by vantage node so
# the re-verify can ask "is node N attached to vantage V RIGHT NOW" from the
# live RPT_ALINKS feed instead of the stats API's (lagging) bridge record.
# Written only by start()/stop() on the main thread; read by scan/watch threads.
_REGISTRY: dict[int, "AmiListener"] = {}


def live_alinks(vantage_node: int) -> Optional[tuple[set[int], float, bool]]:
    """Live adjacent-link membership of a vantage from its AMI feed.

    Returns (node ids in the LAST RPT_ALINKS frame, seconds since that frame,
    connected) or None when nothing live is known: no started listener for
    the vantage, not logged in, or no RPT_ALINKS frame yet in THIS session
    (a frame from a previous session could say "absent" for a node that
    joined during the outage). Reads one atomically-swapped tuple; never
    touches the socket. Age is informational — an unchanged ALINKS is still
    correct — so callers must not veto on it."""
    try:
        lst = _REGISTRY.get(int(vantage_node))
    except (TypeError, ValueError):
        return None
    if lst is None or not getattr(lst, "connected", False):
        return None
    value, at, sess = getattr(lst, "_alinks_snap", ("", 0.0, 0))
    if not at or sess != getattr(lst, "_session_no", -1):
        return None
    nodes = set()
    for node, _mode, _keyed in parse_alinks(value):
        try:
            nodes.add(int(node))
        except ValueError:
            continue
    return nodes, max(0.0, time.monotonic() - at), True


def parse_alinks(value: str) -> list[tuple[str, str, bool]]:
    """RPT_ALINKS EventValue "N,12345TK,67890RU,..." -> [(node, mode, keyed)].
    node = leading digits; mode = the letter after them ('T'/'R'/'L'/'C' or
    '' when absent); keyed = trailing 'K'. Malformed entries are skipped.
    Pure function (selftested)."""
    out = []
    for part in (value or "").split(",")[1:]:
        part = part.strip()
        if not part:
            continue
        i = 0
        while i < len(part) and part[i].isdigit():
            i += 1
        if i == 0:
            continue
        node, rest = part[:i], part[i:]
        keyed = rest.endswith("K")
        mode = rest[:-1] if rest and rest[-1] in ("K", "U") else rest
        out.append((node, mode, keyed))
    return out


def parse_ami_stream(buf: str):
    """Split a receive buffer into (complete_blocks, remainder).

    Each block is a dict of header->value. Lines without a colon (e.g. the
    ctime fragments) are ignored. A block with no recognizable headers
    yields an empty dict, which callers skip.
    """
    blocks = []
    # Normalize CRLF; a lone \r (from the ctime damage) becomes empty on strip.
    while True:
        # An AMI block ends at a blank line ("\r\n\r\n"); tolerate bare "\n\n".
        for sep in ("\r\n\r\n", "\n\n"):
            idx = buf.find(sep)
            if idx != -1:
                raw, buf = buf[:idx], buf[idx + len(sep):]
                break
        else:
            return blocks, buf
        block = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            block[key.strip()] = value.strip()
        blocks.append(block)


class AmiListener(threading.Thread):
    """Daemon thread: SSH tunnel + AMI session + wake-on-link-change."""

    def __init__(self, vantage_node: int, ssh_host: str, ssh_user: str,
                 ssh_key: str, ssh_port: int, local_port: int,
                 remote_port: int, username: str, secret: str,
                 on_link_change: Callable[[str], None],
                 on_listener_keyed: Optional[Callable[[int, str], None]] = None,
                 listener_ids_provider: Optional[Callable[[], frozenset]] = None):
        super().__init__(name="ami-listener", daemon=True)
        self.vantage_node = vantage_node
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.ssh_key = ssh_key
        self.ssh_port = ssh_port
        self.local_port = local_port
        self.remote_port = remote_port
        self.username = username
        self._secret = secret
        self._on_link_change = on_link_change
        # Step 2 trigger B (2026-09-07): a permitted listener whose link to
        # the vantage shows K (keyed toward us) has, by that fact, sent audio
        # over a link it reports as monitor-only. Report it (the daemon
        # vetoes its listener status and scans at once). Provider returns
        # the current permitted-listener ids (LinkWatcher.listener_ids).
        self._on_listener_keyed = on_listener_keyed
        self._listener_ids_provider = listener_ids_provider
        self._last_keyed_report: dict[int, float] = {}   # node -> monotonic
        self._keyed_state: dict[int, bool] = {}          # node -> K in the last frame
        self._stop = threading.Event()
        self._tunnel: Optional[subprocess.Popen] = None
        self._sock: Optional[socket.socket] = None
        self._last_values: dict[str, str] = {}    # event name -> EventValue
        self._last_wake = 0.0
        self.connected = False                     # for logging/telemetry
        # --- QSO activity tracking (2026-07-06) ------------------------------
        # AllStar audio floods the mesh, so ANY keyed indication at the
        # vantage (an adjacent link's K suffix in RPT_ALINKS, or the
        # vantage's own TX/RX keyed events) means a QSO is in progress
        # network-wide. A QSO "ends" only after qso_hold_s of silence —
        # over-to-over gaps must not toggle the state.
        self.qso_hold_s = _DEFAULT_QSO_HOLD_S
        self._keyed_sources: dict[str, bool] = {}  # source -> currently keyed
        # Snapshot tuple, swapped atomically (GIL) for lock-free readers:
        # (currently_keyed, active_since_epoch, last_keyed_epoch)
        self._qso_snap: tuple = (False, None, None)
        # Coherence (2026-10-12): last RPT_ALINKS frame as one atomically
        # swapped tuple (raw value, monotonic time, login session number) for
        # live_alinks(); the session number keeps a pre-outage frame from
        # answering for the current session.
        self._alinks_snap: tuple = ("", 0.0, 0)
        self._session_no = 0

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        try:
            _REGISTRY[int(self.vantage_node)] = self
        except (TypeError, ValueError):
            pass
        super().start()

    def stop(self) -> None:
        self._stop.set()
        try:
            if _REGISTRY.get(int(self.vantage_node)) is self:
                _REGISTRY.pop(int(self.vantage_node), None)
        except (TypeError, ValueError):
            pass
        self._close_socket()
        self._kill_tunnel()

    def run(self) -> None:
        logger.info("ami_listener: thread started (vantage %d via localhost:%d)",
                    self.vantage_node, self.local_port)
        backoff = _BACKOFF_START_S
        while not self._stop.is_set():
            try:
                self._ensure_tunnel()
                self._connect_and_login()
                backoff = _BACKOFF_START_S       # a good session resets backoff
                self._event_loop()               # returns on error/disconnect
            except Exception as e:
                if not self._stop.is_set():
                    logger.warning("ami_listener: session ended: %s — "
                                   "reconnecting in %ds", e, backoff)
            self.connected = False
            self._close_socket()
            if self._stop.is_set():
                break
            self._stop.wait(backoff)
            backoff = min(backoff * 2, _BACKOFF_MAX_S)
        self._close_socket()
        self._kill_tunnel()
        logger.info("ami_listener: thread stopped")

    # --- tunnel --------------------------------------------------------------

    def _ensure_tunnel(self) -> None:
        if self._tunnel is not None and self._tunnel.poll() is None:
            return
        self._kill_tunnel()
        cmd = [
            "ssh", "-N",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-p", str(self.ssh_port),
            "-i", str(Path(self.ssh_key).expanduser()),
            "-L", f"127.0.0.1:{self.local_port}:127.0.0.1:{self.remote_port}",
            f"{self.ssh_user}@{self.ssh_host}",
        ]
        self._tunnel = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("ami_listener: SSH tunnel started (pid %d, local port %d)",
                    self._tunnel.pid, self.local_port)
        # Give the forward a moment to establish before we dial it, then
        # confirm the child is actually alive: ExitOnForwardFailure makes a
        # bind failure (e.g. the port held by an orphaned ssh from a hard
        # kill) exit immediately, and connecting through an unmanaged orphan
        # must not masquerade as a healthy session (audit 2026-07-03 #4, S2).
        self._stop.wait(2)
        if self._tunnel.poll() is not None:
            rc = self._tunnel.returncode
            self._tunnel = None
            raise ConnectionError(
                f"SSH tunnel exited immediately (rc={rc}) — local port "
                f"{self.local_port} may be held by an orphaned ssh from a "
                f"previous hard kill; it will be retried after backoff")

    def _kill_tunnel(self) -> None:
        if self._tunnel is not None:
            try:
                self._tunnel.terminate()
                self._tunnel.wait(timeout=5)
            except Exception:
                try:
                    self._tunnel.kill()
                except Exception:
                    pass
            self._tunnel = None

    # --- AMI session -----------------------------------------------------------

    def _close_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _connect_and_login(self) -> None:
        self._sock = socket.create_connection(
            ("127.0.0.1", self.local_port), timeout=10)
        self._sock.settimeout(10)
        banner = self._sock.recv(1024).decode("utf-8", "replace")
        if "Asterisk Call Manager" not in banner:
            raise ConnectionError(f"unexpected AMI banner: {banner[:60]!r}")
        login = (f"Action: Login\r\nUsername: {self.username}\r\n"
                 f"Secret: {self._secret}\r\nEvents: on\r\n\r\n")
        self._sock.sendall(login.encode())
        # Read until the login response block arrives.
        buf = ""
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            buf += self._sock.recv(4096).decode("utf-8", "replace")
            blocks, buf = parse_ami_stream(buf)
            for b in blocks:
                if b.get("Response") == "Success":
                    self._session_no += 1
                    # A new session starts with no known values: the first
                    # frames are stored (and may wake once) even if they
                    # equal the previous session's (audit S9).
                    self._last_values.clear()
                    self.connected = True
                    logger.info("ami_listener: logged in to AMI on vantage %d",
                                self.vantage_node)
                    self._residual = buf
                    return
                if b.get("Response") == "Error":
                    # Never log the secret; the message is safe.
                    raise ConnectionError(
                        f"AMI login rejected: {b.get('Message', '?')}")
        raise ConnectionError("AMI login timed out")

    def _event_loop(self) -> None:
        buf = getattr(self, "_residual", "")
        self._sock.settimeout(_SOCKET_IDLE_TIMEOUT_S)
        while not self._stop.is_set():
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                # Idle: AMI keepalive. A dead session raises on send/recv.
                self._sock.sendall(b"Action: Ping\r\n\r\n")
                continue
            if not chunk:
                raise ConnectionError("AMI socket closed by peer")
            buf += chunk.decode("utf-8", "replace")
            if len(buf) > 1_000_000:      # runaway garbage guard
                buf = ""
                continue
            blocks, buf = parse_ami_stream(buf)
            for b in blocks:
                self._handle_block(b)

    # --- QSO activity ----------------------------------------------------------

    def _update_qso(self, event: str, value: str) -> None:
        """Fold one event into the QSO snapshot. Called only from the
        listener thread; readers use qso_state().

        RPT_ALINKS keyed suffixes are treated as a PULSE (they refresh
        last_keyed), never as a persistent source: ALINKS is only emitted on
        transitions, so a K frozen into a stale snapshot must not latch the
        state ACTIVE forever (audit 2026-07-06, S1). The vantage's own
        TX/RX keyed events carry explicit 0/1 and are safe to hold as
        persistent booleans."""
        pulse = False
        if event == "RPT_ALINKS":
            # "N,12345TK,67890TU,...": an entry ending K = that link keyed.
            pulse = any(part and part[-1] == "K"
                        for part in value.split(",")[1:])
            if not pulse and not any(self._keyed_sources.values()):
                # Membership/keyed snapshot shows silence: nothing to add,
                # and the hold timer will age last_keyed out naturally.
                return
        elif event in _KEYED_EVENTS:
            self._keyed_sources[event] = value.strip() not in ("", "0")
        else:
            return
        keyed = any(self._keyed_sources.values()) or pulse
        was_keyed, active_since, last_keyed = self._qso_snap
        now = time.time()
        if keyed:
            gap_over = (last_keyed is None
                        or (now - last_keyed) > self.qso_hold_s)
            if (not was_keyed and (active_since is None or gap_over)) \
                    or active_since is None:
                active_since = now       # a NEW QSO (silence gap elapsed)
            last_keyed = now
        # currently_keyed reflects only the PERSISTENT sources; pulses live
        # on through last_keyed + the hold window in qso_state().
        self._qso_snap = (any(self._keyed_sources.values()),
                          active_since, last_keyed)

    def qso_state(self):
        """(state, since_datetime) — state is 'active' / 'inactive' / None
        (None = no keyed indication observed yet this session, e.g. right
        after a restart on a quiet mesh). Thread-safe, lock-free."""
        from datetime import datetime
        keyed, active_since, last_keyed = self._qso_snap
        if last_keyed is None:
            return None, None
        if keyed or (time.time() - last_keyed) <= self.qso_hold_s:
            since = active_since or last_keyed
            return "active", datetime.fromtimestamp(since).astimezone()
        return "inactive", datetime.fromtimestamp(last_keyed).astimezone()

    def qso_caption(self) -> str:
        """Short caption line for the bubble map, '' when unknown."""
        state, since = self.qso_state()
        if state is None:
            return ""
        return (f"{'ACTIVE' if state == 'active' else 'inactive'} since "
                f"{since.strftime('%H:%M %Z')}")

    def _handle_block(self, block: dict) -> None:
        event = block.get("Event", "")
        node = block.get("Node", "")
        if node and node != str(self.vantage_node):
            return
        value = block.get("EventValue", "")
        if event in _KEYED_EVENTS or event == "RPT_ALINKS":
            try:
                self._update_qso(event, value)
            except Exception as e:
                logger.debug("ami_listener: qso update failed: %s", e)
        if event not in _LINK_EVENTS:
            return
        if self._last_values.get(event) == value:
            return                       # no actual change for this variable
        self._last_values[event] = value
        if event == "RPT_ALINKS":
            self._alinks_snap = (value, time.monotonic(), getattr(self, "_session_no", 0))
            # After the dedup (audit 2026-09-08 C1): a K is reported only on
            # a TRANSITION frame, never re-reported from a repeated value.
            try:
                self._check_listener_keyed(value)
            except Exception as e:
                logger.error("ami_listener: listener-keyed check failed "
                             "(non-fatal): %s", e)
        now = time.monotonic()
        if (now - self._last_wake) < _MIN_WAKE_INTERVAL_S:
            return                       # burst debounce: one wake suffices
        self._last_wake = now
        logger.info("ami_listener: link change on %d (%s=%s) — waking watcher",
                    self.vantage_node, event,
                    value if len(value) < 120 else value[:117] + "...")
        try:
            self._on_link_change(f"AMI {event} change on {self.vantage_node}")
        except Exception as e:
            logger.error("ami_listener: wake callback failed: %s", e)


    def _check_listener_keyed(self, value: str) -> None:
        """Trigger B: any K entry whose node is a permitted listener."""
        if self._on_listener_keyed is None or self._listener_ids_provider is None:
            return
        # Per-node TRANSITIONS only (audit 2026-09-08 C-1): a node that is
        # still K when some OTHER link changes the frame is not a new keyup.
        parsed = parse_alinks(value)
        now_keyed: dict[int, bool] = {}
        for node, _mode, keyed in parsed:
            try:
                now_keyed[int(node)] = keyed
            except ValueError:
                continue
        prev_state = getattr(self, "_keyed_state", {})
        self._keyed_state = now_keyed
        rising = [n for n, k in now_keyed.items() if k and not prev_state.get(n, False)]
        if not rising:
            return
        listeners = self._listener_ids_provider() or frozenset()
        if not listeners:
            return
        now = time.monotonic()
        for nid in rising:
            if nid not in listeners:
                continue
            last = self._last_keyed_report.get(nid, 0.0)
            if (now - last) < _LISTENER_KEYED_DEBOUNCE_S:
                continue
            self._last_keyed_report[nid] = now
            logger.warning("ami_listener: watched node %d KEYED toward "
                           "vantage %d (RPT_ALINKS=%s) — reporting",
                           nid, self.vantage_node,
                           value if len(value) < 120 else value[:117] + "...")
            # Arity decided ONCE per callback (audit S4): a TypeError raised
            # INSIDE a 3-arg callback must never re-dispatch it as 2-arg.
            if _keyed_callback_takes_vantage(self._on_listener_keyed):
                self._on_listener_keyed(nid, value, self.vantage_node)
            else:
                self._on_listener_keyed(nid, value)     # legacy 2-arg callback


_ARITY_CACHE: dict = {}


def _keyed_callback_takes_vantage(cb) -> bool:
    """True when `cb` accepts a third positional argument (the reporting
    vantage). Decided by signature inspection, cached per callback object;
    an uninspectable callable is treated as legacy 2-arg."""
    key = id(cb)
    hit = _ARITY_CACHE.get(key)
    if hit is not None and hit[0] is cb:
        return hit[1]
    takes = False
    try:
        params = list(inspect.signature(cb).parameters.values())
        positional = [p for p in params
                      if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        takes = (len(positional) >= 3
                 or any(p.kind == p.VAR_POSITIONAL for p in params))
    except (TypeError, ValueError):
        takes = False
    _ARITY_CACHE[key] = (cb, takes)
    return takes


def build_ami_listener(config: dict, on_link_change,
                       on_listener_keyed=None,
                       listener_ids_provider=None,
                       vantage_override: Optional[dict] = None) -> Optional[AmiListener]:
    """Build (not start) an AmiListener, or None if disabled/misconfigured.

    SSH credentials come from the matching auto_disconnect.nodes entry (like
    rpt_reader); AMI credentials come from secrets.yaml's `ami:` block,
    merged into config["ami"] by load_config. Never raises.

    `vantage_override` (step 2b): one entry of `ami_listener.vantages`
    ({node, enabled, local_port, remote_port}) — builds a listener for that
    node instead of the top-level vantage_node.
    """
    try:
        acfg = config.get("ami_listener") or {}
        if not isinstance(acfg, dict) or not acfg.get("enabled", False):
            return None
        if vantage_override:
            if vantage_override.get("enabled", True) is False:
                return None
            acfg = {**acfg, **{k: v for k, v in vantage_override.items()
                               if k in ("local_port", "remote_port", "qso_hold_seconds")},
                    "vantage_node": vantage_override.get("node")}
        vantage = int(acfg.get("vantage_node")
                      or (config.get("rpt_reader") or {}).get("vantage_node", 0))
        if not vantage:
            logger.error("ami_listener: enabled but no vantage_node")
            return None
        node_cfg = next(
            (n for n in (config.get("auto_disconnect", {}) or {}).get("nodes", [])
             if n.get("node_id") == vantage), None)
        if node_cfg is None:
            logger.error("ami_listener: vantage %d has no auto_disconnect.nodes "
                         "entry (need its SSH creds)", vantage)
            return None
        secrets = config.get("ami") or {}
        cred = secrets.get(vantage) or secrets.get(str(vantage)) or {}
        if not cred.get("secret"):
            logger.error("ami_listener: no AMI secret for node %d in "
                         "secrets.yaml (ami: block) — listener disabled", vantage)
            return None
        listener = AmiListener(
            vantage_node=vantage,
            ssh_host=node_cfg["ssh_host"],
            ssh_user=node_cfg.get("ssh_user", "root"),
            ssh_key=node_cfg.get("ssh_key", "~/.ssh/id_rsa"),
            ssh_port=node_cfg.get("ssh_port", 22),
            local_port=int(acfg.get("local_port", 61220)),
            remote_port=int(acfg.get("remote_port", 5038)),
            username=str(cred.get("username", "admin")),
            secret=str(cred["secret"]),
            on_link_change=on_link_change,
            on_listener_keyed=on_listener_keyed,
            listener_ids_provider=listener_ids_provider,
        )
        try:
            listener.qso_hold_s = max(
                10, int(acfg.get("qso_hold_seconds", _DEFAULT_QSO_HOLD_S)))
        except (TypeError, ValueError):
            logger.warning("ami_listener: bad qso_hold_seconds; using %d",
                           _DEFAULT_QSO_HOLD_S)
        logger.info("AMI listener: ENABLED (vantage=%d, tunnel localhost:%d -> "
                    "%s:%d -> 127.0.0.1:%d)", vantage, listener.local_port,
                    listener.ssh_host, listener.ssh_port, listener.remote_port)
        return listener
    except Exception as e:
        logger.error("ami_listener init failed (disabled this run): %s", e)
        return None


def build_ami_listeners(config: dict, on_link_change,
                        on_listener_keyed=None,
                        listener_ids_provider=None) -> list:
    """Step 2b: the primary vantage (top-level `vantage_node`) plus every
    entry of `ami_listener.vantages` with `enabled` not false, deduped by
    node. Each extra vantage needs its own `local_port`. Per-node opt-out is
    `enabled: false` on that entry (e.g. if a node's sysadmin declines).
    Never raises; returns [] when the block is disabled."""
    out: list = []
    try:
        acfg = config.get("ami_listener") or {}
        if not isinstance(acfg, dict):
            acfg = {}
        entries = acfg.get("vantages") or []
        if not isinstance(entries, list):
            logger.error("ami_listener: `vantages` must be a list — ignored")
            entries = []
        # Primary opt-out (audit S5): a `vantages` entry naming the primary
        # node with enabled: false disables the primary feed too.
        try:
            primary_node = int(acfg.get("vantage_node")
                               or (config.get("rpt_reader") or {}).get("vantage_node", 0))
        except (TypeError, ValueError):
            primary_node = 0
        primary_opted_out = any(
            isinstance(e, dict) and str(e.get("node")) == str(primary_node)
            and e.get("enabled", True) is False for e in entries)
        if primary_opted_out:
            logger.warning("ami_listener: primary vantage %d opted out (enabled: "
                           "false in `vantages`) — no feed from it", primary_node)
        else:
            primary = build_ami_listener(config, on_link_change, on_listener_keyed,
                                         listener_ids_provider)
            if primary is not None:
                out.append(primary)
        used_ports = {l.local_port for l in out}
        for entry in entries:
            try:                                          # audit S5: per-entry
                if not isinstance(entry, dict) or not entry.get("node"):
                    logger.error("ami_listener: malformed `vantages` entry %r — skipped",
                                 entry)
                    continue
                node = int(entry.get("node"))
                if any(l.vantage_node == node for l in out):
                    continue
                if entry.get("enabled", True) is False:
                    logger.info("ami_listener: vantage %d opted out (enabled: false)", node)
                    continue
                port = int(entry.get("local_port", 0) or 0)
                if port <= 0 or port in used_ports:
                    logger.error("ami_listener: vantage %d needs its own free local_port "
                                 "— skipped", node)
                    continue
                extra = build_ami_listener(config, on_link_change, on_listener_keyed,
                                           listener_ids_provider, vantage_override=entry)
                if extra is not None:
                    out.append(extra)
                    used_ports.add(extra.local_port)
            except Exception as e:
                logger.error("ami_listener: `vantages` entry %r skipped: %s", entry, e)
    except Exception as e:
        logger.error("ami_listener: build_ami_listeners failed (non-fatal): %s", e)
    return out


def _selftest() -> int:            # pragma: no cover - developer tool
    """QSO state-machine unit tests (no network)."""
    failures = []

    def check(name, cond):
        print(f"  [{'OK' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    l = AmiListener.__new__(AmiListener)
    l.qso_hold_s = 120
    l._keyed_sources = {}
    l._qso_snap = (False, None, None)

    check("unknown before any event", l.qso_state() == (None, None))
    # ALINKS keyed pulse starts a QSO
    l._update_qso("RPT_ALINKS", "2,34567TU,23456TK")
    st, since = l.qso_state()
    check("alinks K pulse -> active", st == "active" and since is not None)
    t0 = since
    # Audit S1: the pulse must NOT latch — an unkeyed ALINKS follows, state
    # stays active only through the hold window, not forever.
    l._update_qso("RPT_ALINKS", "2,34567TU,23456TU")
    check("pulse does not latch currently_keyed", l._qso_snap[0] is False)
    check("still active within hold", l.qso_state()[0] == "active")
    # Re-key during same QSO: start time preserved
    l._update_qso("RPT_ALINKS", "2,34567TK,23456TU")
    check("same QSO keeps start", l.qso_state()[1] == t0)
    # Simulate hold expiry -> inactive (nothing persistent held)
    k, a, _ = l._qso_snap
    l._qso_snap = (k, a, time.time() - 200)
    check("hold expiry -> inactive", l.qso_state()[0] == "inactive")
    # New QSO via vantage TX keyed (persistent source)
    l._update_qso("RPT_TXKEYED", "1")
    st, since = l.qso_state()
    check("TXKEYED -> new active with fresh start",
          st == "active" and since > t0)
    check("persistent source holds keyed", l._qso_snap[0] is True)
    l._update_qso("RPT_TXKEYED", "0")
    check("TXKEYED 0 releases source", l._qso_snap[0] is False)
    # Degenerate values never raise
    for ev, val in (("RPT_ALINKS", "0"), ("RPT_ALINKS", ""),
                    ("RPT_ALINKS", "1,"), ("RPT_RXKEYED", ""),
                    ("RPT_ALINKS", "2,23456T,X")):
        l._update_qso(ev, val)
    check("degenerate values tolerated", True)
    check("caption formats", "since" in (l.qso_caption() or "since"))

    # --- step 2 trigger B: listener keyed ----------------------------------
    check("parse_alinks: modes + keyed flags",
          parse_alinks("3,23456TU,34567RK,45678LU")
          == [("23456", "T", False), ("34567", "R", True), ("45678", "L", False)])
    check("parse_alinks: legacy no-mode entries, empties, garbage",
          parse_alinks("3,23456K,,abc,34567U") == [("23456", "", True), ("34567", "", False)])
    check("parse_alinks: empty value", parse_alinks("") == [] and parse_alinks("0") == [])
    reports = []
    k = AmiListener.__new__(AmiListener)
    k.vantage_node = 12345
    k._on_listener_keyed = lambda nid, v: reports.append(nid)
    k._listener_ids_provider = lambda: frozenset({34567})
    k._last_keyed_report = {}
    k._check_listener_keyed("2,23456TU,34567RK")
    check("listener keyed -> reported once", reports == [34567])
    k._check_listener_keyed("2,23456TU,34567RK")
    check("held K (same state) -> not reported again", reports == [34567])
    k._check_listener_keyed("2,23456TU,34567RU")
    k._check_listener_keyed("2,23456TU,34567RK")
    check("unkey/key inside the debounce window -> still one report", reports == [34567])
    k._check_listener_keyed("2,23456TK,34567RU")
    check("non-listener keyed -> ignored", reports == [34567])

    # --- coherence (2026-10-12): live_alinks accessor -----------------------
    saved_reg = dict(_REGISTRY)
    try:
        _REGISTRY.clear()
        check("live_alinks: unknown vantage -> None", live_alinks(2000) is None)
        a = AmiListener.__new__(AmiListener)
        a.vantage_node = 2000
        a.connected = False
        a._alinks_snap = ("2,4000TU,1000TU", time.monotonic(), 1)
        a._session_no = 1
        _REGISTRY[2000] = a
        check("live_alinks: not connected -> None", live_alinks(2000) is None)
        a.connected = True
        got = live_alinks(2000)
        check("live_alinks: connected -> parsed set + age + True",
              got is not None and got[0] == {4000, 1000} and got[1] < 5 and got[2] is True)
        a._session_no = 2                       # re-login, no frame yet this session
        check("live_alinks: frame from a previous session -> None", live_alinks(2000) is None)
        a._alinks_snap = ("1,1000TU", time.monotonic(), 2)
        got = live_alinks(2000)
        check("live_alinks: new-session frame -> guest absent", got is not None and got[0] == {1000})
        a._alinks_snap = ("", 0.0, 2)
        check("live_alinks: no frame yet -> None", live_alinks(2000) is None)
        check("live_alinks: junk vantage -> None", live_alinks("x") is None)
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(saved_reg)
    k._last_keyed_report[34567] -= _LISTENER_KEYED_DEBOUNCE_S + 1
    k._check_listener_keyed("2,23456TU,34567TK")
    check("new K transition after the debounce window -> reported again",
          reports == [34567, 34567])
    k._listener_ids_provider = lambda: frozenset()
    k._last_keyed_report = {}
    k._check_listener_keyed("2,23456TU,34567RK")
    check("no listeners -> nothing", reports == [34567, 34567])
    k._on_listener_keyed = None
    k._listener_ids_provider = lambda: frozenset({34567})
    k._check_listener_keyed("2,34567RK")
    check("no callback wired -> inert", reports == [34567, 34567])
    # full _handle_block path (audit ADV-5): Node filter, then keyed check,
    # then the link-change dedup — a keyed frame identical to the last one
    # still reaches the keyed check (it is not gated by _last_values).
    hb = AmiListener.__new__(AmiListener)
    hb.vantage_node = 12345
    hb._keyed_sources = {}; hb._qso_snap = (False, None, None); hb.qso_hold_s = 120
    hb._last_values = {}; hb._last_wake = 0.0
    hb._on_link_change = lambda reason: None
    hb_reports = []
    hb._on_listener_keyed = lambda nid, v: hb_reports.append(nid)
    hb._listener_ids_provider = lambda: frozenset({34567})
    hb._last_keyed_report = {}
    hb._handle_block({"Event": "RPT_ALINKS", "Node": "99999", "EventValue": "1,34567RK"})
    check("_handle_block: other node's event ignored", hb_reports == [])
    hb._handle_block({"Event": "RPT_ALINKS", "Node": "12345", "EventValue": "1,34567RK"})
    check("_handle_block: vantage keyed frame reaches the keyed check", hb_reports == [34567])
    hb._handle_block({"Event": "RPT_NUMLINKS", "Node": "12345", "EventValue": "9"})
    check("_handle_block: non-ALINKS link events never report keyed", hb_reports == [34567])
    # step 2b: 3-arg callback gets the vantage; multi-vantage builder + opt-out
    v_reports = []
    hb._on_listener_keyed = lambda nid, v, vantage: v_reports.append((nid, vantage))
    hb._last_keyed_report = {}; hb._last_values = {}; hb._keyed_state = {}
    hb._handle_block({"Event": "RPT_ALINKS", "Node": "12345", "EventValue": "1,34567RK"})
    check("keyed callback receives the reporting vantage", v_reports == [(34567, 12345)])
    hb._last_keyed_report = {}
    hb._handle_block({"Event": "RPT_ALINKS", "Node": "12345", "EventValue": "1,34567RK"})
    check("C1 (audit 3): a repeated identical ALINKS value never re-reports K",
          v_reports == [(34567, 12345)])
    # C-1 (audit 4): a HELD key must not re-report when another link changes
    hb._last_keyed_report = {}
    hb._handle_block({"Event": "RPT_ALINKS", "Node": "12345", "EventValue": "2,34567RK,45678TU"})
    check("C-1: held K + a different frame (other node changed) -> no second report",
          v_reports == [(34567, 12345)])
    hb._handle_block({"Event": "RPT_ALINKS", "Node": "12345", "EventValue": "2,34567RU,45678TU"})
    hb._last_keyed_report = {}
    hb._handle_block({"Event": "RPT_ALINKS", "Node": "12345", "EventValue": "2,34567RK,45678TU"})
    check("C-1: unkey then key again -> a second report (a real transition)",
          v_reports == [(34567, 12345), (34567, 12345)])
    hb._handle_block({"Event": "RPT_ALINKS", "Node": "12345", "EventValue": "2,34567RK,45678TK"})
    check("C-1: another node keying in the same frame is not attributed to the listener",
          v_reports == [(34567, 12345), (34567, 12345)])
    cfgm = {"ami_listener": {"enabled": True, "vantage_node": 12345, "local_port": 61220,
                             "vantages": [{"node": 45678, "local_port": 61221},
                                          {"node": 56789, "local_port": 61222, "enabled": False},
                                          {"node": 12345, "local_port": 61223},
                                          {"node": 67890, "local_port": 61220}]},
            "auto_disconnect": {"nodes": [
                {"node_id": 12345, "ssh_host": "192.0.2.1", "ssh_key": "k", "ssh_port": 22},
                {"node_id": 45678, "ssh_host": "192.0.2.2", "ssh_key": "k", "ssh_port": 22},
                {"node_id": 56789, "ssh_host": "192.0.2.3", "ssh_key": "k", "ssh_port": 22},
                {"node_id": 67890, "ssh_host": "192.0.2.4", "ssh_key": "k", "ssh_port": 22}]},
            "ami": {12345: {"secret": "x"}, 45678: {"secret": "y"},
                    56789: {"secret": "z"}, 67890: {"secret": "w"}}}
    built = build_ami_listeners(cfgm, on_link_change=lambda r: None)
    check("multi-vantage: primary + enabled extra; opted-out, duplicate and port-clash skipped",
          [l.vantage_node for l in built] == [12345, 45678]
          and [l.local_port for l in built] == [61220, 61221])
    check("multi-vantage: disabled block -> []",
          build_ami_listeners({"ami_listener": {"enabled": False}}, lambda r: None) == [])
    # S5: one malformed entry must not drop the rest; primary can opt out
    cfgm2 = dict(cfgm); cfgm2["ami_listener"] = dict(cfgm["ami_listener"])
    cfgm2["ami_listener"]["vantages"] = ["garbage", {"node": "x"}, {"node": 45678, "local_port": "bad"},
                                         {"node": 67890, "local_port": 61224}]
    built2 = build_ami_listeners(cfgm2, on_link_change=lambda r: None)
    check("S5: malformed entries skipped one by one, later entries still built",
          [l.vantage_node for l in built2] == [12345, 67890])
    cfgm3 = dict(cfgm); cfgm3["ami_listener"] = dict(cfgm["ami_listener"])
    cfgm3["ami_listener"]["vantages"] = [{"node": 12345, "enabled": False},
                                         {"node": 45678, "local_port": 61221}]
    built3 = build_ami_listeners(cfgm3, on_link_change=lambda r: None)
    check("S5: primary opts out via its own `vantages` entry",
          [l.vantage_node for l in built3] == [45678])
    # S4: arity by inspection, never by catching TypeError
    boom = []
    def cb3(nid, v, vantage):
        boom.append((nid, vantage)); raise TypeError("inside the callback")
    check("S4: 3-arg callback detected", _keyed_callback_takes_vantage(cb3) is True
          and _keyed_callback_takes_vantage(lambda a, b: None) is False
          and _keyed_callback_takes_vantage(lambda a, b, c=None: None) is True)
    hb._on_listener_keyed = cb3
    hb._last_keyed_report = {}; hb._last_values = {}; hb._keyed_state = {}
    try:
        hb._handle_block({"Event": "RPT_ALINKS", "Node": "12345", "EventValue": "1,34567RK"})
    except TypeError:
        pass
    check("S4: a TypeError inside a 3-arg callback is NOT re-dispatched as 2-arg",
          boom == [(34567, 12345)])

    print(f"\n{'PASS' if not failures else 'FAIL'}: "
          f"{len(failures)} failure(s) {failures or ''}")
    return 1 if failures else 0


def main() -> int:
    """Standalone connectivity test: tunnel + login + a short listen window.
    Prints only status — never credentials."""
    import argparse

    import yaml

    ap = argparse.ArgumentParser(description="AMI listener connectivity test")
    ap.add_argument("--config")
    ap.add_argument("--selftest", action="store_true",
                    help="run the QSO state-machine selftest and exit")
    ap.add_argument("--seconds", type=int, default=20,
                    help="listen window after login")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.selftest:
        return _selftest()
    if not args.config:
        ap.error("--config is required unless --selftest")

    from asl_link_detector import load_config
    config = load_config(args.config)
    hits = []
    listener = build_ami_listener(config, lambda r: hits.append(r))
    if listener is None:
        print("ami_listener disabled or misconfigured (see log)")
        return 1
    listener.start()
    deadline = time.monotonic() + args.seconds + 5
    while time.monotonic() < deadline and not listener.connected:
        time.sleep(0.5)
    if not listener.connected:
        print("FAILED: no AMI login within the window")
        listener.stop()
        return 1
    print(f"AMI login OK; listening {args.seconds}s for link events "
          f"(none expected on a quiet mesh)...")
    time.sleep(args.seconds)
    listener.stop()
    print(f"done; link-change wakes during window: {len(hits)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
