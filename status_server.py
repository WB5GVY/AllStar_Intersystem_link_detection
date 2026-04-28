"""HTTP status server for Home Assistant integration.

Exposes a GET /status endpoint with a JSON payload containing all
monitoring system state, and a GET /health endpoint for liveness checks.

Runs as a background daemon thread in the existing monitor process.
All data served is cached from the most recent scan cycle — no HTTP
request triggers SSH, API calls, or any other side effect.
"""

import copy
import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# A repeated detection of the same path within this many minutes is treated
# as the same incident for the "violations today" counter — matches the
# notification per-path cooldown semantics so the count means "distinct
# incidents", not "scan observations".
VIOLATION_DEDUP_WINDOW_MIN = 15.0


class StatusCollector:
    """Thread-safe accumulator for monitoring system state.

    The main scan loop calls update_*() methods after each phase.
    The HTTP handler calls get_snapshot() to read the current state.
    A single Lock serializes access.
    """

    def __init__(self, db_path: str = "notifications.db"):
        self._lock = threading.Lock()
        self.db_path = db_path
        self._bridge_nodes: set[int] = set()
        self._state = {
            "version": "1.1",
            "timestamp": None,
            "scan_ok": False,
            "violations": {"count": 0, "details": []},
            "topology": {"total_nodes": 0, "focus_node_links": 0},
            "managed_nodes": {},
            "last_violation": None,
            "last_disconnect": None,
            "api": {"healthy": True, "rate_limit_remaining": None, "last_429": None},
            "email": {"healthy": True, "last_send": None},
            "qrz": {"healthy": True},
            "notifications": {
                "suppressed": False,
                "quiet_hours_active": False,
                "rate_limited": False,
            },
            "config": {"last_reload": None},
        }
        self._init_persistence()
        self._load_persisted_state()

    def _init_persistence(self):
        """Create the status-state and event-log tables if they don't exist.

        Co-located in notifications.db so monitor state lives alongside
        notification rate-limit tracking — one DB, owned by this process.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS status_state (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS violations_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        path_description TEXT NOT NULL,
                        offending_node INTEGER NOT NULL,
                        offending_callsign TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_viol_ts ON violations_log(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_viol_path ON violations_log(path_description)")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS disconnects_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        managed_node TEXT NOT NULL,
                        target_node INTEGER NOT NULL,
                        success INTEGER NOT NULL,
                        action TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_disc_ts ON disconnects_log(timestamp)")
        except sqlite3.Error as e:
            logger.warning(f"Status persistence init failed ({self.db_path}): {e}. "
                           f"Counters and last_* fields will not survive restarts.")

    def _load_persisted_state(self):
        """Load last_violation / last_disconnect from status_state into memory."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT key, value FROM status_state WHERE key IN ('last_violation','last_disconnect')"
                ).fetchall()
        except sqlite3.Error as e:
            logger.warning(f"Could not load persisted status state: {e}")
            return
        for key, value in rows:
            try:
                self._state[key] = json.loads(value)
            except (json.JSONDecodeError, KeyError):
                continue

    def _persist_state(self, key: str, value):
        """Write a single state field to status_state. Best-effort; logs on error."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO status_state (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(value), datetime.now(timezone.utc).isoformat())
                )
        except sqlite3.Error as e:
            logger.warning(f"Failed to persist {key}: {e}")

    def attach_disconnector(self, disconnector):
        """Capture the bridge_nodes set so manageability can be computed in
        get_snapshot() without holding a reference to the disconnector itself.
        Call once at startup, after the disconnector is constructed.
        """
        try:
            self._bridge_nodes = set(disconnector.bridge_nodes)
        except AttributeError:
            self._bridge_nodes = set()

    def update_scan(self, result):
        """Update state from a completed scan.

        Persists each detected violation to violations_log (deduped by
        path within VIOLATION_DEDUP_WINDOW_MIN), and updates last_violation
        in both memory and status_state.

        Args:
            result: ScanResult from GraphAnalyzer.scan()
        """
        violations = []
        for ev in result.bridging_events:
            violations.append({
                "offending_node": ev.offending_node,
                "offending_callsign": ev.offending_callsign,
                "path_description": ev.path_description,
                "path": list(ev.path),
                "rule": ev.rule,
            })

        # Count focus node direct links from topology
        focus_links = 0
        for node_id, info in result.topology.items():
            if info.get("depth") == 1:
                focus_links += 1

        # Persist new violation rows (deduped) and pick the most recent for
        # last_violation. Done outside the lock — SQLite handles its own
        # concurrency, and we don't want disk I/O blocking get_snapshot.
        new_last_violation = None
        if result.bridging_events:
            now_iso = datetime.now(timezone.utc).isoformat()
            cutoff = (datetime.utcnow() - timedelta(minutes=VIOLATION_DEDUP_WINDOW_MIN)).isoformat()
            try:
                with sqlite3.connect(self.db_path) as conn:
                    for ev in result.bridging_events:
                        # Dedup: same path within the window counts as one incident
                        recent = conn.execute(
                            "SELECT 1 FROM violations_log "
                            "WHERE path_description = ? AND timestamp > ? LIMIT 1",
                            (ev.path_description, cutoff)
                        ).fetchone()
                        if recent:
                            continue
                        conn.execute(
                            "INSERT INTO violations_log (timestamp, path_description, offending_node, offending_callsign) "
                            "VALUES (?, ?, ?, ?)",
                            (now_iso, ev.path_description, ev.offending_node, ev.offending_callsign)
                        )
            except sqlite3.Error as e:
                logger.warning(f"Failed to record violations to log: {e}")
            # Use the most recent (last) event as last_violation, regardless of dedup
            ev = result.bridging_events[-1]
            new_last_violation = {
                "timestamp": now_iso,
                "offending_node": ev.offending_node,
                "offending_callsign": ev.offending_callsign,
                "path_description": ev.path_description,
                "path": list(ev.path),
            }
            self._persist_state("last_violation", new_last_violation)

        with self._lock:
            self._state["timestamp"] = result.timestamp
            self._state["scan_ok"] = not result.has_problems
            self._state["violations"] = {
                "count": len(result.bridging_events),
                "details": violations,
            }
            self._state["topology"] = {
                "total_nodes": len(result.topology),
                "focus_node_links": focus_links,
            }
            if new_last_violation is not None:
                self._state["last_violation"] = new_last_violation

    def update_disconnect(self, disc_result):
        """Update state from a disconnect attempt.

        Args:
            disc_result: DisconnectResult from AutoDisconnector.attempt_disconnect()
        """
        node_key = str(disc_result.managed_node)
        is_ssh_success = disc_result.action != "ssh_failed"
        disconnect_info = {
            "target_node": disc_result.target_node,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "success": disc_result.success,
            "action": disc_result.action,
        }

        with self._lock:
            # Update per-node SSH health and last disconnect
            if node_key in self._state["managed_nodes"]:
                node_state = self._state["managed_nodes"][node_key]
                node_state["ssh_healthy"] = is_ssh_success
                if disc_result.action in ("disconnected", "ssh_failed"):
                    node_state["last_disconnect"] = disconnect_info
                # Update flag file state if it was checked
                if disc_result.action == "skipped_flagfile":
                    node_state["flag_file_disabled"] = True
                elif "flag_file_disabled" in node_state and disc_result.action != "skipped_local_override":
                    # Flag file was checked and passed (not disabled)
                    node_state["flag_file_disabled"] = False

            # Update top-level last_disconnect (most recent across all nodes)
            if disc_result.action in ("disconnected", "ssh_failed"):
                self._state["last_disconnect"] = {
                    "node": node_key,
                    "target": disc_result.target_node,
                    "timestamp": disconnect_info["timestamp"],
                    "success": disc_result.success,
                    "action": disc_result.action,
                }

        # Persist outside the lock — every attempt goes to the log so
        # disconnects_today reflects all auto-disconnect activity (including
        # skips). last_disconnect is persisted only for actual SSH attempts.
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO disconnects_log (timestamp, managed_node, target_node, success, action) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (disconnect_info["timestamp"], node_key,
                     disc_result.target_node,
                     1 if disc_result.success else 0,
                     disc_result.action)
                )
        except sqlite3.Error as e:
            logger.warning(f"Failed to record disconnect to log: {e}")
        if disc_result.action in ("disconnected", "ssh_failed"):
            self._persist_state("last_disconnect", self._state["last_disconnect"])

    def update_managed_nodes(self, disconnector):
        """Refresh enabled/local_override state for all managed nodes.

        Reads from AutoDisconnector.managed_nodes (in-memory attributes)
        and checks local override files (local /tmp filesystem only).
        No SSH or network I/O.

        Args:
            disconnector: AutoDisconnector instance
        """
        nodes_state = {}
        for node_id, managed in disconnector.managed_nodes.items():
            node_key = str(node_id)
            override_path = Path(f"/tmp/autodisconnect_disabled_{node_id}")
            node_entry = {
                "enabled": managed.enabled,
                "local_override": override_path.exists(),
                "ssh_healthy": None,
                "last_disconnect": None,
            }
            if managed.flag_file_check:
                node_entry["flag_file_disabled"] = None
            nodes_state[node_key] = node_entry

        with self._lock:
            # Preserve existing ssh_healthy, last_disconnect, flag_file_disabled
            # from prior updates (don't overwrite with None)
            for node_key, new_entry in nodes_state.items():
                if node_key in self._state["managed_nodes"]:
                    existing = self._state["managed_nodes"][node_key]
                    new_entry["ssh_healthy"] = existing.get("ssh_healthy")
                    new_entry["last_disconnect"] = existing.get("last_disconnect")
                    if "flag_file_disabled" in new_entry:
                        new_entry["flag_file_disabled"] = existing.get("flag_file_disabled")
            self._state["managed_nodes"] = nodes_state

    def update_api_health(self, api_client):
        """Update API health from ASLApiClient attributes.

        Reads in-memory attributes only — no network I/O.

        Args:
            api_client: ASLApiClient instance
        """
        with self._lock:
            self._state["api"] = {
                "healthy": api_client._api_healthy,
                "rate_limit_remaining": api_client.last_rate_limit_remaining,
                "last_429": api_client.last_429_timestamp,
            }

    def update_email_health(self, notifier):
        """Update email health from Notifier attributes.

        Reads in-memory attributes only.

        Args:
            notifier: Notifier instance
        """
        with self._lock:
            self._state["email"] = {
                "healthy": notifier._email_healthy,
                "last_send": notifier._last_email_send,
            }

    def update_qrz_health(self, notifier):
        """Update QRZ health from Notifier attributes.

        Reads in-memory attributes only.

        Args:
            notifier: Notifier instance
        """
        with self._lock:
            self._state["qrz"] = {"healthy": notifier._qrz_healthy}

    def update_notification_state(self, notifier):
        """Update notification suppression state.

        Calls notifier.is_quiet_hours() (pure datetime arithmetic) and
        reads from notifier.tracker (local SQLite query). No network I/O.

        Args:
            notifier: Notifier instance
        """
        quiet = notifier.is_quiet_hours()

        # Check if rate-limited by comparing recent count to configured limits
        rate_limited = False
        try:
            window_min = notifier.rate_limits.get("window_minutes", 15)
            max_per_window = notifier.rate_limits.get("max_per_window", 2)
            recent_count = notifier.tracker.count_recent(window_min)
            if recent_count >= max_per_window:
                rate_limited = True
        except Exception:
            pass  # If tracker query fails, assume not rate-limited

        with self._lock:
            self._state["notifications"] = {
                "suppressed": quiet or rate_limited,
                "quiet_hours_active": quiet,
                "rate_limited": rate_limited,
            }

    def update_ssh_health(self, results: dict):
        """Update SSH health status for managed nodes.

        Args:
            results: {node_id_int: bool} from AutoDisconnector.check_ssh_health()
        """
        with self._lock:
            for node_id, healthy in results.items():
                node_key = str(node_id)
                if node_key in self._state["managed_nodes"]:
                    self._state["managed_nodes"][node_key]["ssh_healthy"] = healthy

    def update_flag_files(self, results: dict):
        """Update flag file status for managed nodes.

        Args:
            results: {node_id_int: bool} from AutoDisconnector.check_flag_files()
                     True = disabled (flag exists), False = enabled
        """
        with self._lock:
            for node_id, disabled in results.items():
                node_key = str(node_id)
                if node_key in self._state["managed_nodes"]:
                    if "flag_file_disabled" in self._state["managed_nodes"][node_key]:
                        self._state["managed_nodes"][node_key]["flag_file_disabled"] = disabled

    def update_config_reload(self, success: bool):
        """Record a config reload event.

        Args:
            success: Whether the reload succeeded
        """
        if success:
            with self._lock:
                self._state["config"]["last_reload"] = (
                    datetime.now(timezone.utc).isoformat()
                )

    def record_startup(self):
        """Record the initial config load timestamp at process startup.

        Sets config.last_reload so it is never null after startup.
        """
        with self._lock:
            self._state["config"]["last_reload"] = (
                datetime.now(timezone.utc).isoformat()
            )

    def _today_start_iso(self) -> str:
        """UTC midnight today, ISO formatted, as a string comparator for SQLite."""
        now = datetime.now(timezone.utc)
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return midnight.isoformat()

    def _compute_counters(self) -> dict:
        """Count today's violations and disconnects from the event logs."""
        cutoff = self._today_start_iso()
        violations_today = 0
        disconnects_today = 0
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM violations_log WHERE timestamp > ?",
                    (cutoff,)
                ).fetchone()
                violations_today = row[0] if row else 0
                row = conn.execute(
                    "SELECT COUNT(*) FROM disconnects_log WHERE timestamp > ?",
                    (cutoff,)
                ).fetchone()
                disconnects_today = row[0] if row else 0
        except sqlite3.Error as e:
            logger.warning(f"Counter query failed: {e}")
        return {
            "violations_today": violations_today,
            "disconnects_today": disconnects_today,
        }

    def _is_managed_operational(self, node_state: dict) -> bool:
        """A managed node is operational iff it can perform a disconnect right now."""
        if not node_state.get("enabled", False):
            return False
        if node_state.get("local_override"):
            return False
        if node_state.get("flag_file_disabled"):
            return False
        if node_state.get("ssh_healthy") is False:
            return False
        return True

    def _compute_health(self, state: dict) -> dict:
        """Build the health block: which managed nodes are degraded, whether
        any are operational, and how many current violations have no
        operational managed node in their disconnect path.
        """
        managed = state.get("managed_nodes", {})
        degraded = []
        for node_key, node_state in managed.items():
            reasons = []
            if not node_state.get("enabled", False):
                reasons.append("config_disabled")
            if node_state.get("local_override"):
                reasons.append("local_override")
            if node_state.get("flag_file_disabled"):
                reasons.append("flag_file_disabled")
            if node_state.get("ssh_healthy") is False:
                reasons.append("ssh_unhealthy")
            if reasons:
                degraded.append({"node": node_key, "reasons": reasons})

        disconnect_capable = any(
            self._is_managed_operational(s) for s in managed.values()
        )

        # For each current violation, see whether some node in its path is an
        # operational managed node whose next-in-path is a disconnect target
        # (not a bridge or another managed node). Mirrors the can_disconnect
        # logic in auto_disconnect.py.
        unmanageable = 0
        bridge_nodes = self._bridge_nodes
        for v in state.get("violations", {}).get("details", []):
            path = v.get("path") or []
            manageable = False
            for i, node_id in enumerate(path):
                node_key = str(node_id)
                if node_key not in managed:
                    continue
                if not self._is_managed_operational(managed[node_key]):
                    continue
                if i + 1 >= len(path):
                    continue  # nothing to disconnect after this
                next_in_path = path[i + 1]
                if next_in_path in bridge_nodes:
                    continue  # don't disconnect a bridge
                if str(next_in_path) in managed:
                    continue  # don't disconnect a managed node
                manageable = True
                break
            if not manageable:
                unmanageable += 1

        return {
            "disconnect_capable": disconnect_capable,
            "unmanageable_violations": unmanageable,
            "degraded_managed_nodes": degraded,
        }

    def get_snapshot(self) -> dict:
        """Return a thread-safe deep copy of the current state, plus
        derived counters and health fields computed at request time.

        Counters are queried from SQLite per request — cheap (indexed
        COUNT queries on small tables), bounded (rows are pruned implicitly
        by the today-window).
        """
        with self._lock:
            snapshot = copy.deepcopy(self._state)
        # Derived fields (no lock held — they read from SQLite and from
        # the just-copied snapshot).
        snapshot["counters"] = self._compute_counters()
        snapshot["health"] = self._compute_health(snapshot)
        return snapshot


class StatusHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the status endpoint.

    Serves cached state only — no side effects, no SSH, no API calls.
    """

    collector: Optional[StatusCollector] = None

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
        elif self.path == "/status":
            if self.collector is not None:
                snapshot = self.collector.get_snapshot()
                self._send_json(200, snapshot)
            else:
                self._send_json(503, {"error": "collector not initialized"})
        else:
            self._send_json(404, {"error": "not found", "endpoints": ["/health", "/status"]})

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Route HTTP access logs to Python logger instead of stderr."""
        logger.debug("HTTP %s", format % args)


def start_status_server(
    collector: StatusCollector,
    host: str = "0.0.0.0",
    port: int = 61211,
) -> Optional[threading.Thread]:
    """Start the HTTP status server in a background daemon thread.

    Binds to host:port and serves /health and /status endpoints.
    If the port is already in use, logs a warning and returns None
    (the monitor continues without the HTTP server).

    Args:
        collector: StatusCollector instance to serve data from
        host: Bind address (default 0.0.0.0 for LAN access)
        port: Port number (default 61211)

    Returns:
        The server thread, or None if startup failed
    """
    StatusHandler.collector = collector

    try:
        server = ThreadingHTTPServer((host, port), StatusHandler)
    except OSError as e:
        logger.warning(
            f"Status server failed to start on {host}:{port}: {e}. "
            f"Monitoring continues without HTTP status endpoint."
        )
        return None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info(f"Status server started on {host}:{port}")
    return thread
