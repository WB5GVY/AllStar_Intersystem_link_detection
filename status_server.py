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
import threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class StatusCollector:
    """Thread-safe accumulator for monitoring system state.

    The main scan loop calls update_*() methods after each phase.
    The HTTP handler calls get_snapshot() to read the current state.
    A single Lock serializes access.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._state = {
            "version": "1.0",
            "timestamp": None,
            "scan_ok": False,
            "violations": {"count": 0, "details": []},
            "topology": {"total_nodes": 0, "focus_node_links": 0},
            "managed_nodes": {},
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

    def update_scan(self, result):
        """Update state from a completed scan.

        Args:
            result: ScanResult from GraphAnalyzer.scan()
        """
        violations = []
        for ev in result.bridging_events:
            violations.append({
                "offending_node": ev.offending_node,
                "offending_callsign": ev.offending_callsign,
                "path_description": ev.path_description,
                "rule": ev.rule,
            })

        # Count focus node direct links from topology
        focus_node = result.focus_node
        focus_links = 0
        for node_id, info in result.topology.items():
            if info.get("depth") == 1:
                focus_links += 1

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
                }

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

    def get_snapshot(self) -> dict:
        """Return a thread-safe deep copy of the current state.

        Called by the HTTP handler. Acquires lock briefly for the copy.
        """
        with self._lock:
            return copy.deepcopy(self._state)


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
