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
from email.utils import formatdate
from urllib.parse import parse_qs
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# A guest that flaps (reconnects within this window) does not re-announce
# in the guest_arrivals feed — one annunciation per visit, not per bounce.
_ARRIVAL_COOLDOWN_S = 600

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
            "version": "1.2",
            "timestamp": None,
            "scan_ok": False,
            "monitor_only": False,
            # Present from startup so /status consumers see the key (with
            # null) before the first scan completes (2026-08-22).
            "vantage_trust": None,
            # Phase 2 (2026-09-07): permitted all-monitor listeners and the
            # two-number count they imply. Present from startup like
            # vantage_trust; filled by update_listeners() each scan.
            "listeners": {"permitted": False, "present": [], "notice": None},
            "dark_guests": {},          # step 2b: node -> state record
            # Change 1 (2026-09-08): guests posting a fresh EMPTY link list
            # while their attach node still lists them (a stuck
            # attach-side link). Informational; filled every scan.
            "linkless": [],
            # Change 3 (2026-09-08): guests' links still CONNECTING (dialled,
            # not answered) — exempt from the listener test / bridging for a
            # grace period. Informational; filled every scan.
            "connecting": [],
            # Coherence (2026-10-12): guests seen on a pre-join record this
            # scan — not judged, never cut; filled by update_unconfirmed().
            "unconfirmed": [],
            # Three-state node health (2026-10-18): per monitored node the
            # registered / posting / parent-letter facts, debounced state,
            # counts. None until node_health is enabled and the first scan
            # completes; filled by update_node_health().
            "node_health": None,
            # Team status page feed (2026-10-20): public_export.Exporter.status()
            # — render/write/push counters, last error (type only), SAS presence.
            # None until the exporter is enabled; filled by update_public_export().
            "public_export": None,
            "node_counts": {"system_reachable": 0, "monitored_by_guest": 0,
                            "mesh_unaccounted": None},
            "violations": {"count": 0, "details": []},
            "topology": {
                "total_nodes": 0,
                "focus_node_links": 0,
                # Counts of topology entries by client_type, set by update_scan().
                # The classification is documented in asl_api.py near the
                # endpoint-classification comment block. Added 2026-05-13.
                "client_types": {
                    "allstar": 0,
                    "echolink": 0,
                    "webtransceiver_type": 0,
                },
            },
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
            # Operator-awareness alerts for non-AllStar leaf peer names that
            # match neither the amateur-callsign pattern nor EchoLink-NNNNNN.
            # currently_observed reflects the live dedup-table rowcount.
            # last_alert is the most recently inserted row (first_seen DESC).
            # Added 2026-05-13.
            "unusual_externals": {
                "currently_observed": 0,
                "last_alert": None,
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
        """Load persisted fields from status_state into memory. Guest-arrival
        keys persist too, so a daemon restart does not re-announce every
        currently-connected guest as a new arrival (audit 2026-07-04, S1)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT key, value FROM status_state WHERE key IN "
                    "('last_violation','last_disconnect',"
                    "'current_guest_keys','guest_arrivals',"
                    "'listener_notice_last_sent','dark_guest_notices','dark_guest_posting')"
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

        # Count focus node direct links + client_type breakdown from topology
        focus_links = 0
        client_type_counts = {"allstar": 0, "echolink": 0, "webtransceiver_type": 0}
        monitored = 0
        for node_id, info in result.topology.items():
            if info.get("role") == "monitored_by_guest":
                # Outside nodes a listener monitors are not system topology:
                # counted separately (node_counts), not in totals.
                monitored += 1
                continue
            if info.get("depth") == 1:
                focus_links += 1
            ct = info.get("client_type")
            if ct in client_type_counts:
                client_type_counts[ct] += 1

        # Persist new violation rows (deduped) and pick the most recent for
        # last_violation. Done outside the lock — SQLite handles its own
        # concurrency, and we don't want disk I/O blocking get_snapshot.
        new_last_violation = None
        if result.bridging_events:
            now_iso = datetime.now(timezone.utc).isoformat()
            cutoff = (datetime.now(timezone.utc).replace(tzinfo=None)
                      - timedelta(minutes=VIOLATION_DEDUP_WINDOW_MIN)).isoformat()
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
                "total_nodes": len(result.topology) - monitored,
                "focus_node_links": focus_links,
                "client_types": client_type_counts,
            }
            self._state["node_counts"]["system_reachable"] = (
                len(result.topology) - monitored)
            self._state["node_counts"]["monitored_by_guest"] = monitored
            if new_last_violation is not None:
                self._state["last_violation"] = new_last_violation

    def update_listeners(self, permitted: bool, listeners: list,
                         mesh_unaccounted: Optional[int],
                         notice_status: Optional[dict],
                         vetoes: Optional[dict] = None) -> None:
        """Phase 2: listener block + mesh-unaccounted count for /status.
        Called after link_watch's roster is fed so the count is current."""
        with self._lock:
            self._state["listeners"] = {
                "permitted": bool(permitted),
                "present": [
                    {"node": l.get("node"), "callsign": l.get("callsign"),
                     "attached_to": l.get("attached_to"),
                     "attachment": l.get("attachment"),
                     "monitored": list(l.get("monitored") or [])}
                    for l in (listeners or [])],
                "notice": notice_status,
                # Step 2 trigger B: nodes refused listener status because the
                # vantage saw them keyed toward us (reason text, expires).
                "keyed_vetoes": {str(k): (v if isinstance(v, dict) else {"reason": v})
                                 for k, v in (vetoes or {}).items()},
            }
            self._state["node_counts"]["mesh_unaccounted"] = mesh_unaccounted

    def listener_notice_last_sent(self) -> Optional[float]:
        with self._lock:
            v = self._state.get("listener_notice_last_sent")
        try:
            return float(v) if v else None
        except (TypeError, ValueError):
            return None

    def set_listener_notice_last_sent(self, ts: float) -> None:
        with self._lock:
            self._state["listener_notice_last_sent"] = ts
        self._persist_state("listener_notice_last_sent", ts)

    # Step 2b (2026-09-07): dark-guest notice times (node -> epoch) survive
    # restarts so a trustee notice is not repeated on every daemon start.
    def dark_guest_notices(self) -> dict:
        with self._lock:
            v = self._state.get("dark_guest_notices")
        return dict(v) if isinstance(v, dict) else {}

    def set_dark_guest_notices(self, data: dict) -> None:
        with self._lock:
            self._state["dark_guest_notices"] = dict(data or {})
        self._persist_state("dark_guest_notices", dict(data or {}))

    def dark_guest_posting(self) -> dict:
        with self._lock:
            v = self._state.get("dark_guest_posting")
        return dict(v) if isinstance(v, dict) else {}

    def set_dark_guest_posting(self, data: dict) -> None:
        with self._lock:
            self._state["dark_guest_posting"] = dict(data or {})
        self._persist_state("dark_guest_posting", dict(data or {}))

    def update_dark_guests(self, status: dict) -> None:
        """/status dark_guests block (presentation only)."""
        with self._lock:
            self._state["dark_guests"] = dict(status or {})

    def update_connecting(self, connecting) -> None:
        """/status connecting block (presentation only): one entry per
        (node, target) pair the node reports as CONNECTING this scan."""
        out = []
        for rec in (connecting or [])[:50]:
            try:
                out.append({"node": int(rec.get("node")),
                            "target": int(rec.get("target")),
                            "attached_to": rec.get("attached_to"),
                            "attachment": rec.get("attachment"),
                            "age_seconds": rec.get("age_seconds")})
            except (TypeError, ValueError, AttributeError):
                continue
        with self._lock:
            self._state["connecting"] = out

    def update_unconfirmed(self, unconfirmed) -> None:
        """/status unconfirmed block (presentation only; coherence 2026-10-12):
        one entry per guest / hub node whose OWN stats record did not name
        the node it is attached to this scan (a pre-join / post-leave
        record) — seen, not judged, never cut."""
        out = []
        for rec in (unconfirmed or [])[:50]:
            try:
                age = rec.get("post_age_seconds")
                out.append({"node": int(rec.get("node")),
                            "callsign": rec.get("callsign"),
                            "attached_to": rec.get("attached_to"),
                            "attachment": rec.get("attachment"),
                            "outside": [int(x) for x in (rec.get("outside") or [])[:20]],
                            "post_age_seconds": (round(float(age)) if age is not None else None),
                            "post_time": rec.get("post_time"),
                            "raw_nodes": str(rec.get("raw_nodes") or "")[:200],
                            "age_seconds": rec.get("age_seconds"),
                            "state": rec.get("state")})
            except (TypeError, ValueError, AttributeError):
                continue
        with self._lock:
            self._state["unconfirmed"] = out

    def update_linkless(self, linkless) -> None:
        """/status linkless block (presentation only): one entry per guest
        posting a fresh empty link list this scan."""
        out = []
        for rec in (linkless or []):
            try:
                age = rec.get("post_age_seconds")
                out.append({"node": int(rec.get("node")),
                            "callsign": rec.get("callsign"),
                            "attached_to": rec.get("attached_to"),
                            "attachment": rec.get("attachment"),
                            "post_age_seconds": (round(float(age)) if age is not None else None)})
            except (TypeError, ValueError, AttributeError):
                continue
        with self._lock:
            self._state["linkless"] = out

    def update_node_health(self, block: Optional[dict]) -> None:
        """/status node_health block (node_health.NodeHealthTracker.observe()
        output, presentation only) and the registered / linked / posting
        counts (with their 'known' denominators) under node_counts."""
        counts = (block or {}).get("counts") or {}
        with self._lock:
            self._state["node_health"] = block
            # A gated scan observed nothing: keep the last real counts rather
            # than publishing zeros (the HA card would read "0 linked").
            if not (block or {}).get("scan_gated"):
                for k in ("registered", "registered_known", "linked", "linked_known",
                          "posting", "posting_known"):
                    if k in counts:
                        self._state["node_counts"][k] = counts[k]
                self._state["node_counts"]["health_updated"] = (block or {}).get("updated")

    def update_public_export(self, block: Optional[dict]) -> None:
        """/status public_export block (public_export.Exporter.status(); the
        SAS itself is never part of it — presence flag and counters only)."""
        with self._lock:
            self._state["public_export"] = dict(block) if isinstance(block, dict) else None

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
                # alerts queued during quiet hours, delivered when they end;
                # expired/failed are 7-day table counts (survive a reload)
                "deferred_queued": getattr(notifier, "_deferred_queued", 0),
                "deferred_expired": getattr(notifier, "_deferred_expired", 0),
                "deferred_failed": getattr(notifier, "_deferred_failed", 0),
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

    def update_monitor_only(self, monitor_only: bool):
        """Reflect the live `monitor_only` flag to HA. The flag determines
        whether the detector will send emails and run SSH disconnect at all,
        so it's the single most important sensor for "is this thing about to
        act?" Added 2026-05-13."""
        with self._lock:
            self._state["monitor_only"] = bool(monitor_only)

    def update_bubble_map(self, png_path: str, rendered_at: str,
                          wide_path: Optional[str] = None,
                          spread_path: Optional[str] = None,
                          spread_wide_path: Optional[str] = None,
                          asl_path: Optional[str] = None,
                          asl_health: Optional[dict] = None,
                          vantage_overlay: Optional[dict] = None):
        """Record the latest locally-rendered bubble maps (bubble_map_gen).
        The HTTP handler serves them at GET /bubble.png and /bubble_wide.png;
        ?layout=spread selects the airy prism variant, ?layout=asl the
        ASL-style custom placement (2026-07-18; the asl render is already
        landscape, so BOTH endpoints serve the same file). asl_health is the
        custom path's fallback counter/last-error block — a permanently
        broken asl path must be visible here, not just in logs."""
        with self._lock:
            self._state["bubble_map"] = {
                "path": png_path,
                "wide_path": wide_path,
                "spread_path": spread_path,
                "spread_wide_path": spread_wide_path,
                "asl_path": asl_path,
                "asl_health": asl_health,
                # Vantage-overlay counters (2026-07-21): listed/drawn/
                # suppressed; a big suppressed count = sustained ghost
                # union being filtered (the 2026-07-20 incident signature).
                "vantage_overlay": vantage_overlay,
                "rendered_at": rendered_at,
            }

    def get_bubble_map_path(self, key: str = "path") -> Optional[str]:
        with self._lock:
            return (self._state.get("bubble_map") or {}).get(key)

    def get_bubble_map_wide_path(self) -> Optional[str]:
        return self.get_bubble_map_path("wide_path")

    def attach_qso_source(self, source) -> None:
        """Wire the AMI listener as the live QSO-activity source. Read at
        snapshot time (the listener's qso_state is thread-safe)."""
        self._qso_source = source

    def _qso_block(self) -> Optional[dict]:
        src = getattr(self, "_qso_source", None)
        if src is None:
            return None
        try:
            state, since = src.qso_state()
        except Exception:
            return None
        if state is None:
            return {"state": "unknown", "since": None}
        return {"state": state,
                "since": since.isoformat() if since else None}

    def update_guest_arrivals(self, current: dict):
        """Track guest/external arrivals for the HA audible-annunciation
        automation (2026-07-04). `current` maps a stable key (node id or
        external name) -> {"callsign": str, "attached_to": ...,
        "kind": "node"|"external"}. Diffs against the previous scan's set;
        new keys are appended to a rolling arrivals list (newest first,
        capped) exposed in /status as guest_arrivals. HA triggers TTS on
        a change of guest_arrivals[0].ts."""
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        with self._lock:
            prev = set(self._state.get("current_guest_keys") or [])
            arrivals = list(self._state.get("guest_arrivals") or [])
            changed = False
            for key, info in current.items():
                if key in prev:
                    continue
                # Flap damping (audit 2026-07-04, S2): a guest that bounces
                # does not re-announce within the cooldown of its own last
                # arrival — one TTS per visit, not one per reconnect. Also
                # softens the known ext_* key-form inconsistency.
                recent = next((a for a in arrivals if a.get("key") == key), None)
                if recent is not None:
                    try:
                        prev_ts = datetime.fromisoformat(recent["ts"])
                        if (now_dt - prev_ts).total_seconds() < _ARRIVAL_COOLDOWN_S:
                            continue
                    except (ValueError, KeyError, TypeError):
                        pass
                arrivals.insert(0, {
                    "key": key,
                    "callsign": str(info.get("callsign", "")) or str(key),
                    "attached_to": info.get("attached_to"),
                    "kind": info.get("kind", "node"),
                    "ts": now,
                })
                changed = True
            self._state["guest_arrivals"] = arrivals[:10]
            new_keys = sorted(current.keys())
            keys_changed = new_keys != self._state.get("current_guest_keys")
            self._state["current_guest_keys"] = new_keys
        # Persist OUTSIDE the lock (sqlite write). Survives restarts so the
        # first post-restart scan doesn't re-announce every present guest.
        if changed:
            self._persist_state("guest_arrivals", self._state["guest_arrivals"])
        if keys_changed:
            self._persist_state("current_guest_keys", new_keys)

    def update_link_watchdog(self, status: Optional[dict]):
        """Latest link-state-watchdog block for /status (2026-07-21)."""
        with self._lock:
            self._state["link_watchdog"] = status

    def update_vantage_trust(self, block: Optional[dict]):
        """Latest vantage-trust block for /status (2026-08-22)."""
        with self._lock:
            self._state["vantage_trust"] = block

    def update_unusual_externals(self, db_path: Optional[str] = None):
        """Refresh the unusual-externals summary from the SQLite dedup table.

        Reads the row count (currently_observed) and the most recently inserted
        row (last_alert). Called from the scan loop after
        Notifier.process_unusual_externals() so the snapshot is consistent
        with the alerts that just fired. Added 2026-05-13."""
        path = db_path or self.db_path
        currently_observed = 0
        last_alert = None
        try:
            with sqlite3.connect(path) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM unusual_externals"
                ).fetchone()
                currently_observed = int(row[0]) if row else 0
                row = conn.execute(
                    "SELECT host_node, external_name, client_type, first_seen "
                    "FROM unusual_externals ORDER BY first_seen DESC LIMIT 1"
                ).fetchone()
                if row:
                    last_alert = {
                        "host_node": int(row[0]),
                        "external_name": str(row[1]),
                        "client_type": str(row[2] or ""),
                        "first_seen": str(row[3]),
                    }
        except sqlite3.Error as e:
            logger.warning(f"Could not refresh unusual_externals summary: {e}")
            return
        with self._lock:
            self._state["unusual_externals"] = {
                "currently_observed": currently_observed,
                "last_alert": last_alert,
            }

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
        qso = self._qso_block()
        if qso is not None:
            snapshot["qso"] = qso
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
        elif self.path.split("?", 1)[0] == "/bubble.png":
            self._serve_png(self._pick_map("path", "spread_path"))
        elif self.path.split("?", 1)[0] == "/bubble_wide.png":
            # Landscape companion render (2026-07-05).
            self._serve_png(self._pick_map("wide_path", "spread_wide_path"))
        else:
            self._send_json(404, {"error": "not found",
                                  "endpoints": ["/health", "/status",
                                                "/bubble.png",
                                                "/bubble_wide.png"]})

    def _pick_map(self, dense_key: str, spread_key: str) -> Optional[str]:
        """Layout selection: ?layout=spread (2026-07-06) picks the airy
        prism variant; ?layout=asl (2026-07-18) picks the ASL-style custom
        placement (same file on both endpoints — it is already landscape).
        Precedence when both values appear: asl > spread. Anything else, or
        a missing selected render, falls back to the dense default."""
        if self.collector is None:
            return None
        query = parse_qs(self.path.partition("?")[2])
        layouts = query.get("layout", [])
        if "asl" in layouts:
            p = self.collector.get_bubble_map_path("asl_path")
            if p:
                return p
        if "spread" in layouts:
            p = self.collector.get_bubble_map_path(spread_key)
            if p:
                return p
        return self.collector.get_bubble_map_path(dense_key)

    def _serve_png(self, path: Optional[str]):
        """Serve a locally-rendered bubble map PNG. Query strings (HA
        cache-busters) are tolerated by the callers. no-cache so the
        dashboard revalidates each load; the file is written atomically
        so a torn image can never be served."""
        if not path or not Path(path).is_file():
            self._send_json(404, {"error": "no bubble map rendered yet"})
            return
        try:
            # mtime/size BEFORE read: if os.replace lands a newer file
            # between the two, Last-Modified is older than the body
            # served — consumers revalidate and converge. The reverse
            # order could stamp a stale body as fresh. HEAD skips the
            # multi-hundred-KB read entirely (audit 2026-07-04 v2, A3);
            # its Content-Length comes from the same stat.
            st = Path(path).stat()
            mtime = st.st_mtime
            body = b"" if self.command == "HEAD" else Path(path).read_bytes()
        except OSError as e:
            self._send_json(500, {"error": f"bubble map unreadable: {e}"})
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length",
                             str(st.st_size if self.command == "HEAD"
                                 else len(body)))
            self.send_header("Cache-Control", "no-cache, must-revalidate")
            self.send_header("Last-Modified", formatdate(mtime, usegmt=True))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Client (HA) went away mid-transfer of a multi-hundred-KB
            # PNG — routine, not error-worthy.
            logger.debug("bubble map transfer aborted by client")

    # HEAD support (2026-07-04, flagged by the HA session): BaseHTTPRequestHandler
    # returns 501 for verbs without a do_* method, and HA picture cards /
    # browser cache revalidation issue HEAD requests. Reuse do_GET wholesale —
    # every write path checks self.command and sends headers only for HEAD,
    # so Content-Length/Last-Modified match what GET would return.
    do_HEAD = do_GET

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
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
