"""Notification system with rate limiting, quiet hours, and a single
fail-safe email-dispatch chokepoint.

Design (2026-05-14 chokepoint refactor):
    Every outbound email in this module MUST go through `Notifier._dispatch_email`.
    No other function in this file is permitted to call `smtplib.SMTP.sendmail`.
    The chokepoint enforces three cross-cutting invariants:

      (A) Recipient scoping by category. Only VIOLATION_SYSADMIN and
          OFFENDER_COURTESY may reach external recipients (operators
          beyond the internal_recipients list). HIDDEN_PATH_ANOMALY,
          OPERATOR_AWARENESS, TEST, and ERROR_REPORT are stripped to
          internal_recipients only, regardless of what the caller passes.

      (B) Hard 6-hour per-external-recipient cap. Independent of any other
          rate limit. Enforced from rows in the `external_recipient_sends`
          table.

      (C) monitor_only / dry-run gate. Even if a future caller forgets to
          check, the chokepoint refuses to send when self.dry_run is True.

    Pre-write before send: every outbound email is recorded as a 'pending'
    row in the appropriate counter table BEFORE smtplib is invoked, then
    transitioned to 'sent' or 'failed'. This makes the launchd
    restart-loop scenario idempotent — orphan 'pending' rows older than
    five minutes at startup are upgraded to 'sent' (worst-case assumes the
    send went out and the crash was after).

Anyone editing this file: do not add another smtplib callsite. If you
need a new email path, add an EmailCategory enum entry, update the
category policy table in `_dispatch_email`, and route through it.
"""

import enum
import logging
import os
import re
import smtplib
import sqlite3
from datetime import datetime, timedelta, timezone
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

from graph_analyzer import BridgingEvent, ScanResult
from qrz_lookup import QRZLookup

logger = logging.getLogger(__name__)

DB_FILE = "notifications.db"

# Per the 2026-05-14 audit (C6), an empty/whitespace-only name must NOT be
# classified as "unusual" — it is a missing-data condition that must not
# trigger an alert.
CALLSIGN_LIKE = re.compile(r'^[A-Z]{1,2}\d[A-Z]{1,4}[A-Za-z0-9]*$')


def is_unusual_external_name(name: str) -> bool:
    """True if `name` is a non-AllStar external peer name that does not match
    either an amateur radio callsign or the source-verified EchoLink-NNNNNN
    format. Empty/whitespace names return False (missing-data condition)."""
    if name is None:
        return False
    name = name.strip()
    if not name:
        return False
    if name.startswith("EchoLink-"):
        return False
    return not CALLSIGN_LIKE.fullmatch(name)


class EmailCategory(enum.Enum):
    """Routing class for outbound emails. Determines recipient scope,
    quiet-hours bypass, and which counter table records the send."""
    VIOLATION_SYSADMIN  = "violation_sysadmin"   # path #1 — full recipients
    OFFENDER_COURTESY   = "offender_courtesy"    # path #2 — offender + BCC full
    HIDDEN_PATH_ANOMALY = "hidden_path_anomaly"  # path #3 — Bennett only
    OPERATOR_AWARENESS  = "operator_awareness"   # path #4 — Bennett only (reclassified 2026-05-14)
    TEST                = "test"                 # path #5 — Bennett only
    ERROR_REPORT        = "error_report"         # new path — Bennett only


# Per-category policy. Centralized so the chokepoint enforces it uniformly.
# Anyone adding a new category MUST add an entry here.
#
# bypass_dry_run is True ONLY for ERROR_REPORT — monitor_only is intended to
# suppress externally-visible side effects (emails to other operators, SSH
# disconnects), but operational-failure reports go to Bennett only by
# category-A invariant, so suppressing them defeats the fail-safe goal:
# during monitor_only Bennett still wants to know if reload failed or the
# daemon crashed (audit S-4, 2026-05-15 self-review).
CATEGORY_POLICY = {
    EmailCategory.VIOLATION_SYSADMIN:  dict(allow_external=True,  bypass_quiet=False, bypass_dry_run=False),
    EmailCategory.OFFENDER_COURTESY:   dict(allow_external=True,  bypass_quiet=True,  bypass_dry_run=False),
    EmailCategory.HIDDEN_PATH_ANOMALY: dict(allow_external=False, bypass_quiet=False, bypass_dry_run=False),
    EmailCategory.OPERATOR_AWARENESS:  dict(allow_external=False, bypass_quiet=False, bypass_dry_run=False),
    EmailCategory.TEST:                dict(allow_external=False, bypass_quiet=True,  bypass_dry_run=False),
    EmailCategory.ERROR_REPORT:        dict(allow_external=False, bypass_quiet=True,  bypass_dry_run=True),
}


class RecipientResolutionError(RuntimeError):
    """Raised when secrets.yaml cannot be reduced to a non-empty
    internal_recipients list. Fail-closed per audit C1."""


class NotificationTracker:
    """SQLite-backed rate-limit and dedup state for the Notifier.

    Schema (2026-05-14 chokepoint refactor):
      notifications              — per-event sends (now with type + status)
      unusual_externals          — per-(host, peer_name) dedup
      external_recipient_sends   — 6-hour-per-external-recipient cap (B)
    """

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()
        self._cleanup_orphan_pending()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    offending_node INTEGER NOT NULL,
                    hub_node INTEGER NOT NULL,
                    bridge_node INTEGER NOT NULL,
                    path_key TEXT NOT NULL DEFAULT '',
                    message TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_timestamp ON notifications(timestamp)")
            # Forward-only migrations. Each ADD COLUMN is idempotent.
            for ddl in (
                "ALTER TABLE notifications ADD COLUMN path_key TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE notifications ADD COLUMN notification_type TEXT NOT NULL DEFAULT 'violation'",
                "ALTER TABLE notifications ADD COLUMN status TEXT NOT NULL DEFAULT 'sent'",
            ):
                try:
                    conn.execute(ddl)
                except sqlite3.OperationalError:
                    pass  # column already present
            conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_path_key ON notifications(path_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_type ON notifications(notification_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_status ON notifications(status)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS unusual_externals (
                    host_node INTEGER NOT NULL,
                    external_name TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    client_type TEXT,
                    PRIMARY KEY (host_node, external_name)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS external_recipient_sends (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_address TEXT NOT NULL,
                    category TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ers_addr_time "
                         "ON external_recipient_sends(recipient_address, sent_at)")

    def _cleanup_orphan_pending(self):
        """Orphan 'pending' rows older than five minutes at startup are
        upgraded to 'sent'. Defensive: a crash between sendmail and the
        commit leaves a pending row — assume the send went out so we do not
        re-send on the next scan (C3 fix)."""
        cutoff = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                n1 = conn.execute(
                    "UPDATE notifications SET status='sent' "
                    "WHERE status='pending' AND timestamp < ?",
                    (cutoff,)
                ).rowcount
                n2 = conn.execute(
                    "UPDATE external_recipient_sends SET status='sent' "
                    "WHERE status='pending' AND sent_at < ?",
                    (cutoff,)
                ).rowcount
            if n1 or n2:
                logger.warning(
                    "Startup: upgraded %d orphan pending row(s) in notifications "
                    "and %d in external_recipient_sends (presumed sent before crash).",
                    n1, n2
                )
        except sqlite3.Error as e:
            logger.error("Startup orphan-pending cleanup failed: %s", e)

    # ---- counter reads (fail-closed on DB error: return inf → caller blocks) ----

    def count_recent(self, minutes: float = 15.0,
                     notification_type: str = "violation") -> float:
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM notifications "
                    "WHERE timestamp > ? AND notification_type = ? "
                    "AND status IN ('sent','pending')",
                    (cutoff, notification_type)
                ).fetchone()
                return row[0] if row else 0
        except sqlite3.Error as e:
            logger.error("count_recent fail-closed: %s", e)
            return float("inf")

    def count_today(self, notification_type: str = "violation") -> float:
        today_start = datetime.utcnow().replace(
            hour=0, minute=0, second=0, microsecond=0).isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM notifications "
                    "WHERE timestamp > ? AND notification_type = ? "
                    "AND status IN ('sent','pending')",
                    (today_start, notification_type)
                ).fetchone()
                return row[0] if row else 0
        except sqlite3.Error as e:
            logger.error("count_today fail-closed: %s", e)
            return float("inf")

    def count_last_24h(self, notification_type: str) -> float:
        cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM notifications "
                    "WHERE timestamp > ? AND notification_type = ? "
                    "AND status IN ('sent','pending')",
                    (cutoff, notification_type)
                ).fetchone()
                return row[0] if row else 0
        except sqlite3.Error as e:
            logger.error("count_last_24h fail-closed: %s", e)
            return float("inf")

    def last_notification_for_path(self, event: BridgingEvent) -> Optional[datetime]:
        path_key = event.path_description
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT timestamp FROM notifications WHERE path_key = ? "
                    "AND notification_type = 'violation' "
                    "AND status IN ('sent','pending') "
                    "ORDER BY timestamp DESC LIMIT 1",
                    (path_key,)
                ).fetchone()
                return datetime.fromisoformat(row[0]) if row else None
        except sqlite3.Error as e:
            logger.error("last_notification_for_path fail-closed: %s", e)
            # Fail-closed: act as if a recent send blocks this path.
            return datetime.utcnow()

    # ---- pending-write helpers ----

    def record_pending_notification(self, event: BridgingEvent,
                                    notification_type: str) -> int:
        hub_node = event.path[0] if event.path else 0
        bridge_node = event.path[1] if len(event.path) > 1 else 0
        path_key = event.path_description
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO notifications "
                "(timestamp, offending_node, hub_node, bridge_node, path_key, "
                " message, notification_type, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                (datetime.utcnow().isoformat(), event.offending_node,
                 hub_node, bridge_node, path_key, str(event), notification_type)
            )
            return cur.lastrowid

    def record_pending_hidden_path(self) -> int:
        """Pre-write a hidden-path notification row. Uses synthetic offender 0
        because by definition the API could not identify the offending node."""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO notifications "
                "(timestamp, offending_node, hub_node, bridge_node, path_key, "
                " message, notification_type, status) "
                "VALUES (?, 0, 0, 0, ?, ?, 'hidden_path', 'pending')",
                (datetime.utcnow().isoformat(),
                 "hidden_path_alert",
                 "hidden-path alert (no specific offender)")
            )
            return cur.lastrowid

    def record_pending_simple(self, notification_type: str,
                              note: str = "") -> int:
        """Pre-write a row for non-event categories (OPERATOR_AWARENESS,
        TEST, ERROR_REPORT)."""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO notifications "
                "(timestamp, offending_node, hub_node, bridge_node, path_key, "
                " message, notification_type, status) "
                "VALUES (?, 0, 0, 0, ?, ?, ?, 'pending')",
                (datetime.utcnow().isoformat(), notification_type, note,
                 notification_type)
            )
            return cur.lastrowid

    def mark_notification_status(self, row_id: int, status: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE notifications SET status = ? WHERE id = ?",
                (status, row_id)
            )

    # ---- 6-hour external-recipient cap (Invariant B) ----

    def external_recipient_sent_within(self, addr: str, hours: int) -> bool:
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT 1 FROM external_recipient_sends "
                    "WHERE recipient_address = ? AND sent_at > ? "
                    "AND status IN ('sent','pending') LIMIT 1",
                    (addr, cutoff)
                ).fetchone()
                return row is not None
        except sqlite3.Error as e:
            logger.error("external_recipient_sent_within fail-closed: %s", e)
            return True  # fail-closed: pretend recently sent → block

    def record_pending_external_send(self, addr: str,
                                     category: EmailCategory) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO external_recipient_sends "
                "(recipient_address, category, sent_at, status) "
                "VALUES (?, ?, ?, 'pending')",
                (addr, category.value, datetime.utcnow().isoformat())
            )
            return cur.lastrowid

    def mark_external_send_status(self, row_id: int, status: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE external_recipient_sends SET status = ? WHERE id = ?",
                (status, row_id)
            )

    # ---- unusual-externals dedup (unchanged from prior version) ----

    def get_alerted_unusual_externals(self) -> set[tuple[int, str]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT host_node, external_name FROM unusual_externals"
                ).fetchall()
            return {(int(h), str(n)) for h, n in rows}
        except sqlite3.Error as e:
            logger.error("get_alerted_unusual_externals: %s", e)
            return set()

    def mark_unusual_external_alerted(self, host_node: int, external_name: str,
                                       client_type: Optional[str], now_iso: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO unusual_externals "
                "(host_node, external_name, first_seen, last_seen, client_type) "
                "VALUES (?, ?, ?, ?, ?)",
                (int(host_node), str(external_name), now_iso, now_iso,
                 client_type or ""),
            )

    def touch_unusual_external(self, host_node: int, external_name: str,
                                now_iso: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE unusual_externals SET last_seen = ? "
                "WHERE host_node = ? AND external_name = ?",
                (now_iso, int(host_node), str(external_name)),
            )

    def clear_unusual_external(self, host_node: int, external_name: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM unusual_externals "
                "WHERE host_node = ? AND external_name = ?",
                (int(host_node), str(external_name)),
            )


class Notifier:
    """Manages notifications with rate limiting, quiet hours, and the
    single-chokepoint email-dispatch invariant set."""

    def __init__(self, config: dict):
        self.config = config
        self.tracker = NotificationTracker(
            db_path=str(Path(config.get("db_path", DB_FILE)))
        )
        self.rate_limits = config.get("rate_limits", {})
        self.quiet_config = config.get("quiet_hours", {})
        self.email_config = config.get("notifications", {}).get("email", {})

        # 6-hour external cap (B). Configurable; default 6.
        self.external_cooldown_hours = int(
            self.rate_limits.get("external_recipient_cooldown_hours", 6)
        )

        # ERROR_REPORT volume cap. Default 4/24h.
        self.error_report_max_per_day = int(
            self.rate_limits.get("error_report_max_per_day", 4)
        )

        # Defense-in-depth gate (C). Detector sets this each scan; chokepoint
        # also enforces. Default True (fail-closed: a freshly-constructed
        # Notifier with no explicit set_dry_run() call refuses to send).
        self._dry_run: bool = True

        # Health tracking for the StatusCollector.
        self._email_healthy: bool = True
        self._last_email_send: Optional[str] = None
        self._qrz_healthy: bool = True

        # Resolve internal_recipients FAIL-CLOSED (C1).
        self._internal_recipients = self._resolve_internal_recipients()
        # External recipients = full list minus internal.
        all_recipients = list(self.email_config.get("recipients") or [])
        self._external_recipients = [
            a for a in all_recipients if a not in self._internal_recipients
        ]
        logger.info(
            "Recipient scope resolved: internal=%s external=%s",
            self._internal_recipients, self._external_recipients
        )

        # QRZ.
        qrz_config = config.get("qrz", {})
        self.qrz: Optional[QRZLookup] = None
        if qrz_config.get("enabled", False):
            username = qrz_config.get("username", "")
            password = qrz_config.get("password", "")
            if username and password:
                self.qrz = QRZLookup(username, password)
                logger.info("QRZ callsign lookup: ENABLED")
            else:
                logger.warning("QRZ enabled but credentials missing")

    def set_dry_run(self, dry_run: bool):
        """Detector calls this before each scan with the effective
        dry_run / monitor_only state. The chokepoint will refuse to
        send when True."""
        self._dry_run = bool(dry_run)

    # ------------------------------------------------------------------
    # Recipient resolution (C1)
    # ------------------------------------------------------------------

    def _resolve_internal_recipients(self) -> list[str]:
        """Resolve the Bennett-only list, fail-closed.

        Precedence:
          1. notifications.email.internal_recipients (preferred, new field)
          2. notifications.email.hidden_path_recipients (legacy, deprecated)

        Raises RecipientResolutionError if neither yields a non-empty list
        AFTER stripping whitespace-only entries. We do NOT silently fall
        back to the full recipients list (the 2026-05-03 flood scenario).
        """
        cfg = self.email_config

        def _clean(raw) -> list[str]:
            if not isinstance(raw, list):
                return []
            return [str(a).strip() for a in raw if str(a).strip()]

        explicit = _clean(cfg.get("internal_recipients"))
        if explicit:
            return explicit

        # Field present but all entries blank/whitespace — this is a config
        # bug that must NOT silently fall back. Audit C-1 (2026-05-15 self-review).
        if cfg.get("internal_recipients") is not None:
            raise RecipientResolutionError(
                "secrets.yaml: 'internal_recipients' is present but contains "
                "no non-empty entries after stripping whitespace. Provide an "
                "explicit Bennett email address."
            )

        legacy = _clean(cfg.get("hidden_path_recipients"))
        if legacy:
            logger.warning(
                "Using legacy 'hidden_path_recipients' as internal_recipients. "
                "Rename to 'internal_recipients' in secrets.yaml."
            )
            return legacy

        if cfg.get("hidden_path_recipients") is not None:
            raise RecipientResolutionError(
                "secrets.yaml: 'hidden_path_recipients' is present but "
                "contains no non-empty entries after stripping whitespace."
            )

        raise RecipientResolutionError(
            "secrets.yaml: neither 'internal_recipients' nor "
            "'hidden_path_recipients' is set to a non-empty list under "
            "notifications.email. The detector refuses to start without an "
            "explicit Bennett-only recipient list — silently falling back to "
            "the full recipients list is the failure mode that caused the "
            "2026-05-03 incident."
        )

    # ------------------------------------------------------------------
    # Quiet hours (C7: fail-closed)
    # ------------------------------------------------------------------

    def is_quiet_hours(self) -> bool:
        """True if current time is within quiet hours. On ANY parsing/config
        exception this returns True (fail-closed: behave as if quiet so
        sysadmin emails are suppressed; offender courtesy is the only path
        that bypasses quiet hours and is unaffected)."""
        if not self.quiet_config.get("enabled", False):
            return False
        try:
            tz = ZoneInfo(self.quiet_config.get("timezone", "America/Chicago"))
            now = datetime.now(tz)
            start_str = self.quiet_config.get("start", "22:00")
            end_str = self.quiet_config.get("end", "07:00")
            start_h, start_m = map(int, start_str.split(":"))
            end_h, end_m = map(int, end_str.split(":"))
            start_minutes = start_h * 60 + start_m
            end_minutes = end_h * 60 + end_m
            now_minutes = now.hour * 60 + now.minute
            if start_minutes > end_minutes:
                return now_minutes >= start_minutes or now_minutes < end_minutes
            return start_minutes <= now_minutes < end_minutes
        except Exception as e:
            logger.error("Error parsing quiet_hours config — failing CLOSED "
                         "(treating as quiet): %s", e)
            return True

    # ------------------------------------------------------------------
    # Violation rate-limit gate (unchanged semantics, type-scoped queries)
    # ------------------------------------------------------------------

    def can_notify(self, event: BridgingEvent) -> tuple[bool, str]:
        window_min = self.rate_limits.get("window_minutes", 15)
        max_per_window = self.rate_limits.get("max_per_window", 2)
        if self.tracker.count_recent(minutes=window_min) >= max_per_window:
            return False, f"window limit ({max_per_window}/{window_min}min) reached"

        max_daily = self.rate_limits.get("max_per_day", 24)
        if self.tracker.count_today() >= max_daily:
            return False, f"daily limit ({max_daily}/day) reached"

        cooldown_min = self.rate_limits.get("cooldown_per_path_minutes", 15)
        last = self.tracker.last_notification_for_path(event)
        if last is not None:
            elapsed = (datetime.utcnow() - last).total_seconds() / 60
            if elapsed < cooldown_min:
                remaining = cooldown_min - elapsed
                return False, (f"cooldown for path '{event.path_description}' "
                               f"({remaining:.0f}min remaining)")
        return True, "ok"

    # ==================================================================
    # THE CHOKEPOINT — the ONLY function in this module that calls
    # smtplib.SMTP.sendmail. Do not duplicate.
    # ==================================================================

    def _dispatch_email(self,
                        category: EmailCategory,
                        subject: str,
                        body: str,
                        attachments: Optional[list[Path]] = None,
                        offender_address: Optional[str] = None,
                        tracker_row_id: Optional[int] = None,
                        ) -> bool:
        """Send one email, applying invariants (A), (B), (C).

        Args:
            category: Routing class.
            subject, body, attachments: Message content.
            offender_address: For OFFENDER_COURTESY only — the To: address.
                External recipients become BCC. Ignored for other categories.
            tracker_row_id: If the caller has already pre-written a row in
                the `notifications` table, pass its id so we transition
                it from 'pending' to 'sent'/'failed'. If None, the chokepoint
                pre-writes a row for this category.

        Returns True iff at least one envelope was successfully sent.
        """
        if category not in CATEGORY_POLICY:
            logger.error("BUG: unknown email category %r — refusing to send.",
                         category)
            return False

        policy = CATEGORY_POLICY[category]

        # (C) Universal dry-run / monitor-only gate. ERROR_REPORT bypasses
        # this gate because its recipient is Bennett-only (category-A
        # invariant guarantees) and monitor_only is meant to suppress
        # externally-visible side effects, not silence Bennett.
        if self._dry_run and not policy.get("bypass_dry_run", False):
            logger.info("Email suppressed (dry-run / monitor-only): "
                        "category=%s subject=%r", category.value, subject)
            if tracker_row_id is not None:
                try:
                    self.tracker.mark_notification_status(tracker_row_id, 'failed')
                except sqlite3.Error:
                    pass
            return False

        if not self.email_config.get("enabled", False):
            logger.warning("Email not enabled in config; logging only. "
                           "category=%s subject=%r", category.value, subject)
            if tracker_row_id is not None:
                try:
                    self.tracker.mark_notification_status(tracker_row_id, 'failed')
                except sqlite3.Error:
                    pass
            return False

        # Quiet-hours gate (categories that respect quiet hours).
        if not policy["bypass_quiet"] and self.is_quiet_hours():
            logger.info("Email suppressed (quiet hours): category=%s subject=%r",
                        category.value, subject)
            if tracker_row_id is not None:
                try:
                    self.tracker.mark_notification_status(tracker_row_id, 'failed')
                except sqlite3.Error:
                    pass
            return False

        # (A) Recipient resolution by category.
        internal = list(self._internal_recipients)
        external = list(self._external_recipients) if policy["allow_external"] else []

        # (B) 6-hour external cap, per-address.
        external_kept = []
        external_capped = []
        for addr in external:
            if self.tracker.external_recipient_sent_within(
                    addr, self.external_cooldown_hours):
                external_capped.append(addr)
            else:
                external_kept.append(addr)
        if external_capped:
            logger.info(
                "6-hour external cap suppressed %s for category=%s",
                external_capped, category.value
            )

        # Compose envelope recipient set + To/Cc/Bcc headers.
        if category == EmailCategory.OFFENDER_COURTESY:
            if not offender_address:
                logger.warning("OFFENDER_COURTESY with no offender_address; "
                               "skipping.")
                if tracker_row_id is not None:
                    self.tracker.mark_notification_status(tracker_row_id, 'failed')
                return False
            to_header = offender_address
            bcc = internal + external_kept
            envelope_recipients = [offender_address] + bcc
        else:
            primary = internal + external_kept
            if not primary:
                logger.warning(
                    "No recipients after (A)/(B) for category=%s; "
                    "skipping send.", category.value
                )
                if tracker_row_id is not None:
                    self.tracker.mark_notification_status(tracker_row_id, 'failed')
                return False
            to_header = ", ".join(primary)
            envelope_recipients = primary

        # Pre-write external-recipient cap rows for each kept external.
        ers_row_ids: list[int] = []
        try:
            for addr in external_kept:
                rid = self.tracker.record_pending_external_send(addr, category)
                ers_row_ids.append(rid)
        except sqlite3.Error as e:
            logger.error("Pre-write of external_recipient_sends failed; "
                         "refusing to send. %s", e)
            if tracker_row_id is not None:
                try:
                    self.tracker.mark_notification_status(tracker_row_id, 'failed')
                except sqlite3.Error:
                    pass
            return False

        # If the caller didn't pre-write a notifications row, do it now.
        owned_row_id = None
        if tracker_row_id is None:
            try:
                owned_row_id = self.tracker.record_pending_simple(
                    notification_type=category.value, note=subject)
            except sqlite3.Error as e:
                logger.error("Pre-write of notifications row failed; "
                             "refusing to send. %s", e)
                for rid in ers_row_ids:
                    try:
                        self.tracker.mark_external_send_status(rid, 'failed')
                    except sqlite3.Error:
                        pass
                return False

        # Build the MIME message.
        cfg = self.email_config
        msg = MIMEMultipart("mixed")
        prefix = cfg.get("subject_prefix", "[ASL Link Alert]")
        msg["Subject"] = f"{prefix} {subject}" if not subject.startswith(prefix) else subject
        msg["From"] = cfg.get("from_addr", cfg.get("username", ""))
        msg["To"] = to_header
        msg.attach(MIMEText(body, "plain"))
        for att in (attachments or []):
            try:
                img_part = MIMEImage(att.read_bytes(), _subtype="jpeg")
                img_part.add_header("Content-Disposition", "attachment",
                                    filename=att.name)
                msg.attach(img_part)
            except Exception as e:
                logger.warning("Failed to attach %s: %s", att, e)

        # Send.
        success = False
        try:
            server = smtplib.SMTP(cfg["smtp_server"], cfg.get("smtp_port", 587))
            if cfg.get("use_tls", True):
                server.starttls()
            server.login(cfg["username"], cfg["password"])
            server.sendmail(
                cfg.get("from_addr", cfg["username"]),
                envelope_recipients,
                msg.as_string()
            )
            server.quit()
            success = True
            self._email_healthy = True
            self._last_email_send = datetime.now(timezone.utc).isoformat()
            logger.info(
                "Email sent: category=%s recipients=%s (external_kept=%s)",
                category.value, envelope_recipients, external_kept
            )
        except Exception as e:
            self._email_healthy = False
            logger.error("Email send failed: category=%s err=%s",
                         category.value, e)

        # Transition counter rows.
        final_status = 'sent' if success else 'failed'
        rid_for_notification = tracker_row_id if tracker_row_id is not None else owned_row_id
        try:
            if rid_for_notification is not None:
                self.tracker.mark_notification_status(rid_for_notification, final_status)
            for rid in ers_row_ids:
                self.tracker.mark_external_send_status(rid, final_status)
        except sqlite3.Error as e:
            logger.error("Failed to transition tracker rows from pending: %s", e)

        return success

    # ==================================================================
    # Path #1 — VIOLATION_SYSADMIN
    # ==================================================================

    def notify(self, scan_result: ScanResult,
               bubble_image_path: Optional[str] = None) -> int:
        if not scan_result.has_problems:
            return 0
        sent_count = 0
        for event in scan_result.bridging_events:
            allowed, reason = self.can_notify(event)
            if not allowed:
                logger.info("Notification suppressed for node %s: %s",
                            event.offending_node, reason)
                continue

            # Pre-write the notifications row before sending (C3).
            try:
                row_id = self.tracker.record_pending_notification(
                    event, notification_type="violation")
            except sqlite3.Error as e:
                logger.error("Pre-write failed for violation: %s — skipping send",
                             e)
                continue

            attach_path = self._resolve_attachment(bubble_image_path)
            attachments = [attach_path] if attach_path else []

            subject = (f"Unauthorized bridging by node {event.offending_node} "
                       f"({event.offending_callsign})")
            body = self._format_email_body(event, scan_result)
            if attach_path:
                body += (f"\nThe bubble map captured at scan time is attached as "
                         f"{attach_path.name}.\n")

            sysadmin_ok = self._dispatch_email(
                EmailCategory.VIOLATION_SYSADMIN,
                subject=subject,
                body=body,
                attachments=attachments,
                tracker_row_id=row_id,
            )

            # Offender courtesy email (path #2) — independent send, bypasses quiet.
            if self.qrz and event.offending_callsign and event.offending_callsign != "Unknown":
                self._notify_offender(event, scan_result, bubble_image_path)

            if sysadmin_ok:
                sent_count += 1
        return sent_count

    @staticmethod
    def _resolve_attachment(image_path: Optional[str]) -> Optional[Path]:
        if not image_path:
            return None
        p = Path(image_path)
        if not p.is_file():
            logger.warning("Bubble attachment not found at %s, sending without", p)
            return None
        return p

    # ==================================================================
    # Path #2 — OFFENDER_COURTESY
    # ==================================================================

    def _notify_offender(self, event: BridgingEvent, scan_result: ScanResult,
                         bubble_image_path: Optional[str] = None):
        callsign = event.offending_callsign
        if not callsign or callsign == "Unknown":
            return

        qrz_info = self.qrz.lookup(callsign)
        self._qrz_healthy = qrz_info is not None
        if qrz_info is None:
            logger.warning("QRZ lookup failed for %s", callsign)
            return
        offender_email = qrz_info.get("email", "")
        if not offender_email:
            logger.info("QRZ: no email on file for %s", callsign)
            return

        offender_name = f"{qrz_info.get('fname', '')} {qrz_info.get('name', '')}".strip()
        if not offender_name:
            offender_name = callsign

        attach_path = self._resolve_attachment(bubble_image_path)
        attachments = [attach_path] if attach_path else []

        subject = (f"AllStarLink — Courtesy notice regarding node "
                   f"{event.offending_node}")
        body = self._format_offender_email(event, scan_result, offender_name, callsign)
        if attach_path:
            body += (f"\nThe bubble map captured at the time of detection is "
                     f"attached as {attach_path.name} for your reference.\n")

        self._dispatch_email(
            EmailCategory.OFFENDER_COURTESY,
            subject=subject,
            body=body,
            attachments=attachments,
            offender_address=offender_email,
        )

    # ==================================================================
    # Path #3 — HIDDEN_PATH_ANOMALY
    # ==================================================================

    def send_hidden_path_alert(self, scan_timestamp: str,
                              image_max_distance: int,
                              api_max_depth: int,
                              warnings: list[str],
                              image_path: Optional[str] = None) -> bool:
        """Hidden-path alerts use a type-scoped counter (C2/C4 fix) and
        route through the chokepoint with category HIDDEN_PATH_ANOMALY
        (Bennett-only, respects quiet hours)."""
        max_hourly = self.rate_limits.get("max_per_hour", 3)
        if self.tracker.count_recent(minutes=60.0,
                                     notification_type='hidden_path') >= max_hourly:
            logger.info("Hidden-path alert suppressed: hourly rate limit "
                        "(%d/hour) reached", max_hourly)
            return False
        max_daily = self.rate_limits.get("max_per_day_hidden_path", 5)
        if self.tracker.count_today(notification_type='hidden_path') >= max_daily:
            logger.info("Hidden-path alert suppressed: daily safety net "
                        "(%d/day) reached", max_daily)
            return False

        try:
            row_id = self.tracker.record_pending_hidden_path()
        except sqlite3.Error as e:
            logger.error("Pre-write failed for hidden-path: %s — skipping", e)
            return False

        attach_path = self._resolve_attachment(image_path)
        attachments = [attach_path] if attach_path else []

        warning_text = "\n".join(f"  - {w}" for w in warnings)
        attach_note = (f"\nThe bubble map captured at scan time is attached "
                       f"as {attach_path.name}.\n" if attach_path else "")
        body = f"""AllStarLink HIDDEN PATH Bridging Alert
=====================================

Detected at: {scan_timestamp}

The bubble map image analysis detected nodes at distance {image_max_distance}
from the focus node, but the API-based scan only found nodes at depth
{api_max_depth}. This discrepancy suggests unauthorized bridging through
a node whose connection list is not visible to the API.

CROSS-CHECK WARNINGS:
{warning_text}

This is a HIDDEN PATH alert — the API cannot identify the specific
offending node. Check the bubble map at:
  https://stats.allstarlink.org/stats/<FOCUS_NODE>/networkMap
{attach_note}
RECOMMENDED ACTION:
  Visually inspect the bubble map to identify the bridging path.
  The offending node may be a non-reporting guest node.

---
This is an automated alert from the ASL Intersystem Link Detector.
"""
        subject = (f"HIDDEN PATH — Image detects possible bridging "
                   f"(distance {image_max_distance})")
        return self._dispatch_email(
            EmailCategory.HIDDEN_PATH_ANOMALY,
            subject=subject,
            body=body,
            attachments=attachments,
            tracker_row_id=row_id,
        )

    # ==================================================================
    # Path #4 — OPERATOR_AWARENESS (reclassified 2026-05-14)
    # Previously routed to full recipients; per audit, classifier is fragile
    # enough that this is anomaly-class and goes to Bennett only until
    # field-validated.
    # ==================================================================

    def process_unusual_externals(self, scan_result: ScanResult) -> int:
        if not self.email_config.get("enabled", False):
            return 0

        observed: dict[tuple[int, str], dict] = {}
        for key, info in scan_result.topology.items():
            if info.get("role") != "permitted_external":
                continue
            ext_name = info.get("callsign", "")
            if not is_unusual_external_name(ext_name):
                continue
            try:
                host_node = int(info.get("parent") or 0)
            except (TypeError, ValueError):
                host_node = 0
            if host_node == 0:
                continue
            observed[(host_node, ext_name)] = {
                "host_node": host_node,
                "external_name": ext_name,
                "client_type": info.get("client_type", "webtransceiver_type"),
                "host_info": scan_result.topology.get(host_node, {}),
                "scan_timestamp": scan_result.timestamp,
            }

        alerted_before = self.tracker.get_alerted_unusual_externals()
        now_iso = datetime.utcnow().isoformat()

        gone = alerted_before - set(observed.keys())
        for host_node, ext_name in gone:
            logger.info("Unusual external '%s' on node %s no longer observed; "
                        "clearing dedup state.", ext_name, host_node)
            self.tracker.clear_unusual_external(host_node, ext_name)

        new_alerts = 0
        for pair, ctx in observed.items():
            if pair in alerted_before:
                self.tracker.touch_unusual_external(pair[0], pair[1], now_iso)
                continue

            subject = (f"UNUSUAL external '{ctx['external_name']}' observed on "
                       f"node {ctx['host_node']} "
                       f"({ctx['host_info'].get('callsign', '?')})")
            body = self._format_unusual_external_body(ctx)
            sent = self._dispatch_email(
                EmailCategory.OPERATOR_AWARENESS,
                subject=subject,
                body=body,
            )
            if sent:
                self.tracker.mark_unusual_external_alerted(
                    ctx["host_node"], ctx["external_name"],
                    ctx.get("client_type"), now_iso,
                )
                new_alerts += 1
        return new_alerts

    @staticmethod
    def _format_unusual_external_body(ctx: dict) -> str:
        host_info = ctx.get("host_info", {}) or {}
        return f"""AllStarLink Unusual External Connection — Operator Awareness Alert
====================================================================

Detected at: {ctx.get('scan_timestamp', '?')}

UNUSUAL EXTERNAL:
  Peer name:        '{ctx['external_name']}'
  Client type:      {ctx.get('client_type', 'webtransceiver_type')}
  Host node:        {ctx['host_node']}
  Host callsign:    {host_info.get('callsign', '?')}
  Host location:    {host_info.get('location', '?')}
  Host role:        {host_info.get('role', '?')}

WHY THIS IS UNUSUAL:
  The peer name does not match the amateur-radio callsign pattern that
  WebTransceiver, RepeaterPhone, and softphone clients normally use, and
  it does not match the chan_echolink "EchoLink-NNNNNN" format. Peer
  names like 'DVSwitch', 'IAX_Bridge', 'Analog_Bridge', 'MMDVM_Bridge',
  'analog_bridge', or arbitrary session labels fall into this category.

WHAT THIS MEANS:
  This connection has NOT been detected as forming a bridge to other
  networks. The detector continues to allow it as a permitted leaf
  attachment. The classifier raised this for human review only.

NO INTERVENTION:
  No auto-disconnect has been or will be performed for this connection.

---
This is an automated alert from the ASL Intersystem Link Detector.
"""

    # ==================================================================
    # Path #5 — TEST (Bennett-only; gated by ASL_ALLOW_TEST_EMAIL env var
    # in the CLI handler in asl_link_detector.py)
    # ==================================================================

    def send_test_email(self) -> bool:
        cfg = self.email_config
        if not cfg.get("enabled", False):
            logger.error("Email notifications are not enabled in config.")
            return False
        for field in ("username", "password"):
            if not cfg.get(field):
                logger.error("Email config missing required field: %s", field)
                return False
        body = (
            "ASL Intersystem Link Detector — SMTP Test\n"
            "==========================================\n\n"
            "This is a test message confirming SMTP configuration.\n"
            f"SMTP server: {cfg['smtp_server']}:{cfg.get('smtp_port', 587)}\n"
            "If you received this, email alerts are working.\n\n"
            "---\n"
            "ASL Intersystem Link Detector\n"
        )
        return self._dispatch_email(
            EmailCategory.TEST,
            subject="Test — SMTP configuration verified",
            body=body,
        )

    # ==================================================================
    # New path — ERROR_REPORT (Bennett-only, capped, bypasses quiet hours)
    # ==================================================================

    def report_error(self, subject: str, body: str,
                     exc: Optional[BaseException] = None) -> bool:
        """Send a daemon-level error report to Bennett. Capped at
        error_report_max_per_day per 24h to prevent a self-induced flood
        from a tight error loop. Bypasses quiet hours by category policy
        (so Bennett sees real problems when they happen)."""
        # Volume cap.
        try:
            sent_24h = self.tracker.count_last_24h(
                notification_type='error_report')
        except Exception as e:
            logger.error("ERROR_REPORT volume-cap query failed: %s — "
                         "logging only.", e)
            return False
        if sent_24h >= self.error_report_max_per_day:
            logger.warning(
                "ERROR_REPORT cap reached (%d/24h) — error logged but not "
                "emailed: %s", self.error_report_max_per_day, subject
            )
            return False

        full_body = body
        if exc is not None:
            import traceback
            full_body += "\n\nException:\n" + "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            )
        return self._dispatch_email(
            EmailCategory.ERROR_REPORT,
            subject=f"ERROR — {subject}",
            body=full_body,
        )

    # ==================================================================
    # Email body formatters (unchanged from prior version)
    # ==================================================================

    def _format_offender_email(self, event: BridgingEvent,
                                scan_result: ScanResult,
                                offender_name: str, callsign: str) -> str:
        template = self._load_offender_template()
        return template.format(
            offender_name=offender_name,
            callsign=callsign,
            offending_node=event.offending_node,
            path_description=event.path_description,
        )

    def _load_offender_template(self) -> str:
        template_path = Path(__file__).parent / "offender_email_draft.txt"
        if template_path.exists():
            try:
                return template_path.read_text()
            except Exception as e:
                logger.warning("Could not read offender template: %s", e)
        return """Hello {offender_name} ({callsign}),

This is an automated notice from our repeater system.

Our monitoring system has detected that your node {offending_node}
is currently (or was recently) connected to our system while
also having a connection to another AllStarLink network node:

  Connection path: {path_description}

Such bridging can create confusion and chaos unless previously
discussed and authorized by the system trustee.

When connecting to our system always "Disconnect before Connect."
This will ensure that your node has no other active connections
when linking to our repeater system.

It's possible we have already disconnected your node. You are welcome
to reconnect after clearing your other connections.

If you believe this notice was sent in error, or if you have
questions, please contact the repeater support team.

73
"""

    def _format_email_body(self, event: BridgingEvent, scan_result: ScanResult) -> str:
        dragged_in = [
            f"  - Node {nid} ({info.get('callsign', '?')}, {info.get('location', '?')})"
            for nid, info in scan_result.topology.items()
            if info.get("role") == "dragged_in"
        ]
        dragged_list = "\n".join(dragged_in[:20]) if dragged_in else "  (none detected beyond the offending node)"

        non_allstar_lines = []
        for nid, info in scan_result.topology.items():
            ct = info.get("client_type")
            if ct == "echolink":
                disp = info.get("callsign", "?")
                parent = info.get("parent", "?")
                el_id = disp.split("-", 1)[1] if disp.startswith("EchoLink-") else "?"
                non_allstar_lines.append(
                    f"  - {disp} on host node {parent}"
                    f"\n      EchoLink endpoint (node ID {el_id}, via chan_echolink)"
                )
            elif ct == "webtransceiver_type":
                disp = info.get("callsign", "?")
                parent = info.get("parent", "?")
                non_allstar_lines.append(
                    f"  - '{disp}' on host node {parent}"
                    f"\n      WebTransceiver-type IAX2 softclient"
                    f"\n      (WebTransceiver / AllScan / RepeaterPhone / generic"
                    f" softphone — not distinguishable from stats API alone)"
                )
        if non_allstar_lines:
            non_allstar_section = "\n".join(non_allstar_lines[:30])
        else:
            non_allstar_section = "  (none observed in this scan)"

        return f"""AllStarLink Unauthorized Bridging Alert
========================================

Detected at: {scan_result.timestamp}

OFFENDING NODE: {event.offending_node}
  Callsign:    {event.offending_callsign}
  Location:    {event.offending_location}

BRIDGING PATH:
  {event.path_description}

DETECTION RULE:
  {event.rule}

The offending node at depth {event.depth} is creating an unauthorized bridge
between this repeater system and other networks.

ADDITIONAL NODES CONNECTED VIA THE UNAUTHORIZED BRIDGING:
{dragged_list}

NON-ALLSTAR ENDPOINTS OBSERVED IN THIS SCAN:
{non_allstar_section}

RECOMMENDED ACTION:
  Node {event.offending_node} ({event.offending_callsign}) should disconnect
  from all other nodes before connecting to this system.
  ("Disconnect before connect" best practice.)

---
This is an automated alert from the ASL Intersystem Link Detector.
"""


# ----------------------------------------------------------------------
# Import-time self-check: enforce the "only the chokepoint calls
# .sendmail()" invariant via AST. Counts actual Attribute call sites,
# so this file's own assertion source doesn't trip the count.
# Future maintainers: do NOT add another smtplib.SMTP(...).sendmail call.
# ----------------------------------------------------------------------
def _self_check_single_sendmail():
    import ast as _ast
    try:
        tree = _ast.parse(Path(__file__).read_text())
    except Exception as e:
        # S-2 fix (2026-05-15 self-review): warn loudly so the operator
        # notices that the chokepoint invariant is no longer enforced.
        logger.warning(
            "notifier.py: chokepoint AST self-check could not read source "
            "(%s). The single-sendmail invariant is NOT being enforced at "
            "import time. Verify by hand: only _dispatch_email should call "
            ".sendmail().", e
        )
        return
    callsites = []
    for node in _ast.walk(tree):
        if (isinstance(node, _ast.Call)
                and isinstance(node.func, _ast.Attribute)
                and node.func.attr == "sendmail"):
            callsites.append(node.lineno)
    if len(callsites) > 1:
        raise RuntimeError(
            f"notifier.py invariant violated: {len(callsites)} .sendmail() "
            f"callsites at lines {callsites}; only _dispatch_email is permitted."
        )


_self_check_single_sendmail()
