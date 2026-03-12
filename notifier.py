"""Notification system with rate limiting and quiet hours."""

import logging
import smtplib
import sqlite3
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

from graph_analyzer import BridgingEvent, ScanResult
from qrz_lookup import QRZLookup

logger = logging.getLogger(__name__)

DB_FILE = "notifications.db"


class NotificationTracker:
    """SQLite-based rate limiting for notifications."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()

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
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_notif_timestamp
                ON notifications(timestamp)
            """)
            # Add path_key column if upgrading from older schema
            try:
                conn.execute("SELECT path_key FROM notifications LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE notifications ADD COLUMN path_key TEXT NOT NULL DEFAULT ''")
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_notif_path_key
                ON notifications(path_key)
            """)

    @staticmethod
    def _make_path_key(event: BridgingEvent) -> str:
        """Create a unique key from the violation path."""
        return event.path_description

    def record_notification(self, event: BridgingEvent):
        """Record that a notification was sent for this event."""
        hub_node = event.path[0] if event.path else 0
        bridge_node = event.path[1] if len(event.path) > 1 else 0
        path_key = self._make_path_key(event)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO notifications (timestamp, offending_node, hub_node, bridge_node, path_key, message) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (datetime.utcnow().isoformat(), event.offending_node,
                 hub_node, bridge_node, path_key, str(event))
            )

    def count_recent(self, minutes: float = 15.0) -> int:
        """Count notifications sent in the last N minutes."""
        cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM notifications WHERE timestamp > ?", (cutoff,)
            ).fetchone()
            return row[0] if row else 0

    def count_today(self) -> int:
        """Count notifications sent today (UTC)."""
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM notifications WHERE timestamp > ?", (today_start,)
            ).fetchone()
            return row[0] if row else 0

    def last_notification_for_path(self, event: BridgingEvent) -> Optional[datetime]:
        """Get timestamp of last notification for a specific violation path."""
        path_key = self._make_path_key(event)
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT timestamp FROM notifications WHERE path_key = ? "
                "ORDER BY timestamp DESC LIMIT 1", (path_key,)
            ).fetchone()
            if row:
                return datetime.fromisoformat(row[0])
            return None


class Notifier:
    """Manages notifications with rate limiting and quiet hours."""

    def __init__(self, config: dict):
        self.config = config
        self.tracker = NotificationTracker(
            db_path=str(Path(config.get("db_path", DB_FILE)))
        )
        self.rate_limits = config.get("rate_limits", {})
        self.quiet_config = config.get("quiet_hours", {})
        self.email_config = config.get("notifications", {}).get("email", {})

        # QRZ lookup for offender notification
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

    def is_quiet_hours(self) -> bool:
        """Check if current time is within quiet hours."""
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
                # Crosses midnight (e.g., 22:00 - 07:00)
                return now_minutes >= start_minutes or now_minutes < end_minutes
            else:
                return start_minutes <= now_minutes < end_minutes
        except Exception as e:
            logger.error(f"Error checking quiet hours: {e}")
            return False

    def can_notify(self, event: BridgingEvent) -> tuple[bool, str]:
        """Check if we're allowed to send a notification for this event.

        Rate limiting rules:
          - Max N per window (e.g., 2 per 15 minutes) across all paths
          - Max N per day across all paths
          - Per-path cooldown: same violation path won't re-notify within window

        Note: quiet hours are NOT checked here — they are applied selectively
        in notify() so that offender emails are always sent regardless of
        quiet hours, while sys admin emails are suppressed during quiet hours.

        Returns (allowed, reason).
        """
        # Check per-window limit (all paths combined)
        window_min = self.rate_limits.get("window_minutes", 15)
        max_per_window = self.rate_limits.get("max_per_window", 2)
        if self.tracker.count_recent(minutes=window_min) >= max_per_window:
            return False, f"window limit ({max_per_window}/{window_min}min) reached"

        # Check per-day limit
        max_daily = self.rate_limits.get("max_per_day", 24)
        if self.tracker.count_today() >= max_daily:
            return False, f"daily limit ({max_daily}/day) reached"

        # Check per-path cooldown
        cooldown_min = self.rate_limits.get("cooldown_per_path_minutes", 15)
        last = self.tracker.last_notification_for_path(event)
        if last is not None:
            elapsed = (datetime.utcnow() - last).total_seconds() / 60
            if elapsed < cooldown_min:
                remaining = cooldown_min - elapsed
                return False, (f"cooldown for path '{event.path_description}' "
                               f"({remaining:.0f}min remaining)")

        return True, "ok"

    def notify(self, scan_result: ScanResult) -> int:
        """Send notifications for all bridging events in a scan result.

        Quiet hours suppress sys admin emails but NOT offender courtesy emails.
        Rate limits apply to all notifications regardless of quiet hours.

        Returns the number of notifications actually sent.
        """
        if not scan_result.has_problems:
            return 0

        quiet = self.is_quiet_hours()
        sent_count = 0
        for event in scan_result.bridging_events:
            allowed, reason = self.can_notify(event)
            if not allowed:
                logger.info(f"Notification suppressed for node {event.offending_node}: {reason}")
                continue

            success = self._send_notification(event, scan_result, quiet)
            if success:
                self.tracker.record_notification(event)
                sent_count += 1

        return sent_count

    def _send_notification(self, event: BridgingEvent, scan_result: ScanResult,
                           quiet: bool = False) -> bool:
        """Send notification via all enabled channels. Returns True if any succeeded."""
        any_success = False

        if self.email_config.get("enabled", False):
            if quiet:
                logger.info(f"Sys admin email suppressed for node {event.offending_node}: quiet hours")
            else:
                if self._send_email(event, scan_result):
                    any_success = True

        # Send courtesy email to offending operator via QRZ lookup
        # Always sent regardless of quiet hours
        if self.qrz and self.email_config.get("enabled", False):
            self._notify_offender(event, scan_result)
            any_success = True

        # If no channels produced output, just log
        if not any_success:
            logger.warning(f"NOTIFICATION (no channels enabled): {event}")
            # Still count as "sent" for rate limiting so we don't spam logs
            any_success = True

        return any_success

    def _send_email(self, event: BridgingEvent, scan_result: ScanResult) -> bool:
        """Send email notification for a bridging event."""
        try:
            cfg = self.email_config
            msg = MIMEMultipart("alternative")
            prefix = cfg.get("subject_prefix", "[ASL Link Alert]")
            msg["Subject"] = (
                f"{prefix} Unauthorized bridging by node {event.offending_node} "
                f"({event.offending_callsign})"
            )
            msg["From"] = cfg.get("from_addr", cfg.get("username", ""))
            msg["To"] = ", ".join(cfg.get("recipients", []))

            # Plain text body
            body = self._format_email_body(event, scan_result)
            msg.attach(MIMEText(body, "plain"))

            # Send
            server = smtplib.SMTP(cfg["smtp_server"], cfg.get("smtp_port", 587))
            if cfg.get("use_tls", True):
                server.starttls()
            server.login(cfg["username"], cfg["password"])
            server.sendmail(
                cfg.get("from_addr", cfg["username"]),
                cfg["recipients"],
                msg.as_string()
            )
            server.quit()

            logger.info(f"Email sent for node {event.offending_node} to {cfg['recipients']}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    def send_hidden_path_alert(self, scan_timestamp: str,
                              image_max_distance: int,
                              api_max_depth: int,
                              warnings: list[str]) -> bool:
        """Send an alert for hidden-path bridging detected by image but not API.

        This is a separate path from per-event notifications because the API
        couldn't identify the specific offending node.
        """
        if self.is_quiet_hours():
            logger.info("Hidden-path alert suppressed: quiet hours")
            return False

        # Use general rate limits (not per-node, since we don't know the node)
        max_hourly = self.rate_limits.get("max_per_hour", 3)
        if self.tracker.count_recent(hours=1.0) >= max_hourly:
            logger.info("Hidden-path alert suppressed: hourly rate limit")
            return False

        cfg = self.email_config
        if not cfg.get("enabled", False):
            logger.warning(f"HIDDEN PATH ALERT (no email configured): "
                           f"Image max_distance={image_max_distance}, "
                           f"API max_depth={api_max_depth}")
            return False

        try:
            msg = MIMEMultipart("alternative")
            prefix = cfg.get("subject_prefix", "[ASL Link Alert]")
            msg["Subject"] = (
                f"{prefix} HIDDEN PATH — Image detects possible bridging "
                f"(distance {image_max_distance})"
            )
            msg["From"] = cfg.get("from_addr", cfg.get("username", ""))
            msg["To"] = ", ".join(cfg.get("recipients", []))

            warning_text = "\n".join(f"  - {w}" for w in warnings)
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

RECOMMENDED ACTION:
  Visually inspect the bubble map to identify the bridging path.
  The offending node may be a non-reporting guest node.

---
This is an automated alert from the ASL Intersystem Link Detector.
"""
            msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP(cfg["smtp_server"], cfg.get("smtp_port", 587))
            if cfg.get("use_tls", True):
                server.starttls()
            server.login(cfg["username"], cfg["password"])
            server.sendmail(
                cfg.get("from_addr", cfg["username"]),
                cfg["recipients"],
                msg.as_string()
            )
            server.quit()

            logger.info(f"Hidden-path alert email sent to {cfg['recipients']}")
            return True

        except Exception as e:
            logger.error(f"Failed to send hidden-path alert email: {e}")
            return False

    def send_test_email(self) -> bool:
        """Send a test email to verify SMTP configuration.

        Returns True if the test email was sent successfully.
        """
        cfg = self.email_config
        if not cfg.get("enabled", False):
            logger.error("Email notifications are not enabled in config.")
            return False

        for field in ("username", "password", "recipients"):
            if not cfg.get(field):
                logger.error(f"Email config missing required field: {field}")
                return False

        try:
            msg = MIMEMultipart("alternative")
            prefix = cfg.get("subject_prefix", "[ASL Link Alert]")
            msg["Subject"] = f"{prefix} Test — SMTP configuration verified"
            msg["From"] = cfg.get("from_addr", cfg.get("username", ""))
            msg["To"] = ", ".join(cfg["recipients"])

            body = (
                "ASL Intersystem Link Detector — SMTP Test\n"
                "==========================================\n\n"
                "This is a test message confirming that email notifications\n"
                "are correctly configured.\n\n"
                f"SMTP server: {cfg['smtp_server']}:{cfg.get('smtp_port', 587)}\n"
                f"From: {msg['From']}\n"
                f"To: {msg['To']}\n\n"
                "If you received this, email alerts are working.\n\n"
                "---\n"
                "ASL Intersystem Link Detector\n"
            )
            msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP(cfg["smtp_server"], cfg.get("smtp_port", 587))
            if cfg.get("use_tls", True):
                server.starttls()
            server.login(cfg["username"], cfg["password"])
            server.sendmail(
                cfg.get("from_addr", cfg["username"]),
                cfg["recipients"],
                msg.as_string()
            )
            server.quit()

            logger.info(f"Test email sent successfully to {cfg['recipients']}")
            return True

        except Exception as e:
            logger.error(f"Test email failed: {e}")
            return False

    def _notify_offender(self, event: BridgingEvent, scan_result: ScanResult):
        """Look up the offending operator via QRZ and send a courtesy email."""
        callsign = event.offending_callsign
        if not callsign or callsign == "Unknown":
            logger.info("Cannot notify offender: no callsign available")
            return

        qrz_info = self.qrz.lookup(callsign)
        if qrz_info is None:
            logger.warning(f"QRZ lookup failed for {callsign}")
            return

        offender_email = qrz_info.get("email", "")
        if not offender_email:
            logger.info(f"QRZ: no email on file for {callsign}")
            return

        offender_name = f"{qrz_info.get('fname', '')} {qrz_info.get('name', '')}".strip()
        if not offender_name:
            offender_name = callsign

        try:
            cfg = self.email_config
            msg = MIMEMultipart("alternative")
            msg["Subject"] = (
                f"AllStarLink — Courtesy notice regarding node "
                f"{event.offending_node}"
            )
            msg["From"] = cfg.get("from_addr", cfg.get("username", ""))
            msg["To"] = offender_email
            # BCC the operator so they know the email went out
            bcc = cfg.get("recipients", [])

            body = self._format_offender_email(
                event, scan_result, offender_name, callsign
            )
            msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP(cfg["smtp_server"], cfg.get("smtp_port", 587))
            if cfg.get("use_tls", True):
                server.starttls()
            server.login(cfg["username"], cfg["password"])
            all_recipients = [offender_email] + bcc
            server.sendmail(
                cfg.get("from_addr", cfg["username"]),
                all_recipients,
                msg.as_string()
            )
            server.quit()

            logger.info(
                f"Offender courtesy email sent to {callsign} ({offender_email})"
            )
        except Exception as e:
            logger.error(f"Failed to send offender email to {callsign}: {e}")

    def _format_offender_email(self, event: BridgingEvent,
                                scan_result: ScanResult,
                                offender_name: str, callsign: str) -> str:
        """Format the courtesy email to the offending operator."""
        # Load the offender email template from file if available,
        # otherwise use the built-in generic template.
        template = self._load_offender_template()
        return template.format(
            offender_name=offender_name,
            callsign=callsign,
            offending_node=event.offending_node,
            path_description=event.path_description,
        )

    def _load_offender_template(self) -> str:
        """Load offender email template from offender_email_draft.txt.

        Falls back to a generic built-in template if the file is not found.
        """
        template_path = Path(__file__).parent / "offender_email_draft.txt"
        if template_path.exists():
            try:
                return template_path.read_text()
            except Exception as e:
                logger.warning(f"Could not read offender template: {e}")

        # Generic fallback template
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
        """Format the email body for a bridging event."""
        # Collect dragged-in nodes from the topology
        dragged_in = [
            f"  - Node {nid} ({info.get('callsign', '?')}, {info.get('location', '?')})"
            for nid, info in scan_result.topology.items()
            if info.get("role") == "dragged_in"
        ]
        dragged_list = "\n".join(dragged_in[:20]) if dragged_in else "  (none detected beyond the offending node)"

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

UNAUTHORIZED NODES PULLED IN:
{dragged_list}

RECOMMENDED ACTION:
  Node {event.offending_node} ({event.offending_callsign}) should disconnect
  from all other nodes before connecting to this system.
  ("Disconnect before connect" best practice.)

---
This is an automated alert from the ASL Intersystem Link Detector.
"""
