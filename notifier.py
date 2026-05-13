"""Notification system with rate limiting and quiet hours."""

import logging
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

# A "looks like an amateur radio callsign" pattern. Accepts the FCC-style
# 1-or-2-letter prefix + digit + 1-to-4-letter suffix, with an optional
# alphanumeric mixed-case trailer (for things like "K1BLUMobile2" seen in
# our logs). Anything that does NOT match this pattern and is NOT an
# "EchoLink-NNNNNN" string is considered an UNUSUAL external — a candidate
# for the one-shot all-operator alert added 2026-05-13. Tightening or
# loosening this regex changes the alert sensitivity.
CALLSIGN_LIKE = re.compile(r'^[A-Z]{1,2}\d[A-Z]{1,4}[A-Za-z0-9]*$')


def is_unusual_external_name(name: str) -> bool:
    """True if `name` is a non-AllStar external peer name that does not match
    either an amateur radio callsign or the source-verified EchoLink-NNNNNN
    format. Such names (e.g. 'DVSwitch', 'IAX_Bridge', 'Analog_Bridge',
    'MMDVM_Bridge', 'analog_bridge',
    'web_user_xyz') indicate a potentially cross-network bridge type and
    warrant operator notification per the 2026-05-13 policy."""
    if not name:
        return True
    if name.startswith("EchoLink-"):
        return False
    return not CALLSIGN_LIKE.match(name)


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
            # Dedup state for unusual-external alerts (one alert per
            # (host_node, external_name) for the duration the external is
            # observed; re-alert if it disappears and later reappears).
            # Added 2026-05-13.
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

    @staticmethod
    def _make_path_key(event: BridgingEvent) -> str:
        """Create a unique key from the violation path."""
        return event.path_description

    def get_alerted_unusual_externals(self) -> set[tuple[int, str]]:
        """Return the set of (host_node, external_name) we've already alerted on."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT host_node, external_name FROM unusual_externals"
            ).fetchall()
        return {(int(h), str(n)) for h, n in rows}

    def mark_unusual_external_alerted(self, host_node: int, external_name: str,
                                       client_type: Optional[str], now_iso: str):
        """Record that we have sent an alert for this (host_node, external_name)."""
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
        """Update last_seen for a still-observed unusual external."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE unusual_externals SET last_seen = ? "
                "WHERE host_node = ? AND external_name = ?",
                (now_iso, int(host_node), str(external_name)),
            )

    def clear_unusual_external(self, host_node: int, external_name: str):
        """Remove a (host_node, external_name) row — the external is no longer
        observed, so the next reappearance should re-alert."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM unusual_externals "
                "WHERE host_node = ? AND external_name = ?",
                (int(host_node), str(external_name)),
            )

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

        # Health tracking (read by StatusCollector — no functional side effects)
        self._email_healthy: bool = True
        self._last_email_send: Optional[str] = None
        self._qrz_healthy: bool = True

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

    def notify(self, scan_result: ScanResult,
               bubble_image_path: Optional[str] = None) -> int:
        """Send notifications for all bridging events in a scan result.

        Quiet hours suppress sys admin emails but NOT offender courtesy emails.
        Rate limits apply to all notifications regardless of quiet hours.

        If bubble_image_path is given (and the file exists), the bubble map JPEG
        is attached to every email this notify cycle produces.

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

            success = self._send_notification(event, scan_result, quiet,
                                              bubble_image_path)
            if success:
                self.tracker.record_notification(event)
                sent_count += 1

        return sent_count

    def _send_notification(self, event: BridgingEvent, scan_result: ScanResult,
                           quiet: bool = False,
                           bubble_image_path: Optional[str] = None) -> bool:
        """Send notification via all enabled channels. Returns True if any succeeded."""
        any_success = False

        if self.email_config.get("enabled", False):
            if quiet:
                logger.info(f"Sys admin email suppressed for node {event.offending_node}: quiet hours")
            else:
                if self._send_email(event, scan_result, bubble_image_path):
                    any_success = True

        # Send courtesy email to offending operator via QRZ lookup
        # Always sent regardless of quiet hours
        if self.qrz and self.email_config.get("enabled", False):
            self._notify_offender(event, scan_result, bubble_image_path)
            any_success = True

        # If no channels produced output, just log
        if not any_success:
            logger.warning(f"NOTIFICATION (no channels enabled): {event}")
            # Still count as "sent" for rate limiting so we don't spam logs
            any_success = True

        return any_success

    @staticmethod
    def _resolve_attachment(image_path: Optional[str]) -> Optional[Path]:
        """Validate an attachment path. Returns the Path if usable, else None
        (also logs a warning when a path was supplied but the file is missing)."""
        if not image_path:
            return None
        p = Path(image_path)
        if not p.is_file():
            logger.warning(f"Bubble attachment not found at {p}, sending without")
            return None
        return p

    @staticmethod
    def _attach_bubble(msg: MIMEMultipart, attach_path: Path) -> None:
        """Attach a bubble JPEG to a MIMEMultipart('mixed') message."""
        img_part = MIMEImage(attach_path.read_bytes(), _subtype="jpeg")
        img_part.add_header(
            "Content-Disposition", "attachment",
            filename=attach_path.name,
        )
        msg.attach(img_part)

    def _send_email(self, event: BridgingEvent, scan_result: ScanResult,
                    bubble_image_path: Optional[str] = None) -> bool:
        """Send email notification for a bridging event."""
        try:
            cfg = self.email_config
            attach_path = self._resolve_attachment(bubble_image_path)
            # "mixed" so we can carry both the text body and the JPEG attachment.
            msg = MIMEMultipart("mixed")
            prefix = cfg.get("subject_prefix", "[ASL Link Alert]")
            msg["Subject"] = (
                f"{prefix} Unauthorized bridging by node {event.offending_node} "
                f"({event.offending_callsign})"
            )
            msg["From"] = cfg.get("from_addr", cfg.get("username", ""))
            msg["To"] = ", ".join(cfg.get("recipients", []))

            # Plain text body — note attachment if present
            body = self._format_email_body(event, scan_result)
            if attach_path:
                body += (
                    f"\nThe bubble map captured at scan time is attached as "
                    f"{attach_path.name}.\n"
                )
            msg.attach(MIMEText(body, "plain"))
            if attach_path:
                self._attach_bubble(msg, attach_path)

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

            self._email_healthy = True
            self._last_email_send = datetime.now(timezone.utc).isoformat()
            logger.info(
                f"Email sent for node {event.offending_node} to {cfg['recipients']}"
                + (f" with attachment {attach_path.name}" if attach_path else "")
            )
            return True

        except Exception as e:
            self._email_healthy = False
            logger.error(f"Failed to send email: {e}")
            return False

    def send_hidden_path_alert(self, scan_timestamp: str,
                              image_max_distance: int,
                              api_max_depth: int,
                              warnings: list[str],
                              image_path: Optional[str] = None) -> bool:
        """Send an alert for hidden-path bridging detected by image but not API.

        This is a separate path from per-event notifications because the API
        couldn't identify the specific offending node. If image_path is given
        and the file exists, the bubble map is attached to the email so the
        recipient can inspect the topology that triggered the alert.
        """
        if self.is_quiet_hours():
            logger.info("Hidden-path alert suppressed: quiet hours")
            return False

        # Use general rate limits (not per-node, since we don't know the node).
        # Hourly cap and a daily safety net — the latter exists specifically to
        # bound the blast radius of any future failure mode (e.g., a new bubble-
        # analyzer artifact pattern that bypasses the triangle suppression).
        max_hourly = self.rate_limits.get("max_per_hour", 3)
        if self.tracker.count_recent(minutes=60.0) >= max_hourly:
            logger.info("Hidden-path alert suppressed: hourly rate limit")
            return False
        max_daily_hidden = self.rate_limits.get("max_per_day_hidden_path", 5)
        if self.tracker.count_today() >= max_daily_hidden:
            logger.info(
                f"Hidden-path alert suppressed: daily safety net "
                f"({max_daily_hidden}/day) reached"
            )
            return False

        cfg = self.email_config
        if not cfg.get("enabled", False):
            logger.warning(f"HIDDEN PATH ALERT (no email configured): "
                           f"Image max_distance={image_max_distance}, "
                           f"API max_depth={api_max_depth}")
            return False

        try:
            attach_path = self._resolve_attachment(image_path)

            # Hidden-path alerts may have a narrower recipient list than regular
            # bridging-event emails (see `hidden_path_recipients` in secrets).
            # Falls back to the full recipient list when no override is set.
            recipients = (
                cfg.get("hidden_path_recipients")
                or cfg.get("recipients", [])
            )

            # "mixed" so we can carry both the text body and the JPEG attachment.
            msg = MIMEMultipart("mixed")
            prefix = cfg.get("subject_prefix", "[ASL Link Alert]")
            msg["Subject"] = (
                f"{prefix} HIDDEN PATH — Image detects possible bridging "
                f"(distance {image_max_distance})"
            )
            msg["From"] = cfg.get("from_addr", cfg.get("username", ""))
            msg["To"] = ", ".join(recipients)

            warning_text = "\n".join(f"  - {w}" for w in warnings)
            attach_note = (
                f"\nThe bubble map captured at scan time is attached as "
                f"{attach_path.name}.\n"
                if attach_path else ""
            )
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
            msg.attach(MIMEText(body, "plain"))
            if attach_path:
                self._attach_bubble(msg, attach_path)

            server = smtplib.SMTP(cfg["smtp_server"], cfg.get("smtp_port", 587))
            if cfg.get("use_tls", True):
                server.starttls()
            server.login(cfg["username"], cfg["password"])
            server.sendmail(
                cfg.get("from_addr", cfg["username"]),
                recipients,
                msg.as_string()
            )
            server.quit()

            self._email_healthy = True
            self._last_email_send = datetime.now(timezone.utc).isoformat()
            logger.info(
                f"Hidden-path alert email sent to {recipients}"
                + (f" with attachment {attach_path.name}" if attach_path else "")
            )
            return True

        except Exception as e:
            self._email_healthy = False
            logger.error(f"Failed to send hidden-path alert email: {e}")
            return False

    def process_unusual_externals(self, scan_result: ScanResult) -> int:
        """Scan topology for unusual non-AllStar externals and emit one-shot
        operator alerts. Dedupe state lives in `unusual_externals` table:
        once we alert on a (host_node, external_name) pair, we do not re-alert
        while that pair remains observed. If it disappears and later returns,
        the next appearance re-alerts.

        Added 2026-05-13 as defensive addition #2 to the auto-disconnect
        policy relaxation. Sent to the full recipient list (all operators)
        because an unusual peer name (e.g. 'DVSwitch', 'IAX_Bridge',
        'Analog_Bridge', 'MMDVM_Bridge',
        'analog_bridge') indicates a peer type that COULD bridge our system
        to a foreign network, even though it has not been detected doing so.

        Returns the number of new alerts sent in this scan.
        """
        if not self.email_config.get("enabled", False):
            return 0

        # Collect (host_node, external_name, client_type) for all unusual
        # externals in this scan's topology.
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

        # Clear rows that are no longer observed — next reappearance re-alerts.
        gone = alerted_before - set(observed.keys())
        for host_node, ext_name in gone:
            logger.info(
                f"Unusual external '{ext_name}' on node {host_node} no longer "
                f"observed; clearing dedup state so any future reappearance "
                f"will re-alert."
            )
            self.tracker.clear_unusual_external(host_node, ext_name)

        # New unusual externals — emit one alert per (host_node, ext_name).
        new_alerts = 0
        for pair, ctx in observed.items():
            if pair in alerted_before:
                # Still observed — touch last_seen, no email.
                self.tracker.touch_unusual_external(pair[0], pair[1], now_iso)
                continue
            # Email volume gate: same per-window / per-day caps as other
            # sysadmin emails. We piggyback on the rate_limits config; if the
            # global hourly/daily caps are exhausted, defer the alert (it will
            # re-fire on a later scan, still as a "new" alert because the row
            # has not yet been inserted).
            if not self._unusual_external_volume_ok():
                logger.info(
                    f"Unusual-external alert for '{ctx['external_name']}' on "
                    f"node {ctx['host_node']} deferred: email volume limit."
                )
                continue
            if self._send_unusual_external_alert(ctx):
                self.tracker.mark_unusual_external_alerted(
                    ctx["host_node"], ctx["external_name"],
                    ctx.get("client_type"), now_iso,
                )
                new_alerts += 1
        return new_alerts

    def _unusual_external_volume_ok(self) -> bool:
        """Apply the per-window / per-day caps from rate_limits config to
        unusual-external alerts. Counts both bridging-event emails (rows in
        `notifications`) and prior unusual-external alerts (rows in
        `unusual_externals` whose `first_seen` falls inside the window) so
        the global email budget is honored regardless of channel."""
        window_min = self.rate_limits.get("window_minutes", 15)
        max_per_window = self.rate_limits.get("max_per_window", 2)
        max_daily = self.rate_limits.get("max_per_day", 24)
        cutoff_window = (datetime.utcnow() - timedelta(minutes=window_min)).isoformat()
        cutoff_day = (datetime.utcnow() - timedelta(days=1)).isoformat()
        with sqlite3.connect(self.tracker.db_path) as conn:
            in_window = conn.execute(
                "SELECT COUNT(*) FROM notifications WHERE timestamp > ?",
                (cutoff_window,),
            ).fetchone()[0]
            in_window += conn.execute(
                "SELECT COUNT(*) FROM unusual_externals WHERE first_seen > ?",
                (cutoff_window,),
            ).fetchone()[0]
            in_day = conn.execute(
                "SELECT COUNT(*) FROM notifications WHERE timestamp > ?",
                (cutoff_day,),
            ).fetchone()[0]
            in_day += conn.execute(
                "SELECT COUNT(*) FROM unusual_externals WHERE first_seen > ?",
                (cutoff_day,),
            ).fetchone()[0]
        return in_window < max_per_window and in_day < max_daily

    def _send_unusual_external_alert(self, ctx: dict) -> bool:
        """Send a single all-operator email for one newly observed unusual
        external. Uses the full `recipients` list — this is an operator
        awareness alert, not an anomaly/uncertainty alert."""
        cfg = self.email_config
        recipients = cfg.get("recipients", [])
        if not recipients:
            logger.error("Unusual-external alert skipped: recipients list is empty.")
            return False

        host_node = ctx["host_node"]
        ext_name = ctx["external_name"]
        client_type = ctx.get("client_type", "webtransceiver_type")
        host_info = ctx.get("host_info", {}) or {}
        host_callsign = host_info.get("callsign", "?")
        host_location = host_info.get("location", "?")
        host_role = host_info.get("role", "?")

        prefix = cfg.get("subject_prefix", "[ASL Link Alert]")
        subject = (
            f"{prefix} UNUSUAL external '{ext_name}' observed on node "
            f"{host_node} ({host_callsign})"
        )
        body = f"""AllStarLink Unusual External Connection — Operator Awareness Alert
====================================================================

Detected at: {ctx.get('scan_timestamp', '?')}

UNUSUAL EXTERNAL:
  Peer name:        '{ext_name}'
  Client type:      {client_type}
  Host node:        {host_node}
  Host callsign:    {host_callsign}
  Host location:    {host_location}
  Host role:        {host_role}

WHY THIS IS UNUSUAL:
  The peer name does not match the amateur-radio callsign pattern that
  WebTransceiver, RepeaterPhone, and softphone clients normally use, and
  it does not match the chan_echolink "EchoLink-NNNNNN" format. Peer
  names like 'DVSwitch', 'IAX_Bridge', 'Analog_Bridge', 'MMDVM_Bridge',
  'analog_bridge', or arbitrary session labels are placed in this
  category. The classifier flagged
  '{ext_name}' as not fitting either of the recognized patterns.

WHAT THIS MEANS:
  This connection has NOT been detected as forming a bridge to other
  networks or repeater systems. The detector continues to allow it as
  a permitted leaf attachment to node {host_node}. However, peer types
  that fall outside the recognized callsign / EchoLink-NNNNNN patterns
  CAN have the potential to bridge an AllStar system to other networks
  (for example, DVSwitch is designed to bridge AllStar audio to DMR,
  D-Star, YSF, NXDN, or other digital-voice networks). We do not have
  enough information from the public stats API alone to distinguish a
  benign unusual peer name from a true cross-network bridge.

RECIPIENT NOTE:
  This is an operator-awareness email sent once per (host node, peer
  name) pair when the unusual peer is first observed. No further email
  will be sent while this connection persists. If the connection
  disappears and later reappears, a fresh alert will fire.

NO INTERVENTION:
  No auto-disconnect has been or will be performed for this connection.
  The detector continues to monitor for the actual bridging signature
  (an AllStar-to-AllStar link from a non-bridge node to a node outside
  the monitored system), which has not been observed here.

---
This is an automated alert from the ASL Intersystem Link Detector.
"""

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = cfg.get("from_addr", cfg.get("username", ""))
            msg["To"] = ", ".join(recipients)
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
                if cfg.get("use_tls", True):
                    server.starttls()
                server.login(cfg["username"], cfg["password"])
                server.sendmail(
                    cfg.get("from_addr", cfg["username"]),
                    recipients,
                    msg.as_string(),
                )
            self._email_healthy = True
            self._last_email_send = datetime.utcnow().isoformat()
            logger.warning(
                f"Unusual-external alert sent to {recipients} for "
                f"'{ext_name}' on node {host_node}."
            )
            return True
        except Exception as e:
            self._email_healthy = False
            logger.error(f"Failed to send unusual-external alert: {e}")
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

    def _notify_offender(self, event: BridgingEvent, scan_result: ScanResult,
                         bubble_image_path: Optional[str] = None):
        """Look up the offending operator via QRZ and send a courtesy email."""
        callsign = event.offending_callsign
        if not callsign or callsign == "Unknown":
            logger.info("Cannot notify offender: no callsign available")
            return

        qrz_info = self.qrz.lookup(callsign)
        self._qrz_healthy = qrz_info is not None
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
            attach_path = self._resolve_attachment(bubble_image_path)
            msg = MIMEMultipart("mixed")
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
            if attach_path:
                body += (
                    f"\nThe bubble map captured at the time of detection is "
                    f"attached as {attach_path.name} for your reference.\n"
                )
            msg.attach(MIMEText(body, "plain"))
            if attach_path:
                self._attach_bubble(msg, attach_path)

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
                + (f" with attachment {attach_path.name}" if attach_path else "")
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
        # Collect dragged-in AllStar nodes from the topology
        dragged_in = [
            f"  - Node {nid} ({info.get('callsign', '?')}, {info.get('location', '?')})"
            for nid, info in scan_result.topology.items()
            if info.get("role") == "dragged_in"
        ]
        dragged_list = "\n".join(dragged_in[:20]) if dragged_in else "  (none detected beyond the offending node)"

        # Collect non-AllStar endpoints (EchoLink or WebTransceiver-type IAX2
        # softclients) anywhere in the scanned topology. These are surfaced
        # from asl_api's schema-based classification: chan_echolink endpoints
        # use the hardcoded "3%06u" name format (source-verified in
        # AllStarLink/app_rpt chan_echolink.c); anything else with a name-only
        # linkedNodes entry is treated as a WebTransceiver-type IAX2 softclient
        # (WebTransceiver / AllScan / RepeaterPhone / generic softphone — the
        # public stats API does not let us distinguish further, and the
        # access_webtransceiver / access_telephoneportal capability flags are
        # advertised intent, not operational truth).
        non_allstar_lines = []
        for nid, info in scan_result.topology.items():
            ct = info.get("client_type")
            if ct == "echolink":
                # Display name carries the EchoLink-NNNNNN form
                disp = info.get("callsign", "?")
                parent = info.get("parent", "?")
                # The trailing digits after "EchoLink-" are the EchoLink node ID
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
