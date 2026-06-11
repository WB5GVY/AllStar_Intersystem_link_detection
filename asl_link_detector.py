#!/usr/bin/env python3
"""AllStar Intersystem Link Detector — Main entry point.

Periodically polls the AllStarLink Stats API, builds a connection graph
from configured hub nodes, detects unauthorized bridging (nodes beyond
max_hop_distance from any hub), and sends notifications.

Usage:
    python3 asl_link_detector.py                 # Run continuous monitoring
    python3 asl_link_detector.py --once           # Run a single scan and exit
    python3 asl_link_detector.py --dry-run        # Single scan, no notifications
    python3 asl_link_detector.py --config alt.yaml  # Use alternate config file
"""

import argparse
import logging
import logging.handlers
import os
import shutil
import signal
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import yaml

from asl_api import ASLApiClient
from auto_disconnect import AutoDisconnector
from bubble_analyzer import fetch_and_analyze, fetch_bubble_map
from cross_checker import cross_check, analyze_structured_paths
from graph_analyzer import GraphAnalyzer
from notifier import Notifier, RecipientResolutionError
from status_server import StatusCollector, start_status_server

logger = logging.getLogger("asl_link_detector")

# Graceful shutdown flag
_shutdown = False
# Config reload flag (set by SIGHUP handler)
_reload_config = False


def handle_signal(signum, frame):
    global _shutdown
    logger.info(f"Received signal {signum}, shutting down...")
    _shutdown = True


def handle_sighup(signum, frame):
    global _reload_config
    logger.info("Received SIGHUP, will reload config on next cycle...")
    _reload_config = True


def setup_logging(config: dict):
    """Configure logging from config settings."""
    log_config = config.get("logging", {})
    level_str = log_config.get("level", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    console.setFormatter(fmt)
    root_logger.addHandler(console)

    # File handler (rotating)
    log_file = log_config.get("file", "asl_link_detector.log")
    max_bytes = log_config.get("max_bytes", 5 * 1024 * 1024)
    backup_count = log_config.get("backup_count", 3)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(fmt)
    root_logger.addHandler(file_handler)


def load_config(config_path: str) -> dict:
    """Load YAML configuration file, merging secrets from external file."""
    path = Path(config_path)
    if not path.exists():
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)
    with open(path) as f:
        config = yaml.safe_load(f)

    # Load and merge secrets from external file (credentials kept outside Dropbox)
    secrets_path = config.get("secrets_file", "")
    if secrets_path:
        secrets_path = Path(secrets_path).expanduser()
        if secrets_path.exists():
            # Verify file permissions — warn if group/other readable
            mode = secrets_path.stat().st_mode
            if mode & 0o077:
                logger.warning(
                    f"Secrets file {secrets_path} is readable by group/other "
                    f"(mode {oct(mode)}). Recommend: chmod 600 {secrets_path}"
                )
            with open(secrets_path) as f:
                secrets = yaml.safe_load(f) or {}

            # Merge email secrets into notifications.email
            if "email" in secrets:
                email_cfg = config.setdefault("notifications", {}).setdefault("email", {})
                for key in ("username", "password", "from_addr",
                            "recipients", "hidden_path_recipients",
                            "internal_recipients"):
                    if key in secrets["email"] and secrets["email"][key]:
                        email_cfg[key] = secrets["email"][key]

            # Merge QRZ secrets
            if "qrz" in secrets:
                qrz_cfg = config.setdefault("qrz", {})
                for key in ("username", "password"):
                    if key in secrets["qrz"] and secrets["qrz"][key]:
                        qrz_cfg[key] = secrets["qrz"][key]

            logger.info(f"Secrets loaded from {secrets_path}")
        else:
            logger.warning(f"Secrets file not found: {secrets_path}")

    return config


HIDDEN_BUBBLE_DIR = Path(__file__).parent / "bubble_maps_hidden"
EVENT_BUBBLE_DIR = Path(__file__).parent / "bubble_maps_events"
# Per-directory cap; oldest beyond this are pruned. A single detection now
# writes up to `max_shots` event images (immediate + burst), so this is sized
# to retain on the order of dozens of distinct detections, not just one image
# each. Raised from 100 when evidence-burst capture landed (2026-06-11).
BUBBLE_KEEP = 300
# _preserve_bubble can now run concurrently (synchronous shot 0 on the scan
# thread vs. burst shots on the evidence-burst thread). Serialize its
# copy+prune critical section so the glob/sort/unlink can't race a copy.
_PRESERVE_LOCK = threading.Lock()

RESTART_LOG = Path(__file__).parent / "last_restart_times.txt"
PANIC_FILE = Path(__file__).parent / "PANIC_STOPPED"


def check_restart_loop(max_restarts: int, window_minutes: int) -> None:
    """S5 daemon-side restart-storm guard.

    Append the current restart timestamp to RESTART_LOG and check whether
    the last `max_restarts` entries all fall within the trailing
    `window_minutes` window. If so, write a PANIC_STOPPED file and exit
    non-zero. launchd's KeepAlive: SuccessfulExit=false will keep
    re-launching, but the panic file causes immediate exit until a human
    clears it. This is the only mechanism that stops a tight crash loop
    from amortizing across launchd's 5-minute ThrottleInterval.
    """
    now = datetime.utcnow()
    if PANIC_FILE.exists():
        # A human must clear the panic file to resume. Exit fast so we
        # don't hog CPU under launchd's KeepAlive.
        sys.stderr.write(
            f"PANIC_STOPPED present at {PANIC_FILE} — refusing to start. "
            f"Investigate, then 'rm {PANIC_FILE}' to resume.\n"
        )
        sys.exit(2)
    try:
        history = []
        if RESTART_LOG.exists():
            for line in RESTART_LOG.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    history.append(datetime.fromisoformat(line))
                except ValueError:
                    continue
        history.append(now)
        # Trim to last 50 entries.
        history = history[-50:]
        RESTART_LOG.write_text("\n".join(t.isoformat() for t in history) + "\n")

        cutoff = now - timedelta(minutes=window_minutes)
        recent = [t for t in history if t >= cutoff]
        if len(recent) >= max_restarts:
            PANIC_FILE.write_text(
                f"Panic-stopped at {now.isoformat()}Z\n"
                f"{len(recent)} restarts in last {window_minutes} minutes "
                f"(threshold {max_restarts}).\n"
                f"\nRecovery: remove this file to resume. The restart-time\n"
                f"history at {RESTART_LOG} has been truncated so the next\n"
                f"start does not immediately re-trip the panic guard.\n"
            )
            # S-1 fix (2026-05-15 self-review): truncate the restart log
            # when writing the panic file so manual recovery (deleting
            # PANIC_STOPPED) does not immediately re-trip the guard with
            # the same accumulated history.
            try:
                RESTART_LOG.write_text("")
            except Exception:
                pass
            sys.stderr.write(
                f"PANIC: {len(recent)} restarts in last {window_minutes} "
                f"minutes; wrote {PANIC_FILE}. Exiting.\n"
            )
            sys.exit(2)
    except SystemExit:
        raise
    except Exception as e:
        # If the guard itself fails, log to stderr but let the daemon start
        # (do not chain-fail the guard).
        sys.stderr.write(f"Restart-loop guard error: {e}\n")


def _preserve_bubble(src_path: str, scan_timestamp: str,
                     dest_dir: Path, suffix: str,
                     tag: str = "") -> Optional[Path]:
    """Copy a temp bubble map to a stable location, returning the new path.

    Bubble maps are normally written to $TMPDIR with random tempfile names
    and get purged by macOS — useless for retrospective inspection. This
    helper preserves the scan-time image so it can be inspected later and
    attached to outgoing alert emails.

    Filename: <YYYY-MM-DD_HH-MM-SS><suffix><tag>.jpg, sortable by time.
    `tag` distinguishes multiple shots that share one scan timestamp (the
    immediate + burst evidence shots of a single detection); the canonical
    attach-to-email shot uses tag="" so its filename matches the historical
    "<stamp>_event.jpg" form. Directory is auto-pruned to BUBBLE_KEEP files.
    """
    if not src_path:
        return None
    src = Path(src_path)
    if not src.is_file():
        logger.warning(f"Bubble image not found at {src}, cannot preserve")
        return None
    try:
        with _PRESERVE_LOCK:
            dest_dir.mkdir(parents=True, exist_ok=True)
            # ScanResult.timestamp is "%Y-%m-%dT%H:%M:%SZ" (UTC). Reformat to a
            # filesystem-friendly, sortable name. Fall back to a wall-clock
            # stamp if the format ever changes.
            try:
                dt = datetime.strptime(scan_timestamp, "%Y-%m-%dT%H:%M:%SZ")
                stamp = dt.strftime("%Y-%m-%d_%H-%M-%S")
            except ValueError:
                stamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
            dst = dest_dir / f"{stamp}{suffix}{tag}.jpg"
            shutil.copy2(src, dst)
            logger.info(f"Preserved bubble map to {dst}")

            existing = sorted(dest_dir.glob(f"*{suffix}*.jpg"))
            excess = len(existing) - BUBBLE_KEEP
            if excess > 0:
                for old in existing[:excess]:
                    try:
                        old.unlink()
                    except OSError as e:
                        logger.warning(f"Could not prune {old}: {e}")
            return dst
    except Exception as e:
        logger.error(f"Failed to preserve bubble map: {e}")
        return None


def preserve_hidden_bubble(src_path: str, scan_timestamp: str) -> Optional[Path]:
    """Preserve a bubble map that triggered a hidden-path alert."""
    return _preserve_bubble(src_path, scan_timestamp, HIDDEN_BUBBLE_DIR, "_hidden")


def preserve_event_bubble(src_path: str, scan_timestamp: str) -> Optional[Path]:
    """Preserve a bubble map that accompanies a regular bridging-event alert."""
    return _preserve_bubble(src_path, scan_timestamp, EVENT_BUBBLE_DIR, "_event")


class EvidenceCapturer:
    """Captures bubble-map evidence the instant a violation is detected.

    Background
    ----------
    The old pipeline fetched a single bubble map at the END of the topology
    walk. On a busy network the walk can run minutes past the moment of
    detection (depth 4-8 "drag-in"), and a transient offending link can
    self-resolve in that window — yielding a courtesy-notice image that shows
    no violation (the 2026-06-10 incident that motivated this).

    Triggered by GraphAnalyzer.on_first_detection, which fires SYNCHRONOUSLY on
    the scan thread the moment the first violation is recorded. Shot 0 (the
    image attached to the courtesy notice) is therefore captured synchronously
    too: it belongs unambiguously to the scan currently running, and is on disk
    before run_scan reads it — no cross-thread handoff, no wait, no chance of a
    later scan's email attaching an earlier scan's image (the failure mode the
    first async draft had during 15-second top-of-hour polling). Only the
    follow-up *burst* shots — purely retrospective decay evidence — run on a
    background daemon thread, guarded so overlapping detections don't stack
    concurrent bursts.

    Cadence is config-driven (config.yaml -> evidence_capture):
        enabled, immediate, burst_interval_s, burst_duration_s, max_shots,
        shot_timeout_s
    """

    def __init__(self, focus_node: int, config: dict):
        ec = (config or {}).get("evidence_capture", {}) or {}
        self.focus_node = focus_node
        self.enabled = bool(ec.get("enabled", True))
        self.immediate = bool(ec.get("immediate", True))
        self.burst_interval_s = float(ec.get("burst_interval_s", 45))
        self.burst_duration_s = float(ec.get("burst_duration_s", 210))
        self.max_shots = int(ec.get("max_shots", 5))
        # Per-shot HTTP fetch timeout. Bounds how long the synchronous shot 0
        # can stall the scan walk; keep well under poll_interval.
        self.shot_timeout_s = int(ec.get("shot_timeout_s", 15))
        self._lock = threading.Lock()
        self._active = False
        # Path of the immediate shot for the CURRENT scan only. Written and read
        # on the scan thread (trigger() then run_scan), so no locking needed.
        self._current_shot0: Optional[Path] = None

    def begin_scan(self) -> None:
        """Clear last scan's immediate-shot path before a new scan starts."""
        self._current_shot0 = None

    def trigger(self, scan_timestamp: str) -> None:
        """Capture shot 0 synchronously, then kick off the async burst.

        Called from the first-detection callback, mid-scan, on the scan thread.
        Shot 0 is captured inline so it is guaranteed to be this scan's image;
        the burst (follow-up shots) is launched on a daemon thread and is a
        no-op if a prior burst is still running.
        """
        if not self.enabled:
            self._current_shot0 = None
            return
        # Shot 0 — synchronous; the image attached to the courtesy notice.
        if self.immediate:
            self._current_shot0 = self._one_shot(scan_timestamp, tag="")
        else:
            self._current_shot0 = None
        # Follow-up burst — background, idempotent while one is in flight.
        if self.max_shots > 1:
            with self._lock:
                if self._active:
                    return
                self._active = True
            threading.Thread(
                target=self._run_burst, args=(scan_timestamp,),
                name="evidence-burst", daemon=True,
            ).start()

    def _run_burst(self, scan_timestamp: str) -> None:
        try:
            start = time.monotonic()
            shots = 1  # shot 0 was already captured synchronously by trigger()
            while shots < self.max_shots:
                if time.monotonic() - start >= self.burst_duration_s:
                    break
                time.sleep(self.burst_interval_s)
                self._one_shot(scan_timestamp, tag=f"_t{shots}")
                shots += 1
        except Exception as e:
            logger.error(f"Evidence-capture burst failed: {e}")
        finally:
            with self._lock:
                self._active = False

    def _one_shot(self, scan_timestamp: str, tag: str) -> Optional[Path]:
        tmp = fetch_bubble_map(self.focus_node, timeout=self.shot_timeout_s)
        if not tmp:
            return None
        try:
            return _preserve_bubble(
                tmp, scan_timestamp, EVENT_BUBBLE_DIR, "_event", tag=tag)
        finally:
            try:
                Path(tmp).unlink()
            except OSError:
                pass

    def last_shot0(self) -> Optional[Path]:
        """The immediate shot for the scan that just ran (None if disabled or
        capture failed — caller then falls back to the end-of-scan image)."""
        return self._current_shot0


def run_scan(analyzer: GraphAnalyzer, notifier: Notifier,
             disconnector: AutoDisconnector,
             focus_node: int, api_client=None,
             collector: StatusCollector = None,
             dry_run: bool = False,
             enable_image_crosscheck: bool = True,
             capturer: "EvidenceCapturer" = None) -> bool:
    """Run a single topology scan with optional image cross-check.

    Returns True if problems were detected.
    """
    logger.info("=" * 60)
    logger.info("Starting topology scan...")

    # === Phase 1: API-based analysis ===
    # Clear last scan's immediate-shot path; the analyzer's first-detection
    # callback (if it fires this scan) repopulates it synchronously.
    if capturer is not None:
        capturer.begin_scan()
    result = analyzer.scan()

    if collector:
        collector.update_scan(result)
        if api_client:
            collector.update_api_health(api_client)

    total_nodes = len(result.topology)
    logger.info(f"API scan complete: {total_nodes} nodes in topology")

    if result.errors:
        for err in result.errors:
            logger.error(f"Scan error: {err}")

    # === Phase 2: Bubble map image cross-check ===
    crosscheck_result = None
    if enable_image_crosscheck:
        logger.info("Fetching bubble map for cross-check...")
        image_result = fetch_and_analyze(focus_node)
        if image_result is not None:
            crosscheck_result = cross_check(result, image_result)
            logger.info(crosscheck_result.summary())

            if crosscheck_result.possible_hidden_path_bridging:
                logger.warning(
                    "HIDDEN PATH ALERT: Image analysis suggests bridging "
                    "through non-reporting node(s) that the API cannot see!"
                )
        else:
            logger.warning("Could not fetch/analyze bubble map — cross-check skipped.")

    # === Phase 2b: Structured hidden-path analysis (Item B, SHADOW MODE) ===
    # Exact BFS over the reported edge union the scan already collected — the
    # eventual replacement for the CV cross-check. Logged for soak-period
    # comparison against the CV verdict; NOT yet an alerting source. Once the
    # logs show it reliably agrees on true paths and rejects the CV's phantom
    # hidden-path false positives, the CV heuristic can be retired.
    try:
        structured = analyze_structured_paths(result)
        logger.info(structured.summary())
        if crosscheck_result is not None:
            cv_hidden = crosscheck_result.possible_hidden_path_bridging
            if cv_hidden != structured.hidden_path:
                logger.warning(
                    "SHADOW DIVERGENCE: CV hidden_path=%s but structured "
                    "hidden_path=%s (structured distance>=3 nodes: %s). If "
                    "structured is correct, the CV verdict is a false %s.",
                    cv_hidden, structured.hidden_path,
                    structured.deep_nodes or "none",
                    "positive" if cv_hidden else "negative",
                )
            else:
                logger.info(
                    "SHADOW AGREE: CV and structured both hidden_path=%s",
                    structured.hidden_path,
                )
    except Exception as e:
        logger.error("Structured-path shadow analysis failed: %s", e)

    # === Evaluate combined results ===
    has_problems = result.has_problems
    if crosscheck_result and crosscheck_result.possible_hidden_path_bridging:
        has_problems = True

    if not has_problems:
        logger.info("No unauthorized bridging detected. All clear.")
        return False

    # Log all API-detected problems
    if result.has_problems:
        logger.warning(f"DETECTED {len(result.bridging_events)} bridging event(s)!")
        for event in result.bridging_events:
            logger.warning(str(event))

    # Preserve the scan-time bubble map (if available) regardless of dry_run.
    # In monitor-only / dry-run, we still want the JPG persisted into
    # bubble_maps_events/ or bubble_maps_hidden/ for retroactive analysis —
    # losing the image would defeat the purpose of a soak period for tuning.
    # Only the actual email/SSH side effects are gated by dry_run below.
    event_bubble = None
    if result.has_problems:
        # Item A: prefer the immediate-on-detection shot, captured the instant
        # the violation was seen (closes the detection→fetch gap that let a
        # transient link vanish before the old end-of-scan fetch). The capturer
        # already saved it synchronously as "<stamp>_event.jpg" during the scan.
        if capturer is not None:
            event_bubble = capturer.last_shot0()
        # Fallback: immediate capture disabled or failed — preserve the
        # end-of-scan cross-check image as before (better than no attachment).
        if (event_bubble is None and crosscheck_result
                and crosscheck_result.image_result):
            event_bubble = preserve_event_bubble(
                crosscheck_result.image_result.image_path,
                result.timestamp,
            )
    hidden_bubble = None
    if (crosscheck_result and crosscheck_result.possible_hidden_path_bridging
            and not result.has_problems and crosscheck_result.image_result):
        hidden_bubble = preserve_hidden_bubble(
            crosscheck_result.image_result.image_path,
            result.timestamp,
        )

    # Send notifications (unless dry run)
    if dry_run:
        logger.info("Dry run — notifications and unusual-external alerts suppressed.")
    else:
        sent = notifier.notify(
            result,
            bubble_image_path=str(event_bubble) if event_bubble else None,
        )
        logger.info(f"Sent {sent} notification(s)")

        # Hidden-path alert: image detects bridging but API has no events
        if (crosscheck_result and crosscheck_result.possible_hidden_path_bridging
                and not result.has_problems):
            notifier.send_hidden_path_alert(
                scan_timestamp=result.timestamp,
                image_max_distance=crosscheck_result.image_max_distance,
                api_max_depth=crosscheck_result.api_max_depth,
                warnings=crosscheck_result.warnings,
                image_path=str(hidden_bubble) if hidden_bubble else None,
            )

        # Unusual-external operator-awareness alert: a non-AllStar leaf whose
        # peer name matches neither a callsign nor EchoLink-NNNNNN. Sent to
        # all operators once per (host_node, peer_name) pair for the duration
        # the peer is observed. Counts against the global email budget.
        # Added 2026-05-13.
        new_unusual = notifier.process_unusual_externals(result)
        if new_unusual:
            logger.info(f"Sent {new_unusual} unusual-external alert(s)")

    if collector:
        collector.update_email_health(notifier)
        collector.update_qrz_health(notifier)
        collector.update_notification_state(notifier)
        # Refresh unusual-externals summary from the dedup table for HA
        # (always — table state is meaningful even in monitor-only).
        collector.update_unusual_externals()

    # === Phase 3: Auto-disconnect (after notification, not in dry-run) ===
    if result.has_problems and not dry_run:
        for event in result.bridging_events:
            disc_result = disconnector.attempt_disconnect(event)
            if disc_result is not None:
                logger.info(
                    f"Auto-disconnect result for node {disc_result.target_node}: "
                    f"{disc_result.action} — {disc_result.message}"
                )
                if collector:
                    collector.update_disconnect(disc_result)

    return True


def main():
    global _reload_config

    parser = argparse.ArgumentParser(
        description="AllStar Intersystem Link Detector"
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to YAML config file (default: config.yaml)"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run a single scan and exit"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run a single scan without sending notifications"
    )
    parser.add_argument(
        "--no-image", action="store_true",
        help="Skip bubble map image cross-check"
    )
    parser.add_argument(
        "--test-email", action="store_true",
        help="Send a test email to verify SMTP configuration, then exit"
    )
    args = parser.parse_args()

    # Load config
    config = load_config(args.config)
    setup_logging(config)

    # S5 daemon-side restart-storm guard. If launchd is hot-restarting us
    # because something keeps crashing, write a panic file and refuse to
    # start until a human clears it. Skip for one-shot invocations.
    if not (args.once or args.dry_run or args.test_email):
        restart_cfg = config.get("restart_loop", {})
        check_restart_loop(
            max_restarts=int(restart_cfg.get("max_restarts", 5)),
            window_minutes=int(restart_cfg.get("window_minutes", 30)),
        )

    focus_node = config["focus_node"]
    bridge_nodes = config.get("bridge_nodes", [])
    monitor_only = config.get("monitor_only", False)
    logger.info("AllStar Intersystem Link Detector starting")
    logger.info(f"Focus node: {focus_node}")
    logger.info(f"Bridge nodes: {bridge_nodes}")
    logger.info(f"Poll interval: {config.get('poll_interval_seconds', 300)}s")
    if monitor_only:
        logger.warning("=" * 60)
        logger.warning("MONITOR-ONLY MODE: emails and auto-disconnect SUPPRESSED")
        logger.warning("Scans run normally and log everything; no side effects.")
        logger.warning("Set monitor_only: false in config.yaml + SIGHUP to go live.")
        logger.warning("=" * 60)

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGHUP, handle_sighup)

    # Construct notifier. Fails-closed if internal_recipients is missing.
    try:
        notifier = Notifier(config)
    except RecipientResolutionError as e:
        logger.error(
            "Refusing to start — recipient resolution failed:\n%s\n"
            "Add an 'internal_recipients: [<bennett@email>]' line under "
            "notifications.email in secrets.yaml and try again.", e
        )
        sys.exit(2)

    # --test-email is gated by env var (S1). It also goes to Bennett only.
    if args.test_email:
        if os.environ.get("ASL_ALLOW_TEST_EMAIL") != "1":
            logger.error(
                "Refusing to send test email: set ASL_ALLOW_TEST_EMAIL=1 "
                "in the environment to authorize. This is gated to prevent "
                "accidental sends from cron / launchd / typo'd argv."
            )
            sys.exit(2)
        # Test email is a real send, not a dry-run scenario.
        notifier.set_dry_run(False)
        success = notifier.send_test_email()
        sys.exit(0 if success else 1)

    # Apply the initial dry-run state to the notifier so the chokepoint's
    # defense-in-depth gate knows we are in monitor-only (if applicable).
    notifier.set_dry_run(monitor_only)

    # Initialize remaining components
    api_client = ASLApiClient()
    analyzer = GraphAnalyzer(
        api_client=api_client,
        focus_node=focus_node,
        bridge_nodes=bridge_nodes,
        allowlist=config.get("allowlist", []),
        stale_threshold_minutes=config.get("stale_threshold_minutes", 120),
    )
    disconnector = AutoDisconnector(config, api_client)

    # Immediate-on-detection evidence capturer (Item A). Wired to the analyzer's
    # first-detection callback so a bubble map is grabbed the instant a
    # violation is seen, not minutes later at end-of-scan.
    capturer = EvidenceCapturer(focus_node, config)
    analyzer.on_first_detection = lambda res, c=capturer: c.trigger(res.timestamp)

    # Status server for Home Assistant integration
    collector = StatusCollector(db_path=str(Path(config.get("db_path", "notifications.db"))))
    collector.attach_disconnector(disconnector)
    collector.record_startup()
    collector.update_managed_nodes(disconnector)
    collector.update_monitor_only(monitor_only)
    status_cfg = config.get("status_server", {})
    health_check_interval = status_cfg.get("health_check_interval_seconds", 300)
    if status_cfg.get("enabled", True):
        start_status_server(
            collector,
            port=status_cfg.get("port", 61211),
        )

    enable_image = not args.no_image
    if enable_image:
        logger.info("Bubble map image cross-check: ENABLED")
    else:
        logger.info("Bubble map image cross-check: DISABLED")

    try:
        if args.once or args.dry_run:
            notifier.set_dry_run(args.dry_run or monitor_only)
            try:
                run_scan(analyzer, notifier, disconnector, focus_node,
                         api_client=api_client, collector=collector,
                         dry_run=args.dry_run, enable_image_crosscheck=enable_image,
                         capturer=capturer)
            except Exception as e:
                logger.exception("run_scan crashed: %s", e)
                notifier.report_error("Scan crashed (single-shot)", str(e), exc=e)
            # Run health checks once for single-scan modes
            try:
                ssh_results = disconnector.check_ssh_health()
                collector.update_ssh_health(ssh_results)
                flag_results = disconnector.check_flag_files()
                collector.update_flag_files(flag_results)
            except Exception as e:
                logger.error(f"Health check error: {e}")
        else:
            # Continuous monitoring loop
            interval = config.get("poll_interval_seconds", 300)
            # Aggressive polling near top of hour (nets typically start at :00)
            top_of_hour = config.get("top_of_hour_polling", {})
            toh_enabled = top_of_hour.get("enabled", True)
            toh_interval = top_of_hour.get("interval_seconds", 15)
            toh_before_minutes = top_of_hour.get("before_minutes", 5)
            toh_after_minutes = top_of_hour.get("after_minutes", 10)

            if toh_enabled:
                logger.info(
                    f"Entering continuous monitoring (normal: {interval}s, "
                    f"top-of-hour: {toh_interval}s from :{60-toh_before_minutes:02d} "
                    f"to :{toh_after_minutes:02d}). Ctrl+C to stop."
                )
            else:
                logger.info(f"Entering continuous monitoring (every {interval}s). Ctrl+C to stop.")

            last_health_check = 0  # Force immediate check on first cycle

            while not _shutdown:
                if _reload_config:
                    _reload_config = False
                    logger.info("Reloading config.yaml...")
                    # C8 fix: build a fully-loaded new namespace first;
                    # only swap bindings if every step succeeded. Any
                    # exception leaves the previous config running.
                    try:
                        new_config = load_config(args.config)
                        new_focus_node = new_config["focus_node"]
                        new_disconnector = AutoDisconnector(new_config, api_client)
                        new_analyzer = GraphAnalyzer(
                            api_client=api_client,
                            focus_node=new_focus_node,
                            bridge_nodes=new_config.get("bridge_nodes", []),
                            allowlist=new_config.get("allowlist", []),
                            stale_threshold_minutes=new_config.get(
                                "stale_threshold_minutes", 120),
                        )
                        new_notifier = Notifier(new_config)
                        new_monitor_only = new_config.get("monitor_only", False)
                        new_health_interval = new_config.get(
                            "status_server", {}
                        ).get("health_check_interval_seconds", 300)
                    except Exception as e:
                        collector.update_config_reload(success=False)
                        logger.error("Config reload failed: %s. "
                                     "Keeping previous config.", e)
                        try:
                            notifier.report_error(
                                "Config reload failed", str(e), exc=e
                            )
                        except Exception as report_err:
                            logger.error("report_error failed: %s", report_err)
                    else:
                        # Atomic rebind — all-or-nothing.
                        config = new_config
                        disconnector = new_disconnector
                        analyzer = new_analyzer
                        focus_node = new_focus_node
                        notifier = new_notifier
                        health_check_interval = new_health_interval
                        # Rebuild the capturer against the (possibly changed)
                        # focus_node and evidence_capture settings, and re-wire
                        # it to the freshly-constructed analyzer.
                        capturer = EvidenceCapturer(new_focus_node, new_config)
                        analyzer.on_first_detection = (
                            lambda res, c=capturer: c.trigger(res.timestamp))
                        if new_monitor_only != monitor_only:
                            if new_monitor_only:
                                logger.warning(
                                    "MONITOR-ONLY MODE now ACTIVE — "
                                    "emails and auto-disconnect SUPPRESSED"
                                )
                            else:
                                logger.warning(
                                    "MONITOR-ONLY MODE now DISABLED — "
                                    "live operation resumed"
                                )
                            monitor_only = new_monitor_only
                        notifier.set_dry_run(monitor_only)
                        collector.update_monitor_only(monitor_only)
                        collector.update_config_reload(success=True)
                        collector.update_managed_nodes(disconnector)
                        logger.info("Config reloaded successfully.")

                notifier.set_dry_run(monitor_only)
                try:
                    run_scan(analyzer, notifier, disconnector, focus_node,
                             api_client=api_client, collector=collector,
                             dry_run=monitor_only,
                             enable_image_crosscheck=enable_image,
                             capturer=capturer)
                except Exception as e:
                    logger.exception("run_scan crashed: %s", e)
                    try:
                        notifier.report_error("Scan crashed", str(e), exc=e)
                    except Exception as report_err:
                        logger.error("report_error failed: %s", report_err)

                # Periodic SSH health and flag file checks
                now_ts = time.time()
                if now_ts - last_health_check >= health_check_interval:
                    last_health_check = now_ts
                    try:
                        logger.debug("Running SSH health checks...")
                        ssh_results = disconnector.check_ssh_health()
                        collector.update_ssh_health(ssh_results)
                        flag_results = disconnector.check_flag_files()
                        collector.update_flag_files(flag_results)
                        logger.info(
                            f"Health checks complete: SSH {ssh_results}, "
                            f"flag files {flag_results}"
                        )
                    except Exception as e:
                        logger.error(f"Health check error: {e}")

                # Determine sleep interval based on proximity to top of hour
                now = datetime.now()
                minutes_in_hour = now.minute
                if (toh_enabled and
                        (minutes_in_hour >= 60 - toh_before_minutes or
                         minutes_in_hour < toh_after_minutes)):
                    sleep_secs = toh_interval
                else:
                    sleep_secs = interval

                # Sleep in small increments to respond to shutdown signal promptly
                for _ in range(sleep_secs):
                    if _shutdown:
                        break
                    time.sleep(1)

            logger.info("Shutdown complete.")
    finally:
        api_client.close()


if __name__ == "__main__":
    main()
