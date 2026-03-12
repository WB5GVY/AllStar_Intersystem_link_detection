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
import signal
import sys
import time
from pathlib import Path

import yaml

from asl_api import ASLApiClient
from auto_disconnect import AutoDisconnector
from bubble_analyzer import fetch_and_analyze
from cross_checker import cross_check
from graph_analyzer import GraphAnalyzer
from notifier import Notifier

logger = logging.getLogger("asl_link_detector")

# Graceful shutdown flag
_shutdown = False


def handle_signal(signum, frame):
    global _shutdown
    logger.info(f"Received signal {signum}, shutting down...")
    _shutdown = True


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
                for key in ("username", "password", "from_addr", "recipients"):
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


def run_scan(analyzer: GraphAnalyzer, notifier: Notifier,
             disconnector: AutoDisconnector,
             focus_node: int, dry_run: bool = False,
             enable_image_crosscheck: bool = True) -> bool:
    """Run a single topology scan with optional image cross-check.

    Returns True if problems were detected.
    """
    logger.info("=" * 60)
    logger.info("Starting topology scan...")

    # === Phase 1: API-based analysis ===
    result = analyzer.scan()

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

    # Send notifications (unless dry run)
    if dry_run:
        logger.info("Dry run — notifications suppressed.")
    else:
        sent = notifier.notify(result)
        logger.info(f"Sent {sent} notification(s)")

        # Hidden-path alert: image detects bridging but API has no events
        if (crosscheck_result and crosscheck_result.possible_hidden_path_bridging
                and not result.has_problems):
            notifier.send_hidden_path_alert(
                scan_timestamp=result.timestamp,
                image_max_distance=crosscheck_result.image_max_distance,
                api_max_depth=crosscheck_result.api_max_depth,
                warnings=crosscheck_result.warnings,
            )

    # === Phase 3: Auto-disconnect (after notification, not in dry-run) ===
    if result.has_problems and not dry_run:
        for event in result.bridging_events:
            disc_result = disconnector.attempt_disconnect(event)
            if disc_result is not None:
                logger.info(
                    f"Auto-disconnect result for node {disc_result.target_node}: "
                    f"{disc_result.action} — {disc_result.message}"
                )

    return True


def main():
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

    focus_node = config["focus_node"]
    bridge_nodes = config.get("bridge_nodes", [])
    logger.info("AllStar Intersystem Link Detector starting")
    logger.info(f"Focus node: {focus_node}")
    logger.info(f"Bridge nodes: {bridge_nodes}")
    logger.info(f"Poll interval: {config.get('poll_interval_seconds', 300)}s")

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Handle --test-email early (only needs config + notifier)
    notifier = Notifier(config)
    if args.test_email:
        success = notifier.send_test_email()
        sys.exit(0 if success else 1)

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

    enable_image = not args.no_image
    if enable_image:
        logger.info("Bubble map image cross-check: ENABLED")
    else:
        logger.info("Bubble map image cross-check: DISABLED")

    try:
        if args.once or args.dry_run:
            run_scan(analyzer, notifier, disconnector, focus_node,
                     dry_run=args.dry_run, enable_image_crosscheck=enable_image)
        else:
            # Continuous monitoring loop
            interval = config.get("poll_interval_seconds", 300)
            logger.info(f"Entering continuous monitoring (every {interval}s). Ctrl+C to stop.")

            while not _shutdown:
                run_scan(analyzer, notifier, disconnector, focus_node,
                         enable_image_crosscheck=enable_image)
                # Sleep in small increments to respond to shutdown signal promptly
                for _ in range(interval):
                    if _shutdown:
                        break
                    time.sleep(1)

            logger.info("Shutdown complete.")
    finally:
        api_client.close()


if __name__ == "__main__":
    main()
