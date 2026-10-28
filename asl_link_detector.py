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
import queue
import shutil
import signal
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yaml

from ami_listener import build_ami_listener, build_ami_listeners
from asl_api import ASLApiClient
from auto_disconnect import AutoDisconnector
from bubble_map_gen import build_bubble_map_generator
from bubble_analyzer import analyze_bubble_map, fetch_and_analyze, fetch_bubble_map
from analytics_db import init_db, Recorder, build_present_from_topology
from cross_checker import cross_check, analyze_structured_paths
from graph_analyzer import GraphAnalyzer, event_has_monitor_link
from link_watch import build_link_watcher
from notifier import Notifier, RecipientResolutionError
from rpt_reader import build_rpt_reader
from status_server import StatusCollector, start_status_server
from vantage_trust import VantageTrustMonitor
from listener_notice import ListenerNotice, DEFAULT_INTERVAL_HOURS
from keyed_veto import KeyedVetoTracker
from dark_guest import DarkGuestTracker

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


def _listener_cfg(config: dict) -> dict:
    """Phase 2 `listeners:` block, read defensively (a bare `listeners:` key
    in YAML is None). Returns {"permit": bool, "notice_interval_hours": float}."""
    block = (config or {}).get("listeners") or {}
    permit = block.get("permit", False) is True
    try:
        hours = float(block.get("notice_interval_hours", DEFAULT_INTERVAL_HOURS))
    except (TypeError, ValueError):
        hours = DEFAULT_INTERVAL_HOURS
    # Step 2 trigger B: how long a keyed-listener veto stays in force. Long
    # enough to outlive the confirming scan and the stats post that follows;
    # short enough that a one-off false K does not brand a node all day.
    try:
        ttl = max(60, int(block.get("keyed_veto_ttl_seconds", 900)))
    except (TypeError, ValueError):
        ttl = 900
    # Audit C1: an enforcement-relevant trigger needs its own switch and a
    # confirmation count (K observations in separate AMI frames within the
    # TTL) before the veto is written. 1 = act on the first keyup.
    kv_enabled = block.get("keyed_veto_enabled", True) is not False
    try:
        confirm = max(1, int(block.get("keyed_veto_confirm_keyups", 2)))
    except (TypeError, ValueError):
        confirm = 2
    return {"permit": permit, "notice_interval_hours": hours,
            "keyed_veto_ttl_seconds": ttl, "keyed_veto_enabled": kv_enabled,
            "keyed_veto_confirm_keyups": confirm}


def _dark_cfg(config: dict) -> dict:
    """Step 2b `dark_guests:` block, read defensively."""
    block = (config or {}).get("dark_guests") or {}
    if not isinstance(block, dict):
        block = {}
    def _int(k, d, lo):
        try:
            return max(lo, int(block.get(k, d)))
        except (TypeError, ValueError):
            return d
    def _f(k, d, lo):
        try:
            return max(lo, float(block.get(k, d)))
        except (TypeError, ValueError):
            return d
    # Evidence threshold defaults to the link-state watchdog's (audit C4:
    # parity — a dark guest is cut on the same excess the watchdog acts on).
    lw = (config or {}).get("link_watch") or {}
    wd = (lw.get("watchdog") or {}) if isinstance(lw, dict) else {}
    if not isinstance(wd, dict):
        wd = {}
    try:
        wd_threshold = max(5, int(wd.get("foreign_threshold", 25)))
    except (TypeError, ValueError):
        wd_threshold = 25
    # Audit 2 S-E: the cut is licensed by the watchdog's foreign-entry
    # metric, so it is armed only where that metric is itself enabled.
    wd_enabled = bool(isinstance(lw, dict) and lw.get("enabled", False)
                      and wd.get("enabled", False))
    cut = block.get("cut_on_keyed", False) is True             # audit 3 A4: opt-in
    if cut and not wd_enabled and block.get("enabled", False) is True:
        logger.warning("dark_guests.cut_on_keyed ignored: link_watch.watchdog is "
                       "not enabled (the cut needs its foreign-entry metric)")
        cut = False
    return {"enabled": block.get("enabled", False) is True,      # audit C2: OFF
            "confirm_scans": _int("confirm_scans", 2, 1),
            "notice_interval_hours": _f("notice_interval_hours", 24.0, 1.0),
            "cut_on_keyed": cut,
            "keyed_cut_cooldown_seconds": _int("keyed_cut_cooldown_seconds", 120, 30),
            "keyed_cut_confirm_keyups": _int("keyed_cut_confirm_keyups", 2, 1),
            "keyed_cut_confirm_window_seconds": _int("keyed_cut_confirm_window_seconds", 900, 60),
            "foreign_threshold": _int("foreign_threshold", wd_threshold, 5),
            "min_attributed_links": _int("min_attributed_links", 1, 1),
            "attribution_max_lookups": _int("attribution_max_lookups", 10, 0),
            "max_dark_guests": _int("max_dark_guests", 3, 1),
            "posting_grace_seconds": _int("posting_grace_seconds", 3600, 0)}


def _coherence_cfg(config: dict) -> dict:
    """Coherence (2026-10-12) `coherence:` block, read defensively. A guest's
    outside link is evidence only when the guest's OWN stats record also
    names the node it is attached to; otherwise one delayed re-look, and
    past `max_unconfirmed_seconds` the node is flagged past_grace (still not
    enforced, v1). `live_mesh_veto` = the re-verify's live-mesh veto.
    Defaults are the shipped values."""
    block = (config or {}).get("coherence") or {}
    if not isinstance(block, dict):
        block = {}
    def _f(k, d, lo):
        try:
            return max(lo, float(block.get(k, d)))
        except (TypeError, ValueError):
            return d
    return {"enabled": block.get("enabled", True) is not False,
            "relook_delay_seconds": _f("relook_delay_seconds", 100.0, 5.0),
            "relook_node_cooldown_seconds": _f("relook_node_cooldown_seconds", 300.0, 30.0),
            "relook_global_min_seconds": _f("relook_global_min_seconds", 60.0, 0.0),
            "max_unconfirmed_seconds": _f(
                "max_unconfirmed_seconds",
                float(GraphAnalyzer.DEFAULT_MAX_UNCONFIRMED_SECONDS), 30.0),
            "live_mesh_veto": block.get("live_mesh_veto", True) is not False}


def _dark_attribute(api, cfg_getter, guest: int, foreign: list,
                    exclude=frozenset(), stale_minutes: int = 120,
                    dns_check=None, now_fn=None, budget: Optional[list] = None):
    """Step 2b attribution (audit 2 C-A; audit 3 C2/C3): which of the attach
    node's foreign union entries POST a stats record that reports a link to
    `guest` — held to the SAME bar as the normal Screen-2 path: the far end
    must be registered in DNS (`_is_node_alive`), its entry for the guest
    must not be older than `stale_threshold_minutes` when a registration
    time is present, and it must not be one of our own or allowlisted nodes
    (the normal path forgives those links). Numeric ids only (EchoLink wire
    forms and callsign tokens cannot be looked up), at most
    `attribution_max_lookups` API calls PER SCAN (`budget`: a one-element
    list shared across the guests of one scan), on the tracker's OWN client.
    Freshness = the far end's own POST time (`stats.data.time`), which must
    be within `stale_minutes`; a far end whose record carries no post time
    is not evidence. Returns None when every lookup failed."""
    from dns_checker import check_node_dns as _dns
    dns_check = dns_check or _dns
    now = now_fn() if now_fn else time.time()
    cap = int((cfg_getter() or {}).get("attribution_max_lookups", 10))
    if budget is None:
        budget = [cap]
    excl = {str(x) for x in exclude}
    out, tried, failed, skipped_cap = [], 0, 0, 0
    seen_tok: set = set()
    for tok in foreign:
        t = str(tok)
        if t in seen_tok:
            continue
        seen_tok.add(t)
        if not t.isdigit() or (len(t) == 7 and t.startswith("3")) or t in excl:
            continue
        if budget[0] <= 0:
            skipped_cap += 1
            continue
        budget[0] -= 1
        tried += 1
        try:
            data = api.get_node_stats(int(t))
            details = api.get_linked_node_details(int(t), data=data) if data is not None else None
        except Exception:
            data, details = None, None
        if details is None:
            failed += 1
            continue
        entry = next((d for d in details
                      if not d.get("is_external", False)
                      and int(d.get("node_id", 0) or 0) == int(guest)), None)
        if entry is None:
            continue
        # freshness of the far end's OWN post (audit 4 C-2): a stale record
        # left on the server after the far end stopped posting is not evidence.
        # None also covers a far-FUTURE post time (change 1, 2026-09-08: a
        # far end whose clock is >5 min fast no longer counts as fresh).
        age_s = ASLApiClient.post_age_seconds(data, now)
        if age_s is None or age_s > stale_minutes * 60:
            logger.info("dark-guest attribution: %s lists %s but its post is %s — ignored",
                        t, guest, ("undated or far-future" if age_s is None
                                   else f"{age_s / 60:.0f} min old"))
            continue
        try:
            alive = bool(dns_check(int(t)).is_registered)
        except Exception:
            alive = False
        if not alive:
            logger.info("dark-guest attribution: %s lists %s but is NOT in DNS — "
                        "stale, ignored", t, guest)
            continue
        out.append(t)
    if skipped_cap:
        logger.warning("dark-guest attribution for %s: lookup cap %d reached, %d "
                       "candidate(s) not checked (attribution_max_lookups)",
                       guest, cap, skipped_cap)
    if tried and failed == tried:
        return None
    return out


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

            # Merge AMI manager credentials (ami_listener). Secrets-only —
            # per-node {username, secret} keyed by node number.
            if "ami" in secrets:
                config["ami"] = secrets["ami"]

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
            # Atomic publish: copy to a temp name then os.replace into place, so
            # a reader (notifier attaching a burst shot, best_shot selecting one)
            # can never observe a half-written JPEG. os.replace is atomic on the
            # same filesystem. The ".tmp" name is excluded from the prune glob.
            tmp_dst = dest_dir / f"{stamp}{suffix}{tag}.jpg.tmp"
            shutil.copy2(src, tmp_dst)
            os.replace(tmp_dst, dst)
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
        # Don't leave a half-written temp behind (it's excluded from the prune
        # glob, so it would accumulate forever otherwise).
        try:
            (dest_dir / f"{stamp}{suffix}{tag}.jpg.tmp").unlink(missing_ok=True)
        except (OSError, NameError):
            pass
        return None


def preserve_hidden_bubble(src_path: str, scan_timestamp: str) -> Optional[Path]:
    """Preserve a bubble map that triggered a hidden-path alert."""
    return _preserve_bubble(src_path, scan_timestamp, HIDDEN_BUBBLE_DIR, "_hidden")


def corroborating_attachment(event_bubble: Optional[Path]) -> Optional[Path]:
    """Return `event_bubble` only if the image actually SHOWS the bridging —
    a node beyond distance 2 from the focus, the cross-checker's own
    visibility test. Otherwise None: an official-map shot whose cache never
    re-rendered within the seconds a violation now lives before
    auto-disconnect would show a CLEAN topology, and attaching it invites
    doubt about the detector instead of confirming it (Bennett, 2026-07-17).
    The image stays preserved on disk for forensics either way; only the
    email attachment is gated. Analysis failure counts as non-corroborating
    (attach only what is POSITIVELY confirmatory)."""
    if event_bubble is None:
        return None
    try:
        analysis = analyze_bubble_map(str(event_bubble))
    except Exception as e:
        analysis = None
        logger.warning("Evidence-image analysis failed (non-fatal): %s", e)
    if analysis is not None and analysis.max_distance >= 3:
        return event_bubble
    seen = ("unanalyzable" if analysis is None
            else f"max distance {analysis.max_distance} (< 3)")
    logger.warning(
        "Evidence image does not show the bridging (%s) — violation email "
        "will go out WITHOUT an attachment; image preserved at %s",
        seen, event_bubble)
    return None


def _render_local_evidence(result, bubble_gen) -> Optional[Path]:
    """Render OUR OWN map of the detection-time topology into
    bubble_maps_events/ (same stamp as the official shots, "_local" tag) and
    cap the PNG count. Returns the path, or None if the render failed."""
    try:
        dt = datetime.strptime(result.timestamp, "%Y-%m-%dT%H:%M:%SZ")
        stamp = dt.strftime("%Y-%m-%d_%H-%M-%S")
    except ValueError:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    path = bubble_gen.render_evidence(
        result.topology,
        EVENT_BUBBLE_DIR / f"{stamp}_event_local.png",
        timestamp=f"{result.timestamp} (local render at detection)")
    if path is not None:
        # The _preserve_bubble pruner only sweeps *.jpg — cap the PNG renders
        # ourselves or they accumulate forever (audit 2026-07-17; the
        # uncorroborated branch is the COMMON case).
        try:
            with _PRESERVE_LOCK:
                pngs = sorted(EVENT_BUBBLE_DIR.glob("*_event_local.png"))
                for old in pngs[:-BUBBLE_KEEP] if len(pngs) > BUBBLE_KEEP else []:
                    old.unlink()
        except OSError as e:
            logger.warning("Could not prune local evidence renders: %s", e)
    return path


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
        # can stall the scan walk — kept at 15s so it never exceeds the 15s
        # top-of-hour poll cadence. A slow render (e.g. a 277-node map ~60s)
        # will time shot 0 out, but the burst-shot fallback (best_shot) then
        # supplies a near-detection image, so shot 0 need not win that race.
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

    @staticmethod
    def _burst_index(p: Path) -> int:
        """Burst sequence N from a '<stamp>_event_t<N>.jpg' filename."""
        try:
            return int(p.stem.rsplit("_t", 1)[1])
        except (IndexError, ValueError):
            return 1 << 30

    def best_shot(self, scan_timestamp: str) -> Optional[Path]:
        """Earliest successfully-captured evidence shot for THIS scan, or None.

        Prefers shot 0 (`<stamp>_event.jpg`); failing that, the earliest burst
        shot (`<stamp>_event_t<N>.jpg`, smallest N) — i.e. the image captured
        CLOSEST to detection time and therefore most likely to still show a
        transient violation. Crucially this is NOT the end-of-scan image: on a
        long scan (a big topology can take many minutes to walk) the offending
        link often self-resolves before the walk finishes, so the end-of-scan
        fetch shows nothing (the 2026-06-21 incident: shot 0 timed out on a slow
        277-node render, and the old fallback attached the collapsed end-of-scan
        map instead of the burst shots that captured the violation).

        Resolved by DISK LOOKUP keyed on the scan's own timestamp, so it is
        inherently per-scan and free of cross-thread / cross-scan races. Returns
        None only if no evidence shot exists at all — caller then falls back to
        the end-of-scan cross-check image as a last resort.
        """
        try:
            dt = datetime.strptime(scan_timestamp, "%Y-%m-%dT%H:%M:%SZ")
            stamp = dt.strftime("%Y-%m-%d_%H-%M-%S")
        except ValueError:
            return self._current_shot0  # best effort if timestamp format changes
        shot0 = EVENT_BUBBLE_DIR / f"{stamp}_event.jpg"
        if shot0.is_file():
            return shot0
        bursts = sorted(EVENT_BUBBLE_DIR.glob(f"{stamp}_event_t*.jpg"),
                        key=self._burst_index)
        return bursts[0] if bursts else None


def _handle_detection_disconnect(event, disconnector: AutoDisconnector,
                                 collector: "StatusCollector",
                                 dry_run: bool,
                                 outcomes: Optional[dict] = None,
                                 live_mesh_fn=None, mesh_trusted_fn=None) -> None:
    """Attempt auto-disconnect for a freshly-detected bridging event.

    Invoked from GraphAnalyzer.on_violation AT DETECTION time (synchronously, on
    the scan thread) so a transient violator is acted on within the re-verify
    window instead of after the full (now bounded) topology walk. ALL innocent-
    protection lives inside disconnector.attempt_disconnect — managed-node
    gating, the 15s re-verify delay, the still-connected / still-alive / still-
    bridging-outside-the-system checks, and the fail-closed flag file — and is
    unchanged by moving the trigger earlier. No-op in dry-run / monitor-only.
    """
    if dry_run:
        logger.info("Auto-disconnect suppressed (monitor-only/dry-run) for "
                    f"detected event: {event.path_description}")
        return
    try:
        disc_result = disconnector.attempt_disconnect(
            event, live_mesh_fn=live_mesh_fn, mesh_trusted_fn=mesh_trusted_fn)
    except Exception as e:
        logger.error(f"Auto-disconnect attempt errored for "
                     f"{event.path_description}: {e}")
        return
    if disc_result is not None:
        logger.info(
            f"Auto-disconnect result for node {disc_result.target_node}: "
            f"{disc_result.action} — {disc_result.message}")
        # Retain the outcome for the sysadmin email (2026-07-17, Bennett:
        # the "RECOMMENDED ACTION" wording predated auto-disconnect and
        # misdescribed an already-handled event).
        if outcomes is not None:
            # One scan emits several events per offender (one per outside
            # target). Keep the DECISIVE outcome: a real disconnect must not
            # be overwritten by the later same-scan events' skipped_cooldown
            # (2026-09-07 23:42 — the email would have said "skipped").
            prev = outcomes.get(event.offending_node)
            rank = {"disconnected": 2}
            def _rank(r):
                a = getattr(r, "action", "") or ""
                return rank.get(a, 0 if a.startswith("skipped") else 1)
            if prev is None or _rank(disc_result) >= _rank(prev):
                outcomes[event.offending_node] = disc_result
        if collector:
            try:
                collector.update_disconnect(disc_result)
            except Exception as e:
                logger.error(f"collector.update_disconnect failed: {e}")


def _analytics_roles(config: dict) -> dict:
    """Derive the analytics role sets from config.

    core   = the focus hub only (analytics.core_nodes overrides).
    bridge = the configured bridge_nodes — the designated bridges that legitimately
             come and go (analytics.bridge_nodes overrides).
    guest  = everything else.
    NB: this is distinct from auto_disconnect's "managed" set (SSH-controllable
    nodes), which happens to include two bridges but is unrelated to topology role.
    """
    acfg = config.get("analytics") or {}
    if not isinstance(acfg, dict):     # present-but-malformed (e.g. `analytics: yes`)
        acfg = {}
    focus = config["focus_node"]
    # core defaults to the focus hub; bridge defaults to the configured
    # bridge_nodes; guest = everything else. For this deployment both sets are
    # set explicitly via analytics.core_nodes / analytics.bridge_nodes (config.yaml),
    # because a node can be core yet also serve as a bridge.
    core = set(acfg.get("core_nodes") or {focus})
    bridges = set(acfg.get("bridge_nodes") or config.get("bridge_nodes", []))
    return {"core": core, "bridges": bridges}


def _build_analytics(config: dict):
    """Open the analytics DB and build a recorder + role sets, or None if disabled
    or on any error (analytics must NEVER block the monitor from starting). ALL
    config access is inside the try — a present-but-empty/malformed `analytics:`
    key must not crash startup."""
    try:
        acfg = config.get("analytics") or {}
        if not isinstance(acfg, dict) or not acfg.get("enabled", False):
            return None
        # Anchor a relative db_path to this file's directory (matches the
        # bubble_maps_* dirs) so it is cwd-independent under launchd/systemd.
        db_path = Path(acfg.get("db_path", "analytics.db"))
        if not db_path.is_absolute():
            db_path = Path(__file__).parent / db_path
        roles = _analytics_roles(config)
        conn = init_db(db_path)
        logger.info("Analytics recording: ENABLED (db=%s, core=%s, bridges=%s)",
                    db_path, sorted(roles["core"]), sorted(roles["bridges"]))
        return {"recorder": Recorder(conn), **roles}
    except Exception as e:
        logger.error("Analytics init failed (recording disabled this run): %s", e)
        return None


def _record_analytics(analytics, result, focus_node: int,
                      mesh_count: Optional[int] = None) -> None:
    """Record this scan's present-set into the analytics DB. Fully fail-safe:
    any error is logged and swallowed so analytics can never break a scan."""
    if not analytics:
        return
    # Validity gate (node health N1, 2026-10-18): when the HUB's record could
    # not be fetched (API error / 429 / timeout) the walk never ran, so this
    # scan observed nothing — record NOTHING (no 'disappeared' for every node,
    # no heartbeat). Before this, one failed hub fetch wrote a mass
    # disappearance and an outage for every core node. A hub that IS fetched
    # but posts an empty record is not gated: that is a real (degraded) state.
    # The hub is added to the topology only once its payload parsed, so "hub
    # not in topology" covers both the fetch failure and the parse failure
    # (audit S2). An EMPTY hub record keeps the hub in the topology: not gated.
    if (focus_node in (getattr(result, "fetch_failed", None) or ())
            or focus_node not in (getattr(result, "topology", None) or {})):
        logger.warning("Analytics: hub record not obtained this scan — presence not "
                       "recorded (gate), no heartbeat written")
        return
    try:
        # Phase 2: outside nodes a listener monitors are not guests of this
        # system — keep them out of presence/dwell statistics.
        topo = {k: v for k, v in result.topology.items()
                if v.get("role") != "monitored_by_guest"}
        present = build_present_from_topology(
            topo, focus_node, analytics["core"], analytics["bridges"])
        analytics["recorder"].reconcile_scan(present, ts=result.timestamp,
                                             mesh_count=mesh_count)
    except Exception as e:
        logger.error("Analytics recording failed (non-fatal): %s", e)
    # Violations recorded separately so a reconcile failure can't drop them
    # (and vice versa). One row per bridging event per scan; the digest
    # aggregates into episodes (2026-07-02 decision).
    try:
        if result.bridging_events:
            analytics["recorder"].record_violations(
                result.bridging_events, ts=result.timestamp)
    except Exception as e:
        logger.error("Analytics violation recording failed (non-fatal): %s", e)
    # Change 2 (2026-09-08): nodes that did not report their links this scan
    # (dark = posting nothing; linkless = fresh empty record) — one row per
    # node per scan for the daily digest's episode list. Own try block.
    try:
        dark = getattr(result, "dark_guests", None) or []
        lkl = getattr(result, "linkless", None) or []
        unc = getattr(result, "unconfirmed", None) or []     # coherence (2026-10-12)
        if dark or lkl or unc:
            analytics["recorder"].record_link_reports(dark, lkl, ts=result.timestamp,
                                                      unconfirmed=unc)
    except Exception as e:
        logger.error("Analytics link-report recording failed (non-fatal): %s", e)


def _build_node_health(config: dict, analytics):
    """Three-state node health tracker (node_health.py), or None when the
    `node_health:` block is absent/disabled or on any init error (pure
    observation — must never block the monitor from starting). Records to
    analytics.db when analytics is enabled; /status only otherwise."""
    try:
        from node_health import node_health_cfg, NodeHealthTracker
        cfg = node_health_cfg(config)
        if cfg is None:
            logger.info("Node health: disabled (no enabled node_health: block)")
            return None
        recorder = analytics["recorder"] if analytics else None
        tracker = NodeHealthTracker(cfg, recorder=recorder)
        logger.info("Node health: ENABLED (%d nodes: %s; confirm_scans=%d; recording=%s)",
                    len(cfg["nodes"]),
                    ", ".join(f"{n}<-{p}" for n, p in sorted(cfg["nodes"].items())),
                    cfg["confirm_scans"], "analytics.db" if recorder else "status only")
        return tracker
    except Exception as e:
        logger.error("Node health init failed (disabled this run): %s", e)
        return None


def _record_node_health(tracker, result, collector, api_client) -> None:
    """Run the node-health tracker on this scan's result (scan thread, after
    the analytics recorder) and publish its block on /status. Fully
    fail-safe: never raises into the scan."""
    if tracker is None:
        return
    block = None
    try:
        block = tracker.observe(result, api=api_client)
    except Exception as e:
        logger.error("Node health update failed (non-fatal): %s", e)
        return
    if collector is not None and block is not None:
        try:
            collector.update_node_health(block)
        except Exception as e:
            logger.error("Node health status update failed (non-fatal): %s", e)


def _build_public_export(config: dict, collector):
    """Team status page exporter (public_export.py), or None when the
    `public_export:` block is absent/disabled or on any init error — pure
    output, must never block the monitor from starting. Also publishes the
    exporter's initial status block so /status shows it before the first scan."""
    try:
        from public_export import public_export_cfg, Exporter
        cfg = public_export_cfg(config)
        if cfg is None:
            logger.info("Public export: disabled (no enabled public_export: block)")
            if collector is not None:
                collector.update_public_export(None)
            return None
        base_dir = os.path.dirname(os.path.abspath(__file__))
        commit = None
        try:
            import subprocess
            r = subprocess.run(["git", "-C", base_dir, "rev-parse", "--short", "HEAD"],
                               capture_output=True, text=True, timeout=3, check=False)
            commit = (r.stdout or "").strip()[:16] or None if r.returncode == 0 else None
        except Exception:                       # noqa: BLE001 — cosmetic only
            commit = None
        import socket as _socket
        exporter = Exporter(cfg, base_dir=base_dir,
                            daemon={"commit": commit, "host": _socket.gethostname().split(".")[0][:32]},
                            on_status=(collector.update_public_export if collector is not None else None))
        logger.info("Public export: ENABLED (%d group(s), %d node(s), dir=%s, push=%s, every>=%ds)",
                    len(cfg["groups"]), sum(len(g["nodes"]) for g in cfg["groups"]), cfg["dir"],
                    "blob" if cfg["blob_url"] else "OFF (no blob_url)", cfg["min_interval_seconds"])
        if collector is not None:
            collector.update_public_export(exporter.status())
        return exporter
    except Exception as e:
        logger.error("Public export init failed (disabled this run): %s", e)
        return None


def _export_public(exporter, collector) -> None:
    """Hand this scan's /status snapshot to the exporter (worker thread) and
    publish the exporter's counters on /status. Fail-safe: never raises."""
    if exporter is None or collector is None:
        return
    try:
        # the snapshot (a deep copy + two small DB reads) is taken on the WORKER, not here;
        # the worker also publishes the counters itself (on_status) — no copy from this thread,
        # so a pre-render copy can never overwrite a fresher one
        exporter.after_scan(collector.get_snapshot)
    except Exception as e:
        logger.error("Public export hand-off failed (non-fatal): %s", type(e).__name__)


def _capture_rpt_snapshot(rpt_reader, holder: dict, tag: str,
                          timeout_seconds: Optional[int] = None) -> None:
    """One-shot per-scan read of the SSH vantage node's link state.

    Fills `holder` with {"snap": RptSnapshot, "tag": tag} on the first call of
    a scan; later calls are no-ops. The latch is set on ATTEMPT, not success —
    if the vantage is unreachable, one scan pays for exactly one timeout, no
    matter how many violations fire (audit 2026-07-03, Significant-1). Fully
    fail-safe — the reader is an optional data source and must never break a
    scan or delay it beyond one SSH timeout.
    """
    if rpt_reader is None or "attempted" in holder:
        return
    holder["attempted"] = True
    try:
        snap = rpt_reader.read(timeout_seconds=timeout_seconds)
    except Exception as e:
        logger.error("RPT reader failed (non-fatal, %s): %s", tag, e)
        return
    if not snap.ok:
        logger.warning("RPT reader unusable (%s): %s", tag, "; ".join(snap.errors))
        return
    holder["snap"] = snap
    holder["tag"] = tag
    for err in snap.errors:            # degraded-but-usable notes (e.g. var lag)
        logger.info("RPT reader note (%s): %s", tag, err)
    logger.info(
        "RPT reader (%s, vantage %d): mesh=%d adjacent=%d RPT_NUMLINKS=%s",
        tag, snap.vantage_node, snap.mesh_count, len(snap.adjacent),
        snap.reported_numlinks)


def _rpt_link_info_line(holder: dict) -> Optional[str]:
    """Human-readable summary of the vantage snapshot for violation emails."""
    snap = holder.get("snap")
    if snap is None:
        return None
    nodes = snap.mesh_nodes
    shown = ", ".join(nodes[:40]) + (" ..." if len(nodes) > 40 else "")
    return (f"Link count from vantage node {snap.vantage_node} (app_rpt view, "
            f"captured {holder['tag']}): {snap.mesh_count} linked nodes "
            f"(RPT_NUMLINKS={snap.reported_numlinks}).\n"
            f"Nodes seen: {shown}")


def _current_guests(topology: dict) -> dict:
    """Present guests/externals keyed stably for arrival tracking (the HA
    audible-annunciation feed). Nodes key by id; externals by their ext_*
    topology key (host-scoped, so the same client on two hosts is two)."""
    out = {}
    for nid, info in topology.items():
        role = info.get("role", "")
        if role in ("guest", "unauthorized", "dragged_in"):
            out[str(nid)] = {"callsign": info.get("callsign", ""),
                             "attached_to": info.get("parent"),
                             "kind": "node"}
        elif role == "permitted_external":
            out[str(nid)] = {"callsign": info.get("callsign", "")
                             or info.get("external_name", ""),
                             "attached_to": info.get("parent"),
                             "kind": "external"}
    return out


def _drain_escalations(watcher, notifier: Notifier) -> None:
    """Send any repeat-offender escalations the watch thread queued.

    Runs on the MAIN thread only (the Notifier and its SQLite tracker are not
    exercised from the watch thread). Fail-safe: a send failure is logged and
    the remaining queue still drains."""
    if watcher is None:
        return
    while True:
        try:
            esc = watcher.escalations.get_nowait()
        except queue.Empty:
            return
        try:
            ok = notifier.send_repeat_offender_alert(
                offender=esc.offender, callsign=esc.callsign,
                strikes=esc.strikes, reappearances=esc.reappearances,
                path_description=esc.path_description,
                window_minutes=esc.window_minutes)
            logger.warning("Repeat-offender alert for node %d: %s",
                           esc.offender, "sent" if ok else "not sent (gated)")
        except Exception as e:
            logger.error("Repeat-offender alert for node %d failed: %s",
                         esc.offender, e)


def _watchdog_candidates(topology: dict, disconnector,
                         exclude=frozenset()) -> list:
    """Enforceable link-state-watchdog targets: numeric guest-class nodes
    attached directly to a managed+enabled node. Returns [(bridge, target)].
    Dragged-in nodes hang off other guests (parent not managed), so only the
    carrier guest itself can match — which is the correct target.
    `exclude`: permitted listener ids (phase 2) — never watchdog targets."""
    out = []
    for nid, info in topology.items():
        key = str(nid)
        if not key.isdigit():
            continue
        if info.get("role") not in ("guest", "unauthorized", "dragged_in"):
            continue
        if int(key) in exclude:
            continue
        try:
            parent_id = int(info.get("parent"))
            target_id = int(key)
        except (TypeError, ValueError):
            continue
        m = disconnector.managed_nodes.get(parent_id)
        if m is None or not m.enabled:
            continue
        if target_id in disconnector.managed_nodes \
                or target_id in disconnector.bridge_nodes:
            continue
        out.append((parent_id, target_id))
    return out


def _drain_watchdog(watcher, disconnector, notifier, rpt_reader,
                    topology: dict, dry_run: bool, collector) -> None:
    """Attribution + enforcement for link-state watchdog alarms (max-prefix
    analogue, Bennett 2026-07-21). Main thread only; never raises. The watch
    thread only measures — everything with side effects happens here.
    Known/accepted (audit A1): this path uses the MAIN AutoDisconnector's
    cooldown map while watch-mode re-kicks use the watcher's dedicated
    instance, so the two paths' cooldowns don't coordinate — worst case is
    one redundant kick of a node the other path already removed."""
    if watcher is None:
        return
    while True:
        try:
            alarm = watcher.watchdog_alarms.get_nowait()
        except queue.Empty:
            return
        try:
            _handle_watchdog_alarm(alarm, watcher, disconnector, notifier,
                                   rpt_reader, topology, dry_run, collector)
        except Exception as e:
            logger.error("Watchdog alarm handling failed (non-fatal): %s", e)


def _handle_watchdog_alarm(alarm, watcher, disconnector, notifier,
                           rpt_reader, topology: dict, dry_run: bool,
                           collector) -> None:
    def record(action: str, bridge=None, target=None, message: str = ""):
        watcher.wd_last_action = {
            "ts": datetime.now().isoformat(),
            "foreign_count": alarm.foreign_count,
            "action": action, "bridge": bridge, "target": target,
            "message": message[:300],
        }
        logger.warning("Link-state watchdog: %s (bridge=%s target=%s) — %s",
                       action, bridge, target, message)
        # Phase 2: while a permitted listener is present, a non-action
        # outcome recurs every alarm cooldown if the listener's outside
        # mesh simply grew past the frozen allowance. Emailing each one
        # would burn the absolute recipient cap and silence real alerts
        # (audit S7) — count it for /status and the listener notice instead.
        listeners_present = bool(getattr(watcher, "listener_ids", lambda: ())())
        if listeners_present and action in (
                "no_enforceable_candidate", "no_carrier_confirmed",
                "attribution_ambiguous"):
            watcher.wd_listener_suppressed_alerts = (
                getattr(watcher, "wd_listener_suppressed_alerts", 0) + 1)
            logger.warning("Link-state watchdog: alert email suppressed while "
                           "a permitted listener is present (%d so far)",
                           watcher.wd_listener_suppressed_alerts)
            return
        try:
            notifier.send_watchdog_alert(
                foreign_count=alarm.foreign_count, threshold=alarm.threshold,
                sample=alarm.sample, bridge=bridge, target=target,
                action=action, message=message)
        except Exception as e:
            logger.error("Watchdog alert email failed (non-fatal): %s", e)

    if dry_run:
        record("monitor_only", message="excess observed; monitor-only mode — "
               "no attribution or enforcement performed")
        return
    candidates = _watchdog_candidates(
        topology, disconnector,
        exclude=watcher.listener_ids() if hasattr(watcher, "listener_ids")
        else frozenset())
    if not candidates:
        record("no_enforceable_candidate",
               message="excess link-state present but no guest-class node "
               "attached to a managed node in the last scan — manual review")
        return
    # Attribution: the carrier bridge must be POSITIVELY identified — its own
    # `rpt nodes` union read successfully AND showing >= threshold foreign
    # entries. A readable below-threshold union EXONERATES that bridge's
    # guests (its union includes everything dragged in behind them); an
    # unreadable union is "could not see", never license to act (audit
    # 2026-07-21 C1 — no fallback kick on system-wide evidence alone).
    per_bridge: dict = {}
    for bridge, _t in candidates:
        if bridge in per_bridge:
            continue
        union = disconnector.read_bridge_union(bridge)
        per_bridge[bridge] = (None if union is None
                              else len(watcher.foreign_entries(union)))
    carriers = [b for b, n in per_bridge.items()
                if n is not None and n >= alarm.threshold]
    if len(carriers) != 1:
        record("no_carrier_confirmed",
               message=f"per-bridge foreign counts {per_bridge}; candidates "
               f"{candidates} — no unique positively-confirmed carrier; "
               "no action (manual review)")
        return
    on_carrier = [(b, t) for b, t in candidates if b == carriers[0]]
    if len(on_carrier) > 1:
        # Multiple guests on the carrying bridge: which one brought the
        # excess is not knowable from here (arrival ordering was judged
        # unreliable — audit S1). Surface, never guess.
        record("attribution_ambiguous",
               message=f"multiple guests on carrier bridge {on_carrier} — "
               "no action (manual review)")
        return
    bridge, target = on_carrier[0]

    def reverify() -> bool:
        # Scoped to the ACCUSED bridge (audit C1): the kick is licensed only
        # by fresh excess on the bridge we are about to act through — a
        # system-wide count cannot catch misattribution.
        union = disconnector.read_bridge_union(bridge)
        if union is None:
            return False
        return len(watcher.foreign_entries(union)) >= alarm.threshold

    result = disconnector.watchdog_disconnect(
        bridge, target, reverify,
        reason=f"link-state watchdog: {alarm.foreign_count} foreign entries "
               f">= {alarm.threshold}")
    if result is None:
        record("not_applicable", bridge=bridge, target=target,
               message="managed node lookup/guard refused the action")
    else:
        record(result.action, bridge=bridge, target=target,
               message=result.message)


_CONNECTING_RESCAN_S = 600             # per (node, target) pair
_CONNECTING_GLOBAL_MIN_S = 180         # between any two connecting-triggered requests
_CONNECTING_RESCAN_DELAY_S = 75        # wait for the next stats post (~60 s cadence)
_connecting_requested: dict = {}       # (node, target) -> monotonic time of the last request
_connecting_last_global = [0.0]


def _request_connecting_rescan(connecting: list, scan_request, delay_s: float = None) -> int:
    """Change 3 helper: request one DELAYED out-of-cycle scan for the first
    sighting of each CONNECTING (node, target) pair. The delay lets the far
    end's next stats post land (an immediate re-scan would re-read the same
    record — round-2 audit C2). Per-pair cooldown _CONNECTING_RESCAN_S plus a
    global floor _CONNECTING_GLOBAL_MIN_S between requests (a node dialling a
    new peer every scan must not drive back-to-back walks — audit S8).
    Returns the number of NEW pairs seen (whether or not a request was made)."""
    now = time.monotonic()
    for k in [k for k, t in _connecting_requested.items()
              if now - t > 2 * _CONNECTING_RESCAN_S]:
        _connecting_requested.pop(k, None)
    fresh = []
    for c in connecting:
        try:
            key = (int(c["node"]), int(c["target"]))
        except (KeyError, TypeError, ValueError):
            continue
        last = _connecting_requested.get(key)
        if last is None or now - last >= _CONNECTING_RESCAN_S:
            fresh.append(key)
    if fresh and scan_request is not None:
        if now - _connecting_last_global[0] >= _CONNECTING_GLOBAL_MIN_S:
            _connecting_last_global[0] = now
            for key in fresh:          # the pair's cooldown starts only when requested
                _connecting_requested[key] = now
            shown = ", ".join(f"{n} -> {t}" for n, t in fresh[:10])
            if len(fresh) > 10:
                shown += f" (+{len(fresh) - 10} more)"
            reason = "connecting link(s) seen, re-check after the next post: " + shown
            d = _CONNECTING_RESCAN_DELAY_S if delay_s is None else delay_s
            if d > 0:
                t = threading.Timer(d, scan_request, args=(reason,))
                t.daemon = True
                t.start()
            else:
                scan_request(reason)
        else:
            logger.info("connecting-link re-scan for %d new pair(s) not requested — "
                        "global %ds floor", len(fresh), _CONNECTING_GLOBAL_MIN_S)
    return len(fresh)


_UNCONFIRMED_DEFAULTS = {"relook_delay_seconds": 100.0,
                         "relook_node_cooldown_seconds": 300.0,
                         "relook_global_min_seconds": 60.0}
_unconfirmed_requested: dict = {}   # node -> monotonic time of the last request
_unconfirmed_last_global = [0.0]


def _request_unconfirmed_relook(unconfirmed: list, scan_request, cfg: Optional[dict] = None,
                                delay_s: float = None) -> int:
    """Coherence (2026-10-12): request ONE delayed out-of-cycle scan for each
    newly seen `unconfirmed` node (its own record predates its attachment).
    The delay lets the node's next stats post reach the API (ASL3 posts on
    a link change within 0.2 s and every 60 s; the API has served records
    45 s+ stale). Own budget — separate from the CONNECTING one, whose
    180 s global floor could otherwise push the re-look to the next 300 s
    poll: per-node cooldown + a global floor. Returns the number of NEW
    nodes seen (whether or not a request was made)."""
    c = dict(_UNCONFIRMED_DEFAULTS)
    c.update({k: v for k, v in (cfg or {}).items() if k in c})
    now = time.monotonic()
    per_node = float(c["relook_node_cooldown_seconds"])
    current = set()
    for u in unconfirmed or []:
        try:
            current.add(int(u["node"]))
        except (KeyError, TypeError, ValueError):
            continue
    # ONE re-look per unconfirmed EPISODE (audit S6): a node drops out of the
    # request table only when a scan no longer lists it (it became coherent
    # or left); while it stays listed, no further re-looks — the regular
    # poll and the past-grace rule cover a stuck record. The node cooldown
    # only guards a flapping node that leaves and is re-listed at once.
    for k in [k for k in _unconfirmed_requested if k not in current
              and now - _unconfirmed_requested[k] >= per_node]:
        _unconfirmed_requested.pop(k, None)
    fresh = [node for node in sorted(current) if node not in _unconfirmed_requested]
    if not fresh or scan_request is None:
        return len(fresh)
    if now - _unconfirmed_last_global[0] < float(c["relook_global_min_seconds"]):
        logger.info("coherence: re-look for %s not requested — another re-look was "
                    "requested %.0f s ago (global floor %.0f s)", fresh,
                    now - _unconfirmed_last_global[0], float(c["relook_global_min_seconds"]))
        return len(fresh)
    for node in fresh:
        _unconfirmed_requested[node] = now
    _unconfirmed_last_global[0] = now
    d = float(c["relook_delay_seconds"]) if delay_s is None else float(delay_s)
    reason = (f"unconfirmed (pre-join?) guest record for {fresh} — re-look "
              f"after the next stats post ({d:.0f} s)")
    if d <= 0:
        scan_request(reason)
    else:
        t = threading.Timer(d, scan_request, args=(reason,))
        t.daemon = True
        t.start()
        logger.info("coherence: re-look scan scheduled in %.0f s for %s", d, fresh)
    return len(fresh)


def run_scan(analyzer: GraphAnalyzer, notifier: Notifier,
             disconnector: AutoDisconnector,
             focus_node: int, api_client=None,
             collector: StatusCollector = None,
             dry_run: bool = False,
             enable_image_crosscheck: bool = True,
             capturer: "EvidenceCapturer" = None,
             veto_status=None,
             dark_tracker=None,
             analytics=None, rpt_reader=None, watcher=None,
             bubble_gen=None, vantage_trust=None,
             listener_notice=None, scan_request=None,
             coherence_cfg: Optional[dict] = None,
             node_health=None, public_exporter=None) -> bool:
    """Run a single topology scan with optional image cross-check.

    `scan_request(reason)`: optional callable that asks the main loop for
    one immediate out-of-cycle scan (change 3: a CONNECTING link should be
    re-checked soon after it is first seen).

    Returns True if problems were detected.
    """
    logger.info("=" * 60)
    logger.info("Starting topology scan...")

    # === Phase 1: API-based analysis ===
    # Clear last scan's immediate-shot path; the analyzer's first-detection
    # callback (if it fires this scan) repopulates it synchronously.
    if capturer is not None:
        capturer.begin_scan()
    # Wire auto-disconnect to fire AT detection time (during the scan, per event)
    # rather than at end-of-scan, so a transient violator is acted on within the
    # re-verify window instead of after a multi-minute walk. dry_run is captured
    # here so monitor-only scans never disconnect. (Set each scan because dry_run
    # can change via SIGHUP and the analyzer is rebuilt on reload.)
    # The vantage snapshot is taken BEFORE the disconnect attempt so its link
    # count still includes the offender (evidence value); one-shot per scan.
    rpt_holder = {}
    disc_outcomes: dict = {}   # offending_node -> DisconnectResult (for email)

    # Coherence (2026-10-12): the re-verify's live-mesh VETO needs a fresh
    # vantage read (one per scan) and the vantage-health verdict read fresh
    # (a cheap local file).
    def _mesh_trusted() -> bool:
        if vantage_trust is None:
            return False
        try:
            return (vantage_trust.evaluate() or {}).get("trust") == "ok"
        except Exception as e:
            logger.error("vantage_trust evaluate failed (non-fatal): %s", e)
            return False

    fresh_holder: dict = {}

    def _fresh_mesh():
        # The re-verify judges a record read 15 s after detection; give it a
        # snapshot at least as fresh (audit S3), not the per-scan latch —
        # but ONE such read per scan (round-2 audit S7: N events must not
        # cost N SSH timeouts; the 2026-07-03 one-timeout-per-scan rule).
        if rpt_reader is None:
            return None
        if "snap" in fresh_holder:
            return fresh_holder["snap"]
        fresh_holder["snap"] = None
        try:
            fresh_holder["snap"] = rpt_reader.read(timeout_seconds=10)
        except Exception as e:
            logger.error("fresh RPT read for re-verify failed (non-fatal): %s", e)
        return fresh_holder["snap"]

    def _on_violation(ev):
        # Own try-guard so no conceivable snapshot failure can consume the
        # shared on_violation exception budget and skip the disconnect
        # (audit 2026-07-03, Advisory-3). The capture must stay FIRST —
        # pre-disconnect is the whole evidence value.
        try:
            _capture_rpt_snapshot(rpt_reader, rpt_holder, "at detection time")
        except Exception as e:
            logger.error("RPT snapshot capture errored (non-fatal): %s", e)
        _handle_detection_disconnect(ev, disconnector, collector, dry_run,
                                     outcomes=disc_outcomes,
                                     live_mesh_fn=_fresh_mesh,
                                     mesh_trusted_fn=_mesh_trusted)
        # Register the offender for post-violation watch mode (fast-poll +
        # re-kick-on-verified-re-offense). Registered in every mode — in
        # monitor-only the watcher observes and logs but never kicks/alerts.
        if watcher is not None:
            try:
                watcher.enter_watch(ev)
            except Exception as e:
                logger.error("link_watch enter_watch failed (non-fatal): %s", e)

    analyzer.on_violation = _on_violation
    result = analyzer.scan()

    # Change 3 (2026-09-08): a guest's CONNECTING (C) link is not a link yet
    # (no audio path; it neither disqualifies a listener nor counts as
    # bridging, for at most the analyzer's CONNECTING_GRACE_SECONDS) — ask
    # for ONE delayed re-scan per newly seen (node, target) pair so a link
    # that settles to T is judged after its next post rather than a full
    # poll interval later. Cooldowns inside the helper.
    try:
        _request_connecting_rescan(getattr(result, "connecting", None) or [],
                                   scan_request)
    except Exception as e:
        logger.error("connecting-link re-scan request failed (non-fatal): %s", e)
    if collector:
        try:
            collector.update_connecting(getattr(result, "connecting", None) or [])
        except Exception as e:
            logger.error("connecting status update failed (non-fatal): %s", e)
    # Coherence (2026-10-12): one delayed re-look per newly unconfirmed node
    # (own budget), and the list on /status.
    try:
        _request_unconfirmed_relook(getattr(result, "unconfirmed", None) or [],
                                    scan_request, coherence_cfg)
    except Exception as e:
        logger.error("unconfirmed re-look request failed (non-fatal): %s", e)
    if collector:
        try:
            collector.update_unconfirmed(getattr(result, "unconfirmed", None) or [])
        except Exception as e:
            logger.error("unconfirmed status update failed (non-fatal): %s", e)

    # Routine per-scan vantage read (no-op if the detection-time attempt above
    # latched the holder). Feeds analytics' mesh_count time-series — the raw
    # material for the planned link-count tripwire. Short timeout: this runs
    # on EVERY scan, including the 15s top-of-hour cadence, so an unreachable
    # vantage may cost at most ~5s per scan (audit 2026-07-03, Significant-2).
    _capture_rpt_snapshot(rpt_reader, rpt_holder, "at end of scan",
                          timeout_seconds=5)

    if collector:
        collector.update_scan(result)
        if api_client:
            collector.update_api_health(api_client)

    total_nodes = len(result.topology)
    logger.info(f"API scan complete: {total_nodes} nodes in topology")

    # === Analytics: record this scan's present-set (fail-safe; never blocks) ===
    # Runs in every mode (incl. monitor-only/dry-run) — it is pure observation
    # with no external side effects. Errors are logged and swallowed inside.
    rpt_snap = rpt_holder.get("snap")
    _record_analytics(analytics, result, focus_node,
                      mesh_count=rpt_snap.mesh_count if rpt_snap else None)

    # === Local bubble map + guest-arrival feed (presentation only) ===
    # Rendered from this scan's own edge data + the vantage snapshot; served
    # at GET /bubble.png for the HA dashboard. Fail-safe: a render problem is
    # logged and the scan proceeds.
    if bubble_gen is not None:
        try:
            png = bubble_gen.render(result.topology, rpt_snap,
                                    timestamp=result.timestamp)
            if png is not None and collector:
                def _p(attr):
                    v = getattr(bubble_gen, attr, None)
                    return str(v) if v else None
                collector.update_bubble_map(
                    str(png), result.timestamp,
                    wide_path=_p("last_wide_png"),
                    spread_path=_p("last_spread_png"),
                    spread_wide_path=_p("last_spread_wide_png"),
                    asl_path=_p("last_asl_png"),
                    asl_health=bubble_gen.asl_health(),
                    vantage_overlay=bubble_gen.vantage_overlay_stats())
        except Exception as e:
            logger.error("Bubble map render failed (non-fatal): %s", e)
    if collector:
        try:
            collector.update_guest_arrivals(_current_guests(result.topology))
        except Exception as e:
            logger.error("Guest-arrival tracking failed (non-fatal): %s", e)

    # Link-state watchdog (2026-07-21): feed the fresh API roster, then
    # attribute/enforce any excess-advertisement alarms the watch thread
    # queued (its trip request is what usually triggered this very scan).
    mesh_unaccounted = None
    if watcher is not None:
        try:
            if focus_node in result.unobserved:
                logger.warning("link_watch roster NOT updated: the hub's record was "
                               "empty this scan (a one-node roster would make the "
                               "whole mesh foreign)")
            else:
                watcher.update_roster(result.topology)
            # Phase 2 (2026-09-07): feed the permitted-listener set from a
            # COMPLETE scan only (focus present, no errors); a degraded scan
            # must not clear a listener that is merely unobserved. The
            # allowance is this scan's foreign count, frozen inside the
            # watcher until the set changes. Done BEFORE the drain so alarms
            # queued without the allowance are discarded, not enforced.
            scan_complete = (not result.errors
                             and any(i.get("role") == "focus"
                                     for i in result.topology.values()))
            if rpt_snap is not None:
                try:
                    mesh_unaccounted = len(
                        watcher.foreign_entries(rpt_snap.mesh_nodes))
                except Exception:
                    mesh_unaccounted = None
            if scan_complete:
                records = {l["node"]: l for l in result.listeners}
                # A previously registered listener that this scan could not
                # observe — its own fetch failed / empty record, or the
                # system node it hangs off was itself unobserved so it was
                # never reached — is kept: unobserved, not disproved (audit
                # C2). One whose attach node WAS observed and no longer
                # lists it has left; one observed and no longer a listener
                # (e.g. flipped to transceive) is dropped — its violation
                # path already ran.
                attach = watcher.listener_attach()
                for prev in watcher.listener_ids():
                    if prev in records:
                        continue
                    hangs_off = attach.get(prev)
                    if (prev in result.unobserved
                            or hangs_off is None
                            or hangs_off in result.unobserved):
                        records[prev] = {"node": prev, "attached_to": hangs_off}
                # Step 2 trigger B (audit SIG-4): a vetoed node keeps no
                # listener privilege anywhere — not in the watcher either
                # (watch exemption, frozen allowance) — even if it was
                # merely unobserved this scan.
                for vetoed in list(getattr(analyzer, "listener_veto", {}) or {}):
                    records.pop(vetoed, None)
                # Allowance sizes ONLY the mesh behind outside branches. A
                # listener with no outside branches contributes nothing, so
                # it must not freeze the current foreign count (which may be
                # a pre-existing ghost wedge) as its allowance (audit C3).
                has_branches = any(l.get("monitored") for l in result.listeners)
                allowance = mesh_unaccounted if has_branches else 0
                watcher.set_listeners(list(records.values()), allowance,
                                      foreign_raw=mesh_unaccounted)
            _drain_watchdog(watcher, disconnector, notifier, rpt_reader,
                            result.topology, dry_run, collector)
            if collector:
                collector.update_link_watchdog(watcher.watchdog_status())
            # Step 2b: dark guests — corroborate against each involved
            # bridge's own union (SSH only when a dark guest exists) AFTER the
            # roster is current, so "foreign" means the same as the watchdog's.
            if dark_tracker is not None:
                try:
                    # Audit 2 C-C: a system node (focus/bridge/managed) that
                    # returned an empty record thins the roster without an
                    # error — everything behind it would read as foreign.
                    system_ids = {int(focus_node)} | {int(b) for b in result.bridge_nodes}
                    system_ids |= {int(k) for k in getattr(disconnector, "managed_nodes", {})}
                    sys_unobserved = sorted(system_ids & set(result.unobserved))
                    if sys_unobserved:
                        logger.warning("dark-guest: system node(s) %s unobserved this "
                                       "scan — dark-guest evidence not advanced",
                                       sys_unobserved)
                    dark_tracker.observe(result.dark_guests, result.topology,
                                         scan_complete=(scan_complete and not sys_unobserved),
                                         posting_ids=getattr(result, "posting", set()))
                    dark_tracker.drain_actions()          # main thread only (audit 2 S-B)
                    if collector:
                        collector.update_dark_guests(dark_tracker.status())
                except Exception as e:
                    logger.error("dark-guest handling failed (non-fatal): %s", e)
        except Exception as e:
            logger.error("Link-state watchdog handling failed "
                         "(non-fatal): %s", e)

    # Change 1 (2026-09-08): fresh-but-empty guests -> /status `linkless`
    # (informational; independent of the watcher/dark tracker being wired).
    if collector:
        try:
            collector.update_linkless(getattr(result, "linkless", []))
        except Exception as e:
            logger.error("linkless status update failed (non-fatal): %s", e)

    # Phase 2 listener notice + /status block (presentation only; the
    # dispatcher's verdict keeps a refused notice pending like vantage_trust).
    if listener_notice is not None or collector:
        try:
            system_count = sum(1 for i in result.topology.values()
                               if i.get("role") != "monitored_by_guest")
            if listener_notice is not None:
                listener_notice.evaluate(
                    result.listeners,
                    rpt_snap.mesh_count if rpt_snap else None,
                    mesh_unaccounted, system_count)
                ln_notice = listener_notice.pending()
                # No dry-run gate here: LISTENER_NOTICE carries
                # bypass_dry_run=True (internal-only) so a monitor-only soak
                # still shows the notice — the chokepoint decides.
                if ln_notice is not None:
                    wd = (watcher.watchdog_status()
                          if watcher is not None else {})
                    if notifier.send_listener_notice(
                            ln_notice["listeners"], ln_notice["mesh_count"],
                            ln_notice["unaccounted"], ln_notice["system_count"],
                            listener_notice.interval_s / 3600.0,
                            allowance=wd.get("listener_allowance"),
                            suppressed_alerts=wd.get(
                                "listener_suppressed_alerts", 0)):
                        listener_notice.mark_sent(ln_notice)
                        if collector:
                            collector.set_listener_notice_last_sent(
                                listener_notice.last_sent_ts)
            if collector:
                collector.update_listeners(
                    analyzer.permit_listeners, result.listeners,
                    mesh_unaccounted,
                    listener_notice.status() if listener_notice else None,
                    vetoes=(veto_status() if veto_status else
                            {n: {"reason": r} for n, r in analyzer.listener_veto.items()}))
        except Exception as e:
            logger.error("Listener notice/status failed (non-fatal): %s", e)

    # Vantage-trust gating (2026-08-22): consume the external vantage-health
    # monitor's local status file and surface whether vantage-derived signals
    # (tripwire, watchdog) are currently trustworthy. Presentation + internal
    # email on transitions; NEVER gates enforcement. A notice refused by the
    # dispatcher (quiet hours, caps, SMTP failure) stays pending and is
    # retried next scan (audit C1, 2026-08-22). Fail-safe like its neighbors.
    if vantage_trust is not None:
        try:
            vt_block = vantage_trust.evaluate()
            vantage_trust.note(vt_block)
            notice = vantage_trust.pending()
            if notice is not None:
                if notifier.send_vantage_trust_alert(
                        notice["old"], notice["new"],
                        notice["block"].get("reason") or "",
                        notice["block"]):
                    vantage_trust.mark_sent(notice)
            if collector:
                collector.update_vantage_trust(vt_block)
        except Exception as e:
            logger.error("Vantage-trust check failed (non-fatal): %s", e)

    # === Three-state node health (2026-10-18) ===
    # registered / posting / parent letter per monitored node, from this
    # scan's records plus bounded extra fetches (<= 10 s, short timeouts, no
    # 429 retry, none at all when the scan found a violation) for nodes the
    # walk did not reach. Pure observation; placed after the watchdog /
    # dark-guest / listener steps so it cannot delay an enforcement action;
    # only the image cross-check and alert delivery follow it (audit C1).
    _record_node_health(node_health, result, collector, api_client)
    # Team status page feed (2026-10-20): hand the fresh /status snapshot to the
    # exporter's worker thread. Returns at once; never raises into the scan.
    _export_public(public_exporter, collector)

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
        # Refresh the notifier-derived /status blocks on EVERY scan (2026-10-12):
        # before this, an All-clear scan returned here and email / qrz /
        # notifications (quiet_hours_active) / unusual-externals only refreshed
        # after a scan WITH a problem — so they went stale for days.
        if collector:
            try:
                collector.update_email_health(notifier)
                collector.update_qrz_health(notifier)
                collector.update_notification_state(notifier)
                collector.update_unusual_externals()
            except Exception as e:
                logger.error(f"Status refresh after All-clear scan failed: {e}")
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
        # Item A: attach the evidence shot captured CLOSEST to detection time —
        # shot 0, or (if it failed/timed out) the earliest burst shot. Never the
        # stale end-of-scan image while a good near-detection shot exists.
        if capturer is not None:
            event_bubble = capturer.best_shot(result.timestamp)
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
        attach_bubble = corroborating_attachment(event_bubble)
        local_render = False
        secondary_local = None
        # Fallback (Bennett, 2026-07-17): when the official-map shot does
        # not show the violation (its cache rarely re-renders within the
        # seconds a violation lives before auto-disconnect), attach OUR OWN
        # render of the detection-time topology instead. Preserved alongside
        # the shots in bubble_maps_events/ (same stamp, "_local" tag).
        if attach_bubble is None and result.has_problems and bubble_gen is not None:
            attach_bubble = _render_local_evidence(result, bubble_gen)
            local_render = attach_bubble is not None
            if local_render:
                logger.info("bubble_map: local evidence render attached "
                            "in place of the official map: %s", attach_bubble)
            else:
                logger.warning("Local evidence render failed — violation "
                               "email will go out without an attachment")
        # Both maps (Bennett, 2026-09-06): the official shot is drawn from
        # the hub's point of view and shows a monitor-only link as two-way,
        # so when the offender has one, our own render (both ends' reports,
        # dashed one-way arrow) rides along as a second attachment.
        elif (attach_bubble is not None and result.has_problems
              and bubble_gen is not None
              and any(event_has_monitor_link(result, ev)
                      for ev in result.bridging_events)):
            secondary_local = _render_local_evidence(result, bubble_gen)
            if secondary_local is not None:
                logger.info("bubble_map: monitor link involved — attaching both "
                            "the official shot and the local render: %s",
                            secondary_local)
            else:
                logger.warning("Local evidence render failed — violation email "
                               "will carry the official map only")
        sent = notifier.notify(
            result,
            bubble_image_path=str(attach_bubble) if attach_bubble else None,
            bubble_image_is_local_render=local_render,
            rpt_link_info=_rpt_link_info_line(rpt_holder),
            disc_outcomes=disc_outcomes,
            secondary_local_render=str(secondary_local) if secondary_local else None,
        )
        logger.info(f"Sent or queued {sent} notification(s)")

        # Hidden-path alert: image detects bridging but API has no events.
        # Coherence (audit S2): the official map is drawn from the same
        # stale records, so an `unconfirmed` guest shows there with its old
        # network at distance >= 3 while the API walk (rightly) stopped at
        # the guest — that is not a hidden path; say so and do not alert.
        # Known residual (round-2 S6): while ANY node is unconfirmed, every
        # CV hidden-path alert is muted (the CV detector is demoted and
        # Bennett-only; the structured edge-union check still logs).
        _fresh_unconfirmed = [u.get("node") for u in (getattr(result, "unconfirmed", None) or [])
                              if u.get("state") != "past_grace"]
        if (crosscheck_result and crosscheck_result.possible_hidden_path_bridging
                and not result.has_problems
                and _fresh_unconfirmed):
            # (past_grace nodes do not mute the alert — round-4 audit S1)
            logger.info("Hidden-path cross-check suppressed: the map's extra depth "
                        "comes from unconfirmed (pre-join) guest record(s) %s",
                        _fresh_unconfirmed)
        elif (crosscheck_result and crosscheck_result.possible_hidden_path_bridging
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

    # === Phase 3: Auto-disconnect ===
    # MOVED to detection time (2026-06-21): auto-disconnect now fires from
    # GraphAnalyzer.on_violation as each event is detected (see
    # _handle_detection_disconnect), so a transient violator is acted on within
    # the re-verify window rather than after the full walk. No end-of-scan
    # disconnect pass remains. Note: this means a disconnect can now precede the
    # violation email (sent above) by the scan duration — the violation and the
    # disconnect result are both logged in real time; the email follows.

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
        max_dragged_in_nodes=config.get("max_dragged_in_nodes", 30),
        permit_listeners=_listener_cfg(config)["permit"],
        linkless_fresh_seconds=config.get(
            "linkless_fresh_seconds", GraphAnalyzer.DEFAULT_LINKLESS_FRESH_SECONDS),
        coherence_enabled=_coherence_cfg(config)["enabled"],
        max_unconfirmed_seconds=_coherence_cfg(config)["max_unconfirmed_seconds"],
    )
    if analyzer.permit_listeners:
        logger.warning("Phase 2 listeners.permit is ON: guests whose every "
                       "AllStar link is monitor-only are permitted")
    _cc = _coherence_cfg(config)
    if _cc["enabled"]:
        logger.info("Coherence gate ON: a guest's outside link counts only when its own "
                    "record names its attach node; re-look %.0f s (node cooldown %.0f s, "
                    "global floor %.0f s); past %.0f s flagged past_grace (still not "
                    "enforced); live_mesh_veto=%s",
                    _cc["relook_delay_seconds"], _cc["relook_node_cooldown_seconds"],
                    _cc["relook_global_min_seconds"], _cc["max_unconfirmed_seconds"],
                    _cc["live_mesh_veto"])
    else:
        logger.warning("Coherence gate OFF (coherence.enabled: false) — the analyzer "
                       "judges stale guest records again; the re-verify keeps the "
                       "no-evidence rules (unreadable/empty record = no cut), the live "
                       "AMI bridge check and the narrower outside filter")
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

    # Analytics observation recorder (separate analytics.db; pure observation,
    # never affects detection). None if disabled or on any init error.
    analytics = _build_analytics(config)
    # Three-state node health (2026-10-18). Built once; a node-list change
    # needs a restart (like link_watch on/off). None when disabled.
    node_health = _build_node_health(config, analytics)
    # Team status page feed (2026-10-20). None when disabled; rebuilt on SIGHUP
    # (which also re-reads the SAS from the keychain).
    public_exporter = _build_public_export(config, collector)

    # Read-only app_rpt vantage reader (SSH). None if disabled or misconfigured.
    rpt_reader = build_rpt_reader(config)

    # Local bubble-map renderer (presentation only; served at /bubble.png).
    # Reuses the notifier's QRZ client for optional operator-name annotation.
    bubble_gen = build_bubble_map_generator(
        config, qrz_client=getattr(notifier, "qrz", None))

    # Between-scan link-count tripwire + post-violation watch mode (loop mode
    # only — single-scan modes have no "between scans"). The watcher gets its
    # OWN AutoDisconnector + ASLApiClient: requests.Session is not thread-safe,
    # so the watch thread must never share the scan thread's client. Cost: a
    # separate disconnect-cooldown map (worst case one redundant, harmless SSH
    # kick). Emails never leave the watch thread — escalations queue to the
    # main loop (_drain_escalations).
    watcher = None
    watch_api = None
    dark_api = None
    # Bound BEFORE the watcher thread starts: its re-kick closure reads this
    # name (the monitor itself is built further down, in every mode).
    vantage_trust = None

    def _mesh_trusted_main() -> bool:
        if vantage_trust is None:
            return False
        try:
            return (vantage_trust.evaluate() or {}).get("trust") == "ok"
        except Exception as e:
            logger.error("vantage_trust evaluate failed (non-fatal): %s", e)
            return False
    scan_now = threading.Event()
    scan_request_fn = None          # change 3: run_scan's re-scan hook (loop mode only)
    if not (args.once or args.dry_run):

        def _trip(reason: str) -> None:
            logger.warning("Immediate out-of-cycle scan requested: %s", reason)
            scan_now.set()
        scan_request_fn = _trip

        # Step 2 trigger B (2026-09-07): keyed-listener veto tracker (see
        # keyed_veto.py — confirmation count, TTL, strikes, consulted-before-
        # expiry, SIGHUP carry). `analyzer` is read through a getter because
        # the loop rebinds it on SIGHUP. Inert while listeners.permit is
        # false (the listener set is empty, so nothing is ever reported).
        keyed_vetoes = None
        try:
            _vn = ((config.get("ami_listener") or {}).get("vantage_node")
                   or (config.get("rpt_reader") or {}).get("vantage_node") or 0)
            keyed_vetoes = KeyedVetoTracker(
                analyzer_getter=lambda: analyzer,
                cfg_getter=lambda: _listener_cfg(config),
                vantage_node=int(_vn) if str(_vn).isdigit() else 0,
                on_trip=_trip, notifier_getter=lambda: notifier,
                listener_ids_getter=lambda: watcher.listener_ids() if watcher else frozenset())
        except Exception as e:
            # A construction failure must never stop the enforcement daemon.
            logger.error("keyed veto tracker unavailable (trigger B off): %s", e)

        # Step 2b (2026-09-07, Bennett): dark-guest tracker. Notice-only until
        # the guest keys toward its own bridge; then a cut through that bridge
        # on the watchdog's rails. Notice times persist across restarts.
        dark_guests = None
        # Own API client + AutoDisconnector (audit C3): the cut runs on a
        # helper thread while the scan thread may be mid-request on the main
        # disconnector's requests.Session. Rebuilt on SIGHUP (holder).
        dark_api = ASLApiClient()
        dark_disc = {"d": None}
        try:
            dark_disc["d"] = AutoDisconnector(config, dark_api)

            def _own_nodes() -> set:
                own = {int(focus_node)} | {int(b) for b in config.get("bridge_nodes", [])}
                d = dark_disc["d"]
                if d is not None:
                    own |= set(int(k) for k in getattr(d, "managed_nodes", {}))
                return own

            _dark_cfg_get = lambda: _dark_cfg(config)
            dark_budget = [0]           # per-scan lookup budget, reset by the tracker
            dark_guests = DarkGuestTracker(
                cfg_getter=_dark_cfg_get,
                disconnector_getter=lambda: dark_disc["d"],
                foreign_fn=lambda u: watcher.foreign_entries(u),   # watcher built below
                notifier_getter=lambda: notifier, on_trip=_trip,
                persist=(collector.set_dark_guest_notices if collector else None),
                is_dry_run=lambda: monitor_only,                       # audit C1
                allowance_fn=lambda: (watcher.listener_allowance() if watcher else 0),
                own_nodes_fn=_own_nodes,
                scan_budget=dark_budget,
                mesh_foreign_fn=lambda: (watcher.mesh_foreign_count() if watcher else None),
                attribute_fn=lambda guest, foreign: _dark_attribute(
                    dark_api, _dark_cfg_get, guest, foreign,
                    exclude=(_own_nodes() | {int(a) for a in config.get("allowlist", [])
                                             if str(a).isdigit()}),
                    stale_minutes=int(config.get("stale_threshold_minutes", 120)),
                    budget=dark_budget),
                listener_ids_fn=lambda: (watcher.listener_ids() if watcher else frozenset()),
                persist_posting=(collector.set_dark_guest_posting if collector else None))
            if collector:
                dark_guests.load_notice_times(collector.dark_guest_notices())
                dark_guests.load_posting_times(collector.dark_guest_posting())
        except Exception as e:
            logger.error("dark-guest tracker unavailable (step 2b off): %s", e)

        def _on_any_keyed(nid: int, alinks: str = "", vantage=None) -> None:
            """AMI keyed dispatcher, routed by MEMBERSHIP (audit S1): a dark
            guest's K goes to the dark tracker only, a listener's K to the
            veto tracker only. Never raises (each tracker is fail-safe)."""
            try:
                n = int(nid)
            except (TypeError, ValueError):
                return
            if dark_guests and n in dark_guests.watch_ids():
                dark_guests.on_keyed(n, alinks, vantage=vantage)
                return
            if keyed_vetoes and n in keyed_vetoes.watch_ids():
                keyed_vetoes.on_keyed(n, alinks, vantage=vantage)

        def _keyed_watch_ids() -> frozenset:
            ids: set = set()
            try:
                if keyed_vetoes:
                    ids |= set(keyed_vetoes.watch_ids())
                if dark_guests:
                    ids |= set(dark_guests.watch_ids())
            except Exception:
                pass
            return frozenset(ids)

        watch_api = ASLApiClient()
        # Bubble-map link-change refresh (2026-07-04): when the watcher sees
        # the vantage mesh set change, ask the generator for a render-only
        # refresh (debounced, own short-lived thread — see bubble_map_gen).
        _bmap_cfg = config.get("bubble_map") or {}
        _refresh_cb = (bubble_gen.request_refresh
                       if bubble_gen is not None
                       and isinstance(_bmap_cfg, dict)
                       and _bmap_cfg.get("refresh_on_link_change", True)
                       else None)
        watcher = build_link_watcher(
            config, rpt_reader, AutoDisconnector(config, watch_api),
            is_dry_run=lambda: monitor_only, on_trip=_trip,
            on_mesh_change=_refresh_cb,
            mesh_trusted_fn=_mesh_trusted_main)
        if watcher is not None:
            watcher.start()
        elif dark_guests is not None:
            # No watcher = no roster/allowance: darkness is recorded, no
            # evidence, no cut (documented in dark_guest.py).
            dark_guests._foreign = None
            logger.warning("dark_guests: link_watch is off — dark guests are recorded "
                           "only; no evidence, no cut")

    # AMI push listener (phase 2, 2026-07-03): on a vantage link-change
    # event it wakes the watcher for an immediate tick, collapsing the
    # ~60s poll latency to seconds. Purely additive — if AMI/tunnel is
    # down, watcher polling continues unaffected. Requires the watcher.
    # NOTE: ami_listener config/credential changes need a daemon restart
    # (the tunnel + session are not rebuilt on SIGHUP by design).
    # Vantage-trust gating (2026-08-22): consumes the external vantage-health
    # monitor's output (local status file). Constructed in every mode —
    # evaluate() is a read-only local file read. Guarded like the other
    # presentation-only builders: a construction failure must never stop the
    # enforcement daemon (audit C2, 2026-08-22). (`vantage_trust` is bound to
    # None earlier, before the watcher thread starts.)
    try:
        vantage_trust = VantageTrustMonitor(config)
        logger.info(vantage_trust.describe())
    except Exception as e:
        logger.error("vantage_trust unavailable (non-fatal): %s", e)

    # Phase 2 listener notice cadence (2026-09-07). The last-sent time is
    # persisted through the collector so a restart does not re-send.
    listener_notice = None
    try:
        listener_notice = ListenerNotice(
            interval_hours=_listener_cfg(config)["notice_interval_hours"],
            last_sent_ts=collector.listener_notice_last_sent() if collector else None)
    except Exception as e:
        logger.error("listener_notice unavailable (non-fatal): %s", e)

    ami = None            # primary vantage (QSO caption source)
    amis: list = []       # step 2b: one listener per enabled vantage
    if watcher is not None:
        amis = build_ami_listeners(config, on_link_change=watcher.wake,
                                   on_listener_keyed=_on_any_keyed,
                                   listener_ids_provider=_keyed_watch_ids)
        for a in amis:
            a.start()
        if amis:
            ami = amis[0]
            # QSO activity (2026-07-06): the listener derives network-wide
            # audio activity from keyed indications at the vantage. Surface
            # it in /status and on the map caption. Presentation only.
            collector.attach_qso_source(ami)
            if bubble_gen is not None:
                bubble_gen.activity_provider = ami.qso_caption

    try:
        if args.once or args.dry_run:
            # monitor_only MUST gate the disconnect side effect too, not just
            # email — otherwise `--once` during a monitor-only soak would perform
            # real SSH disconnects. (Audit CRITICAL, 2026-06-21.)
            single_dry_run = args.dry_run or monitor_only
            notifier.set_dry_run(single_dry_run)
            try:
                run_scan(analyzer, notifier, disconnector, focus_node,
                         api_client=api_client, collector=collector,
                         dry_run=single_dry_run, enable_image_crosscheck=enable_image,
                         capturer=capturer, analytics=analytics,
                         rpt_reader=rpt_reader, watcher=watcher,
                         bubble_gen=bubble_gen, vantage_trust=vantage_trust,
                         listener_notice=listener_notice,
                         coherence_cfg=_coherence_cfg(config),
                         node_health=node_health,
                         public_exporter=None)   # single-shot / dry runs never feed the team page (audit S3)
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
                            max_dragged_in_nodes=new_config.get(
                                "max_dragged_in_nodes", 30),
                            permit_listeners=_listener_cfg(new_config)["permit"],
                            linkless_fresh_seconds=new_config.get(
                                "linkless_fresh_seconds",
                                GraphAnalyzer.DEFAULT_LINKLESS_FRESH_SECONDS),
                            coherence_enabled=_coherence_cfg(new_config)["enabled"],
                            max_unconfirmed_seconds=_coherence_cfg(
                                new_config)["max_unconfirmed_seconds"],
                        )
                        new_notifier = Notifier(new_config)
                        # Never raises — None if disabled/misconfigured; re-reads the SAS.
                        new_public_exporter = _build_public_export(new_config, collector)
                        new_monitor_only = new_config.get("monitor_only", False)
                        new_health_interval = new_config.get(
                            "status_server", {}
                        ).get("health_check_interval_seconds", 300)
                        # Never raises — returns None if disabled/misconfigured.
                        new_rpt_reader = build_rpt_reader(new_config)
                        new_bubble_gen = build_bubble_map_generator(
                            new_config,
                            qrz_client=getattr(new_notifier, "qrz", None))
                        # Watcher's dedicated disconnector, rebuilt against the
                        # new config (reuses the watcher's own api client).
                        new_watch_disconnector = (
                            AutoDisconnector(new_config, watch_api)
                            if watcher is not None else None)
                        # Dark-guest tracker's own disconnector (step 2b).
                        new_dark_disconnector = (
                            AutoDisconnector(new_config, dark_api)
                            if dark_guests is not None else None)
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
                        # Close the outgoing notifier's QRZ session before
                        # rebinding (audit 2026-07-04, A5 — each reload
                        # otherwise orphans a live requests.Session).
                        try:
                            if getattr(notifier, "qrz", None):
                                notifier.qrz.close()
                        except Exception:
                            pass
                        config = new_config
                        disconnector = new_disconnector
                        if dark_guests is not None:
                            dark_disc["d"] = new_dark_disconnector
                        # Change 3: the CONNECTING grace clocks must survive a
                        # reload (round-2 audit S5), like the keyed vetoes.
                        try:
                            new_analyzer._connecting_first_seen = dict(
                                getattr(analyzer, "_connecting_first_seen", {}) or {})
                        except Exception as e:
                            logger.error("connecting-grace carry-over failed: %s", e)
                        # Coherence: the unconfirmed clocks survive a reload too
                        # (unless the reload turned the gate off — audit A4).
                        try:
                            if new_analyzer.coherence_enabled:
                                new_analyzer._unconfirmed_first_seen = dict(
                                    getattr(analyzer, "_unconfirmed_first_seen", {}) or {})
                                new_analyzer._incoherent_warned = set(
                                    getattr(analyzer, "_incoherent_warned", set()) or set())
                        except Exception as e:
                            logger.error("coherence clock carry-over failed: %s", e)
                        try:
                            if keyed_vetoes:
                                keyed_vetoes.carry_to(new_analyzer)
                        except Exception as e:
                            logger.error("keyed veto carry-over failed: %s", e)
                        analyzer = new_analyzer
                        focus_node = new_focus_node
                        notifier = new_notifier
                        # Swap the exporter and CLOSE the old one: its trailing timer /
                        # in-flight retry must not push again with the old SAS or URL.
                        old_public_exporter, public_exporter = public_exporter, new_public_exporter
                        if old_public_exporter is not None:
                            try:
                                old_public_exporter.close()
                            except Exception as e:      # noqa: BLE001
                                logger.error("public export close failed (non-fatal): %s", type(e).__name__)
                        health_check_interval = new_health_interval
                        rpt_reader = new_rpt_reader
                        # Refresh capability survives the reload: the new
                        # generator inherits the last scan's topology so a
                        # link-change refresh before the next scan still
                        # renders (2026-07-04). Never raises.
                        if new_bubble_gen is not None and bubble_gen is not None:
                            new_bubble_gen.carry_last_from(bubble_gen)
                        if new_bubble_gen is not None and ami is not None:
                            new_bubble_gen.activity_provider = ami.qso_caption
                        bubble_gen = new_bubble_gen
                        # Rebuild the capturer against the (possibly changed)
                        # focus_node and evidence_capture settings, and re-wire
                        # it to the freshly-constructed analyzer.
                        capturer = EvidenceCapturer(new_focus_node, new_config)
                        analyzer.on_first_detection = (
                            lambda res, c=capturer: c.trigger(res.timestamp))
                        # Refresh analytics role sets from the new config (the DB
                        # connection persists; enabling/disabling analytics needs
                        # a restart). Fail-safe — never breaks the reload.
                        if analytics:
                            try:
                                analytics.update(_analytics_roles(new_config))
                            except Exception as e:
                                logger.error("Analytics role refresh failed: %s", e)
                        # Hot-swap the watcher's config/reader/disconnector.
                        # Turning link_watch on/off requires a restart (like
                        # analytics); a reload that disables the READER idles
                        # the watcher via clear_reader(). Fail-safe.
                        if watcher is not None:
                            try:
                                lw_cfg = new_config.get("link_watch") or {}
                                if not (isinstance(lw_cfg, dict)
                                        and lw_cfg.get("enabled", False)) \
                                        or new_rpt_reader is None:
                                    watcher.clear_reader()
                                    logger.warning(
                                        "link_watch idled by reload (link_watch "
                                        "or rpt_reader disabled); a later reload "
                                        "that re-enables both resumes it")
                                else:
                                    watcher.update(
                                        cfg=lw_cfg, reader=new_rpt_reader,
                                        disconnector=new_watch_disconnector)
                            except Exception as e:
                                logger.error("link_watch reload update "
                                             "failed: %s", e)
                            # Rebind the mesh-change presentation hook to the
                            # NEW generator (or drop it if the reload disabled
                            # the bubble map / the refresh option).
                            try:
                                b = new_config.get("bubble_map") or {}
                                refresh_on = (isinstance(b, dict)
                                              and b.get("enabled", False)
                                              and b.get("refresh_on_link_change",
                                                        True))
                                watcher.set_mesh_change_callback(
                                    new_bubble_gen.request_refresh
                                    if refresh_on and new_bubble_gen is not None
                                    else None)
                            except Exception as e:
                                logger.error("bubble refresh rebind "
                                             "failed: %s", e)
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
                        # Phase 2 listener state on reload — its OWN try
                        # block so a bad vantage_trust: block cannot skip
                        # it (audit S4). Cadence clock carried; falls back
                        # to the persisted last-sent time. An explicit
                        # permit=false clears the watcher's listener state
                        # now rather than at the next complete scan.
                        try:
                            new_ln = ListenerNotice(
                                interval_hours=_listener_cfg(new_config)[
                                    "notice_interval_hours"],
                                last_sent_ts=collector.listener_notice_last_sent())
                            if listener_notice is not None:
                                new_ln.carry_state_from(listener_notice)
                            listener_notice = new_ln
                            if (not analyzer.permit_listeners
                                    and watcher is not None):
                                watcher.set_listeners([], 0)
                        except Exception as e:
                            logger.error("listener_notice reload update "
                                         "failed (non-fatal): %s", e)
                        # Vantage-trust: rebuild from the new config but
                        # carry transition/cooldown state so a reload
                        # neither re-baselines nor re-announces (2026-08-22).
                        try:
                            new_vt = VantageTrustMonitor(new_config)
                            if vantage_trust is not None:
                                new_vt.carry_state_from(vantage_trust)
                            vantage_trust = new_vt
                            logger.info(vantage_trust.describe())
                        except Exception as e:
                            logger.error("vantage_trust reload update "
                                         "failed: %s", e)
                        logger.info("Config reloaded successfully.")

                notifier.set_dry_run(monitor_only)
                if keyed_vetoes:
                    keyed_vetoes.expire()
                try:
                    run_scan(analyzer, notifier, disconnector, focus_node,
                             api_client=api_client, collector=collector,
                             dry_run=monitor_only,
                             enable_image_crosscheck=enable_image,
                             capturer=capturer, analytics=analytics,
                             rpt_reader=rpt_reader, watcher=watcher,
                             bubble_gen=bubble_gen,
                             vantage_trust=vantage_trust,
                             listener_notice=listener_notice,
                             coherence_cfg=_coherence_cfg(config),
                             veto_status=keyed_vetoes.status if keyed_vetoes else None,
                             dark_tracker=dark_guests,
                             scan_request=scan_request_fn,
                             node_health=node_health, public_exporter=public_exporter)
                except Exception as e:
                    logger.exception("run_scan crashed: %s", e)
                    try:
                        notifier.report_error("Scan crashed", str(e), exc=e)
                    except Exception as report_err:
                        logger.error("report_error failed: %s", report_err)

                # Repeat-offender escalations queued by the watch thread are
                # emailed here, on the main thread (notifier is not used from
                # the watch thread). Never raises.
                _drain_escalations(watcher, notifier)

                # Quiet-hours deferral (2026-10-12): deliver alerts queued
                # overnight once quiet hours end. No-op while quiet; never raises.
                try:
                    flushed = notifier.flush_deferred()
                    if flushed:
                        logger.info(f"Delivered {flushed} deferred (quiet-hours) alert(s)")
                except Exception as e:
                    logger.error(f"flush_deferred failed: {e}")

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

                # Sleep in small increments to respond promptly to shutdown
                # and to the watch thread's "scan now" tripwire signal.
                for _ in range(sleep_secs):
                    if _shutdown:
                        break
                    if scan_now.is_set():
                        scan_now.clear()
                        logger.info("Waking early for tripwire-requested scan")
                        break
                    time.sleep(1)

            for a in amis:
                a.stop()                 # closes AMI socket + SSH tunnel
            if watcher is not None:
                # Join briefly so watch_api isn't closed under a mid-flight
                # API call in the watch thread. A tick stuck in the re-verify
                # sleep just gets abandoned (daemon thread) — harmless.
                watcher.stop()
                watcher.join(timeout=5)
            logger.info("Shutdown complete.")
    finally:
        api_client.close()
        if watch_api is not None:
            watch_api.close()
        if dark_api is not None:
            try:
                dark_api.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
