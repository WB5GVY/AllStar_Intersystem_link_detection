"""Between-scan link-count tripwire + post-violation watch mode.

A background thread polls the read-only SSH vantage reader (rpt_reader.py)
BETWEEN full scans and does two jobs:

TRIPWIRE — the mesh link count is the cheapest violation signal: a bridging
event drags foreign nodes into the mesh, so the count spikes within seconds
(researched 2026-06-30; a flood converges fast). When the count rises faster
than `rate_per_minute` or exceeds the ROLLING baseline (median of recent
samples) by `count_margin`, the watcher asks the daemon for an immediate
out-of-cycle full scan via the `on_trip` callback. The tripwire never
detects/alerts by itself — depth-based detection stays with the API walk;
this only collapses the up-to-300s poll latency when something is happening.

WATCH MODE — the tier-2 "extra sampling" of the repeat-offender escalation
ladder (decided 2026-07-02). After a violation, `enter_watch()` registers the
offender for `watch_window_minutes`. While any watch is active the poll rate
increases. Each watched offender runs a small state machine:

    PENDING_GONE --offender absent--> ARMED --offender present--> re-kick
         ^                                                          |
         +---------- verified re-offense (strike) ------------------+

A reappearance alone is NOT a strike — the offender may have reconnected as
an innocent leaf. The re-kick goes through AutoDisconnector.attempt_disconnect,
whose re-verify chain (still connected / still alive / STILL BRIDGING outside
the system / flag files / cooldown) is the sole authority; only a verified
`disconnected` outcome counts as a strike. At `strike_threshold` verified
strikes the watcher queues ONE escalation (drained by the main loop into a
REPEAT_OFFENDER email that bypasses quiet hours — persistent re-offense is
exactly the case worth waking someone for).

Threading notes: the watcher owns a DEDICATED AutoDisconnector + ASLApiClient
(requests.Session is not thread-safe; sharing the scan thread's client would
race). The cost is a separate disconnect-cooldown map — the worst case is one
redundant SSH kick of an already-gone node, which is harmless. Emails are
never sent from this thread: escalations queue to the main loop. Everything
here is fail-safe — no exception may escape into the daemon.
"""

from __future__ import annotations

import logging
import queue
import statistics
import threading
import time
from collections import deque
from datetime import datetime
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Hard floor between watcher ticks regardless of wake pressure — each tick
# opens a fresh SSH session to the vantage node (audit 2026-07-03 #4, S1).
_MIN_TICK_SPACING_S = 5
# Tripwire: the smallest link-count change that counts as growth (a 1-node
# wobble is jitter) — used by the rate rule and by re-fire muting alike.
_TRIP_MIN_DELTA = 2
# Re-fire muting: consecutive 60 s-cadence samples below the scanned level
# before the level follows the count down / the memory clears (mirrors the
# two-read discipline of absent_confirm_polls).
_PLATEAU_CONFIRM_SAMPLES = 2


@dataclass
class WatchEntry:
    """One offender under post-violation watch."""
    offender: int
    event: object                  # the original BridgingEvent (duck-typed)
    expires_at: float              # time.monotonic() deadline
    armed: bool = False            # True once the offender has been seen ABSENT
    armed_at: float = 0.0          # time.monotonic() of that absence sighting
    watched_at: float = 0.0        # time.monotonic() the watch was created (= the cut)
    absent_reads: int = 0          # consecutive vantage reads without the offender
    strikes: int = 0               # verified re-offenses (re-kick succeeded)
    reappearances: int = 0         # all present-after-absent sightings
    escalated: bool = False


@dataclass
class Escalation:
    """Queued for the main loop to email (never sent from the watch thread)."""
    offender: int
    callsign: str
    strikes: int
    reappearances: int
    path_description: str
    window_minutes: int


@dataclass
class WatchdogAlarm:
    """Sustained link-state excess (max-prefix analogue, Bennett 2026-07-21).
    Queued for the main loop, which owns attribution + enforcement — this
    thread only measures. sample holds the first few foreign entries for
    the log/email record."""
    foreign_count: int
    threshold: int
    sample: list


class LinkWatcher(threading.Thread):
    """Daemon thread: tripwire sampling + watch-mode enforcement."""

    def __init__(self, cfg: dict, reader, disconnector,
                 is_dry_run: Callable[[], bool],
                 on_trip: Callable[[str], None],
                 on_mesh_change: Optional[Callable] = None,
                 mesh_trusted_fn: Optional[Callable[[], bool]] = None):
        super().__init__(name="link-watch", daemon=True)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()   # async tick request (AMI listener)
        self.escalations: "queue.Queue[Escalation]" = queue.Queue()
        self._reader = reader
        self._disconnector = disconnector
        # Coherence (2026-10-12): the re-kick passes a FRESH vantage read and
        # this trust predicate to attempt_disconnect so a reappearance is cut
        # only on a coherent record the live mesh does not contradict.
        self._mesh_trusted_fn = mesh_trusted_fn
        self._is_dry_run = is_dry_run
        self._on_trip = on_trip
        # Presentation hook (bubble-map refresh, 2026-07-04): called with the
        # vantage snapshot when the mesh SET changes between usable reads.
        # Must return fast and never raise (both enforced at the call site).
        self._on_mesh_change = on_mesh_change
        self._last_mesh: Optional[frozenset] = None
        self._last_change_scan = 0.0   # monotonic; mesh-change scan cooldown
        # Link RESTART detection (2026-09-07, step 2 trigger A): per adjacent
        # peer, (reconnects, uptime_s) from the last usable read. A mode
        # change (*2 <-> *3 <-> *75) kills and re-makes the link with the
        # SAME peer, so membership does not change and AMI stays silent
        # (measured 12:16/12:17 CDT); only the reconnect counter and the
        # uptime reset betray it. Also catches a leave+rejoin between ticks.
        self._last_adjacent: dict[str, tuple[int, int]] = {}
        self.restart_ignore_ids: frozenset = frozenset()   # focus/bridges/managed
        self._last_restart_scan = 0.0   # own cooldown (audit S1: must never
                                        # consume the membership-change budget)
        self.last_restart: Optional[dict] = None   # for /status
        self._watches: dict[int, WatchEntry] = {}
        self._samples: deque = deque()      # (monotonic_ts, count); maxlen set in _apply_cfg
        self._last_trip = 0.0
        # Tripwire re-fire muting (2026-09-09): the mesh count at the last
        # trip. While the count sits below it + _TRIP_MIN_DELTA the COUNT rule
        # stays quiet (that level was already scanned). It follows the count
        # down / clears only after _PLATEAU_CONFIRM_SAMPLES consecutive
        # 60 s-cadence samples of the same kind (below the level, resp. under
        # baseline + margin); a wobbling count keeps it pinned high (mute-more
        # direction; regular 300 s and mesh-change 180 s scans still run).
        # A SIGHUP that LOWERS count_margin leaves a set plateau in force
        # (fail-quiet) until the count moves.
        self._trip_plateau: Optional[int] = None
        self._trip_plateau_logged = False
        self._plateau_low_n = 0        # consecutive 60 s samples below the plateau
        self._plateau_low_max = 0      # the highest of those (the new level)
        self._plateau_under_n = 0      # consecutive 60 s samples under baseline + margin
        # Link-state watchdog (2026-07-21): mesh entries the last full scan's
        # API topology cannot account for, sustained over confirm_polls ticks,
        # queue an enforcement alarm. Roster is fed by the main loop per scan.
        self.watchdog_alarms: "queue.Queue[WatchdogAlarm]" = queue.Queue()
        self._roster_ids: frozenset = frozenset()
        self._roster_callsigns: frozenset = frozenset()
        self._roster_at = 0.0            # monotonic; 0 = never fed
        self._wd_streak = 0
        self._wd_last_foreign = 0
        self._wd_last_foreign_at = 0.0    # monotonic of the last measurement
        self._last_wd_alarm = 0.0
        self.wd_last_action: Optional[dict] = None   # set by main-loop drain
        # Phase 2 listeners (2026-09-07): permitted all-monitor guests. The
        # vantage mesh contains the whole outside mesh behind their monitor
        # links (app_rpt appends every neighbor list), flat and unwalked, so
        # those entries cannot be attributed per node. The watchdog therefore
        # runs against an ALLOWANCE frozen at the complete scan that first
        # classified the current listener set — never recomputed per scan,
        # so a slowly growing ghost still trips it. Listener ids are also
        # exempt from watch re-kicks (a former offender returning as a
        # listener is not a re-offense).
        self._listener_ids: frozenset = frozenset()
        self._listener_attach: dict = {}       # listener id -> attach node
        self._listener_allowance = 0
        self._listener_since = 0.0
        # Change 3 (2026-09-08): listener id -> tuple of its outside branch
        # ids as of the last complete scan that reported them. The allowance
        # is re-frozen when the BRANCH set changes (a listener adding its
        # first outside link — live 15:01-15:03: set unchanged, allowance
        # stayed 0, watchdog alarmed every 5 min on a 75-121 entry mesh),
        # and may only RISE during a short settle window after such a
        # change (the far mesh lands in the vantage table seconds AFTER the
        # scan that first saw the branch). Outside the window it is frozen,
        # so a slowly growing ghost wedge still trips the watchdog.
        self._listener_branches: dict = {}
        self._branches_changed_at = 0.0
        # Change 3 round 2: a fresh violation revoked a listener -> the next
        # complete scan must re-size the allowance even if the remaining
        # set looks unchanged (audit S4).
        self._refreeze_pending = False
        self._last_branch_refreeze = 0.0
        # Watchdog alert emails withheld while a listener is present (the
        # main loop increments; reset when the listener set changes).
        self.wd_listener_suppressed_alerts = 0
        self._apply_cfg(cfg)

    # --- configuration -----------------------------------------------------

    def _apply_cfg(self, cfg: dict) -> None:
        self.poll_interval = int(cfg.get("poll_interval_seconds", 60))
        self.read_timeout = int(cfg.get("read_timeout_seconds", 10))
        self.min_baseline_samples = int(cfg.get("min_baseline_samples", 10))
        self.count_margin = int(cfg.get("count_margin", 5))
        self.rate_per_minute = float(cfg.get("rate_per_minute", 5))
        self.trip_cooldown = int(cfg.get("trip_cooldown_seconds", 300))
        self.watch_window_s = int(cfg.get("watch_window_minutes", 45)) * 60
        self.watch_poll_interval = int(cfg.get("watch_poll_interval_seconds", 15))
        self.strike_threshold = int(cfg.get("strike_threshold", 3))
        # D1 (2026-09-08): a full-scan re-detection counts a strike only when
        # the offender's record was fetched this long AFTER the watcher saw
        # it absent — stats.allstarlink.org lags real state by up to ~30 s
        # (25 s measured 2026-09-07), so a record fetched sooner can still
        # describe the pre-cut topology.
        self.stale_record_margin_s = max(0, int(
            cfg.get("stale_record_margin_seconds", 60)))
        # Audit 2026-09-08 S-F: one truncated-but-ok vantage read must not
        # arm a watch (a later fresh re-detection of a CONTINUOUS violation
        # would then strike). Require this many consecutive absent reads.
        self.absent_confirm_polls = max(1, int(cfg.get("absent_confirm_polls", 2)))
        # Mesh-MEMBERSHIP change → one out-of-cycle full scan (2026-07-04,
        # Bennett: single joins should confirm on the map in seconds, not
        # wait out the 300s cadence — the tripwire only catches FLOODS).
        # The cooldown bounds API load under flapping; the tripwire keeps
        # its own separate cooldown/thresholds for storm response.
        self.scan_on_mesh_change = bool(cfg.get("scan_on_mesh_change", True))
        # Change 3: settle window after a listener branch change during which
        # the allowance may RISE (the far mesh lands in the vantage table
        # seconds after the scan that first saw the branch). Must exceed the
        # worst-case latency of the scan that observes it (mesh-change scan
        # cooldown 180 s + a scan), so default 420 (audit S6).
        self.branch_settle_s = max(0, int(cfg.get("listener_branch_settle_seconds", 420)))
        # Minimum spacing between branch-change re-freezes (round-2 audit S2).
        # Upper clamp 3600: the settle-window re-open on a blocked change is
        # bounded only while real re-freezes keep happening (soft-spot audit A5).
        self.branch_refreeze_min_s = min(3600, max(0, int(
            cfg.get("listener_branch_refreeze_min_seconds", 300))))
        self.mesh_change_scan_cooldown = int(
            cfg.get("mesh_change_scan_cooldown_seconds", 180))
        # Same-peer link restart -> one out-of-cycle full scan (shares the
        # membership-change cooldown: one confirmation scan per window).
        self.scan_on_link_restart = bool(cfg.get("scan_on_link_restart", True))
        self.link_restart_scan_cooldown = int(
            cfg.get("link_restart_scan_cooldown_seconds", 180))
        maxlen = int(cfg.get("baseline_window_samples", 240))
        with self._lock:
            self._samples = deque(self._samples, maxlen=maxlen)
        # Link-state watchdog knobs (nested block; default OFF — enabling an
        # autonomous enforcement trigger must be an explicit config act).
        wd = cfg.get("watchdog") or {}
        self.wd_enabled = bool(wd.get("enabled", False))
        self.wd_threshold = max(5, int(wd.get("foreign_threshold", 25)))
        self.wd_confirm = max(1, int(wd.get("confirm_polls", 2)))
        self.wd_alarm_cooldown = max(60, int(
            wd.get("alarm_cooldown_seconds", 600)))
        self.wd_roster_max_age = max(300, int(
            wd.get("roster_max_age_seconds", 900)))

    def update(self, cfg: dict = None, reader=None, disconnector=None) -> None:
        """SIGHUP hot-swap. Baseline samples and active watches survive.
        A reload that DISABLES the reader must call clear_reader() instead
        (None arguments here mean "unchanged")."""
        if cfg is not None:
            self._apply_cfg(cfg)
        if reader is not None:
            self._reader = reader
        if disconnector is not None:
            self._disconnector = disconnector

    def clear_reader(self) -> None:
        """Reload disabled the rpt_reader — watcher idles until re-enabled."""
        self._reader = None

    def set_mesh_change_callback(self, cb: Optional[Callable]) -> None:
        """SIGHUP rebind for the presentation hook (None disables it).
        Separate from update() so None can mean 'remove', not 'unchanged'."""
        self._on_mesh_change = cb

    # --- public API (called from other threads) -----------------------------

    def enter_watch(self, event) -> None:
        """Register a fresh violation's offender for watch mode. Fail-safe."""
        try:
            offender = int(event.offending_node)
        except Exception:
            logger.error("link_watch: event without usable offending_node; "
                         "not watching")
            return
        deadline = time.monotonic() + self.watch_window_s
        with self._lock:
            # A fresh BridgingEvent is proof the node is NOT a listener right
            # now, even if the previous scan registered it as one (the
            # listener→transceive flip is exactly the case to watch; audit
            # S3). _poll_watches drops the watch if a later scan reclassifies.
            # Change 3 (2026-09-08, live 15:58:43): the STALE registration
            # must go NOW — otherwise the very next poll sees the offender
            # in _listener_ids and drops the watch it just entered. Revoke
            # here; the next complete scan re-registers if it really is one.
            entry = self._watches.get(offender)
            # Round-2 audit S5: a stale echo (an event whose record predates
            # the watcher's own absence sighting — see the armed branch
            # below) must not revoke either.
            stale_echo = False
            if entry is not None and entry.armed:
                observed = float(getattr(event, "observed_at", 0.0) or 0.0)
                fresh_after = (max(entry.armed_at, entry.watched_at)
                               + self.stale_record_margin_s)
                stale_echo = observed <= fresh_after
            if offender in self._listener_ids and not stale_echo:
                self._listener_ids = self._listener_ids - {offender}
                self._listener_attach.pop(offender, None)
                self._listener_branches.pop(offender, None)
                self.wd_listener_suppressed_alerts = 0
                if not self._listener_ids:
                    self._listener_allowance = 0
                    self._listener_since = 0.0
                else:
                    # remaining listeners: the allowance still counts the
                    # revoked node's mesh — the next complete scan re-sizes it
                    self._refreeze_pending = True
                logger.warning(
                    "link_watch: listener registration REVOKED for %d — a fresh "
                    "violation is proof it is not a listener now (remaining "
                    "listeners %s, allowance %d%s)", offender,
                    sorted(self._listener_ids) or "none", self._listener_allowance,
                    ", re-freeze at the next scan" if self._listener_ids else "")
            if entry is not None:
                # Already watched: refresh the window and the event (newest
                # path — so watch re-kicks always act on current topology).
                if entry.armed:
                    # The full scan just VERIFIED a fresh violation by this
                    # offender AFTER we watched them leave: a new offense
                    # episode, confirmed by the complete detection chain.
                    # Counting it here closes the path-shift hole (audit
                    # 2026-07-03 #2, S2): a re-offender who comes back via a
                    # different route strikes via the scan even though the
                    # watch re-kick against the old path couldn't verify.
                    # The 15s top-of-hour re-scans of one CONTINUOUS event
                    # do NOT inflate strikes — armed requires an observed
                    # absence in between.
                    #
                    # D1 (2026-09-08): ...and the evidence must be NEWER than
                    # that absence. One scan emits one event per outside
                    # target from a single fetch of the offender's record;
                    # on 2026-09-07 23:42 events 2-4 arrived 77 s after the
                    # cut carrying a record fetched BEFORE it, and struck.
                    # An event whose record predates the absence (plus the
                    # stats-lag margin) is stale — no strike, stay armed; a
                    # real return is caught by the poll re-kick (fresh
                    # re-verify) or by a later scan's fresh fetch.
                    observed = float(getattr(event, "observed_at", 0.0) or 0.0)
                    # Anchored on the LATER of the cut (watch creation) and
                    # the absence sighting (audit 2026-09-08 S6: wake-driven
                    # ticks can arm within seconds of the cut).
                    fresh_after = (max(entry.armed_at, entry.watched_at)
                                   + self.stale_record_margin_s)
                    if observed > fresh_after:
                        entry.armed = False
                        entry.absent_reads = 0
                        self._record_strike_locked(
                            entry, via="full-scan re-detection")
                    else:
                        logger.warning(
                            "link_watch: offender %d re-detected by the full "
                            "scan from a record fetched %.0fs BEFORE the "
                            "watcher saw it absent (+%ds lag margin) — stale "
                            "evidence, NO strike; watch stays armed, window "
                            "and stored path unchanged",
                            offender, max(0.0, fresh_after - observed),
                            self.stale_record_margin_s)
                        return           # a stale echo extends nothing
                entry.expires_at = deadline
                entry.event = event
                logger.info("link_watch: watch window refreshed for offender "
                            "%d (strikes=%d)", offender, entry.strikes)
            else:
                self._watches[offender] = WatchEntry(
                    offender=offender, event=event, expires_at=deadline,
                    watched_at=time.monotonic())
                logger.warning(
                    "link_watch: WATCH MODE entered for offender %d — "
                    "fast-polling every %ds for %d min",
                    offender, self.watch_poll_interval, self.watch_window_s // 60)

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()                 # break the sleep promptly

    def wake(self, reason: str = "") -> None:
        """Request an immediate tick (called from the AMI listener thread).
        The tick itself still runs on THIS thread — enforcement stays
        single-threaded; async sources only collapse the poll latency."""
        logger.info("link_watch: wake requested (%s)", reason or "unspecified")
        self._wake.set()

    def status(self) -> dict:
        """Small snapshot for logging/HA (thread-safe)."""
        with self._lock:
            return {
                "samples": len(self._samples),
                "baseline": self._baseline_locked(),
                "trip_plateau": self._trip_plateau,
                "watches": {o: {"strikes": w.strikes, "armed": w.armed,
                                "reappearances": w.reappearances}
                            for o, w in self._watches.items()},
            }

    # --- link-state watchdog (max-prefix analogue, 2026-07-21) ---------------

    def update_roster(self, topology: dict) -> None:
        """Feed the latest full-scan API topology (main loop, per scan).
        Derives the known-id and known-callsign sets the foreign counter
        excludes. Fail-safe; thread-safe."""
        try:
            # Completeness guard (audit 2026-07-21 S2): a degraded scan (API
            # outage, partial walk — no focus node) must keep the PREVIOUS
            # roster rather than install a thin one that makes legitimate
            # mesh members look foreign. The age gate then idles the
            # watchdog if degradation persists past roster_max_age.
            if not topology or not any(
                    i.get("role") == "focus" for i in topology.values()):
                logger.debug("link_watch: degraded topology — roster kept")
                return
            ids = {str(nid) for nid in topology
                   if not str(nid).startswith("ext_")}
            callsigns = {str(i.get("callsign", "")) for i in topology.values()
                         if i.get("callsign")}
            with self._lock:
                self._roster_ids = frozenset(ids)
                self._roster_callsigns = frozenset(callsigns)
                self._roster_at = time.monotonic()
        except Exception as e:
            logger.error("link_watch: update_roster failed (non-fatal): %s", e)

    def set_listeners(self, ids, foreign_now: Optional[int],
                      foreign_raw: Optional[int] = None) -> None:
        """Feed the permitted-listener set from a COMPLETE full scan (caller
        guarantees completeness — a degraded scan must not call this, so a
        listener that is merely unobserved keeps its allowance). When the set
        CHANGES: freeze the allowance at `foreign_now` (this scan's foreign
        mesh count), drop any watches on listener ids, reset the streak and
        discard alarms queued before the allowance existed. When the set is
        unchanged the allowance is deliberately left frozen. Empty set
        clears everything. Thread-safe; fail-safe."""
        try:
            attach: dict = {}
            branches: dict = {}          # only for entries that REPORT branches
            new_list = []
            for i in (ids or []):
                if isinstance(i, dict):
                    nid = int(i["node"])
                    attach[nid] = i.get("attached_to")
                    if "monitored" in i:  # a retained-unobserved record has none
                        branches[nid] = tuple(sorted(
                            int(x) for x in (i.get("monitored") or [])))
                else:
                    nid = int(i)
                new_list.append(nid)
            new_ids = frozenset(new_list)
            with self._lock:
                if new_ids == self._listener_ids:
                    self._listener_attach.update(attach)
                    # Change 3: same listeners, but did their outside
                    # branch set change (or was a listener just revoked)?
                    # Re-freeze at this scan's count.
                    prev_b = {n: self._listener_branches.get(n) for n in branches}
                    changed = (any(prev_b[n] != branches[n] for n in branches)
                               or (self._refreeze_pending and bool(new_ids)))
                    now = time.monotonic()
                    # The CURRENT foreign count for lowering: the raw count when
                    # the caller supplies it (it passes foreign_now=0 when no
                    # branch was seen, which is a sizing rule, not a count).
                    cur = foreign_raw if foreign_raw is not None else foreign_now
                    # Only when EVERY listener reported its branches this scan
                    # (a retained-unobserved record cannot be sized).
                    all_reported = bool(new_ids) and all(n in branches for n in new_ids)
                    if (not changed and all_reported and cur is not None
                            and int(cur) < self._listener_allowance):
                        # An allowance above the CURRENT foreign count is pure
                        # blindness (a departed guest's mesh, a settle-window
                        # raise that included a transient) — lower it. Lowering
                        # is always the stricter direction (audit S3).
                        old = self._listener_allowance
                        self._listener_allowance = max(0, int(cur))
                        logger.info("link_watch: allowance lowered %d -> %d (foreign "
                                    "count fell)", old, self._listener_allowance)
                    # Snapshot the SIGHUP-hot knobs so one decision cannot mix
                    # old and new values (soft-spot audit A3).
                    refreeze_min_s = self.branch_refreeze_min_s
                    settle_s = self.branch_settle_s
                    if changed and foreign_now is not None:
                        if (now - self._last_branch_refreeze < refreeze_min_s
                                and not self._refreeze_pending):
                            # Round-2 audit S2: a listener adding/dropping a
                            # link every scan must not re-size the allowance
                            # every scan (ghost growth would be absorbed).
                            logger.warning(
                                "link_watch: listener branch set changed again within "
                                "%ds of the last re-freeze — allowance kept at %d "
                                "(settle window re-opened)",
                                refreeze_min_s, self._listener_allowance)
                            self._listener_branches.update(branches)
                            # 2026-09-08 soft spot: the mesh behind THIS change
                            # still has to land, so re-open the settle window
                            # (raise-only) rather than leave the old window to
                            # close under it. The window ends before
                            # last_refreeze + refreeze_min + settle (we are
                            # inside the spacing period); a flapping listener
                            # keeps it open, exactly as the 300 s real
                            # re-freezes already did — and while it flaps the
                            # open window is inert, because the raise below is
                            # an `elif` on `changed`: it runs only on a LATER
                            # scan with UNCHANGED branches (audit S2: a changed
                            # scan never re-sizes upward).
                            self._branches_changed_at = now
                        else:
                            self._refreeze_pending = False   # consumed HERE only
                            self._listener_branches.update(branches)
                            self._branches_changed_at = now
                            self._last_branch_refreeze = now
                            old = self._listener_allowance
                            target = max(0, int(foreign_now))
                            if (target < old and foreign_raw is not None
                                    and int(foreign_raw) > target):
                                # Downward: the far mesh is still draining from
                                # the vantage table (round-2 audit S3) — step
                                # down to the current raw count now and let the
                                # lowering rule follow it to `target`.
                                target = min(old, int(foreign_raw))
                            self._listener_allowance = target
                            self._wd_streak = 0
                            logger.warning(
                                "link_watch: listener branch set changed %s — watchdog "
                                "allowance re-frozen %d -> %d foreign entries",
                                {n: list(b) for n, b in branches.items()}, old,
                                self._listener_allowance)
                    elif (foreign_now is not None
                            and self._branches_changed_at
                            and now - self._branches_changed_at <= settle_s
                            and int(foreign_now) > self._listener_allowance
                            and any(branches.values())):
                        # Settle window: the far mesh is still landing in the
                        # vantage table; the allowance may only rise — and never
                        # above the raw count actually observed (audit A4).
                        old = self._listener_allowance
                        target = int(foreign_now)
                        if foreign_raw is not None:
                            target = min(target, int(foreign_raw))
                        if target > old:
                            self._listener_allowance = target
                            self._wd_streak = 0
                            logger.warning(
                                "link_watch: allowance raised %d -> %d within %ds of a "
                                "listener branch change (mesh still settling)",
                                old, self._listener_allowance, settle_s)
                    return
                if new_ids and foreign_now is None:
                    # No usable vantage snapshot this scan: we cannot size
                    # the allowance. Registering with 0 would freeze the
                    # listener's whole outside mesh as "excess" forever
                    # (audit C1). Keep the previous state; try next scan.
                    logger.warning(
                        "link_watch: listener set %s seen but no vantage "
                        "snapshot to size the allowance — registration "
                        "deferred to the next scan", sorted(new_ids))
                    return
                self._listener_ids = new_ids
                self._listener_attach = {n: attach.get(n, self._listener_attach.get(n))
                                         for n in new_ids}
                self._listener_branches = {
                    n: branches.get(n, self._listener_branches.get(n, ()))
                    for n in new_ids}
                self._branches_changed_at = time.monotonic() if new_ids else 0.0
                self._last_branch_refreeze = self._branches_changed_at
                self._refreeze_pending = False       # a full re-size just happened
                self.wd_listener_suppressed_alerts = 0
                if new_ids:
                    self._listener_allowance = max(0, int(foreign_now))
                    self._listener_since = time.monotonic()
                    dropped = [o for o in self._watches if o in new_ids]
                    for o in dropped:
                        del self._watches[o]
                else:
                    self._listener_allowance = 0
                    self._listener_since = 0.0
                    dropped = []
                self._wd_streak = 0
            discarded = 0
            while True:
                try:
                    self.watchdog_alarms.get_nowait()
                    discarded += 1
                except queue.Empty:
                    break
            if new_ids:
                logger.warning(
                    "link_watch: permitted listener set %s — watchdog allowance "
                    "frozen at %d foreign entries; %d queued alarm(s) discarded; "
                    "watches dropped for %s",
                    sorted(new_ids), self._listener_allowance, discarded,
                    dropped or "none")
            else:
                logger.info("link_watch: listener set cleared — watchdog "
                            "allowance back to 0 (%d queued alarm(s) discarded)",
                            discarded)
        except Exception as e:
            logger.error("link_watch: set_listeners failed (non-fatal): %s", e)

    def listener_ids(self) -> frozenset:
        with self._lock:
            return self._listener_ids

    def listener_attach(self) -> dict:
        """listener id -> the system node it was last seen attached to."""
        with self._lock:
            return dict(self._listener_attach)

    def mesh_foreign_count(self):
        """Foreign entries in the last usable vantage read, or None when the
        watchdog is off or has not measured yet (step 2b: the dark-guest
        tracker skips its SSH union reads while this is 0 — nothing to
        attribute)."""
        if not self.wd_enabled:
            return None
        with self._lock:
            measured = self._roster_at > 0 and self._wd_last_foreign_at > 0
            return self._wd_last_foreign if measured else None

    def listener_allowance(self) -> int:
        """The frozen permitted-listener allowance the watchdog subtracts
        from the foreign count (step 2b: the dark-guest tracker applies the
        same allowance so its evidence bar matches the watchdog's)."""
        with self._lock:
            return int(self._listener_allowance)

    def foreign_entries(self, mesh_nodes) -> list:
        """Mesh entries the last-fed API roster cannot account for. Applies
        the same dedup rules as the bubble overlay: known ids, known
        callsigns, and EchoLink wire-form (3NNNNNN) entries whose
        EchoLink-<id> callsign the API confirmed."""
        with self._lock:
            ids, calls = self._roster_ids, self._roster_callsigns
        out = []
        for mnode in mesh_nodes:
            mstr = str(mnode)
            if mstr in ids or mstr in calls:
                continue
            if mstr.isdigit() and len(mstr) == 7 and mstr.startswith("3"):
                el = mstr[1:].lstrip("0") or "0"
                if f"EchoLink-{el}" in calls:
                    continue
            out.append(mstr)
        return out

    def _process_watchdog(self, mesh_nodes, now: float) -> None:
        """Streak/alarm state machine. Runs on the watch thread per usable
        tick. Measurement only — attribution and any disconnect happen on
        the main loop when it drains watchdog_alarms."""
        if not self.wd_enabled:
            return
        with self._lock:
            roster_age = now - self._roster_at if self._roster_at else None
        if roster_age is None or roster_age > self.wd_roster_max_age:
            # A stale/absent roster must never drive enforcement: without a
            # trustworthy "known" set, everything looks foreign.
            self._wd_streak = 0
            return
        foreign = self.foreign_entries(mesh_nodes)
        self._wd_last_foreign = len(foreign)
        self._wd_last_foreign_at = now
        with self._lock:
            allowance = self._listener_allowance
            effective = len(foreign) - allowance
            if effective >= self.wd_threshold:
                self._wd_streak += 1
            else:
                self._wd_streak = 0
                return
            streak = self._wd_streak
        if streak < self.wd_confirm:
            return
        if (now - self._last_wd_alarm) < self.wd_alarm_cooldown:
            return
        self._last_wd_alarm = now
        alarm = WatchdogAlarm(foreign_count=len(foreign),
                              threshold=self.wd_threshold + allowance,
                              sample=sorted(foreign)[:10])
        self.watchdog_alarms.put(alarm)
        logger.warning(
            "link_watch: LINK-STATE WATCHDOG — %d foreign mesh entries >= "
            "threshold %d for %d consecutive polls (sample: %s) — queueing "
            "enforcement alarm + requesting scan",
            alarm.foreign_count, alarm.threshold, self._wd_streak,
            ", ".join(alarm.sample))
        try:
            self._on_trip(f"link-state watchdog: {alarm.foreign_count} "
                          f"foreign entries >= {alarm.threshold}")
        except Exception as e:
            logger.error("link_watch: on_trip (watchdog) failed: %s", e)

    def watchdog_status(self) -> dict:
        """Watchdog block for /status (thread-safe enough: ints/floats)."""
        with self._lock:
            roster_age = (time.monotonic() - self._roster_at
                          if self._roster_at else None)
            listener_ids = sorted(self._listener_ids)
            allowance = self._listener_allowance
            since = self._listener_since
        return {
            "enabled": self.wd_enabled,
            "foreign_threshold": self.wd_threshold,
            "confirm_polls": self.wd_confirm,
            "last_foreign_count": self._wd_last_foreign,
            "streak": self._wd_streak,
            "trip_plateau": self._trip_plateau,     # count level already scanned (re-fire muting)
            "roster_age_s": round(roster_age) if roster_age is not None else None,
            "last_action": self.wd_last_action,
            # Phase 2: allowance frozen while permitted listeners are present.
            "listener_ids": listener_ids,
            "listener_allowance": allowance,
            "listener_allowance_age_s": (round(time.monotonic() - since)
                                         if since else None),
            "listener_suppressed_alerts": self.wd_listener_suppressed_alerts,
            # Step 2 trigger A: last same-peer link restart seen on the vantage.
            "last_link_restart": self.last_restart,
        }

    # --- thread body ---------------------------------------------------------

    def run(self) -> None:
        logger.info("link_watch: thread started (poll=%ds, watch poll=%ds)",
                    self.poll_interval, self.watch_poll_interval)
        last_tick_start = 0.0
        while not self._stop.is_set():
            # FLOOR between ticks (audit 2026-07-03 #4, S1): each tick costs
            # a fresh SSH session to the vantage Pi, and wake frequency is
            # externally influenced (a flapping neighbor drives AMI events at
            # the 2s debounce). Wakes collapse latency but must never lift
            # the SSH rate above ~1 per _MIN_TICK_SPACING_S.
            gap = time.monotonic() - last_tick_start
            if gap < _MIN_TICK_SPACING_S:
                self._stop.wait(_MIN_TICK_SPACING_S - gap)
                if self._stop.is_set():
                    break
            last_tick_start = time.monotonic()
            try:
                self._tick()
            except Exception as e:
                # Nothing may escape; a broken tick must not kill the thread.
                logger.error("link_watch: tick failed (non-fatal): %s", e)
            interval = (self.watch_poll_interval if self._watches
                        else self.poll_interval)
            # Sleep until the interval elapses OR an async wake (AMI link
            # change, shutdown) arrives. The baseline-append spacing guard in
            # _process_sample keeps wake-driven extra ticks from distorting
            # the rolling median.
            self._wake.wait(interval)
            self._wake.clear()
        logger.info("link_watch: thread stopped")

    def _tick(self) -> None:
        reader = self._reader
        if reader is None:
            return
        snap = reader.read(timeout_seconds=self.read_timeout)
        now = time.monotonic()
        if not snap.ok or not snap.mesh_nodes:
            # A failed read yields no sample and no watch verdict — never
            # treat "couldn't see the mesh" as "offender absent".
            logger.debug("link_watch: unusable read (%s)", snap.errors)
            self._expire_watches(now)
            return
        trip = self._process_sample(snap.mesh_count, now)
        if trip:
            logger.warning("link_watch: TRIPWIRE — %s", trip)
            try:
                self._on_trip(trip)
            except Exception as e:
                logger.error("link_watch: on_trip callback failed: %s", e)
        # Mesh-change hook BEFORE _poll_watches: the callback only schedules
        # work (returns instantly), and must not queue behind a potentially
        # slow SSH re-kick. First-sample suppressed (startup is not a change);
        # failed reads returned above, so "couldn't see" never counts.
        mesh = frozenset(snap.mesh_nodes)
        cb = self._on_mesh_change     # capture once: SIGHUP may rebind mid-tick
        if self._last_mesh is not None and mesh != self._last_mesh:
            if cb is not None:
                try:
                    cb(snap)
                except Exception as e:
                    logger.error("link_watch: mesh-change callback failed "
                                 "(non-fatal): %s", e)
            # Confirmation scan: membership changed → request one
            # out-of-cycle full scan (cooldown-bounded). Joins get their
            # roles/attachment confirmed on the map within a scan's length
            # instead of at the next 300s cycle.
            if self.scan_on_mesh_change and \
                    (now - self._last_change_scan) >= self.mesh_change_scan_cooldown:
                self._last_change_scan = now
                delta_in = sorted(str(n) for n in (mesh - self._last_mesh))
                delta_out = sorted(str(n) for n in (self._last_mesh - mesh))
                try:
                    self._on_trip(
                        f"mesh membership change (join: {delta_in or '-'}, "
                        f"leave: {delta_out or '-'})")
                except Exception as e:
                    logger.error("link_watch: mesh-change scan request "
                                 "failed (non-fatal): %s", e)
        self._last_mesh = mesh
        # Trigger A: same-peer link restart (reconnect counter up, or uptime
        # went backwards) on a peer that is still adjacent. First read after
        # startup is a baseline, never a restart; a peer that only just
        # appeared is a membership change, handled above.
        try:
            restarts = self._detect_restarts(snap.adjacent)
        except Exception as e:
            logger.error("link_watch: restart detection failed (non-fatal): %s", e)
            restarts = []
        if restarts:
            self.last_restart = {"ts": time.time(),
                                 "at": datetime.now().astimezone().isoformat(timespec="seconds"),
                                 "peers": restarts}
            logger.warning("link_watch: LINK RESTART on vantage (same peer): %s "
                           "— mode change or transport blip; confirming by scan",
                           restarts)
            if self.scan_on_link_restart and \
                    (now - self._last_restart_scan) >= self.link_restart_scan_cooldown:
                self._last_restart_scan = now
                try:
                    self._on_trip(f"vantage link restart (same peer): {restarts}")
                except Exception as e:
                    logger.error("link_watch: restart scan request failed "
                                 "(non-fatal): %s", e)
        self._process_watchdog(snap.mesh_nodes, now)
        self._poll_watches(snap, now)
        self._expire_watches(now)

    # --- link restart (trigger A) ----------------------------------------------

    @staticmethod
    def _uptime_seconds(text: str) -> Optional[int]:
        """app_rpt's cumulative 'hh:mm:ss' (hours may exceed 24) -> seconds."""
        try:
            parts = [int(x) for x in str(text).strip().split(":")]
        except ValueError:
            return None
        if any(x < 0 for x in parts):
            return None
        if len(parts) == 4:                       # d:hh:mm:ss, defensively
            return parts[0] * 86400 + parts[1] * 3600 + parts[2] * 60 + parts[3]
        if len(parts) != 3:
            return None
        return parts[0] * 3600 + parts[1] * 60 + parts[2]

    def _detect_restarts(self, adjacent) -> list[str]:
        """Compare this read's adjacent links with the previous read; return
        the peers whose link restarted (reconnects grew, or uptime fell).
        Updates the per-peer memory. Numeric AllStar peers only."""
        prev = self._last_adjacent
        current: dict[str, tuple[int, int]] = {}
        restarted: list[str] = []
        for a in adjacent or []:
            name = str(getattr(a, "node", "")).strip()
            if not name.isdigit():
                continue
            if len(name) == 7 and name[0] == "3":
                continue                          # EchoLink wire form 3NNNNNN
            if name in self.restart_ignore_ids:
                continue                          # our own hub/bridge links (audit SIG-5)
            if str(getattr(a, "state", "ESTABLISHED")).upper() != "ESTABLISHED":
                # CONNECTING churn is not a restart (audit S2), but the
                # peer's last ESTABLISHED baseline must survive the
                # transition so the re-make is caught on return (SIG-3).
                if name in prev:
                    current[name] = prev[name]
                continue
            up = self._uptime_seconds(getattr(a, "connect_time", ""))
            if up is None:
                if name in prev:
                    current[name] = prev[name]
                continue
            try:
                rc = int(getattr(a, "reconnects", 0))
            except (TypeError, ValueError):
                rc = 0
            current[name] = (rc, up)
            if name in prev:
                prc, pup = prev[name]
                if rc > prc or up < pup:
                    restarted.append(f"{name} (reconnects {prc}->{rc}, "
                                     f"uptime {pup}s->{up}s)")
        self._last_adjacent = current
        return restarted

    # --- tripwire ------------------------------------------------------------

    def _baseline_locked(self) -> Optional[float]:
        if len(self._samples) < self.min_baseline_samples:
            return None
        return statistics.median(c for _, c in self._samples)

    def _process_sample(self, count: int, now: float) -> Optional[str]:
        """Record one sample; return a trip reason or None."""
        with self._lock:
            prev = self._samples[-1] if self._samples else None
            baseline = self._baseline_locked()
            # Append at the TRIPWIRE cadence only: watch mode's 15s fast polls
            # must not compress the baseline window's timespan or drag the
            # median up during a long event — that would desensitize the
            # count trigger exactly when it matters (audit 2026-07-03 #2, S1).
            # Trip evaluation below still runs on every poll.
            appended = prev is None or (now - prev[0]) >= self.poll_interval * 0.9
            if appended:
                self._samples.append((now, count))

        reason = None
        if prev is not None:
            prev_ts, prev_count = prev
            dt_min = max((now - prev_ts) / 60.0, 1e-6)
            delta = count - prev_count
            # Two-node minimum keeps a 1-node jitter on a tiny dt from tripping.
            if delta >= _TRIP_MIN_DELTA and (delta / dt_min) >= self.rate_per_minute:
                reason = (f"link count rose {prev_count}->{count} "
                          f"({delta / dt_min:.1f}/min >= {self.rate_per_minute}/min)")
        count_rule = baseline is not None and count >= baseline + self.count_margin
        # Re-fire muting (2026-09-09): the plateau (level already scanned by
        # the last trip) follows the count DOWN and clears when the count is
        # back under baseline + margin — but only on CONFIRMED evidence: two
        # consecutive 60 s-cadence samples (never the 5–15 s wake/fast ticks,
        # never a single read; audit S1/S2 — a softclient blinking out for one
        # sample must not wipe the memory and re-arm a fire).
        # Two separate streaks so a mixed pair (one "below the level", one
        # "under the threshold") can neither clear nor lower (round-2 audit).
        if self._trip_plateau is not None and appended:
            if not count_rule:
                self._plateau_under_n += 1
                self._plateau_low_n = 0
                self._plateau_low_max = 0
                if self._plateau_under_n >= _PLATEAU_CONFIRM_SAMPLES:
                    logger.info("link_watch: count %d back under rolling baseline + "
                                "margin — count re-fire muting ended", count)
                    self._trip_plateau = None
                    self._trip_plateau_logged = False
                    self._plateau_under_n = 0
            elif count < self._trip_plateau:
                self._plateau_low_n += 1
                self._plateau_low_max = max(self._plateau_low_max, count)
                self._plateau_under_n = 0
                if self._plateau_low_n >= _PLATEAU_CONFIRM_SAMPLES:
                    logger.info("link_watch: scanned level lowered %d -> %d (count "
                                "fell; re-fires still muted below %d)",
                                self._trip_plateau, self._plateau_low_max,
                                self._plateau_low_max + _TRIP_MIN_DELTA)
                    self._trip_plateau = self._plateau_low_max
                    self._trip_plateau_logged = False
                    self._plateau_low_n = 0
                    self._plateau_low_max = 0
            else:
                self._plateau_low_n = 0
                self._plateau_low_max = 0
                self._plateau_under_n = 0
        if reason is None and count_rule:
            if (self._trip_plateau is not None
                    and count < self._trip_plateau + _TRIP_MIN_DELTA):
                # This level (or lower) was already scanned by the last trip
                # and the 4 h median has not caught up yet. Regular and
                # mesh-change scans still run; a rise of >= _TRIP_MIN_DELTA
                # above the scanned level (the rate rule's two-node minimum)
                # trips again.
                if not self._trip_plateau_logged:
                    logger.info("link_watch: count %d still >= rolling baseline "
                                "%.0f + margin %d but not above the level already "
                                "scanned (%d) — count re-fires muted until it rises",
                                count, baseline, self.count_margin, self._trip_plateau)
                    self._trip_plateau_logged = True
                return None
            reason = (f"link count {count} >= rolling baseline "
                      f"{baseline:.0f} + margin {self.count_margin}")
        if reason is None:
            return None
        if (now - self._last_trip) < self.trip_cooldown:
            logger.info("link_watch: trip condition (%s) within %ds cooldown — "
                        "not re-firing", reason, self.trip_cooldown)
            return None
        self._last_trip = now
        if count_rule:
            # This level is about to be scanned; remember it (rate trips too).
            self._trip_plateau = count
            self._trip_plateau_logged = False
            self._plateau_low_n = 0
            self._plateau_low_max = 0
            self._plateau_under_n = 0
        return reason

    # --- watch mode ------------------------------------------------------------

    def _poll_watches(self, snap, now: float) -> None:
        with self._lock:
            entries = list(self._watches.values())
        if not entries:
            return
        mesh = set(snap.mesh_nodes)
        for entry in entries:
            present = str(entry.offender) in mesh
            # Entry mutations happen under the lock because enter_watch (scan
            # thread) can now also write armed/strikes/escalated (audit
            # 2026-07-03 #2, A1). The long re-kick runs OUTSIDE the lock.
            with self._lock:
                if entry.offender not in self._watches:
                    continue             # expired/removed meanwhile
                if entry.offender in self._listener_ids:
                    # Reclassified as a permitted listener by the full scan:
                    # a reappearance is not a re-offense. Drop the watch.
                    del self._watches[entry.offender]
                    logger.info("link_watch: watch dropped for %d — now a "
                                "permitted listener", entry.offender)
                    continue
                if not entry.armed:
                    if not present:
                        entry.absent_reads += 1
                        if entry.absent_reads >= self.absent_confirm_polls:
                            entry.armed = True
                            entry.armed_at = time.monotonic()
                            logger.info("link_watch: offender %d absent on %d "
                                        "consecutive reads — armed for "
                                        "reconnect detection", entry.offender,
                                        entry.absent_reads)
                    else:
                        entry.absent_reads = 0
                    continue
                if not present:
                    continue
                entry.absent_reads = 0
                # Armed and present again: a reappearance. Verify + act.
                entry.armed = False      # re-arm only after seen absent again
                entry.reappearances += 1
                reappearance = entry.reappearances
                strikes = entry.strikes
            logger.warning(
                "link_watch: offender %d REAPPEARED in the mesh "
                "(reappearance #%d, strikes=%d) — verifying via "
                "auto-disconnect chain", entry.offender, reappearance, strikes)
            if self._is_dry_run():
                logger.info("link_watch: monitor-only/dry-run — no re-kick, "
                            "no strike recorded for offender %d", entry.offender)
                continue
            def _fresh_mesh(_reader=self._reader, _t=self.read_timeout):
                if _reader is None:
                    return None
                return _reader.read(timeout_seconds=_t)
            # The stored event's coherence verdict was about the ORIGINAL
            # record; a reappearance is a new record and must earn its own
            # (round-2 audit C2).
            try:
                import copy
                ev = copy.copy(entry.event)
                if hasattr(ev, "incoherent_for_seconds"):
                    ev.incoherent_for_seconds = None
                if hasattr(ev, "guest_record_coherent"):
                    ev.guest_record_coherent = False
            except Exception as e:
                # Fail CLOSED: never re-kick on the original event's verdict.
                logger.error("link_watch: could not copy the stored event for %d (%s) "
                             "— re-kick skipped this poll", entry.offender, e)
                continue
            try:
                result = self._disconnector.attempt_disconnect(
                    ev, live_mesh_fn=_fresh_mesh,
                    mesh_trusted_fn=self._mesh_trusted_fn)
            except Exception as e:
                logger.error("link_watch: re-kick attempt errored for offender "
                             "%d: %s", entry.offender, e)
                continue
            if result is None:
                # The (possibly stale) stored path has no enforceable managed
                # node — the offender may have reconnected via a DIFFERENT
                # route. Ask for an immediate full scan: it re-verifies with
                # current topology, kicks through the normal detection chain,
                # and refreshes this watch's event/strike state (audit S2).
                logger.warning(
                    "link_watch: offender %d reappeared but stored path is "
                    "not enforceable — requesting verification scan",
                    entry.offender)
                try:
                    self._on_trip(f"watched offender {entry.offender} "
                                  "reappeared (path shift?) — verification "
                                  "scan needed")
                except Exception as e:
                    logger.error("link_watch: on_trip failed: %s", e)
                continue
            logger.info("link_watch: re-kick result for offender %d: %s — %s",
                        entry.offender, result.action, result.message)
            with self._lock:
                if entry.offender not in self._watches:
                    continue
                if result.action == "skipped_cooldown":
                    # Unverified; stay armed so the next poll retries after
                    # the disconnect cooldown expires.
                    entry.armed = True
                elif result.action == "disconnected":
                    # Re-verify chain confirmed the offender was BRIDGING again.
                    self._record_strike_locked(entry, via="watch re-kick")

    def _record_strike_locked(self, entry: WatchEntry, via: str) -> None:
        """Count a VERIFIED re-offense. Caller must hold self._lock."""
        entry.strikes += 1
        logger.warning("link_watch: verified re-offense by %d (%s) — "
                       "strike %d/%d", entry.offender, via, entry.strikes,
                       self.strike_threshold)
        if entry.strikes >= self.strike_threshold and not entry.escalated:
            entry.escalated = True
            self._queue_escalation(entry)

    def _queue_escalation(self, entry: WatchEntry) -> None:
        esc = Escalation(
            offender=entry.offender,
            callsign=str(getattr(entry.event, "offending_callsign", "Unknown")),
            strikes=entry.strikes,
            reappearances=entry.reappearances,
            path_description=str(getattr(entry.event, "path_description",
                                         "(unavailable)")),
            window_minutes=self.watch_window_s // 60,
        )
        self.escalations.put(esc)
        logger.warning(
            "link_watch: ESCALATION queued for offender %d (%s) — %d verified "
            "re-offenses; requesting immediate scan + repeat-offender alert",
            esc.offender, esc.callsign, esc.strikes)
        try:
            # Wake the main loop so the escalation email goes out promptly.
            self._on_trip(f"repeat-offender escalation for {esc.offender}")
        except Exception as e:
            logger.error("link_watch: on_trip (escalation) failed: %s", e)

    def _expire_watches(self, now: float) -> None:
        with self._lock:
            expired = [o for o, w in self._watches.items()
                       if now >= w.expires_at]
            for offender in expired:
                w = self._watches.pop(offender)
                logger.info(
                    "link_watch: watch window expired for offender %d "
                    "(reappearances=%d, verified strikes=%d, escalated=%s)",
                    offender, w.reappearances, w.strikes, w.escalated)


def build_link_watcher(config: dict, reader, disconnector,
                       is_dry_run: Callable[[], bool],
                       on_trip: Callable[[str], None],
                       on_mesh_change: Optional[Callable] = None,
                       mesh_trusted_fn: Optional[Callable[[], bool]] = None,
                       ) -> Optional[LinkWatcher]:
    """Build (not start) a LinkWatcher, or None if disabled/no reader.

    Never raises — like the reader and analytics, this is an optional add-on
    that must not block daemon startup.
    """
    try:
        cfg = config.get("link_watch") or {}
        if not isinstance(cfg, dict) or not cfg.get("enabled", False):
            return None
        if reader is None:
            logger.warning("link_watch: enabled but rpt_reader is disabled/"
                           "unavailable — watcher not started")
            return None
        watcher = LinkWatcher(cfg, reader, disconnector, is_dry_run, on_trip,
                              on_mesh_change=on_mesh_change,
                              mesh_trusted_fn=mesh_trusted_fn)
        try:
            ignore = {str(config.get("focus_node", ""))}
            ignore.update(str(b) for b in (config.get("bridge_nodes") or []))
            ignore.update(str(n.get("node_id")) for n in
                          ((config.get("auto_disconnect") or {}).get("nodes") or []))
            watcher.restart_ignore_ids = frozenset(i for i in ignore if i.isdigit())
        except Exception as e:
            logger.warning("link_watch: restart ignore set not built: %s", e)
        logger.info(
            "Link watch: ENABLED (tripwire poll=%ds, baseline window=%d "
            "samples, margin=+%d, rate=%s/min; watch poll=%ds, window=%d min, "
            "strike threshold=%d; watchdog=%s threshold=%d confirm=%d)",
            watcher.poll_interval, watcher._samples.maxlen,
            watcher.count_margin, watcher.rate_per_minute,
            watcher.watch_poll_interval, watcher.watch_window_s // 60,
            watcher.strike_threshold,
            "on" if watcher.wd_enabled else "off",
            watcher.wd_threshold, watcher.wd_confirm)
        return watcher
    except Exception as e:
        logger.error("link_watch init failed (disabled this run): %s", e)
        return None


# --- selftest (watchdog state machine) ---------------------------------------

def _selftest() -> int:               # pragma: no cover - developer tool
    failures = []

    def check(name, cond):
        print(f"  [{'OK' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    trips = []
    w = LinkWatcher(
        {"watchdog": {"enabled": True, "foreign_threshold": 5,
                      "confirm_polls": 2, "alarm_cooldown_seconds": 600}},
        reader=object(), disconnector=object(),
        is_dry_run=lambda: False, on_trip=trips.append)
    topology = {
        12345: {"callsign": "N0CALL", "role": "focus"},
        23456: {"callsign": "N0CALL", "role": "bridge"},
        "ext_23456_EchoLink-567899": {"callsign": "EchoLink-567899"},
    }
    w.update_roster(topology)
    check("known id not foreign", "12345" not in w.foreign_entries(["12345"]))
    check("known callsign not foreign",
          w.foreign_entries(["N0CALL"]) == [])
    check("confirmed EchoLink wire form not foreign",
          w.foreign_entries(["3567899"]) == [])
    w.update_roster({12345: {"callsign": "N0CALL", "role": "focus"},
                     "ext_x": {"callsign": "EchoLink-123"}})
    check("leading-zero EchoLink wire form not foreign (audit A3)",
          w.foreign_entries(["3000123"]) == [])
    w.update_roster(topology)   # restore main fixture (has focus below)
    check("unknown entries foreign",
          w.foreign_entries(["3888888", "51444", "W1ABC"])
          == ["3888888", "51444", "W1ABC"])

    ghost = [str(400000 + i) for i in range(6)]      # 6 >= threshold 5
    now = time.monotonic()
    w._process_watchdog(ghost, now)
    check("first excess poll: streak only, no alarm",
          w._wd_streak == 1 and w.watchdog_alarms.empty())
    w._process_watchdog(ghost, now + 1)
    check("confirm_polls reached: alarm queued + scan requested",
          not w.watchdog_alarms.empty() and len(trips) == 1)
    alarm = w.watchdog_alarms.get_nowait()
    check("alarm carries count/threshold/sample",
          alarm.foreign_count == 6 and alarm.threshold == 5
          and len(alarm.sample) == 6)
    w._process_watchdog(ghost, now + 2)
    check("alarm cooldown suppresses refire",
          w.watchdog_alarms.empty() and len(trips) == 1)
    w._process_watchdog(["12345"], now + 3)
    check("clean poll resets streak", w._wd_streak == 0)
    w._last_wd_alarm = now - 700
    w._process_watchdog(ghost, now + 4)
    w._process_watchdog(ghost, now + 5)
    check("re-arms after cooldown + fresh confirm",
          not w.watchdog_alarms.empty())
    w.watchdog_alarms.get_nowait()

    w._roster_at = time.monotonic() - 10_000        # stale roster
    w._wd_streak = 0
    w._last_wd_alarm = 0.0
    w._process_watchdog(ghost, time.monotonic())
    check("stale roster never drives enforcement",
          w._wd_streak == 0 and w.watchdog_alarms.empty())

    ids_before = w._roster_ids
    w.update_roster({})                                  # degraded: empty
    w.update_roster({99: {"callsign": "X", "role": "guest"}})  # no focus
    check("degraded topology keeps previous roster (audit S2)",
          w._roster_ids == ids_before)

    # --- Phase 2: permitted listeners -> frozen watchdog allowance ---------
    import types
    w._roster_at = time.monotonic()
    w._wd_streak = 0
    w._last_wd_alarm = 0.0
    trips.clear()
    # Pretend an alarm was queued just before the scan classified a listener.
    w.watchdog_alarms.put(WatchdogAlarm(foreign_count=6, threshold=5, sample=[]))
    w.enter_watch(types.SimpleNamespace(offending_node=77777))
    w.set_listeners([77777], foreign_now=len(ghost))
    check("listener set: allowance frozen, queued alarm discarded, watch dropped",
          w._listener_allowance == 6 and w.watchdog_alarms.empty()
          and 77777 not in w._watches and w.listener_ids() == frozenset({77777}))
    w._process_watchdog(ghost, time.monotonic())
    w._process_watchdog(ghost, time.monotonic() + 1)
    check("foreign mesh within allowance: no streak, no alarm",
          w._wd_streak == 0 and w.watchdog_alarms.empty() and not trips)
    w.set_listeners([77777], foreign_now=999)            # unchanged set
    check("unchanged listener set keeps the frozen allowance",
          w._listener_allowance == 6)
    grown = ghost + [str(500000 + i) for i in range(5)]  # +5 >= threshold
    w._process_watchdog(grown, time.monotonic() + 2)
    w._process_watchdog(grown, time.monotonic() + 3)
    check("growth beyond allowance + threshold still alarms",
          not w.watchdog_alarms.empty())
    a2 = w.watchdog_alarms.get_nowait()
    check("alarm threshold reports allowance-adjusted value",
          a2.threshold == 5 + 6 and a2.foreign_count == 11)
    w.enter_watch(types.SimpleNamespace(offending_node=77777))
    check("fresh violation by a registered listener IS watched (flip case)",
          77777 in w._watches)
    # Change 3: the stale registration is revoked at once, so the next poll
    # cannot drop the watch it just entered; the only listener gone ->
    # allowance 0.
    check("change 3: fresh violation REVOKES the stale listener registration",
          w.listener_ids() == frozenset() and w._listener_allowance == 0)
    check("change 3: the watch survives the revocation", 77777 in w._watches)
    del w._watches[77777]
    w.set_listeners([{"node": 77777, "monitored": [1]}], foreign_now=6)   # re-register
    check("re-registered listener, allowance frozen again",
          w.listener_ids() == frozenset({77777}) and w._listener_allowance == 6)
    # Change 3: branch-set change re-freezes; settle window may only raise;
    # outside the window the allowance is frozen even if the mesh grows.
    w.set_listeners([{"node": 77777, "monitored": [1, 2]}], foreign_now=40)
    check("change 3: a branch change within the re-freeze spacing keeps the allowance (S2)",
          w._listener_allowance == 6)
    # 2026-09-08 soft spot: a BLOCKED branch change re-opens the settle window
    # so a LATER unchanged scan can still raise; the blocked scan itself never
    # raises (S2 upward direction kept) and never counts as a re-freeze.
    w._branches_changed_at = time.monotonic() - w.branch_settle_s - 1     # old window closed
    w._last_branch_refreeze = time.monotonic() - 10                       # inside the spacing
    rf_before = w._last_branch_refreeze
    w.set_listeners([{"node": 77777, "monitored": [1, 2, 9]}], foreign_now=40)
    check("soft spot: a blocked branch change re-opens the settle window, does NOT raise in "
          "the same call and is NOT a re-freeze",
          w._listener_allowance == 6
          and time.monotonic() - w._branches_changed_at < 5
          and w._last_branch_refreeze == rf_before)
    w.set_listeners([{"node": 77777, "monitored": [1, 2, 9]}], foreign_now=30)
    check("soft spot: ...so a later UNCHANGED scan inside the re-opened window can still raise",
          w._listener_allowance == 30)
    w.set_listeners([{"node": 77777, "monitored": [1, 2, 9]}], foreign_now=50, foreign_raw=42)
    check("soft spot: a settle-window raise never exceeds the raw count (A4)",
          w._listener_allowance == 42)
    w.set_listeners([{"node": 77777, "monitored": [1, 2, 9]}], foreign_now=6)  # unchanged -> lowered
    w.set_listeners([{"node": 77777, "monitored": [1, 2]}], foreign_now=6)     # back (blocked)
    check("soft spot: state restored for the next checks", w._listener_allowance == 6)
    w._last_branch_refreeze = time.monotonic() - w.branch_refreeze_min_s - 1
    w.set_listeners([{"node": 77777, "monitored": [1, 2, 3]}], foreign_now=40)
    check("change 3: listener branch set changed -> allowance re-frozen at this scan's count",
          w._listener_allowance == 40)
    w.set_listeners([{"node": 77777, "monitored": [1, 2]}], foreign_now=40)   # back, no re-freeze
    w.set_listeners([{"node": 77777, "monitored": [1, 2]}], foreign_now=75)
    check("change 3: same branches inside the settle window -> allowance may RISE",
          w._listener_allowance == 75)
    w.set_listeners([{"node": 77777, "monitored": [1, 2]}], foreign_now=60)
    check("change 3: ...and may fall when the foreign count falls (never above reality)",
          w._listener_allowance == 60)
    w._branches_changed_at = time.monotonic() - w.branch_settle_s - 1
    w.set_listeners([{"node": 77777, "monitored": [1, 2]}], foreign_now=200)
    check("change 3: same branches OUTSIDE the settle window -> frozen (ghost growth still trips)",
          w._listener_allowance == 60)
    w.set_listeners([{"node": 77777}], foreign_now=0)        # retained-unobserved record
    check("change 3: a record without a branch list changes nothing (no lowering on a 0 from "
          "an unobserved listener)", w._listener_allowance == 60)
    # round-2 audit S4: two listeners, one revoked by a fresh violation ->
    # the next complete scan re-sizes even though the remaining set looks
    # unchanged; a stale echo (armed entry, old record) revokes nothing.
    w.set_listeners([], foreign_now=None)
    w.set_listeners([{"node": 77777, "monitored": [1]}, {"node": 88888, "monitored": [2]}],
                    foreign_now=100)
    w.enter_watch(types.SimpleNamespace(offending_node=88888, observed_at=time.monotonic()))
    check("change 3: revoking one of two listeners keeps the other and flags a re-freeze",
          w.listener_ids() == frozenset({77777}) and w._listener_allowance == 100
          and w._refreeze_pending)
    w.set_listeners([{"node": 77777, "monitored": [1]}], foreign_now=None)
    check("change 3: a no-snapshot scan does NOT consume the pending re-freeze (round-2 C1)",
          w._listener_allowance == 100 and w._refreeze_pending)
    w.set_listeners([{"node": 77777, "monitored": [1]}], foreign_now=40)
    check("change 3: next sized scan re-freezes the allowance for the remaining listener",
          w._listener_allowance == 40 and not w._refreeze_pending)
    # (an armed watch and a registration cannot normally coexist — set_listeners
    # drops watches on listener ids and enter_watch revokes registrations — so
    # the state is set up by hand to prove the gate itself)
    e = w._watches[88888]; e.armed = True; e.armed_at = time.monotonic()
    with w._lock:
        w._listener_ids = frozenset({77777, 88888}); w._listener_allowance = 90
    w.enter_watch(types.SimpleNamespace(offending_node=88888, observed_at=time.monotonic() - 3600))
    check("change 3: a STALE echo event (record older than the absence) does not revoke",
          88888 in w.listener_ids() and w._listener_allowance == 90)
    w.enter_watch(types.SimpleNamespace(offending_node=88888,
                                        observed_at=time.monotonic() + w.stale_record_margin_s + 5))
    check("change 3: a FRESH event on the armed entry does revoke",
          88888 not in w.listener_ids())
    w._watches.pop(88888, None)
    w._last_branch_refreeze = time.monotonic() - w.branch_refreeze_min_s - 1
    w.set_listeners([{"node": 77777, "monitored": []}], foreign_now=0, foreign_raw=45)
    check("change 3: branches dropped while the mesh still drains -> steps down to the raw "
          "count, not to 0 (S3)", w._listener_allowance == 45)
    w.set_listeners([{"node": 77777, "monitored": []}], foreign_now=0, foreign_raw=12)
    check("change 3: ...then follows the draining count down", w._listener_allowance == 12)
    w.set_listeners([{"node": 77777, "monitored": []}], foreign_now=0, foreign_raw=0)
    check("change 3: ...to 0 once drained", w._listener_allowance == 0)
    w.set_listeners([], foreign_now=None)
    w.set_listeners([77777], foreign_now=6)              # fresh registration, allowance 6
    w._branches_changed_at = 0.0
    # C1: a new listener set with no usable snapshot must not register.
    w.set_listeners([77777, 88888], foreign_now=None)
    check("new listener set without a snapshot is deferred (allowance kept)",
          w.listener_ids() == frozenset({77777}) and w._listener_allowance == 6)
    w.set_listeners([], foreign_now=None)
    check("listener set cleared -> allowance 0",
          w._listener_allowance == 0 and w.listener_ids() == frozenset())
    check("status carries listener fields",
          "listener_allowance" in w.watchdog_status()
          and w.watchdog_status()["listener_ids"] == [])
    w._wd_streak = 0
    w._last_wd_alarm = 0.0

    w2 = LinkWatcher({}, reader=object(), disconnector=object(),
                     is_dry_run=lambda: False, on_trip=trips.append)
    w2.update_roster(topology)
    w2._process_watchdog(ghost, time.monotonic())
    w2._process_watchdog(ghost, time.monotonic() + 1)
    check("watchdog default OFF", w2.watchdog_alarms.empty()
          and w2.wd_enabled is False)

    st = w.watchdog_status()
    check("status block populated",
          st["enabled"] is True and st["foreign_threshold"] == 5
          and "last_foreign_count" in st and "roster_age_s" in st)

    # --- daemon-side attribution/enforcement fidelity (audit S5) ----------
    # Stubs exercise _watchdog_candidates + _handle_watchdog_alarm without
    # any network. foreign = entries starting with "9" (stand-in rule).
    import asl_link_detector as ald

    class _MN:
        def __init__(self, enabled=True):
            self.enabled = enabled

    class _Disc:
        def __init__(self, unions):
            self.managed_nodes = {68: _MN(), 52: _MN()}
            self.bridge_nodes = {43}
            self.unions = unions
            self.kicks = []

        def read_bridge_union(self, b, timeout_s=15):
            return self.unions.get(b)

        def watchdog_disconnect(self, b, t, reverify, reason):
            self.kicks.append((b, t, reverify()))

            class _R:
                action = "disconnected"
                message = "stub"
            return _R()

    class _WStub:
        wd_last_action = None

        def foreign_entries(self, entries):
            return [e for e in entries if str(e).startswith("9")]

    class _NStub:
        def __init__(self):
            self.sent = []

        def send_watchdog_alert(self, **kw):
            self.sent.append(kw)
            return True

    alarm = WatchdogAlarm(foreign_count=30, threshold=25, sample=["9000001"])
    topo1 = {12345: {"role": "focus", "parent": None},
             68: {"role": "bridge", "parent": 12345},
             777: {"role": "guest", "parent": 68}}
    check("candidates: guest on managed bridge",
          ald._watchdog_candidates(topo1, _Disc({})) == [(68, 777)])

    d = _Disc({68: ["1", "2"]})          # readable + CLEAN union
    ws, ns = _WStub(), _NStub()
    ald._handle_watchdog_alarm(alarm, ws, d, ns, None, topo1, False, None)
    check("C1: readable clean union exonerates — no kick",
          d.kicks == [] and ws.wd_last_action["action"] == "no_carrier_confirmed")

    d = _Disc({68: None})                # unreadable union
    ws, ns = _WStub(), _NStub()
    ald._handle_watchdog_alarm(alarm, ws, d, ns, None, topo1, False, None)
    check("C1: unreadable union never licenses a kick",
          d.kicks == [] and ws.wd_last_action["action"] == "no_carrier_confirmed")

    d = _Disc({68: [f"9{i:06d}" for i in range(30)]})   # confirmed carrier
    ws, ns = _WStub(), _NStub()
    ald._handle_watchdog_alarm(alarm, ws, d, ns, None, topo1, False, None)
    check("confirmed carrier: kick fires with carrier-scoped reverify",
          d.kicks == [(68, 777, True)]
          and ws.wd_last_action["action"] == "disconnected"
          and len(ns.sent) == 1)

    topo2 = dict(topo1)
    topo2[888] = {"role": "guest", "parent": 68}
    d = _Disc({68: [f"9{i:06d}" for i in range(30)]})
    ws, ns = _WStub(), _NStub()
    ald._handle_watchdog_alarm(alarm, ws, d, ns, None, topo2, False, None)
    check("multi-guest carrier is ambiguous — no kick, no guessing",
          d.kicks == [] and ws.wd_last_action["action"] == "attribution_ambiguous")

    d = _Disc({68: [f"9{i:06d}" for i in range(30)]})
    ws, ns = _WStub(), _NStub()
    ald._handle_watchdog_alarm(alarm, ws, d, ns, None, topo1, True, None)
    check("monitor-only: no attribution, no kick, Bennett still notified",
          d.kicks == [] and ws.wd_last_action["action"] == "monitor_only"
          and len(ns.sent) == 1)

    d = _Disc({})
    ws, ns = _WStub(), _NStub()
    ald._handle_watchdog_alarm(
        alarm, ws, d, ns, None,
        {12345: {"role": "focus", "parent": None}}, False, None)
    check("no candidates surfaces for manual review",
          d.kicks == [] and
          ws.wd_last_action["action"] == "no_enforceable_candidate")

    # --- step 2 trigger A: same-peer link restart -------------------------
    class _Adj:
        def __init__(self, node, reconnects, connect_time, state="ESTABLISHED"):
            self.node, self.reconnects, self.connect_time = node, reconnects, connect_time
            self.state = state

    rw = LinkWatcher({}, reader=object(), disconnector=object(),
                     is_dry_run=lambda: False, on_trip=lambda r: None)
    check("uptime parse hh:mm:ss (hours > 24)",
          rw._uptime_seconds("56:49:11") == 56 * 3600 + 49 * 60 + 11)
    check("uptime parse garbage -> None", rw._uptime_seconds("n/a") is None)
    base = [_Adj("23456", 7, "56:49:11"), _Adj("34567", 1, "00:06:41")]
    check("first read is baseline, no restart", rw._detect_restarts(base) == [])
    later = [_Adj("23456", 7, "56:50:41"), _Adj("34567", 1, "00:08:11")]
    check("uptime growing, no restart", rw._detect_restarts(later) == [])
    flip = [_Adj("23456", 7, "56:51:46"), _Adj("34567", 2, "00:00:03")]
    r = rw._detect_restarts(flip)
    check("reconnects up + uptime reset = restart on that peer only",
          len(r) == 1 and r[0].startswith("34567 ("))
    reset_only = [_Adj("23456", 7, "56:52:00"), _Adj("34567", 2, "00:00:02")]
    r = rw._detect_restarts(reset_only)
    check("uptime fell with same reconnect count = restart",
          len(r) == 1 and r[0].startswith("34567 ("))
    joined = [_Adj("23456", 7, "56:53:00"), _Adj("34567", 2, "00:01:02"),
              _Adj("56789", 0, "00:00:01")]
    check("new peer is not a restart (membership path owns it)",
          rw._detect_restarts(joined) == [])
    gone = [_Adj("23456", 7, "56:54:00")]
    check("departed peer is not a restart", rw._detect_restarts(gone) == [])
    check("echolink/non-numeric peers ignored",
          rw._detect_restarts([_Adj("23456", 7, "56:55:00"),
                               _Adj("EchoLink-1", 3, "00:00:01")]) == [])
    check("status carries last_link_restart key",
          "last_link_restart" in rw.watchdog_status())
    check("4-field d:hh:mm:ss uptime parsed", rw._uptime_seconds("1:02:03:04") == 93784)
    rw2 = LinkWatcher({}, reader=object(), disconnector=object(),
                      is_dry_run=lambda: False, on_trip=lambda r: None)
    rw2._detect_restarts([_Adj("23456", 7, "10:00:00"), _Adj("34567", 0, "00:00:20", "CONNECTING")])
    r = rw2._detect_restarts([_Adj("23456", 7, "10:01:00"), _Adj("34567", 1, "00:00:02", "CONNECTING")])
    check("CONNECTING peer never counts as a restart (audit S2)", r == [])
    r = rw2._detect_restarts([_Adj("23456", 7, "10:02:00"), _Adj("34567", 1, "00:00:05")])
    check("first ESTABLISHED read after CONNECTING with no prior baseline is a baseline", r == [])
    # SIG-3: an ESTABLISHED peer seen CONNECTING mid-transition keeps its baseline
    rw4 = LinkWatcher({}, reader=object(), disconnector=object(),
                      is_dry_run=lambda: False, on_trip=lambda r: None)
    rw4._detect_restarts([_Adj("34567", 1, "00:10:00")])
    check("CONNECTING read yields no restart",
          rw4._detect_restarts([_Adj("34567", 1, "00:00:03", "CONNECTING")]) == [])
    r = rw4._detect_restarts([_Adj("34567", 2, "00:00:04")])
    check("re-make after a CONNECTING read IS caught (audit SIG-3)",
          len(r) == 1 and r[0].startswith("34567 ("))
    rw4.restart_ignore_ids = frozenset({"23456"})
    rw4._detect_restarts([_Adj("23456", 7, "10:00:00"), _Adj("34567", 2, "00:01:00")])
    r = rw4._detect_restarts([_Adj("23456", 8, "00:00:02"), _Adj("34567", 2, "00:02:00")])
    check("our own hub/bridge link restarts are ignored (audit SIG-5)", r == [])
    rw2._detect_restarts([_Adj("23456", 7, "10:03:00"), _Adj("3123456", 0, "00:10:00")])
    r = rw2._detect_restarts([_Adj("23456", 7, "10:04:00"), _Adj("3123456", 1, "00:00:01")])
    check("EchoLink 3NNNNNN wire form ignored (audit A4)", r == [])
    # own cooldown: a restart must not consume the membership-change budget
    trips2 = []
    rw3 = LinkWatcher({"link_restart_scan_cooldown_seconds": 180,
                       "mesh_change_scan_cooldown_seconds": 180},
                      reader=object(), disconnector=object(),
                      is_dry_run=lambda: False, on_trip=trips2.append)
    check("restart cooldown is a separate clock (audit S1)",
          hasattr(rw3, "_last_restart_scan") and rw3._last_restart_scan == 0.0
          and rw3._last_change_scan == 0.0)

    # D1 (2026-09-08, the 23:42 stale echo): a full-scan re-detection after
    # an observed absence strikes ONLY when the offender's record was
    # fetched after that absence plus the stats-lag margin.
    d1 = LinkWatcher({"stale_record_margin_seconds": 30, "strike_threshold": 3},
                     reader=object(), disconnector=object(),
                     is_dry_run=lambda: False, on_trip=lambda r: None)
    t0 = time.monotonic()
    ev_old = types.SimpleNamespace(offending_node=4600, observed_at=t0 - 120)
    d1.enter_watch(ev_old)                       # 23:40 detection, cut, watched
    with d1._lock:
        e = d1._watches[4600]
        e.watched_at = t0 - 100                  # the cut
        e.armed, e.armed_at = True, t0 - 60      # 23:41:13 seen absent
    d1.enter_watch(types.SimpleNamespace(offending_node=4600, observed_at=t0 - 120))
    check("D1: same-scan re-detection from the pre-cut record -> no strike, stays armed",
          d1._watches[4600].strikes == 0 and d1._watches[4600].armed is True)
    d1.enter_watch(types.SimpleNamespace(offending_node=4600, observed_at=t0 - 45))
    check("D1: record fetched inside the lag margin after the absence -> no strike",
          d1._watches[4600].strikes == 0 and d1._watches[4600].armed is True)
    d1.enter_watch(types.SimpleNamespace(offending_node=4600, observed_at=t0 - 10))
    check("D1: record fetched after absence + margin -> verified strike, disarmed",
          d1._watches[4600].strikes == 1 and d1._watches[4600].armed is False)
    # S6: the gate is anchored on the LATER of the cut and the absence — a
    # wake-driven arm 5 s after the cut must not shorten the margin.
    with d1._lock:
        d1._watches[4600].watched_at = t0 + 20            # the cut
        d1._watches[4600].armed, d1._watches[4600].armed_at = True, t0 + 25
    d1.enter_watch(types.SimpleNamespace(offending_node=4600, observed_at=t0 + 40))
    check("S6: record fetched 20 s after the cut (armed 5 s after it) -> no strike",
          d1._watches[4600].strikes == 1 and d1._watches[4600].armed is True)
    d1.enter_watch(types.SimpleNamespace(offending_node=4600, observed_at=t0 + 60))
    check("S6: record fetched past the margin from the cut -> strike",
          d1._watches[4600].strikes == 2 and d1._watches[4600].armed is False)
    with d1._lock:
        d1._watches[4600].armed, d1._watches[4600].armed_at = True, t0
    d1.enter_watch(types.SimpleNamespace(offending_node=4600))
    check("D1: an event without a fetch stamp never strikes",
          d1._watches[4600].strikes == 2)
    # S-F: arming needs absent_confirm_polls consecutive absent reads; a
    # stale echo does not extend the window or replace the stored path.
    sf = LinkWatcher({"absent_confirm_polls": 2, "watch_window_minutes": 45},
                     reader=object(), disconnector=object(),
                     is_dry_run=lambda: False, on_trip=lambda r: None)
    ev0 = types.SimpleNamespace(offending_node=4600, observed_at=t0 - 120, tag="orig")
    sf.enter_watch(ev0)
    exp0 = sf._watches[4600].expires_at
    snap_absent = types.SimpleNamespace(mesh_nodes=["1000", "2000"])
    snap_present = types.SimpleNamespace(mesh_nodes=["1000", "2000", "4600"])
    sf._poll_watches(snap_absent, time.monotonic())
    check("S-F: one absent read does not arm", sf._watches[4600].armed is False
          and sf._watches[4600].absent_reads == 1)
    sf._poll_watches(snap_present, time.monotonic())
    sf._poll_watches(snap_absent, time.monotonic())
    check("S-F: a present read resets the absent count",
          sf._watches[4600].armed is False and sf._watches[4600].absent_reads == 1)
    sf._poll_watches(snap_absent, time.monotonic())
    check("S-F: two consecutive absent reads arm", sf._watches[4600].armed is True)
    sf.enter_watch(types.SimpleNamespace(offending_node=4600, observed_at=t0 - 120, tag="echo"))
    check("S-F: stale echo leaves window and stored event unchanged",
          sf._watches[4600].expires_at == exp0 and sf._watches[4600].event.tag == "orig"
          and sf._watches[4600].armed is True)
    # Coherence (2026-10-13, round-2 audit C2): a re-kick passes a COPY of the
    # stored event with the coherence verdict cleared (the reappearance must
    # earn its own), and the kwargs for the live-mesh veto.
    class _RecDisc:
        def __init__(self):
            self.seen = []
        def attempt_disconnect(self, ev, **kw):
            self.seen.append((ev, kw))
            return types.SimpleNamespace(action="skipped_reverify", message="x",
                                         reason="no_evidence", success=True)
    rkd = _RecDisc()
    rk = LinkWatcher({"absent_confirm_polls": 1, "watch_window_minutes": 45},
                     reader=object(), disconnector=rkd,
                     is_dry_run=lambda: False, on_trip=lambda r: None,
                     mesh_trusted_fn=lambda: True)
    ev_rk = types.SimpleNamespace(offending_node=4600, observed_at=t0 - 120,
                                  path=[1000, 2000, 4600, 9000],
                                  guest_record_coherent=True, incoherent_for_seconds=12.0)
    rk.enter_watch(ev_rk)
    rk._poll_watches(snap_absent, time.monotonic())
    rk._poll_watches(snap_present, time.monotonic())
    check("re-kick: a copy of the event is passed, verdict cleared, original untouched, kwargs present",
          len(rkd.seen) == 1 and rkd.seen[0][0] is not ev_rk
          and rkd.seen[0][0].guest_record_coherent is False
          and rkd.seen[0][0].incoherent_for_seconds is None
          and rkd.seen[0][0].path == [1000, 2000, 4600, 9000]
          and ev_rk.guest_record_coherent is True and ev_rk.incoherent_for_seconds == 12.0
          and "live_mesh_fn" in rkd.seen[0][1] and "mesh_trusted_fn" in rkd.seen[0][1]
          and rk._watches[4600].strikes == 0)

    # --- tripwire re-fire muting (2026-09-09) -----------------------------
    # Baseline 9 (median), margin 5 (threshold 14), cooldown 300, poll 60.
    # Synthetic monotonic times: +301 clears the cooldown, +61 is a 60 s-cadence
    # sample INSIDE the cooldown, +5 is a wake/fast tick (not appended).
    tw = LinkWatcher({"count_margin": 5, "rate_per_minute": 5,
                      "trip_cooldown_seconds": 300, "poll_interval_seconds": 60,
                      "min_baseline_samples": 10},
                     reader=object(), disconnector=object(),
                     is_dry_run=lambda: False, on_trip=lambda r: None)
    tcur = [time.monotonic()]
    def fs(count, gap):
        tcur[0] += gap
        return tw._process_sample(count, tcur[0])
    for _ in range(10):
        fs(9, 60)                                        # baseline 9 armed
    r = fs(140, 601)                                     # the mesh lands
    check("tripmute: a fast rise trips (rate rule) and records the level",
          bool(r) and "rose" in r and tw._trip_plateau == 140)
    r = fs(147, 61)                                      # inside the cooldown
    check("tripmute: a cooldown-blocked trip does NOT record the level",
          r is None and tw._trip_plateau == 140)
    r = fs(148, 301)
    check("tripmute: >= 2 above the scanned level trips again (count rule)",
          bool(r) and "baseline" in r and tw._trip_plateau == 148)
    r = fs(148, 301)
    check("tripmute: the same level after the cooldown is MUTED (logged once)",
          r is None and tw._trip_plateau_logged)
    r = fs(149, 301)
    check("tripmute: +1 (jitter) stays muted", r is None and tw._trip_plateau == 148)
    r = fs(100, 5)                                       # fast tick, one low read
    check("tripmute: a fast-tick read never moves the level (S2)",
          r is None and tw._trip_plateau == 148 and tw._plateau_low_n == 0)
    r = fs(13, 61)                                       # softclient blinks out: one sample under threshold
    check("tripmute: ONE sample under the threshold does not clear the memory (S1)",
          r is None and tw._trip_plateau == 148 and tw._plateau_under_n == 1)
    r = fs(14, 61)                                       # back to 14 (the 22:24 replay)
    check("tripmute: the return to 14 after a one-sample blink does NOT fire (the 22:24 "
          "replay); the level is untouched by the mixed pair",
          r is None and tw._trip_plateau == 148 and tw._plateau_low_n == 1
          and tw._plateau_under_n == 0)
    r = fs(14, 301)                                      # second consecutive below-level sample
    check("tripmute: two consecutive below-level samples lower the level to their max; "
          "still muted; a fresh mute line is logged",
          r is None and tw._trip_plateau == 14 and tw._trip_plateau_logged)
    r = fs(16, 301)
    check("tripmute: re-growth of 2 from the lowered level trips", bool(r) and tw._trip_plateau == 16)
    r = fs(60, 301)                                      # 44 nodes in ~5 min = 8.8/min
    check("tripmute: the rate rule fires while a level is recorded (rule (a) untouched)",
          bool(r) and "rose" in r and tw._trip_plateau == 60)
    r = fs(30, 61)                                       # below the level, above the threshold
    r = fs(9, 61)                                        # then ONE sample under the threshold
    check("tripmute: a MIXED pair (below-level, then under-threshold) neither lowers nor clears",
          r is None and tw._trip_plateau == 60 and tw._plateau_under_n == 1
          and tw._plateau_low_n == 0)
    r = fs(200, 301)                                     # a fire resets both streaks
    check("tripmute: a fire resets the streaks", bool(r) and tw._trip_plateau == 200
          and tw._plateau_under_n == 0 and tw._plateau_low_n == 0)
    r = fs(9, 301)
    check("tripmute: one sample under baseline + margin keeps the memory",
          r is None and tw._trip_plateau == 200)
    r = fs(9, 301)
    check("tripmute: the second clears it", r is None and tw._trip_plateau is None
          and tw._plateau_under_n == 0)
    r = fs(14, 301)
    check("tripmute: the next excursion trips afresh", bool(r) and tw._trip_plateau == 14)
    check("tripmute: watchdog_status (the /status feed) carries trip_plateau",
          tw.watchdog_status().get("trip_plateau") == 14)
    tw2 = LinkWatcher({"count_margin": 5, "rate_per_minute": 5, "min_baseline_samples": 10},
                      reader=object(), disconnector=object(),
                      is_dry_run=lambda: False, on_trip=lambda r: None)
    t2 = time.monotonic()
    tw2._process_sample(9, t2); tw2._process_sample(9, t2 + 60)
    r = tw2._process_sample(50, t2 + 120)
    check("tripmute: no baseline yet -> the rate rule still fires and no level is recorded",
          bool(r) and "rose" in r and tw2._trip_plateau is None)

    print(f"\n{'PASS' if not failures else 'FAIL'}: "
          f"{len(failures)} failure(s) {failures or ''}")
    return 1 if failures else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print("Usage: python3 link_watch.py --selftest", file=sys.stderr)
