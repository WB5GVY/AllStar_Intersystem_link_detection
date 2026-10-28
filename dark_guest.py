"""Dark-guest tracker — step 2b (2026-09-07, Bennett's design; rebuilt
2026-09-08 after two adversarial audits).

A "dark" guest is a node linked to one of our bridges (or the hub) that is
online (registered in DNS) but posts nothing to stats.allstarlink.org, so the
stats-based screens cannot see its outside links. Posting is OFF by default
on HamVoIP and on hand-configured ASL3 nodes, so darkness is not proof of
intent — but a dark guest that also carries other systems into ours, and
then transmits, is a bridge in use.

Why a bridge's learned-node union alone cannot attribute (audit 2, C-A):
app_rpt propagates every neighbour list transitively, so `rpt nodes` on ANY
bridge lists the whole connected graph — a ghost behind bridge A shows up in
bridge B's union too. Two evidence classes are therefore used:

  ATTRIBUTED (strong, per guest) — foreign entries in the bridge's union that
    themselves POST to stats and whose own record reports a link to the dark
    guest. Two independent sources agree: the outside node says "I am linked
    to G", and our own bridge says that node is in the mesh. That is the
    Screen-2 violation (a guest with a link beyond) proven from the far end.
    `min_attributed_links` (default 1) such nodes are required.

  EXCESS (weak, system-wide) — the union's foreign count minus the permitted-
    listener allowance is at or above `foreign_threshold`, AND the guest's
    attach node is a bridge (never the hub — the hub's union is the system's
    own excess, audit 2 C-B), AND no other managed node hosts a non-system
    node this scan (the watchdog's unique-carrier rule — audit 2 C-A). Used
    only when every outside node behind the guest is dark too.

Either class on `confirm_scans` consecutive scans puts the guest in state
UNVERIFIED; if another non-system node hangs off the same attach node the
attribution is AMBIGUOUS (notice only, never a cut). While UNVERIFIED the
trustees get at most one notice per node per `notice_interval_hours`.
`keyed_cut_confirm_keyups` (default 2) keyed (K) transitions for the guest
on its OWN attach node's AMI feed within `keyed_cut_confirm_window_seconds`
while UNVERIFIED = a bridge in use → cut through that node via
`watchdog_disconnect` (still connected per the node's own record, cooldown,
flag file). The re-verify re-reads the union and re-checks the SAME
evidence class (attributed set re-fetched; excess still over threshold and
overlapping). Only a real `disconnected` outcome is emailed, and the email
is queued for the MAIN loop (`drain_actions`), never sent from the helper
thread.

Guards: feature OFF unless `enabled` is exactly true; monitor_only never
cuts; `cut_on_keyed` off logs "would cut" (soak mode); a scan is degraded —
no state advances — when it is incomplete, when a system node was
unobserved, when more than `max_dark_guests` guests are dark at once, or for
a guest seen posting within `posting_grace_seconds` (persisted); a guest that moves to
another attach node starts over; a departed guest's record and pending
notice are dropped; a K with no reporting vantage is ignored; one cut at a
time system-wide; a cooldown between cuts per node.

Dependencies (documented for SIGHUP): `foreign_fn` and `allowance_fn` come
from the link watcher (roster refreshed by every scan; allowance frozen at
listener registration) — without the watcher the tracker only records
darkness. `attribute_fn` uses the tracker's OWN API client. Config,
disconnector, notifier and dry-run flag are read through getters, so a
SIGHUP that rebuilds them takes effect at the next call while the tracker's
state survives. Its own AutoDisconnector (own requests.Session) is required
because `_cut` runs on a helper thread while the scan thread may be mid-
request on the main one.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Callable, Optional

logger = logging.getLogger(__name__)

STATE_CANDIDATE = "candidate"     # dark, evidence seen < confirm_scans times
STATE_UNVERIFIED = "unverified"   # dark + evidence confirmed, sole guest
STATE_AMBIGUOUS = "ambiguous"     # confirmed, but another guest shares the attach node
STATE_DARK_ONLY = "dark_only"     # dark, no evidence behind its attach node

EVIDENCE_ATTRIBUTED = "attributed"
EVIDENCE_EXCESS = "excess"

_RETENTION_S = 7 * 24 * 3600     # forget bookkeeping of long-gone nodes


def _as_int_set(items) -> set:
    out: set = set()
    for x in items or []:
        try:
            out.add(int(x))
        except (TypeError, ValueError):
            continue
    return out


class DarkGuestTracker:
    def __init__(self, cfg_getter: Callable[[], dict],
                 disconnector_getter: Callable[[], object],
                 foreign_fn: Optional[Callable[[list], list]],
                 notifier_getter: Optional[Callable[[], object]] = None,
                 on_trip: Optional[Callable[[str], None]] = None,
                 persist: Optional[Callable[[dict], None]] = None,
                 clock: Callable[[], float] = time.time,
                 is_dry_run: Optional[Callable[[], bool]] = None,
                 allowance_fn: Optional[Callable[[], int]] = None,
                 own_nodes_fn: Optional[Callable[[], set]] = None,
                 attribute_fn: Optional[Callable[[int, list], Optional[list]]] = None,
                 listener_ids_fn: Optional[Callable[[], frozenset]] = None,
                 persist_posting: Optional[Callable[[dict], None]] = None,
                 scan_budget: Optional[list] = None,
                 mesh_foreign_fn: Optional[Callable[[], Optional[int]]] = None):
        self._cfg = cfg_getter
        self._disc = disconnector_getter
        self._foreign = foreign_fn            # union tokens -> foreign entries (None = no watcher)
        self._notifier = notifier_getter
        self._on_trip = on_trip
        self._persist = persist               # notice times -> durable store
        self._clock = clock
        self._dry_run = is_dry_run or (lambda: False)
        self._allowance = allowance_fn or (lambda: 0)
        self._own_nodes = own_nodes_fn or (lambda: set())
        self._attribute = attribute_fn        # (guest, foreign tokens) -> tokens linked to guest
        self._listener_ids = listener_ids_fn or (lambda: frozenset())
        self._persist_posting = persist_posting
        self._scan_budget = scan_budget       # [n]: attribution lookups left this scan
        self._mesh_foreign = mesh_foreign_fn  # vantage mesh foreign count (None = unknown)
        self._cut_flag_prev: Optional[bool] = None
        self._keyed_seen: dict[int, list[float]] = {}   # node -> K frame times (audit 3 C1)
        self._lock = threading.Lock()
        self._cut_lock = threading.Lock()     # one cut at a time (audit 2 S-A)
        self._state: dict[int, dict] = {}     # node -> record
        self._notice_at: dict[int, float] = {}
        self._cut_at: dict[int, float] = {}
        self._pending_notice: dict[int, dict] = {}
        self._pending_actions: list[tuple] = []   # (snapshot, reason, action, message)
        self._last_posting: dict[int, float] = {}
        self.last_degraded_reason: Optional[str] = None

    # --- config -----------------------------------------------------------------

    @staticmethod
    def _enabled(cfg: dict) -> bool:
        return isinstance(cfg, dict) and cfg.get("enabled", False) is True

    # --- durable notice times (survive restarts) -----------------------------

    def load_notice_times(self, data: Optional[dict]) -> None:
        try:
            with self._lock:
                self._notice_at = {int(k): float(v) for k, v in (data or {}).items()}
        except Exception as e:
            logger.error("dark_guest: load_notice_times failed: %s", e)

    def load_posting_times(self, data: Optional[dict]) -> None:
        """Audit 3 S7: the posting-hiccup grace survives a restart."""
        try:
            with self._lock:
                self._last_posting = {int(k): float(v) for k, v in (data or {}).items()}
        except Exception as e:
            logger.error("dark_guest: load_posting_times failed: %s", e)

    # --- scan-thread input ---------------------------------------------------

    def observe(self, dark_guests: list, topology: dict,
                scan_complete: bool = True,
                posting_ids=None) -> list[int]:
        """Feed one scan's dark guests. Reads each involved attach node's
        union once (only when a dark guest exists — zero SSH cost
        otherwise). `posting_ids`: nodes whose stats record was fetched
        NON-EMPTY this scan (a fresh EMPTY record — `linkless`, change 1
        2026-09-08 — earns no grace: it proves nothing about links).
        Returns the node ids newly confirmed
        UNVERIFIED/AMBIGUOUS this call. A degraded scan changes no state."""
        newly: list[int] = []
        try:
            cfg = self._cfg()
            if not self._enabled(cfg):
                return newly
            now = self._clock()
            pids = _as_int_set(posting_ids)
            if pids:
                with self._lock:
                    for pid in pids:
                        self._last_posting[pid] = now
                    grace_keep = max(0.0, float(cfg.get("posting_grace_seconds", 3600)))
                    snap = {str(k): v for k, v in self._last_posting.items()
                            if (now - v) <= grace_keep}
                if self._persist_posting:
                    try:
                        self._persist_posting(snap)
                    except Exception as e:
                        logger.error("dark_guest: persist posting failed: %s", e)
            self.last_degraded_reason = None
            if not scan_complete:
                self.last_degraded_reason = "scan incomplete or a system node unobserved"
                return newly
            guests = self._normalise(dark_guests)
            if self._scan_budget is not None:
                self._scan_budget[0] = max(0, int(cfg.get("attribution_max_lookups", 10)))
            max_dark = max(1, int(cfg.get("max_dark_guests", 3)))
            if len(guests) > max_dark:
                self.last_degraded_reason = (
                    f"{len(guests)} dark guests in one scan (> {max_dark}) — "
                    "stats-server hiccup suspected; no state advanced")
                logger.warning("dark_guest: %s", self.last_degraded_reason)
                return newly
            self._observe_guests(guests, topology, cfg, now, newly)
            self._flush_notices()
        except Exception as e:
            logger.error("dark_guest: observe failed (non-fatal): %s", e)
        return newly

    @staticmethod
    def _normalise(dark_guests) -> list[dict]:
        out = []
        for g in dark_guests or []:
            try:
                nid, bridge = int(g["node"]), int(g["attached_to"])
            except (KeyError, TypeError, ValueError):
                continue
            out.append({**g, "node": nid, "attached_to": bridge})
        return out

    def _other_hosts(self, topology: dict, disc, bridge: int, own: set) -> list[int]:
        """Managed nodes OTHER than `bridge` that host a non-system numeric
        node this scan (the watchdog's unique-carrier rule, audit 2 C-A)."""
        managed = getattr(disc, "managed_nodes", {}) if disc else {}
        try:
            listeners = set(int(x) for x in self._listener_ids())
        except Exception:
            listeners = set()
        hosts: set = set()
        for n, info in (topology or {}).items():
            if not str(n).isdigit() or int(n) in own or int(n) in listeners:
                continue
            # guest-class only (the watchdog's candidate roles): a hub's
            # regular hop-1 nodes are not carriers for this purpose
            # (audit 3 S1 — otherwise the class could never fire).
            if info.get("role") not in ("guest", "unauthorized", "dragged_in"):
                continue
            try:
                parent = int(info.get("parent"))
            except (TypeError, ValueError):
                continue
            if parent == bridge or parent not in managed:
                continue
            if getattr(managed.get(parent), "enabled", False):
                hosts.add(parent)
        return sorted(hosts)

    def _observe_guests(self, guests: list[dict], topology: dict, cfg: dict,
                        now: float, newly: list[int]) -> None:
        confirm = max(1, int(cfg.get("confirm_scans", 2)))
        threshold = max(1, int(cfg.get("foreign_threshold", 25)))
        min_attr = max(1, int(cfg.get("min_attributed_links", 1)))
        grace = max(0, float(cfg.get("posting_grace_seconds", 3600)))
        disc = self._disc()
        own = _as_int_set(self._own_nodes())
        try:
            allowance = max(0, int(self._allowance() or 0))
        except Exception:
            allowance = 0
        seen: set[int] = set()
        by_bridge: dict[int, list[dict]] = {}
        for g in guests:
            by_bridge.setdefault(g["attached_to"], []).append(g)
        # Nothing foreign anywhere in the vantage mesh = nothing to attribute:
        # skip the SSH union reads this scan (a persistent dark hub-side node
        # would otherwise cost one `rpt nodes` per scan forever).
        mesh_clean = False
        if self._mesh_foreign is not None:
            try:
                mf = self._mesh_foreign()
                mesh_clean = (mf is not None and int(mf) == 0)
            except Exception:
                mesh_clean = False
        for bridge, bguests in by_bridge.items():
            union = None
            managed = getattr(disc, "managed_nodes", {}).get(bridge) if disc else None
            if mesh_clean:
                for g in bguests:
                    nid = g["node"]
                    seen.add(nid)
                    with self._lock:
                        rec = self._state.get(nid)
                        if rec is None or rec.get("bridge") != bridge:
                            rec = {"node": nid, "bridge": bridge,
                                   "attachment": g.get("attachment", "bridge"),
                                   "callsign": g.get("callsign", "Unknown"),
                                   "first_seen": now, "consecutive": 0,
                                   "state": STATE_DARK_ONLY, "evidence": None,
                                   "foreign_sample": [], "foreign_set": [],
                                   "foreign_count": 0, "attributed": [],
                                   "union_readable": None, "co_guests": [],
                                   "keyed_cuts": 0}
                        rec["last_seen"] = now
                        rec["note"] = "vantage mesh has no foreign entries — nothing to attribute"
                        rec["consecutive"] = 0
                        rec["evidence"] = None
                        rec["foreign_count"] = 0
                        rec["foreign_sample"] = []
                        rec["foreign_set"] = []
                        if rec.get("state") in (STATE_UNVERIFIED, STATE_AMBIGUOUS):
                            logger.info("dark_guest: node %d back to dark_only (mesh clean)", nid)
                        rec["state"] = STATE_DARK_ONLY
                        self._keyed_seen.pop(nid, None)
                        self._state[nid] = rec
                continue
            if managed is not None and getattr(managed, "enabled", False) \
                    and self._foreign is not None:
                try:
                    union = disc.read_bridge_union(bridge)
                except Exception as e:
                    logger.warning("dark_guest: union read of %s failed: %s", bridge, e)
                    union = None
            foreign = [str(x) for x in self._foreign(union)] if union is not None else None
            union_set = {str(x) for x in union} if union is not None else set()
            effective = (len(foreign) - allowance) if foreign is not None else None
            other_hosts = self._other_hosts(topology, disc, bridge, own)
            for g in bguests:
                nid = g["node"]
                seen.add(nid)
                attachment = g.get("attachment", "bridge")
                if "co_adjacent" in g:
                    co = _as_int_set(g.get("co_adjacent"))
                else:
                    co = {int(n) for n, i in topology.items()
                          if str(n).isdigit() and i.get("parent") == bridge}
                # Advisory (audit 2): the attach node's stats record can be
                # short/stale — cross-check with the walk's own children.
                co |= {int(n) for n, i in topology.items()
                       if str(n).isdigit() and i.get("parent") == bridge}
                others = sorted(co - own - {nid, bridge})
                recently_posting = (nid in self._last_posting
                                    and (now - self._last_posting[nid]) < grace)
                # Attribution lookups (API, own client) only when needed.
                attributed: Optional[list] = None
                if foreign and not recently_posting and self._attribute is not None:
                    with self._lock:
                        prev_attr = list((self._state.get(nid) or {}).get("attributed") or [])
                    # previously attributed nodes first so the lookup cap
                    # always re-checks the evidence already on record
                    ordered = [x for x in prev_attr if x in foreign] + \
                              [x for x in foreign if x not in prev_attr]
                    try:
                        attributed = self._attribute(nid, ordered)
                    except Exception as e:
                        logger.warning("dark_guest: attribution lookup for %d failed: %s",
                                       nid, e)
                        attributed = None
                    if attributed is not None:
                        attributed = [str(x) for x in attributed if str(x) in union_set]
                with self._lock:
                    rec = self._state.get(nid)
                    if rec is not None and rec.get("bridge") != bridge:
                        logger.info("dark_guest: node %d moved %s -> %s; evidence "
                                    "restarts", nid, rec.get("bridge"), bridge)
                        rec = None                       # audit S6
                        self._keyed_seen.pop(nid, None)  # audit 4 S-2
                    if rec is None:
                        rec = {"node": nid, "bridge": bridge, "attachment": attachment,
                               "callsign": g.get("callsign", "Unknown"),
                               "first_seen": now, "consecutive": 0,
                               "state": STATE_CANDIDATE, "evidence": None,
                               "foreign_sample": [], "foreign_set": [],
                               "foreign_count": 0, "attributed": [],
                               "union_readable": union is not None,
                               "co_guests": others, "keyed_cuts": 0}
                    rec["last_seen"] = now
                    rec["union_readable"] = union is not None
                    rec["co_guests"] = others
                    rec["other_hosts"] = other_hosts
                    rec["allowance"] = allowance
                    rec["foreign_count"] = len(foreign) if foreign is not None else None
                    if recently_posting:
                        rec["note"] = "seen posting recently — hiccup suspected"
                        self._state[nid] = rec
                        continue
                    rec.pop("note", None)
                    if union is None:
                        self._state[nid] = rec           # could not see: keep state
                        continue
                    if str(nid) not in union_set:
                        rec["note"] = "attach node's union does not list the guest"
                        rec["consecutive"] = 0
                        rec["evidence"] = None
                        rec["state"] = STATE_DARK_ONLY
                        self._state[nid] = rec
                        continue
                    evidence = None
                    if attributed is not None and len(attributed) >= min_attr:
                        evidence = EVIDENCE_ATTRIBUTED
                    elif (effective is not None and effective >= threshold
                          and attachment != "hub" and not other_hosts):
                        evidence = EVIDENCE_EXCESS
                    if evidence and rec.get("evidence") not in (None, evidence):
                        rec["consecutive"] = 0           # class changed: restart
                    if evidence:
                        rec["consecutive"] = rec.get("consecutive", 0) + 1
                        rec["evidence"] = evidence
                        rec["foreign_sample"] = list(foreign[:20])
                        rec["foreign_set"] = list(foreign)
                        rec["attributed"] = list(attributed or [])
                    else:
                        rec["consecutive"] = 0
                        rec["evidence"] = None
                        rec["foreign_sample"] = []
                        rec["foreign_set"] = []
                        rec["attributed"] = list(attributed or [])
                        if (effective is not None and effective >= threshold
                                and (attachment == "hub" or other_hosts)):
                            rec["note"] = ("system-wide excess not attributable "
                                           + ("(hub-attached)" if attachment == "hub"
                                              else f"(other hosts {other_hosts})"))
                    prev = rec["state"]
                    if rec["consecutive"] >= confirm:
                        rec["state"] = STATE_AMBIGUOUS if others else STATE_UNVERIFIED
                    elif rec["consecutive"] == 0:
                        rec["state"] = STATE_DARK_ONLY
                    else:
                        rec["state"] = STATE_CANDIDATE
                    if rec["state"] != STATE_UNVERIFIED:
                        self._keyed_seen.pop(nid, None)  # audit 4 S-2: K count dies with the evidence
                    if rec["state"] in (STATE_UNVERIFIED, STATE_AMBIGUOUS):
                        if prev not in (STATE_UNVERIFIED, STATE_AMBIGUOUS):
                            newly.append(nid)
                            logger.warning(
                                "DARK GUEST %s: node %d (%s) on %s %d posts no stats; "
                                "evidence=%s (attributed outside links %s; union "
                                "foreign %d, allowance %d, threshold %d; sample %s) "
                                "on %d consecutive scans; co-adjacent non-system nodes "
                                "%s — benefit of the doubt until it keys",
                                rec["state"].upper(), nid, rec["callsign"],
                                attachment, bridge, rec["evidence"],
                                rec["attributed"][:8], len(foreign), allowance,
                                threshold, rec["foreign_sample"][:8],
                                rec["consecutive"], others or "none")
                        self._queue_notice_locked(rec, now, cfg)
                    elif prev in (STATE_UNVERIFIED, STATE_AMBIGUOUS):
                        logger.info("dark_guest: node %d back to %s", nid, rec["state"])
                    self._state[nid] = rec
        with self._lock:
            for nid in [n for n in self._state if n not in seen]:
                rec = self._state.pop(nid)
                self._pending_notice.pop(nid, None)          # audit S3
                logger.info("dark_guest: node %d no longer a dark guest (was %s)",
                            nid, rec.get("state"))
            for d in (self._cut_at, self._last_posting):
                for k in [k for k, t in d.items()
                          if k not in self._state and (now - t) > _RETENTION_S]:
                    d.pop(k, None)
            for k in [k for k in self._keyed_seen if k not in self._state]:
                self._keyed_seen.pop(k, None)
            stale = [k for k, t in self._notice_at.items()
                     if k not in self._state and (now - t) > _RETENTION_S]
            for k in stale:
                self._notice_at.pop(k, None)
            snapshot = dict(self._notice_at) if stale else None
        if snapshot is not None:
            self._persist_notice_times(snapshot)

    def _persist_notice_times(self, snapshot: dict) -> None:
        if self._persist:
            try:
                self._persist({str(k): v for k, v in snapshot.items()})
            except Exception as e:
                logger.error("dark_guest: persist failed: %s", e)

    def _queue_notice_locked(self, rec: dict, now: float, cfg: dict) -> None:
        hours = float(cfg.get("notice_interval_hours", 24))
        last = self._notice_at.get(rec["node"])
        if last is not None and (now - last) < hours * 3600:
            return
        self._pending_notice[rec["node"]] = dict(rec)

    def _flush_notices(self) -> None:
        nt = self._notifier() if self._notifier else None
        if nt is None:
            return
        with self._lock:
            items = list(self._pending_notice.items())
        for nid, rec in items:
            ok = False
            try:
                ok = bool(nt.send_dark_guest_notice(rec))
            except Exception as e:
                logger.error("dark_guest: notice failed (non-fatal): %s", e)
            if ok:
                with self._lock:
                    self._notice_at[nid] = self._clock()
                    self._pending_notice.pop(nid, None)
                    snapshot = dict(self._notice_at)
                self._persist_notice_times(snapshot)

    def drain_actions(self) -> int:
        """MAIN loop only (audit 2 S-B): send the queued action records.
        Returns the number sent."""
        nt = self._notifier() if self._notifier else None
        with self._lock:
            items, self._pending_actions = list(self._pending_actions), []
        sent = 0
        for snapshot, reason, action, message in items:
            if nt is None:
                continue
            try:
                if nt.send_dark_guest_action(snapshot, reason, action, message):
                    sent += 1
            except Exception as e:
                logger.error("dark_guest: action email failed (non-fatal): %s", e)
        return sent

    # --- AMI-thread input ----------------------------------------------------

    def watch_ids(self) -> frozenset:
        """Ids whose K on their own attach node's feed is actionable."""
        try:
            if not self._enabled(self._cfg()):
                return frozenset()
        except Exception:
            return frozenset()
        with self._lock:
            return frozenset(n for n, r in self._state.items()
                             if r.get("state") == STATE_UNVERIFIED)

    def on_keyed(self, node: int, alinks: str = "", vantage: Optional[int] = None) -> bool:
        """K seen for `node` on `vantage`'s link list. Actionable only when
        the node is UNVERIFIED and the reporting vantage IS its attach node
        (the keyed flag is per adjacent link; another node's feed says
        nothing about this guest; an unknown vantage is not evidence).
        Runs the cut on a helper thread. Returns True when a cut was
        dispatched."""
        try:
            cfg = self._cfg()
            if not self._enabled(cfg):
                return False
            nid = int(node)
            if vantage is None:
                logger.info("dark_guest: K for %d with no reporting vantage — ignored", nid)
                return False
            with self._lock:
                rec = self._state.get(nid)
                if not rec or rec.get("state") != STATE_UNVERIFIED:
                    return False
                if int(vantage) != int(rec["bridge"]):
                    return False
                bridge = int(rec["bridge"])
                snapshot = dict(rec)
            stamp = datetime.fromtimestamp(self._clock()).astimezone().strftime("%H:%M:%S %Z")
            reason = (f"dark guest keyed toward {bridge} at {stamp}; evidence "
                      f"{snapshot.get('evidence')}: attributed outside links "
                      f"{snapshot.get('attributed', [])[:6]}, union foreign "
                      f"{snapshot.get('foreign_count', 0)} (threshold "
                      f"{int(cfg.get('foreign_threshold', 25))}, allowance "
                      f"{snapshot.get('allowance', 0)}); RPT_ALINKS={alinks[:80]}")
            if self._dry_run():
                logger.warning("DARK GUEST KEYED (monitor-only/dry-run — would cut): "
                               "node %d — %s", nid, reason)
                return False
            cut_flag = bool(cfg.get("cut_on_keyed", False))
            with self._lock:
                if self._cut_flag_prev is False and cut_flag:
                    self._keyed_seen.clear()             # audit 4 S-1: soak counts never carry
                self._cut_flag_prev = cut_flag
            if not cut_flag:
                logger.warning("DARK GUEST KEYED (cut_on_keyed off — would count toward a "
                               "cut): node %d — %s", nid, reason)
                return False
            # Audit 3 C1: no single-observation path to enforcement. Need
            # `keyed_cut_confirm_keyups` K frames (the AMI listener reports
            # per-node K transitions only, one per node per 30 s) inside the window.
            need = max(1, int(cfg.get("keyed_cut_confirm_keyups", 2)))
            window = max(60, int(cfg.get("keyed_cut_confirm_window_seconds", 900)))
            now = self._clock()
            with self._lock:
                recent = [x for x in self._keyed_seen.get(nid, []) if (now - x) <= window]
                recent.append(now)
                self._keyed_seen[nid] = recent
                seen_n = len(recent)
            if seen_n < need:
                logger.warning("DARK GUEST KEYED: node %d (%d/%d observations before a cut) "
                               "— %s", nid, seen_n, need, reason)
                return False
            disc = self._disc()                              # audit 2 S-G: resolve once
            if disc is None:
                return False
            with self._lock:
                cooldown = int(cfg.get("keyed_cut_cooldown_seconds", 120))
                last = self._cut_at.get(nid, 0.0)
                if (now - last) < cooldown:
                    return False
                if not self._cut_lock.acquire(blocking=False):   # audit 2 S-A
                    logger.info("dark_guest: a cut is already in flight — K for %d deferred",
                                nid)
                    return False
                self._cut_at[nid] = now
            logger.warning("DARK GUEST KEYED (confirmed %d/%d): node %d — %s",
                           seen_n, need, nid, reason)
            t = threading.Thread(target=self._cut,
                                 args=(disc, nid, bridge, reason, snapshot),
                                 name=f"dark-cut-{nid}", daemon=True)
            try:
                t.start()
            except Exception as e:                           # audit 3 S2: no lock leak
                with self._lock:
                    self._cut_at.pop(nid, None)
                try:
                    self._cut_lock.release()
                except RuntimeError:
                    pass
                logger.error("dark_guest: cut thread for %d could not start: %s", nid, e)
                return False
            if self._on_trip:
                try:
                    self._on_trip(f"dark guest {nid} keyed toward its attach node {bridge}")
                except Exception as e:
                    logger.error("dark_guest: trip callback failed: %s", e)
            return True
        except Exception as e:
            logger.error("dark_guest: on_keyed failed (non-fatal): %s", e)
            return False

    def _reverify(self, disc, nid: int, bridge: int, snapshot: dict) -> bool:
        """Re-check the SAME evidence class against a fresh union read,
        scoped to the accused attach node: union readable, guest still
        listed, and — attributed: the re-fetched attributed set still meets
        the minimum and overlaps the confirmed set; excess: still at or above
        threshold after the allowance and overlapping the confirmed set."""
        union = disc.read_bridge_union(bridge)
        if union is None or self._foreign is None:
            return False              # could not see = do not cut
        union_set = {str(x) for x in union}
        if str(nid) not in union_set:
            logger.info("dark_guest: reverify — %d no longer lists %d", bridge, nid)
            return False
        foreign = [str(x) for x in self._foreign(union)]
        cfg = self._cfg()
        if snapshot.get("evidence") == EVIDENCE_ATTRIBUTED:
            if self._attribute is None:
                return False
            fresh = self._attribute(nid, list(foreign))
            if fresh is None:
                return False
            fresh = {str(x) for x in fresh if str(x) in union_set}
            before = set(snapshot.get("attributed") or [])
            need = max(1, int(cfg.get("min_attributed_links", 1)))
            if len(fresh) < need or not (fresh & before):
                logger.info("dark_guest: reverify — attributed links for %d now %s "
                            "(was %s)", nid, sorted(fresh), sorted(before))
                return False
            return True
        try:
            allowance = max(0, int(self._allowance() or 0))
        except Exception:
            allowance = 0
        threshold = max(1, int(cfg.get("foreign_threshold", 25)))
        if len(foreign) - allowance < threshold:
            logger.info("dark_guest: reverify — excess %d - %d < %d on %d",
                        len(foreign), allowance, threshold, bridge)
            return False
        before = set(snapshot.get("foreign_set") or [])
        if before and not (before & set(foreign)):
            logger.info("dark_guest: reverify — excess on %d no longer overlaps the "
                        "confirmed set", bridge)
            return False
        return True

    def _cut(self, disc, nid: int, bridge: int, reason: str, snapshot: dict) -> None:
        result = None
        try:
            result = disc.watchdog_disconnect(
                bridge, nid, lambda: self._reverify(disc, nid, bridge, snapshot), reason)
        except Exception as e:
            logger.error("dark_guest: cut of %d via %d failed: %s", nid, bridge, e)
        finally:
            try:
                self._cut_lock.release()
            except RuntimeError:
                pass
        action = getattr(result, "action", None) if result is not None else "not_applicable"
        message = (getattr(result, "message", "") or "") if result is not None else ""
        with self._lock:
            rec = self._state.get(nid)
            if rec is not None:
                rec["last_cut"] = {"ts": self._clock(), "action": action,
                                   "message": message[:300]}
                if action == "disconnected":
                    rec["keyed_cuts"] = rec.get("keyed_cuts", 0) + 1
            if action == "disconnected":                 # audit S2: no-ops are log-only
                self._pending_actions.append((snapshot, reason, action, message))
        logger.warning("dark_guest: cut of %d via %d -> %s", nid, bridge, action)

    # --- presentation --------------------------------------------------------

    def status(self) -> dict:
        """{"nodes": {id: record}, "degraded": reason|None, "pending_actions": n}."""
        def _iso(t):
            return datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")
        with self._lock:
            nodes = {
                str(n): {
                    "state": r.get("state"), "evidence": r.get("evidence"),
                    "bridge": r.get("bridge"),
                    "attachment": r.get("attachment"), "callsign": r.get("callsign"),
                    "first_seen": _iso(r["first_seen"]) if r.get("first_seen") else None,
                    "consecutive": r.get("consecutive", 0),
                    "foreign_count": r.get("foreign_count", 0),
                    "foreign_sample": r.get("foreign_sample", [])[:8],
                    "attributed": r.get("attributed", [])[:8],
                    "allowance": r.get("allowance", 0),
                    "co_guests": r.get("co_guests", []),
                    "other_hosts": r.get("other_hosts", []),
                    "union_readable": r.get("union_readable"),
                    "note": r.get("note"),
                    "last_notice": _iso(self._notice_at[n]) if n in self._notice_at else None,
                    "notice_pending": n in self._pending_notice,
                    "keyed_cuts": r.get("keyed_cuts", 0),
                    "keyed_observations": len(self._keyed_seen.get(n, [])),
                    "last_cut": r.get("last_cut"),
                }
                for n, r in self._state.items()}
            pending = len(self._pending_actions)
        return {"nodes": nodes, "degraded": self.last_degraded_reason,
                "pending_actions": pending}


# --- selftest ----------------------------------------------------------------

def _selftest() -> int:            # pragma: no cover - developer tool
    import types
    failures = []

    def check(name, cond):
        print(f"  [{'OK' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    t = {"w": 1_000_000.0}
    cfg = {"enabled": True, "confirm_scans": 2, "notice_interval_hours": 24,
           "cut_on_keyed": True, "keyed_cut_cooldown_seconds": 120,
           "foreign_threshold": 3, "min_attributed_links": 1,
           "max_dark_guests": 3, "posting_grace_seconds": 3600}
    big = [f"70000{i}" for i in range(5)]                       # 5 foreign entries
    unions = {2000: ["1000", "4000"] + big}
    # far-end records: which foreign nodes report a link to which guest
    links_to = {"700001": {4000}, "700002": {4000}}
    calls = {"union": 0, "wd": [], "attr": 0}
    dry = {"on": False}
    allowance = {"n": 0}

    def attribute(guest, foreign):
        calls["attr"] += 1
        return [f for f in foreign if guest in links_to.get(f, set())]

    class _Disc:
        managed_nodes = {2000: types.SimpleNamespace(enabled=True),
                         3000: types.SimpleNamespace(enabled=True)}
        bridge_nodes = {2000, 3000}

        def read_bridge_union(self, b):
            calls["union"] += 1
            return unions.get(b)

        def watchdog_disconnect(self, bridge, target, reverify, reason):
            ok = reverify()
            calls["wd"].append((bridge, target, ok))
            return types.SimpleNamespace(action="disconnected" if ok else "skipped_reverify",
                                         message="stub")

    class _Nt:
        def __init__(self):
            self.notices, self.actions = [], []
            self.refuse = False

        def send_dark_guest_notice(self, rec):
            if self.refuse:
                return False
            self.notices.append(rec["node"]); return True

        def send_dark_guest_action(self, rec, reason, action, msg):
            self.actions.append((rec["node"], action)); return True

    persisted = {}
    disc, nt = _Disc(), _Nt()
    roster = {"1000", "2000", "3000", "4000"}
    trips = []

    def mk(c=cfg, attr=attribute):
        return DarkGuestTracker(lambda: c, lambda: disc,
                                foreign_fn=lambda u: [x for x in u if x not in roster],
                                notifier_getter=lambda: nt, on_trip=trips.append,
                                persist=lambda d: (persisted.clear(), persisted.update(d)),
                                clock=lambda: t["w"], is_dry_run=lambda: dry["on"],
                                allowance_fn=lambda: allowance["n"],
                                own_nodes_fn=lambda: {1000, 2000, 3000},
                                attribute_fn=attr)
    dg = mk()
    topo = {1000: {"role": "focus"}, 2000: {"role": "bridge", "parent": 1000},
            3000: {"role": "bridge", "parent": 1000}, 4000: {"role": "guest", "parent": 2000}}
    dark = [{"node": 4000, "attached_to": 2000, "attachment": "bridge",
             "callsign": "C4000", "co_adjacent": [1000, 4000]}]

    def wait():
        time.sleep(0.2)

    # --- default OFF (audit C2) ---
    off = mk({})
    off.observe(dark, topo)
    check("C2: no `enabled: true` -> inert (no SSH, no state, no watch ids)",
          calls["union"] == 0 and off.status()["nodes"] == {} and off.watch_ids() == frozenset()
          and off.on_keyed(4000, "", 2000) is False)
    off2 = mk({"enabled": "true"})
    off2.observe(dark, topo)
    check("C2: enabled must be boolean True (string ignored)", calls["union"] == 0)

    check("no dark guests -> no SSH, no state",
          dg.observe([], topo) == [] and calls["union"] == 0 and dg.status()["nodes"] == {})
    n1 = dg.observe(dark, topo)
    s = dg.status()["nodes"]["4000"]
    check("scan 1: candidate via ATTRIBUTED evidence, one union read, one attribution "
          "lookup, no notice yet",
          n1 == [] and calls["union"] == 1 and calls["attr"] == 1
          and s["state"] == STATE_CANDIDATE and s["evidence"] == EVIDENCE_ATTRIBUTED
          and s["attributed"] == ["700001", "700002"] and nt.notices == [])
    check("candidate is not keyed-actionable",
          dg.watch_ids() == frozenset() and dg.on_keyed(4000, "", 2000) is False)
    n2 = dg.observe(dark, topo)
    check("scan 2: UNVERIFIED, notice sent once, persisted",
          n2 == [4000] and dg.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED
          and nt.notices == [4000] and persisted.get("4000") == t["w"])
    dg.observe(dark, topo)
    check("scan 3: no repeat notice within 24 h", nt.notices == [4000])
    check("unverified is keyed-actionable on its own attach node only",
          dg.watch_ids() == {4000} and dg.on_keyed(4000, "2,4000TK", vantage=9999) is False)
    check("S4: K with no reporting vantage is not actionable",
          dg.on_keyed(4000, "2,4000TK", vantage=None) is False and calls["wd"] == [])
    dry["on"] = True
    check("C1: monitor-only/dry-run -> no cut, no thread, no trip",
          dg.on_keyed(4000, "2,4000TK", vantage=2000) is False and calls["wd"] == []
          and trips == [])
    dry["on"] = False
    cfg["cut_on_keyed"] = False
    dg.on_keyed(4000, "2,4000TK", vantage=2000); dg.on_keyed(4000, "2,4000TK", vantage=2000)
    check("soak: cut_on_keyed off -> logged, no cut, NOT counted",
          calls["wd"] == [] and dg.status()["nodes"]["4000"]["keyed_observations"] == 0)
    cfg["cut_on_keyed"] = True
    check("C1 (audit 3): the FIRST K after arming never cuts (1/2 observations)",
          dg.on_keyed(4000, "2,4000TK", vantage=2000) is False and calls["wd"] == []
          and dg.status()["nodes"]["4000"]["keyed_observations"] == 1)
    ok = dg.on_keyed(4000, "2,4000TK", vantage=2000)
    wait()
    check("keyed on own attach node -> attributed reverify -> cut, action QUEUED, trip",
          ok and calls["wd"] == [(2000, 4000, True)] and nt.actions == []
          and dg.status()["pending_actions"] == 1
          and dg.status()["nodes"]["4000"]["keyed_cuts"] == 1 and len(trips) == 1)
    check("S-B: action email sent only by the main-loop drain",
          dg.drain_actions() == 1 and nt.actions == [(4000, "disconnected")]
          and dg.status()["pending_actions"] == 0)
    check("cut cooldown blocks an immediate second cut",
          dg.on_keyed(4000, "2,4000TK", vantage=2000) is False)
    # reverify: far end no longer reports the link -> no cut, no email
    t["w"] += 200
    links_to.clear()
    dg.on_keyed(4000, "2,4000TK", vantage=2000); wait()
    check("reverify: attributed links gone -> skipped; S2: no email queued",
          calls["wd"][-1] == (2000, 4000, False) and dg.drain_actions() == 0)
    # reverify: every far-end lookup failed -> None -> no cut
    t["w"] += 200
    links_to.update({"700001": {4000}, "700002": {4000}})
    dg._attribute = lambda g, f: None
    dg.on_keyed(4000, "2,4000TK", vantage=2000); wait()
    check("reverify: all far-end lookups failed (None) -> skipped",
          calls["wd"][-1] == (2000, 4000, False))
    # reverify: far end now names a DIFFERENT set (no overlap) -> no cut
    t["w"] += 200
    dg._attribute = lambda g, f: ["700004"]
    dg.on_keyed(4000, "2,4000TK", vantage=2000); wait()
    check("reverify: attributed set does not overlap the confirmed set -> skipped",
          calls["wd"][-1] == (2000, 4000, False))
    # reverify: no attribution function at all -> no cut
    t["w"] += 200
    dg._attribute = None
    dg.on_keyed(4000, "2,4000TK", vantage=2000); wait()
    check("reverify: attribution unavailable -> skipped",
          calls["wd"][-1] == (2000, 4000, False))
    dg._attribute = attribute
    # reverify: attach node no longer lists the guest
    t["w"] += 200
    unions[2000] = ["1000"] + big
    dg.on_keyed(4000, "2,4000TK", vantage=2000); wait()
    check("reverify: union no longer lists the guest -> skipped",
          calls["wd"][-1] == (2000, 4000, False))
    unions[2000] = ["1000", "4000"] + big
    # --- EXCESS evidence path (all outside nodes dark) ---
    links_to.clear()
    dg2 = mk()
    dg2.observe(dark, topo); dg2.observe(dark, topo)
    check("excess: no attributable links, 5 foreign >= 3, sole host -> UNVERIFIED via EXCESS",
          dg2.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED
          and dg2.status()["nodes"]["4000"]["evidence"] == EVIDENCE_EXCESS)
    allowance["n"] = 3
    dg2.observe(dark, topo)
    check("C4: listener allowance subtracts from the excess (5-3 < 3) -> DARK_ONLY",
          dg2.status()["nodes"]["4000"]["state"] == STATE_DARK_ONLY
          and dg2.status()["nodes"]["4000"]["allowance"] == 3)
    allowance["n"] = 0
    # C-A: another managed node hosts a guest -> excess is not attributable
    topo_two = dict(topo); topo_two[4700] = {"role": "guest", "parent": 3000}
    dg3 = mk()
    dg3.observe(dark, topo_two); dg3.observe(dark, topo_two)
    s3 = dg3.status()["nodes"]["4000"]
    check("C-A: excess with another managed host present -> not evidence (DARK_ONLY, note)",
          s3["state"] == STATE_DARK_ONLY and s3["other_hosts"] == [3000]
          and "not attributable" in (s3["note"] or ""))
    topo_reg = dict(topo); topo_reg[4800] = {"role": "regular", "parent": 3000}
    dg3r = mk()
    dg3r.observe(dark, topo_reg); dg3r.observe(dark, topo_reg)
    check("S1 (audit 3): a REGULAR hop-1 node on another managed node is not a host",
          dg3r.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED
          and dg3r.status()["nodes"]["4000"]["other_hosts"] == [])
    dg3l = DarkGuestTracker(lambda: cfg, lambda: disc,
                            foreign_fn=lambda u: [x for x in u if x not in roster],
                            clock=lambda: t["w"], own_nodes_fn=lambda: {1000, 2000, 3000},
                            listener_ids_fn=lambda: frozenset({4700}))
    dg3l.observe(dark, topo_two); dg3l.observe(dark, topo_two)
    check("S1 (audit 3): a permitted listener on another managed node is not a host",
          dg3l.status()["nodes"]["4000"]["other_hosts"] == []
          and dg3l.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED)
    links_to.update({"700001": {4000}})
    dg3.observe(dark, topo_two); dg3.observe(dark, topo_two)
    check("C-A: ...but ATTRIBUTED evidence still confirms with another host present",
          dg3.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED
          and dg3.status()["nodes"]["4000"]["evidence"] == EVIDENCE_ATTRIBUTED)
    links_to.clear()
    # C-B: hub-attached guest never confirms on excess
    unions[1000] = ["2000", "4900"] + big
    disc.managed_nodes[1000] = types.SimpleNamespace(enabled=True)
    hub_dark = [{"node": 4900, "attached_to": 1000, "attachment": "hub",
                 "callsign": "C4900", "co_adjacent": [2000, 3000, 4900]}]
    dg4 = mk()
    dg4.observe(hub_dark, topo); dg4.observe(hub_dark, topo)
    check("C-B: hub-attached dark guest never confirms on system-wide excess",
          dg4.status()["nodes"]["4900"]["state"] == STATE_DARK_ONLY
          and "hub-attached" in (dg4.status()["nodes"]["4900"]["note"] or ""))
    links_to.update({"700003": {4900}})
    dg4.observe(hub_dark, topo); dg4.observe(hub_dark, topo)
    check("C-B: ...attributed evidence still works for a hub-attached guest",
          dg4.status()["nodes"]["4900"]["state"] == STATE_UNVERIFIED)
    links_to.clear()
    # reverify EXCESS path
    dg2.observe(dark, topo); dg2.observe(dark, topo)
    dg2.on_keyed(4000, "2,4000TK", vantage=2000)
    ok2 = dg2.on_keyed(4000, "2,4000TK", vantage=2000); wait()
    check("excess reverify: still >= threshold and overlapping -> cut (2nd K)",
          ok2 and calls["wd"][-1] == (2000, 4000, True))
    t["w"] += 200
    unions[2000] = ["1000", "4000", "800001", "800002", "800003", "800004"]
    dg2.on_keyed(4000, "2,4000TK", vantage=2000); wait()
    check("excess reverify: excess does not overlap the confirmed set -> skipped",
          calls["wd"][-1] == (2000, 4000, False))
    unions[2000] = ["1000", "4000"] + big
    # C5 ambiguity: an ALLOWLISTED co-adjacent node (absent from topology) counts
    links_to.update({"700001": {4000}})
    dark_co = [{**dark[0], "co_adjacent": [1000, 4000, 4500]}]
    dg5 = mk()
    dg5.observe(dark_co, topo); dg5.observe(dark_co, topo)
    check("C5: co-adjacent non-system node from the attach node's own report -> "
          "AMBIGUOUS, never keyed-actionable",
          dg5.status()["nodes"]["4000"]["state"] == STATE_AMBIGUOUS
          and dg5.watch_ids() == frozenset()
          and dg5.status()["nodes"]["4000"]["co_guests"] == [4500])
    topo_child = dict(topo); topo_child[4600] = {"role": "guest", "parent": 2000}
    dg5b = mk()
    dg5b.observe(dark, topo_child); dg5b.observe(dark, topo_child)
    check("ADV: a co-guest known only from the walk's topology also makes it AMBIGUOUS",
          dg5b.status()["nodes"]["4000"]["state"] == STATE_AMBIGUOUS)
    dark_co2 = [{**dark[0], "co_adjacent": [1000, 4000, 3000]}]
    dg5.observe(dark_co2, topo)
    check("C5: our own nodes never count as co-guests",
          dg5.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED
          and dg5.status()["nodes"]["4000"]["co_guests"] == [])
    # unreadable union keeps state
    unions[2000] = None
    dg5.observe(dark, topo)
    check("unreadable union keeps prior state",
          dg5.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED
          and dg5.status()["nodes"]["4000"]["union_readable"] is False)
    unions[2000] = ["1000", "4000"] + big
    # S6: attach-node change restarts the evidence
    unions[3000] = ["1000", "4000"] + big
    moved = [{**dark[0], "attached_to": 3000, "co_adjacent": [1000, 4000]}]
    dg5.observe(moved, topo)
    check("S6: guest moves to another attach node -> consecutive restarts at 1, CANDIDATE",
          dg5.status()["nodes"]["4000"]["state"] == STATE_CANDIDATE
          and dg5.status()["nodes"]["4000"]["consecutive"] == 1
          and dg5.status()["nodes"]["4000"]["bridge"] == 3000)
    # S3: departure clears record AND pending notice
    nt.refuse = True; nt.notices.clear()
    t["w"] += 25 * 3600
    dg5.observe(dark, topo); dg5.observe(dark, topo)
    check("refused notice stays pending",
          dg5.status()["nodes"]["4000"]["notice_pending"] is True and nt.notices == [])
    dg5.observe([], topo)
    nt.refuse = False
    dg5.observe([], topo)
    check("S3: guest gone -> record AND pending notice dropped",
          dg5.status()["nodes"] == {} and nt.notices == [])
    nt.refuse = True; persisted.clear()
    dg5.observe(dark, topo); dg5.observe(dark, topo)
    nt.refuse = False
    dg5.observe(dark, topo)
    check("pending notice retried and sent", nt.notices == [4000]
          and dg5.status()["nodes"]["4000"]["notice_pending"] is False)
    before = dg5.status()["nodes"]
    dg5.observe([], topo, scan_complete=False)
    check("degraded scan changes no state (and says so)",
          dg5.status()["nodes"] == before and dg5.status()["degraded"])
    many = [{**dark[0], "node": n, "co_adjacent": [1000]} for n in (4000, 4100, 4200, 4300)]
    u_before = calls["union"]
    dg5.observe(many, topo)
    check("C6: > max_dark_guests dark in one scan -> degraded, no SSH, no state change",
          calls["union"] == u_before and dg5.status()["degraded"]
          and dg5.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED
          and "4100" not in dg5.status()["nodes"])
    fresh = mk()
    fresh.observe([], topo, posting_ids=[4000])
    a_before = calls["attr"]
    fresh.observe(dark, topo); fresh.observe(dark, topo)
    check("C6: dark guest that posted within the grace window -> no evidence, no lookups",
          fresh.status()["nodes"]["4000"]["state"] == STATE_CANDIDATE
          and fresh.status()["nodes"]["4000"]["consecutive"] == 0
          and calls["attr"] == a_before
          and "hiccup" in (fresh.status()["nodes"]["4000"]["note"] or ""))
    t["w"] += 4000
    fresh.observe(dark, topo); fresh.observe(dark, topo)
    check("C6: after the grace window the evidence advances normally",
          fresh.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED)
    cfg["enabled"] = False
    check("disabled -> inert", dg5.on_keyed(4000, "", 2000) is False
          and dg5.watch_ids() == frozenset())
    cfg["enabled"] = True
    dg6 = mk()
    dg6.load_notice_times(persisted)
    nt.notices.clear()
    dg6.observe(dark, topo); dg6.observe(dark, topo)
    check("loaded notice time suppresses a repeat after restart", nt.notices == [])
    nowatch = DarkGuestTracker(lambda: cfg, lambda: disc, foreign_fn=None)
    u_before = calls["union"]
    nowatch.observe(dark, topo)
    check("no watcher -> darkness recorded, no SSH, no evidence",
          calls["union"] == u_before and nowatch.status()["nodes"]["4000"]["state"] == STATE_CANDIDATE
          and nowatch.status()["nodes"]["4000"]["union_readable"] is False)
    # S-2 (audit 4): the K count dies when the evidence resets
    dgk = mk()
    dgk.observe(dark, topo); dgk.observe(dark, topo)
    dgk.on_keyed(4000, "2,4000TK", vantage=2000)
    check("S-2: one K recorded while UNVERIFIED",
          dgk.status()["nodes"]["4000"]["keyed_observations"] == 1)
    links_to.clear(); unions[2000] = ["1000", "4000"]
    dgk.observe(dark, topo)
    links_to.update({"700001": {4000}, "700002": {4000}}); unions[2000] = ["1000", "4000"] + big
    dgk.observe(dark, topo); dgk.observe(dark, topo)
    check("S-2: evidence reset -> K count cleared; first K after re-confirmation does not cut",
          dgk.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED
          and dgk.on_keyed(4000, "2,4000TK", vantage=2000) is False)
    # per-scan attribution budget
    bud = [0]
    seen_calls = []
    dgb = DarkGuestTracker(lambda: {**cfg, "attribution_max_lookups": 4}, lambda: disc,
                           foreign_fn=lambda u: [x for x in u if x not in roster],
                           clock=lambda: t["w"], own_nodes_fn=lambda: {1000, 2000, 3000},
                           scan_budget=bud,
                           attribute_fn=lambda g, f: (seen_calls.append(list(f)) or []))
    dgb.observe(dark, topo)
    check("budget: reset to attribution_max_lookups at each scan", bud[0] == 4)
    # mesh clean -> no SSH union read, DARK_ONLY
    mesh = {"n": 0}
    dgm = DarkGuestTracker(lambda: cfg, lambda: disc,
                           foreign_fn=lambda u: [x for x in u if x not in roster],
                           clock=lambda: t["w"], own_nodes_fn=lambda: {1000, 2000, 3000},
                           attribute_fn=attribute, mesh_foreign_fn=lambda: mesh["n"])
    u_before = calls["union"]
    dgm.observe(dark, topo); dgm.observe(dark, topo)
    check("mesh clean (0 foreign at the vantage) -> no union read, DARK_ONLY, note",
          calls["union"] == u_before and dgm.status()["nodes"]["4000"]["state"] == STATE_DARK_ONLY
          and "nothing to attribute" in (dgm.status()["nodes"]["4000"]["note"] or ""))
    mesh["n"] = 5
    dgm.observe(dark, topo); dgm.observe(dark, topo)
    check("mesh foreign > 0 -> union read resumes and evidence confirms",
          calls["union"] == u_before + 2 and dgm.status()["nodes"]["4000"]["state"] == STATE_UNVERIFIED)
    mesh["n"] = None
    dgm.observe(dark, topo)
    check("mesh count unknown (None) -> reads proceed", calls["union"] == u_before + 3)
    # S7 (audit 3): posting grace persists across a restart
    posted = {}
    pp = DarkGuestTracker(lambda: cfg, lambda: disc,
                          foreign_fn=lambda u: [x for x in u if x not in roster],
                          clock=lambda: t["w"], own_nodes_fn=lambda: {1000, 2000, 3000},
                          attribute_fn=attribute, persist_posting=lambda d: posted.update(d))
    pp.observe([], topo, posting_ids=[4000])
    pp2 = DarkGuestTracker(lambda: cfg, lambda: disc,
                           foreign_fn=lambda u: [x for x in u if x not in roster],
                           clock=lambda: t["w"], own_nodes_fn=lambda: {1000, 2000, 3000},
                           attribute_fn=attribute)
    pp2.load_posting_times(posted)
    pp2.observe(dark, topo); pp2.observe(dark, topo)
    check("S7: persisted posting time suppresses evidence after a restart",
          posted.get("4000") == t["w"] and pp2.status()["nodes"]["4000"]["consecutive"] == 0)
    # S-A: one cut at a time
    dg7 = mk()
    dg7.observe(dark, topo); dg7.observe(dark, topo)
    dg7._cut_lock.acquire()
    check("S-A: a K while another cut is in flight is deferred",
          dg7.on_keyed(4000, "2,4000TK", vantage=2000) is False)
    dg7._cut_lock.release()

    print(f"\n{'PASS' if not failures else 'FAIL'}: {len(failures)} failure(s) {failures or ''}")
    return 1 if failures else 0


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
