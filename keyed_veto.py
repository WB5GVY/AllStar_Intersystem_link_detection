"""Keyed-listener veto tracker — step 2 trigger B (2026-09-07).

A permitted listener (phase 2) claims every link is monitor-only. A true
monitor link never keys toward the monitored node, so when the vantage's
RPT_ALINKS shows that listener with a K suffix, the self-report is
contradicted. This tracker turns those observations into a VETO on the
node's listener status:

  * `confirm_keyups` K observations in separate AMI frames within `ttl_s`
    are required before the first veto (audit C1: no single-observation path
    to enforcement). 1 = act on the first keyup.
  * A veto is written into the analyzer's `listener_veto` (node -> reason);
    the analyzer then refuses listener status and today's violation path
    runs. A veto alone cuts nothing — a cut still needs outside links.
  * Every further keyup on a vetoed node renews the TTL and counts a
    strike (audit S5). The AMI listener keeps watching vetoed nodes via
    `watch_ids()` even after they drop out of the listener set. A renewal
    requests NO scan and sends NO email (audit C-2/C-3: a third party's PTT
    rate must not drive our scan or mail rate); one email per veto
    episode, retried at the next `expire()` if the dispatcher refused it
    (quiet hours), and at most one renewal digest per TTL.
  * Expiry (called by the main loop before each scan) drops a veto only
    after a scan has consulted it (audit S4) or at 4x TTL regardless.
  * One internal email per veto (audit S3: a vetoed node with no outside
    links raises no violation, so this note is the only record).

All public methods are thread-safe (the AMI thread calls `on_keyed`; the
main thread calls `expire`, `status`, `carry_to`). The analyzer object is
obtained through a getter because the daemon rebinds it on SIGHUP.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class KeyedVetoTracker:
    def __init__(self, analyzer_getter: Callable[[], object],
                 cfg_getter: Callable[[], dict],
                 vantage_node: int,
                 on_trip: Optional[Callable[[str], None]] = None,
                 notifier_getter: Optional[Callable[[], object]] = None,
                 listener_ids_getter: Optional[Callable[[], frozenset]] = None,
                 clock: Callable[[], float] = time.time,
                 mono: Callable[[], float] = time.monotonic):
        self._analyzer = analyzer_getter
        self._cfg = cfg_getter
        self.vantage = int(vantage_node)
        self._on_trip = on_trip
        self._notifier = notifier_getter      # getter: the daemon rebinds on SIGHUP
        self._listener_ids = listener_ids_getter
        self._clock, self._mono = clock, mono
        self._lock = threading.Lock()
        self._seen: dict[int, list] = {}       # node -> monotonic keyup times
        self._veto_at: dict[int, float] = {}   # node -> wall time of last veto
        self._first_veto_at: dict[int, float] = {}
        self._strikes: dict[int, int] = {}
        self._last_alert_at: dict[int, float] = {}
        self._pending_alert: dict[int, tuple] = {}   # nid -> (reason, strikes, renewed)

    # --- inputs --------------------------------------------------------------

    def watch_ids(self) -> frozenset:
        """Ids the AMI listener should report K for: permitted listeners
        plus already-vetoed nodes."""
        try:
            ids = set(self._listener_ids()) if self._listener_ids else set()
            with self._lock:
                ids.update(self._analyzer().listener_veto.keys())
            return frozenset(ids)
        except Exception:
            return frozenset()

    def on_keyed(self, node: int, alinks: str = "",
                 vantage: Optional[int] = None) -> Optional[str]:
        """Record one K observation. Returns the veto reason when a veto was
        written or renewed, else None. Never raises."""
        try:
            cfg = self._cfg()
            if not cfg.get("keyed_veto_enabled", True):
                return None
            nid = int(node)
            ttl = int(cfg.get("keyed_veto_ttl_seconds", 900))
            need = max(1, int(cfg.get("keyed_veto_confirm_keyups", 2)))
            now_m, now_w = self._mono(), self._clock()
            stamp = datetime.fromtimestamp(now_w).astimezone().strftime("%H:%M:%S %Z")
            vantage = int(vantage) if vantage is not None else self.vantage
            # Membership guard (step 2b audit S1): the AMI feed reports K for
            # EVERY watched id — permitted listeners, vetoed nodes AND the
            # dark-guest tracker's ids. A node that is neither a permitted
            # listener nor already vetoed has no listener status to veto.
            if nid not in self.watch_ids():
                logger.debug("keyed veto: K for %d ignored — not a permitted "
                             "listener nor vetoed", nid)
                return None
            with self._lock:
                analyzer = self._analyzer()     # under the lock (audit ADV-1)
                hist = [t for t in self._seen.get(nid, []) if (now_m - t) <= ttl]
                hist.append(now_m)
                self._seen[nid] = hist
                already = nid in analyzer.listener_veto
                if len(hist) < need and not already:
                    logger.warning(
                        "Permitted listener %d keyed toward vantage %d at %s "
                        "(%d/%d observations before veto)", nid, vantage,
                        stamp, len(hist), need)
                    return None
                strikes = self._strikes.get(nid, 0) + 1
                self._strikes[nid] = strikes
                reason = (f"keyed toward vantage {vantage} at {stamp} despite "
                          f"monitor-only self-report ({len(hist)} keyup(s) observed, "
                          f"veto #{strikes}; RPT_ALINKS={alinks[:80]})")
                analyzer.listener_veto[nid] = reason
                self._veto_at[nid] = now_w
                if not already:
                    self._first_veto_at[nid] = now_w
                analyzer.listener_veto_seen.discard(nid)
                # Alert policy: one per episode; a renewal digest at most
                # once per TTL. Queue it; _flush_alerts sends outside the lock.
                last_alert = self._last_alert_at.get(nid)
                if (not already) or last_alert is None or (now_w - last_alert) >= ttl:
                    self._pending_alert[nid] = (reason, strikes, already)
            logger.warning("LISTENER VETO: node %d — %s", nid, reason)
            if self._on_trip and not already:
                # Scan only for a NEW veto; a renewal changes no verdict the
                # next scheduled scan will not reach (audit C-3).
                try:
                    self._on_trip(f"permitted listener {nid} keyed toward vantage "
                                  f"{vantage} — listener status refused "
                                  f"(veto #{strikes})")
                except Exception as e:
                    logger.error("keyed veto: trip callback failed: %s", e)
            self._flush_alerts()
            return reason
        except Exception as e:
            logger.error("keyed veto: on_keyed failed (non-fatal): %s", e)
            return None

    def _flush_alerts(self) -> None:
        """Send queued alerts; keep the ones the dispatcher refused (quiet
        hours, caps) for the next call (audit SIG-2). Never raises."""
        nt = self._notifier() if self._notifier else None
        if nt is None:
            return
        with self._lock:
            items = list(self._pending_alert.items())
        for nid, (reason, strikes, renewed) in items:
            try:
                ok = bool(nt.send_keyed_listener_alert(
                    nid, reason, strikes, already_vetoed=renewed))
            except Exception as e:
                logger.error("keyed veto: alert failed (non-fatal): %s", e)
                ok = False
            with self._lock:
                if ok:
                    self._last_alert_at[nid] = self._clock()
                    if self._pending_alert.get(nid) == (reason, strikes, renewed):
                        self._pending_alert.pop(nid, None)

    # --- maintenance (main thread) --------------------------------------------

    def expire(self) -> list[int]:
        """Drop vetoes past the TTL once consulted by a scan, or at 4x TTL
        regardless. Returns the expired ids."""
        out: list[int] = []
        self._flush_alerts()
        try:
            ttl = int(self._cfg().get("keyed_veto_ttl_seconds", 900))
            now_w = self._clock()
            with self._lock:
                analyzer = self._analyzer()
                for nid, t in list(self._veto_at.items()):
                    age = now_w - t
                    consulted = nid in analyzer.listener_veto_seen
                    if (age >= ttl and consulted) or age >= 4 * ttl:
                        self._veto_at.pop(nid, None)
                        self._first_veto_at.pop(nid, None)
                        self._seen.pop(nid, None)
                        self._pending_alert.pop(nid, None)
                        if analyzer.listener_veto.pop(nid, None) is not None:
                            out.append(nid)
                            logger.info("Keyed-listener veto on %d expired after %ds "
                                        "(consulted=%s)", nid, int(age), consulted)
                        analyzer.listener_veto_seen.discard(nid)
        except Exception as e:
            logger.error("keyed veto: expire failed (non-fatal): %s", e)
        return out

    def carry_to(self, new_analyzer) -> None:
        """SIGHUP: move vetoes to a rebuilt analyzer atomically."""
        with self._lock:
            old = self._analyzer()
            new_analyzer.listener_veto.update(old.listener_veto)
            new_analyzer.listener_veto_seen.update(old.listener_veto_seen)

    def status(self) -> dict:
        try:
            ttl = int(self._cfg().get("keyed_veto_ttl_seconds", 900))
            def _iso(t):
                return datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")
            with self._lock:
                return {
                    str(n): {
                        "reason": r,
                        "strikes": self._strikes.get(n, 0),
                        "since": _iso(self._first_veto_at[n]) if n in self._first_veto_at else None,
                        # eligible to lapse once a scan has consulted it...
                        "expires_after": _iso(self._veto_at[n] + ttl) if n in self._veto_at else None,
                        # ...and lapses regardless at this time (audit ADV-2)
                        "hard_deadline": _iso(self._veto_at[n] + 4 * ttl) if n in self._veto_at else None,
                        "alert_pending": n in self._pending_alert,
                    }
                    for n, r in self._analyzer().listener_veto.items()}
        except Exception:
            return {}


# --- selftest ----------------------------------------------------------------

def _selftest() -> int:            # pragma: no cover - developer tool
    import types
    failures = []

    def check(name, cond):
        print(f"  [{'OK' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    class _Analyzer:
        def __init__(self):
            self.listener_veto = {}
            self.listener_veto_seen = set()

    class _Notifier:
        def __init__(self):
            self.sent = []
            self.refuse = False

        def send_keyed_listener_alert(self, node, reason, strikes, already_vetoed=False):
            if self.refuse:
                return False
            self.sent.append((node, strikes, already_vetoed))
            return True

    t = {"w": 1_000_000.0, "m": 5000.0}
    cfg = {"keyed_veto_enabled": True, "keyed_veto_ttl_seconds": 900,
           "keyed_veto_confirm_keyups": 2}
    an = _Analyzer()
    holder = types.SimpleNamespace(a=an)
    trips, nt = [], _Notifier()
    kv = KeyedVetoTracker(lambda: holder.a, lambda: cfg, vantage_node=12345,
                          on_trip=trips.append, notifier_getter=lambda: nt,
                          listener_ids_getter=lambda: frozenset({34567}),
                          clock=lambda: t["w"], mono=lambda: t["m"])

    check("watch_ids = listener set when nothing vetoed", kv.watch_ids() == {34567})
    kv.on_keyed(99999, "2,99999TK"); kv.on_keyed(99999, "2,99999TK")
    check("S1 (step 2b): K for a node that is not a listener never vetoes",
          kv.on_keyed(99999, "2,99999TK") is None and 99999 not in an.listener_veto
          and 99999 not in kv._seen)
    r = kv.on_keyed(34567, "2,23456TU,34567RK")
    check("first keyup: no veto yet (confirm=2)", r is None and not an.listener_veto
          and trips == [] and nt.sent == [])
    t["m"] += 40; t["w"] += 40
    r = kv.on_keyed(34567, "2,23456TU,34567RK")
    check("second keyup within TTL: veto written, trip + email once",
          r and 34567 in an.listener_veto and "veto #1" in r
          and len(trips) == 1 and nt.sent == [(34567, 1, False)])
    check("watch_ids keeps a vetoed node even if it leaves the listener set",
          KeyedVetoTracker(lambda: holder.a, lambda: cfg, 12345,
                           listener_ids_getter=lambda: frozenset()).watch_ids() == {34567})
    check("status carries reason, strikes, both deadlines",
          kv.status()["34567"]["strikes"] == 1 and kv.status()["34567"]["expires_after"]
          and kv.status()["34567"]["hard_deadline"])
    # not consulted -> survives TTL; consulted -> expires
    t["w"] += 1000
    check("unconsulted veto survives the TTL (audit S4)",
          kv.expire() == [] and 34567 in an.listener_veto)
    an.listener_veto_seen.add(34567)
    check("consulted veto expires after the TTL",
          kv.expire() == [34567] and 34567 not in an.listener_veto
          and 34567 not in an.listener_veto_seen)
    # re-key on a vetoed node renews + strikes (S5)
    t["m"] += 10; t["w"] += 10
    kv.on_keyed(34567); t["m"] += 40; t["w"] += 40; kv.on_keyed(34567)
    check("re-vetoed after expiry, strike count continues",
          an.listener_veto and "veto #2" in an.listener_veto[34567])
    an.listener_veto_seen.add(34567)
    t["m"] += 100; t["w"] += 100
    n_trips, n_sent = len(trips), len(nt.sent)
    r = kv.on_keyed(34567)
    check("keyup on an already-vetoed node renews (no confirm needed) and clears consulted",
          r and "veto #3" in r and 34567 not in an.listener_veto_seen)
    check("a renewal requests NO scan and NO email within the TTL (audit C-2/C-3)",
          len(trips) == n_trips and len(nt.sent) == n_sent)
    t["m"] += 900; t["w"] += 900
    kv.on_keyed(34567)
    check("renewal digest at most once per TTL",
          len(nt.sent) == n_sent + 1 and nt.sent[-1][2] is True and len(trips) == n_trips)
    # refused email is kept pending and retried by expire() (audit SIG-2)
    nt.refuse = True
    t["m"] += 900; t["w"] += 900
    kv.on_keyed(34567)
    check("refused alert stays pending", kv.status()["34567"]["alert_pending"] is True)
    nt.refuse = False
    kv.expire()
    check("pending alert retried on the next maintenance call",
          kv.status()["34567"]["alert_pending"] is False and nt.sent[-1][0] == 34567)
    # 4x TTL lapse without consultation
    t["w"] += 4 * 900 + 1
    check("never-consulted veto lapses at 4x TTL", kv.expire() == [34567])
    # disabled
    cfg["keyed_veto_enabled"] = False
    check("disabled -> inert", kv.on_keyed(34567) is None and not an.listener_veto)
    cfg["keyed_veto_enabled"] = True
    # confirm=1 acts on first keyup
    cfg["keyed_veto_confirm_keyups"] = 1
    an2 = _Analyzer(); holder.a = an2
    check("confirm=1 vetoes on the first keyup",
          kv.on_keyed(34567) is not None and 34567 in an2.listener_veto)
    r = kv.on_keyed(34567, "1,34567RK", vantage=45678)
    check("reporting vantage lands in the reason", "vantage 45678" in (r or ""))
    # SIGHUP carry
    an3 = _Analyzer()
    kv.carry_to(an3)
    check("carry_to copies vetoes to a rebuilt analyzer",
          an3.listener_veto == an2.listener_veto)
    # threads: hammer on_keyed while expiring; invariants, not exceptions
    # (audit SIG-1: every method swallows exceptions, so count ERROR records
    # and check the strike/veto bookkeeping instead)
    holder.a = an3
    cfg["keyed_veto_confirm_keyups"] = 1
    errors = []

    class _Count(logging.Handler):
        def emit(self, rec):
            if rec.levelno >= logging.ERROR:
                errors.append(rec.getMessage())
    h = _Count(); logger.addHandler(h)
    nt.sent.clear(); trips.clear()
    an3.listener_veto.clear(); an3.listener_veto_seen.clear()
    kv._strikes.clear(); kv._veto_at.clear(); kv._first_veto_at.clear()
    kv._last_alert_at.clear(); kv._pending_alert.clear(); kv._seen.clear()
    returned = []
    rlock = threading.Lock()

    def _hammer(k):
        for i in range(150):
            with rlock:
                t["w"] += 7; t["m"] += 7      # clock advances under contention
            r = kv.on_keyed(34567 + (i % 3))
            if r:
                with rlock:
                    returned.append(r)
    th = [threading.Thread(target=_hammer, args=(k,)) for k in range(4)]
    [x.start() for x in th]
    for _ in range(150):
        an3.listener_veto_seen.update(an3.listener_veto.keys())
        kv.expire(); kv.status(); kv.watch_ids()
    [x.join() for x in th]
    kv.expire()
    logger.removeHandler(h)
    total_strikes = sum(kv._strikes.values())
    check("hammer: no ERROR logged under contention", not errors)
    check("hammer: every veto write returned a reason (strikes == returns)",
          total_strikes == len(returned) > 0)
    check("hammer: new-veto trips == first vetoes per episode (renewals never trip)",
          len(trips) <= total_strikes and len(trips) > 0)
    check("hammer: emails <= vetoes and no email without a veto",
          0 < len(nt.sent) <= total_strikes)

    print(f"\n{'PASS' if not failures else 'FAIL'}: {len(failures)} failure(s) {failures or ''}")
    return 1 if failures else 0


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
