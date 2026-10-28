"""Phase 2 listener notice cadence (2026-09-07).

While a permitted all-monitor "listener" guest with at least one outside
branch is present, the operator gets an INFREQUENT internal email saying that
the system's link counts (Supermon, *70, RPT_NUMLINKS) include mesh entries
reachable only through that guest's monitor links, and that the link-state
watchdog is running on a frozen allowance. Pattern copied from
vantage_trust.py: evaluate on the scan thread, keep an undelivered notice
pending across refused sends (quiet hours, caps, SMTP), retry next scan,
persist the last-sent time so a restart or SIGHUP does not re-send.

Never gates enforcement. Fail-safe: every public method swallows its own
errors and logs.
"""

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_HOURS = 24.0


class ListenerNotice:
    def __init__(self, interval_hours: float = DEFAULT_INTERVAL_HOURS,
                 last_sent_ts: Optional[float] = None):
        try:
            self.interval_s = max(3600.0, float(interval_hours) * 3600.0)
        except (TypeError, ValueError):
            logger.error("listener_notice: bad interval_hours %r; using %g h",
                         interval_hours, DEFAULT_INTERVAL_HOURS)
            self.interval_s = DEFAULT_INTERVAL_HOURS * 3600.0
        # Wall-clock (time.time) so it survives restarts via persistence.
        self.last_sent_ts: Optional[float] = (
            float(last_sent_ts) if last_sent_ts else None)
        self._pending: Optional[dict] = None
        self.last_eval: dict = {"listeners": 0, "with_branches": 0}

    # ---- scan-thread API ---------------------------------------------------

    def evaluate(self, listeners: list, mesh_count: Optional[int],
                 unaccounted: Optional[int], system_count: int,
                 now: Optional[float] = None) -> None:
        """Decide whether a notice is due. A notice becomes pending when at
        least one listener has an outside branch and the interval since the
        last SENT notice has elapsed. A listener set with no outside
        branches (pure monitor of the system) is not worth an email."""
        try:
            now = time.time() if now is None else now
            with_branches = [l for l in (listeners or []) if l.get("monitored")]
            self.last_eval = {"listeners": len(listeners or []),
                              "with_branches": len(with_branches)}
            if not with_branches:
                self._pending = None
                return
            if self._pending is not None:
                # Refresh the payload; the send is still owed.
                self._pending.update(listeners=with_branches, mesh_count=mesh_count,
                                     unaccounted=unaccounted,
                                     system_count=system_count)
                return
            due = (self.last_sent_ts is None
                   or now - self.last_sent_ts >= self.interval_s)
            if due:
                self._pending = {"listeners": with_branches,
                                 "mesh_count": mesh_count,
                                 "unaccounted": unaccounted,
                                 "system_count": system_count}
        except Exception as e:
            logger.error("listener_notice: evaluate failed (non-fatal): %s", e)

    def pending(self) -> Optional[dict]:
        return self._pending

    def mark_sent(self, notice: dict, now: Optional[float] = None) -> None:
        if notice is self._pending or notice == self._pending:
            self._pending = None
        self.last_sent_ts = time.time() if now is None else now

    def carry_state_from(self, other: "ListenerNotice") -> None:
        """SIGHUP rebuild: keep the cadence clock and any owed notice."""
        self.last_sent_ts = other.last_sent_ts
        self._pending = other._pending
        self.last_eval = dict(other.last_eval)

    def status(self) -> dict:
        return {
            "interval_hours": round(self.interval_s / 3600.0, 2),
            "last_sent_ts": self.last_sent_ts,
            "pending": self._pending is not None,
            **self.last_eval,
        }


def _selftest() -> int:
    checks = []
    L = [{"node": 4000, "monitored": [5000]}]
    n = ListenerNotice(interval_hours=24, last_sent_ts=None)
    n.evaluate(L, 134, 125, 9, now=1000.0)
    checks.append(("first sighting -> pending", n.pending() is not None))
    p = n.pending()
    n.mark_sent(p, now=1000.0)
    checks.append(("mark_sent clears pending + stamps time",
                   n.pending() is None and n.last_sent_ts == 1000.0))
    n.evaluate(L, 134, 125, 9, now=1000.0 + 3600)
    checks.append(("inside interval -> not pending", n.pending() is None))
    n.evaluate(L, 134, 125, 9, now=1000.0 + 24 * 3600)
    checks.append(("interval elapsed -> pending again", n.pending() is not None))
    n.evaluate([{"node": 4000, "monitored": []}], 9, 0, 9, now=1000.0 + 25 * 3600)
    checks.append(("listener with no branches -> pending cleared, no email",
                   n.pending() is None))
    n.evaluate([], None, None, 9, now=2000.0 + 48 * 3600)
    checks.append(("no listeners -> nothing pending", n.pending() is None))
    m = ListenerNotice(interval_hours=24, last_sent_ts=None)
    m.evaluate(L, 1, 1, 1, now=5000.0)
    m2 = ListenerNotice(interval_hours=12)
    m2.carry_state_from(m)
    checks.append(("carry_state_from keeps the owed notice",
                   m2.pending() is not None and m2.last_sent_ts is None))
    r = ListenerNotice(interval_hours=24, last_sent_ts=9000.0)
    r.evaluate(L, 1, 1, 1, now=9000.0 + 60)
    checks.append(("persisted last_sent honored after restart", r.pending() is None))
    checks.append(("floor of 1 hour on interval",
                   ListenerNotice(interval_hours=0.01).interval_s == 3600.0))
    checks.append(("bad interval falls back",
                   ListenerNotice(interval_hours="x").interval_s
                   == DEFAULT_INTERVAL_HOURS * 3600.0))
    checks.append(("status shape", set(r.status()) >= {
        "interval_hours", "last_sent_ts", "pending", "listeners", "with_branches"}))
    failed = [nm for nm, ok in checks if not ok]
    for nm, ok in checks:
        print(f"  [{'OK' if ok else 'FAIL'}] {nm}")
    print(f"listener_notice selftest: {len(checks) - len(failed)}/{len(checks)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
