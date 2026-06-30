"""Synthetic data seeder for the analytics pipeline (validation only).

Generates a realistic week of 5-minute scans into a throwaway analytics.db so the
schema + recorder + reporter can be exercised end-to-end WITHOUT any live data.
Uses generic placeholder node IDs (1xxx core, 2xxx bridge, 5xxx guests) so this
file carries no real identifiers and the analytics code stays publishable.

    python analytics_seed.py --db /tmp/analytics_demo.db
    python analytics_report.py --db /tmp/analytics_demo.db \
        --start 2026-06-23 --end 2026-06-30 --focus 1001 --core 1002,1003 --bridges 2001
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from analytics_db import (Recorder, PresentNode, init_db,
                          ROLE_CORE, ROLE_BRIDGE, ROLE_GUEST)

BASE = datetime(2026, 6, 23, 0, 0, tzinfo=timezone.utc)
DAYS = 7
TICK = timedelta(minutes=5)

FOCUS = 1001
CORE = [1002, 1003]
BRIDGE = 2001

# Guest visits: (node, attached_to, start_offset, duration). None duration = ongoing.
GUESTS = [
    (5001, 1002, timedelta(days=0, hours=19, minutes=4), timedelta(minutes=37)),
    (5002, 1003, timedelta(days=1, hours=20, minutes=0), timedelta(hours=2, minutes=10)),
    (5003, 1002, timedelta(days=3, hours=14, minutes=0), timedelta(minutes=10)),
    (5004, 1003, timedelta(days=0, hours=0, minutes=0), None),  # resident all week
]

# Core 1002 brief outage; bridge 2001 absent each night 02:00–05:00.
CORE_OUTAGE = (1002, BASE + timedelta(days=2, hours=3, minutes=10), timedelta(minutes=14))


def _present_at(t: datetime) -> list[PresentNode]:
    nodes = [PresentNode(FOCUS, ROLE_CORE)]
    # core
    for c in CORE:
        if c == CORE_OUTAGE[0] and CORE_OUTAGE[1] <= t < CORE_OUTAGE[1] + CORE_OUTAGE[2]:
            continue
        nodes.append(PresentNode(c, ROLE_CORE))
    # bridge: down 02:00–05:00 local-ish each day
    if not (2 <= t.hour < 5):
        nodes.append(PresentNode(BRIDGE, ROLE_BRIDGE))
    # guests
    for gid, att, off, dur in GUESTS:
        gstart = BASE + off
        if t >= gstart and (dur is None or t < gstart + dur):
            nodes.append(PresentNode(gid, ROLE_GUEST, attached_to=att))
    return nodes


def seed(db_path: str) -> dict[str, int]:
    conn = init_db(db_path)
    # clean slate for repeatable demo
    for tbl in ("node_state_events", "guest_sessions", "scan_heartbeat", "current_presence"):
        conn.execute(f"DELETE FROM {tbl}")
    conn.commit()
    rec = Recorder(conn)
    totals = {"appeared": 0, "disappeared": 0, "moved": 0}
    t = BASE
    end = BASE + timedelta(days=DAYS)
    while t < end:
        c = rec.reconcile_scan(_present_at(t), ts=t.isoformat())
        for k in totals:
            totals[k] += c[k]
        t += TICK
    conn.close()
    return totals


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="/tmp/analytics_demo.db")
    args = ap.parse_args()
    totals = seed(args.db)
    print(f"seeded {args.db}: {totals}")


if __name__ == "__main__":
    main()
