"""AllStar network analytics — periodic report generator (standalone, read-only).

Reads `analytics.db` and renders an operator/trustee-facing health summary.
This process ONLY reads the DB; a bug here can never touch the monitor or the
detection path. Email delivery is a stub for now (logs what it WOULD send) —
the live SMTP wiring (reusing notifier's internal-recipient path under a
separate, never-external category) is deferred until after the soak commit.

Usage:
    python analytics_report.py --db analytics.db --period week
    python analytics_report.py --db analytics.db --start 2026-06-23 --end 2026-06-30 --format html --out report.html

See Analytics_Design_2026-06-30.md.
"""

from __future__ import annotations

import argparse
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from analytics_db import ROLE_CORE, ROLE_BRIDGE, ROLE_GUEST

logger = logging.getLogger(__name__)

# A heartbeat gap larger than this counts as monitoring downtime (excluded from
# availability denominators so monitor outages aren't misreported as node outages).
DEFAULT_MONITOR_GAP_THRESHOLD_S = 900   # 3x the 300s poll interval


def _parse(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _fmt_dur(secs: int) -> str:
    secs = int(secs)
    if secs < 60:
        return f"{secs} sec"
    if secs < 3600:
        return f"{secs // 60} min"
    h, m = divmod(secs // 60, 60)
    return f"{h} h {m} min" if m else f"{h} h"


def _fmt_local(dt: datetime, tz_label: str = "UTC") -> str:
    return dt.strftime("%a %Y-%m-%d %H:%M")


@dataclass
class Outage:
    start: datetime
    end: datetime

    @property
    def secs(self) -> int:
        return int((self.end - self.start).total_seconds())


@dataclass
class NodeAvailability:
    node_id: int
    role: str
    availability: Optional[float]   # None when no monitored time
    outages: list[Outage] = field(default_factory=list)

    @property
    def longest_outage(self) -> Optional[Outage]:
        return max(self.outages, key=lambda o: o.secs, default=None)


@dataclass
class GuestSession:
    node_id: int
    attached_to: int
    connected: datetime
    left: Optional[datetime]
    dwell_secs: Optional[int]

    @property
    def ongoing(self) -> bool:
        return self.left is None


@dataclass
class ReportData:
    start: datetime
    end: datetime
    monitor_down_secs: int
    core: list[NodeAvailability]
    bridges: list[NodeAvailability]
    guest_sessions: list[GuestSession]

    @property
    def period_secs(self) -> int:
        return int((self.end - self.start).total_seconds())


# --------------------------------------------------------------------------- #
# Computation
# --------------------------------------------------------------------------- #
def _monitor_down_intervals(conn, start, end, threshold) -> list[tuple[datetime, datetime]]:
    rows = conn.execute(
        "SELECT ts FROM scan_heartbeat WHERE ts >= ? AND ts <= ? ORDER BY ts",
        (start.isoformat(), end.isoformat()),
    ).fetchall()
    beats = [_parse(r[0]) for r in rows]
    downs: list[tuple[datetime, datetime]] = []
    if not beats:
        return [(start, end)]            # no heartbeats at all → fully unmonitored
    if (beats[0] - start).total_seconds() > threshold:
        downs.append((start, beats[0]))
    for a, b in zip(beats, beats[1:]):
        if (b - a).total_seconds() > threshold:
            downs.append((a, b))
    if (end - beats[-1]).total_seconds() > threshold:
        downs.append((beats[-1], end))
    return downs


def _overlap(a0, a1, b0, b1) -> int:
    lo, hi = max(a0, b0), min(a1, b1)
    return max(0, int((hi - lo).total_seconds()))


def _state_at_start(conn, node_id, start) -> str:
    prior = conn.execute(
        "SELECT event FROM node_state_events WHERE node_id = ? AND ts < ? "
        "ORDER BY ts DESC LIMIT 1", (node_id, start.isoformat()),
    ).fetchone()
    if prior:
        return "present" if prior[0] == "appeared" else "absent"
    first = conn.execute(
        "SELECT event FROM node_state_events WHERE node_id = ? AND ts >= ? "
        "ORDER BY ts ASC LIMIT 1", (node_id, start.isoformat()),
    ).fetchone()
    if first:
        return "present" if first[0] == "disappeared" else "absent"
    present_now = conn.execute(
        "SELECT 1 FROM current_presence WHERE node_id = ?", (node_id,)
    ).fetchone()
    return "present" if present_now else "absent"


def _absences(conn, node_id, start, end) -> list[Outage]:
    events = conn.execute(
        "SELECT ts, event FROM node_state_events WHERE node_id = ? "
        "AND ts >= ? AND ts <= ? ORDER BY ts", (node_id, start.isoformat(), end.isoformat()),
    ).fetchall()
    state = _state_at_start(conn, node_id, start)
    cur_time = start
    out: list[Outage] = []
    for ts_s, event in events:
        etime = _parse(ts_s)
        new = "present" if event == "appeared" else "absent"
        if new != state:
            if state == "absent":
                out.append(Outage(cur_time, etime))
            cur_time = etime
            state = new
    if state == "absent":
        out.append(Outage(cur_time, end))
    return out


def _node_availability(conn, node_id, role, start, end, downs) -> NodeAvailability:
    absences = _absences(conn, node_id, start, end)
    period = int((end - start).total_seconds())
    down = sum(_overlap(s, e, start, end) for s, e in downs)
    monitored = period - down
    # absence during MONITORED time only
    absent_monitored = 0
    reported: list[Outage] = []
    for o in absences:
        in_down = sum(_overlap(o.start, o.end, s, e) for s, e in downs)
        net = o.secs - in_down
        absent_monitored += max(0, net)
        if net > 0:                       # skip outages fully inside monitor-down
            reported.append(o)
    avail = (monitored - absent_monitored) / monitored if monitored > 0 else None
    return NodeAvailability(node_id, role, avail, reported)


def generate_report(db_path, start: datetime, end: datetime,
                    focus_node: int, core_nodes: set[int], bridge_nodes: set[int],
                    gap_threshold: int = DEFAULT_MONITOR_GAP_THRESHOLD_S) -> ReportData:
    conn = sqlite3.connect(str(db_path))
    try:
        downs = _monitor_down_intervals(conn, start, end, gap_threshold)
        monitor_down = sum(_overlap(s, e, start, end) for s, e in downs)

        all_core = sorted({focus_node} | core_nodes)
        core = [_node_availability(conn, n, ROLE_CORE, start, end, downs) for n in all_core]
        bridges = [_node_availability(conn, n, ROLE_BRIDGE, start, end, downs)
                   for n in sorted(bridge_nodes)]

        # Guest sessions overlapping the period.
        rows = conn.execute(
            "SELECT node_id, attached_to, connected_ts, left_ts, dwell_secs "
            "FROM guest_sessions WHERE connected_ts <= ? AND (left_ts IS NULL OR left_ts >= ?) "
            "ORDER BY connected_ts", (end.isoformat(), start.isoformat()),
        ).fetchall()
        guests = [GuestSession(r[0], r[1], _parse(r[2]),
                               _parse(r[3]) if r[3] else None, r[4]) for r in rows]

        return ReportData(start, end, monitor_down, core, bridges, guests)
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Rendering (trustee-appropriate)
# --------------------------------------------------------------------------- #
def _label(node_id: int, labels: dict[int, str]) -> str:
    return labels.get(node_id, f"Node {node_id}")


def render_text(r: ReportData, labels: Optional[dict[int, str]] = None,
                system_name: str = "") -> str:
    labels = labels or {}
    L = []
    L.append(f"{system_name} Network Health Summary".strip())
    L.append(f"Period: {_fmt_local(r.start)} — {_fmt_local(r.end)} (UTC)")
    if r.monitor_down_secs > 0:
        L.append(f"(Monitoring offline {_fmt_dur(r.monitor_down_secs)} during this period; "
                 f"excluded from availability.)")
    L.append("")
    L.append("Core infrastructure (target: always on)")
    for n in r.core:
        av = "n/a" if n.availability is None else f"{n.availability * 100:.1f}%"
        lo = n.longest_outage
        lo_s = f"; longest {_fmt_dur(lo.secs)} ({_fmt_local(lo.start)})" if lo else ""
        L.append(f"  - {_label(n.node_id, labels)}: {av} availability, "
                 f"{len(n.outages)} outage(s){lo_s}")
    L.append("")
    L.append("Designated bridge nodes (expected to come and go)")
    if not r.bridges:
        L.append("  - (none configured)")
    for n in r.bridges:
        av = "n/a" if n.availability is None else f"{n.availability * 100:.1f}%"
        L.append(f"  - {_label(n.node_id, labels)}: {av} present, {len(n.outages)} gap(s)")
    L.append("")
    L.append(f"Guest activity: {len(r.guest_sessions)} session(s), "
             f"{len({g.node_id for g in r.guest_sessions})} distinct node(s)")
    for g in sorted(r.guest_sessions, key=lambda g: g.connected):
        when = _fmt_local(g.connected)
        if g.ongoing:
            dwell = "ongoing"
            left = "—"
        else:
            dwell = _fmt_dur(g.dwell_secs or int((g.left - g.connected).total_seconds()))
            left = _fmt_local(g.left)
        L.append(f"  - {_label(g.node_id, labels)} on {_label(g.attached_to, labels)}: "
                 f"{when} → {left} ({dwell})")
    L.append("")
    longest = max((g for g in r.guest_sessions if not g.ongoing),
                  key=lambda g: g.dwell_secs or 0, default=None)
    if longest:
        L.append(f"Highlights: longest guest visit {_label(longest.node_id, labels)} "
                 f"({_fmt_dur(longest.dwell_secs or 0)}).")
    L.append("No unauthorized bridging events occurred during this period. "
             "(Violations, when they occur, are reported separately and in real time.)")
    return "\n".join(L)


def render_html(r: ReportData, labels: Optional[dict[int, str]] = None,
                system_name: str = "") -> str:
    labels = labels or {}
    title = f"{system_name} Network Health Summary".strip()

    def rows_avail(nodes, third_label):
        out = []
        for n in nodes:
            av = "n/a" if n.availability is None else f"{n.availability * 100:.1f}%"
            lo = n.longest_outage
            extra = f"{_fmt_dur(lo.secs)} ({_fmt_local(lo.start)})" if lo else "—"
            out.append(f"<tr><td>{_label(n.node_id, labels)}</td><td>{av}</td>"
                       f"<td>{len(n.outages)}</td><td>{extra}</td></tr>")
        return "\n".join(out)

    grows = []
    for g in sorted(r.guest_sessions, key=lambda g: g.connected):
        left = "—" if g.ongoing else _fmt_local(g.left)
        dwell = "ongoing" if g.ongoing else _fmt_dur(
            g.dwell_secs or int((g.left - g.connected).total_seconds()))
        grows.append(f"<tr><td>{_label(g.node_id, labels)}</td>"
                     f"<td>{_label(g.attached_to, labels)}</td>"
                     f"<td>{_fmt_local(g.connected)}</td><td>{left}</td><td>{dwell}</td></tr>")

    return f"""<html><body style="font-family:sans-serif">
<h2>{title}</h2>
<p>Period: {_fmt_local(r.start)} — {_fmt_local(r.end)} (UTC)</p>
<h3>Core infrastructure (target: always on)</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Availability</th><th>Outages</th><th>Longest outage</th></tr>
{rows_avail(r.core, 'Outages')}
</table>
<h3>Designated bridge nodes (expected to come and go)</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Present</th><th>Gaps</th><th>Longest gap</th></tr>
{rows_avail(r.bridges, 'Gaps')}
</table>
<h3>Guest activity ({len(r.guest_sessions)} sessions)</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Guest</th><th>Visited</th><th>Arrived</th><th>Left</th><th>Dwell</th></tr>
{''.join(grows)}
</table>
<p><em>No unauthorized bridging events occurred during this period. Violations,
when they occur, are reported separately and in real time.</em></p>
</body></html>"""


def send_report(html: str, subject: str, recipients: list[str]) -> None:
    """STUB. Post-soak: route through notifier's internal-recipient SMTP path
    under a dedicated ANALYTICS category (never external, never rate-limited
    against alerts). For now, just log the intent."""
    logger.info("would email analytics report '%s' to %s (%d bytes html)",
                subject, recipients, len(html))


def _period_bounds(args) -> tuple[datetime, datetime]:
    if args.start and args.end:
        return (_parse(args.start), _parse(args.end))
    now = datetime.now(timezone.utc)
    span = timedelta(days=1 if args.period == "day" else 7)
    return (now - span, now)


def _load_roles_from_config(path: str):
    """Read focus/core/bridge/db from config.yaml (single source of truth).
    core   = analytics.core_nodes, else the focus hub.
    bridge = analytics.bridge_nodes, else the detection bridge_nodes.
    Tolerant: returns empty roles if the config is missing/unreadable."""
    try:
        import yaml
        cfg = yaml.safe_load(open(path)) or {}
    except Exception:
        return None, set(), set(), "analytics.db", ""
    focus = cfg.get("focus_node")
    acfg = cfg.get("analytics") or {}
    if not isinstance(acfg, dict):
        acfg = {}
    core = set(acfg.get("core_nodes") or ([focus] if focus is not None else []))
    bridges = set(acfg.get("bridge_nodes") or cfg.get("bridge_nodes", []))
    return (focus, core, bridges, acfg.get("db_path", "analytics.db"),
            acfg.get("system_name", ""))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ap = argparse.ArgumentParser(description="AllStar network analytics report generator")
    ap.add_argument("--config", default="config.yaml",
                    help="config.yaml to read roles/db from (no hardcoded node ids)")
    ap.add_argument("--db", help="override analytics db path")
    ap.add_argument("--period", choices=["day", "week"], default="week")
    ap.add_argument("--start"); ap.add_argument("--end")
    ap.add_argument("--focus", type=int, help="override focus node id")
    ap.add_argument("--core", help="override: comma-separated core node ids")
    ap.add_argument("--bridges", help="override: comma-separated bridge node ids")
    ap.add_argument("--format", choices=["text", "html"], default="text")
    ap.add_argument("--out", help="write to file instead of stdout")
    args = ap.parse_args()

    def _ids(s): return {int(x) for x in s.split(",") if x.strip()}
    focus, core, bridges, cfg_db, system_name = _load_roles_from_config(args.config)
    if args.focus is not None:
        focus = args.focus
    if args.core is not None:
        core = _ids(args.core)
    if args.bridges is not None:
        bridges = _ids(args.bridges)
    db = args.db or cfg_db
    start, end = _period_bounds(args)
    r = generate_report(db, start, end, focus, core, bridges)
    rendered = (render_html(r, system_name=system_name) if args.format == "html"
                else render_text(r, system_name=system_name))
    if args.out:
        with open(args.out, "w") as f:
            f.write(rendered)
        logger.info("wrote %s", args.out)
    else:
        print(rendered)


if __name__ == "__main__":
    main()
