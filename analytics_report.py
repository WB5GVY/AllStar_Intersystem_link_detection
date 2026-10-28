"""AllStar network analytics — periodic report generator (standalone, read-only).

Reads `analytics.db` and renders an operator/trustee-facing health summary.
This process only READS `analytics.db`; on --send it writes solely to its own
isolated `analytics_notifications.db` (never the daemon's `notifications.db`),
so a bug here can never touch the monitor or the detection path. Email
delivery (--send) routes through
notifier.Notifier under EmailCategory.ANALYTICS: Bennett-only
(internal_recipients), never external, not rate-limited against alert traffic,
sent as multipart/alternative (text + HTML).
Team page (--publish, 2026-10-20): the text digest is also written atomically
to `<public_export.dir>/digest.json` (contract v1, see build_digest_doc; rev 2
adds optional `blocks` — the email HTML transcribed into generic headings and
tables by digest_blocks_from_html, so the page can show tables) and
PUT once to the private blob named in `public_export.digest.blob_url`, with
the write-only SAS from the login keychain (item
`public_export.digest.sas_keychain_item`). --send and --publish are
independent: each is attempted, the exit code is 1 if either failed. The
helpers (atomic write, keychain read, PUT) are imported from public_export.py,
which is never modified here.

Usage:
    python analytics_report.py --db analytics.db --period week
    python analytics_report.py --config config.yaml --period day --send --publish
    python analytics_report.py --config config.yaml --period day --publish      # no email: hand test
    python analytics_report.py --db analytics.db --start 2026-06-23 --end 2026-06-30 --format html --out report.html

See Analytics_Design_2026-06-30.md.
"""

from __future__ import annotations

import argparse
import html
from html.parser import HTMLParser
import json
import logging
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

from analytics_db import ROLE_CORE, ROLE_BRIDGE, ROLE_GUEST

# Friendly labels for the external client_type values graph_analyzer emits.
# The stats API cannot distinguish RepeaterPhone / WebTransceiver / AllScan /
# generic IAX2 softphone, so all non-EchoLink IAX2 leaves share one bucket.
_CLIENT_TYPE_LABEL = {
    "echolink": "EchoLink",
    "webtransceiver_type": "WebTransceiver-type IAX2",
}

logger = logging.getLogger(__name__)

# A heartbeat gap larger than this counts as monitoring downtime (excluded from
# availability denominators so monitor outages aren't misreported as node outages).
DEFAULT_MONITOR_GAP_THRESHOLD_S = 900   # 3x the 300s poll interval

# Accuracy disclaimer appended to every report (text + HTML). Phrasing
# reflects the actual sampling design: 300s normal cadence, 15s (≈20x) around
# the top of each hour (the window runs ~:55 → :10), and the ~1–6 min timing
# uncertainty / transient-miss floor that follows from polling at that rate.
TIMING_DISCLAIMER = (
    "Disclaimer: There are significant accuracy limitations in the timing "
    "data above. It is derived from rate-limited polling of the "
    "AllStarLink.org API at strategic intervals each hour, with roughly 20x "
    "more frequent polling around the top of each hour (from about five "
    "minutes before to ten minutes after). Quoted Arrival, Departure, and "
    "Dwell times may generally be off by ~1 to 6 minutes under normal "
    "conditions — and by substantially more during a large-node-count "
    "unauthorized bridging event — and transient connection events "
    "shorter than ~1 to 6 minutes may be missed entirely."
)


def _parse(ts: str) -> datetime:
    # 'Z' suffix is only accepted by fromisoformat on Python 3.11+; normalize
    # for the documented 3.10 floor.
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _table_exists(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _fmt_dur(secs: int) -> str:
    secs = int(secs)
    if secs < 60:
        return f"{secs} sec"
    if secs < 3600:
        return f"{secs // 60} min"
    h, m = divmod(secs // 60, 60)
    return f"{h} h {m} min" if m else f"{h} h"


def _fmt_ts(dt: datetime, tz: Optional[ZoneInfo] = None) -> str:
    """Format a timestamp for display. When `tz` is given the instant is
    converted to that zone (times in the report read as local wall-clock);
    otherwise it is shown as-is (UTC). Render functions shadow this with a
    local `_fmt_local(dt)` closure that binds the report's tz."""
    if tz is not None:
        dt = dt.astimezone(tz)
    return dt.strftime("%a %Y-%m-%d %H:%M")


def _tz_label(dt: datetime, tz: Optional[ZoneInfo]) -> str:
    """Zone abbreviation for the period line/header (e.g. CDT/CST), computed
    from an in-period instant so DST is reflected correctly. 'UTC' when no tz."""
    if tz is None:
        return "UTC"
    return dt.astimezone(tz).strftime("%Z") or "local"


@dataclass
class Outage:
    start: datetime
    end: datetime

    @property
    def secs(self) -> int:
        return int((self.end - self.start).total_seconds())


@dataclass
class PresenceSession:
    """A contiguous interval during which a node was present (connected).
    Used for designated bridge nodes so the report can show arrived/left/dwell
    the same way it does for guests. `arrived is None` means the node was
    already present before the window began (true arrival predates the data);
    `left is None` means still present at the window end (ongoing)."""
    arrived: Optional[datetime]
    left: Optional[datetime]
    dwell_secs: Optional[int]

    @property
    def ongoing(self) -> bool:
        return self.left is None


@dataclass
class NodeAvailability:
    node_id: int
    role: str
    availability: Optional[float]   # None when no monitored time
    outages: list[Outage] = field(default_factory=list)
    sessions: list[PresenceSession] = field(default_factory=list)

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
class ExternalSession:
    """A non-AllStar leaf client (IAX2 softclient / EchoLink) visit, recorded in
    analytics_db.external_sessions. Identified by host node + type + name, not a
    node number."""
    host_node: int
    client_type: str
    ext_name: str
    connected: datetime
    left: Optional[datetime]
    dwell_secs: Optional[int]

    @property
    def ongoing(self) -> bool:
        return self.left is None

    @property
    def type_label(self) -> str:
        return _CLIENT_TYPE_LABEL.get(self.client_type, self.client_type)


@dataclass
class ViolationEpisode:
    """Aggregated view of analytics_db.violation_events rows sharing one
    (offender, path): a violation that persisted across N scans reads as one
    episode with first/last timestamps and a scan count."""
    offender: int
    callsign: str
    first: datetime
    last: datetime
    scans: int
    path: str
    quiet_suppressed: bool = False   # first detection fell in quiet hours →
                                     # the real-time sysadmin alert was HELD
                                     # and delivered when quiet hours ended
                                     # (deferred, 2026-10-12; dropped before
                                     # that); this digest is where it also
                                     # surfaces (2026-07-02 morning-digest
                                     # decision)


@dataclass
class LinkReportEpisode:
    """Aggregated view of analytics_db.link_report_events rows for one
    (node, kind): a node that did not report its links across N scans reads
    as one episode with first/last timestamps and a scan count (change 2,
    2026-09-08). kind: 'dark' (online, posting nothing), 'linkless'
    (posting a fresh record that names no links while still listed) or
    'unconfirmed' (2026-10-12: posting a record that names outside links
    but not the node it is attached to — a pre-join record, not judged)."""
    node: int
    kind: str
    callsign: str
    attached_to: Optional[int]
    attachment: str
    first: datetime
    last: datetime
    scans: int
    # True when the last row is within one episode gap of the period end (or
    # of now, if the period end lies in the future): the condition was still
    # holding when the period closed.
    ongoing: bool = False
    # linkless only: age of the empty post on the LAST scan of the episode.
    post_age_seconds: Optional[int] = None


@dataclass
class ReportData:
    start: datetime
    end: datetime
    monitor_down_secs: int
    core: list[NodeAvailability]
    bridges: list[NodeAvailability]
    guest_sessions: list[GuestSession]
    external_sessions: list[ExternalSession] = field(default_factory=list)
    violations: list[ViolationEpisode] = field(default_factory=list)
    # Guests attached to a NON-member node (not focus/core/bridge) — they can
    # only have arrived through a guest chain, i.e. dragged in by a violation
    # (Bennett, 2026-07-17). Reported in their own table, no callsign lookups.
    unwitting_sessions: list[GuestSession] = field(default_factory=list)
    # Change 2 (2026-09-08): nodes that did not report their links.
    link_reports: list[LinkReportEpisode] = field(default_factory=list)
    # Three-state node health (2026-10-18): per monitored node the
    # registered / posting / parent-letter facts over the window, and the
    # recorded transitions. node_health_available is False for a DB written
    # before the daemon recorded node health (section says so, no crash).
    node_health: list["NodeHealthSummary"] = field(default_factory=list)
    node_health_transitions: list["NodeHealthTransition"] = field(default_factory=list)
    node_health_available: bool = False
    # False when the config was read and has no enabled node_health block
    # (the section then says so instead of replaying the live table forever).
    node_health_enabled: bool = True

    @property
    def dark_episodes(self) -> list["LinkReportEpisode"]:
        return [e for e in self.link_reports if e.kind == "dark"]

    @property
    def linkless_episodes(self) -> list["LinkReportEpisode"]:
        return [e for e in self.link_reports if e.kind == "linkless"]

    @property
    def unconfirmed_episodes(self) -> list["LinkReportEpisode"]:
        """Coherence (2026-10-12): guests whose own record did not name the
        node they were attached to (a pre-join record) — seen, never cut."""
        return [e for e in self.link_reports if e.kind == "unconfirmed"]

    @property
    def period_secs(self) -> int:
        return int((self.end - self.start).total_seconds())

    @property
    def violator_nodes(self) -> set[int]:
        return {v.offender for v in self.violations}


# --------------------------------------------------------------------------- #
# Three-state node health (2026-10-18; node_health.py, PLAN v2 §4.4)
# --------------------------------------------------------------------------- #
try:
    from node_health import LETTER_TEXT as _LETTER_TEXT   # one wording everywhere
except Exception:                      # the report must render without the daemon modules
    _LETTER_TEXT = {"T": "live", "R": "rx-only", "L": "local monitor",
                    "C": "dialing, no audio", "-": "not listed",
                    "?": "parent data unavailable", "self": "hub"}
_LINKED_LETTERS = frozenset("TRL")
_KNOWN_LETTERS = frozenset("TRLC-")
NODE_HEALTH_MAX_TRANSITIONS = 20


@dataclass
class NodeHealthSummary:
    """One node over the window. Percentages are over the time the fact was
    KNOWN while monitoring was up (monitor-down and '?' / no-data time are
    excluded from the denominators and reported separately)."""
    node_id: int
    parent: object                     # int, "self" (the hub) or None (unknown)
    has_data: bool
    linked_pct: Optional[float]        # letter in T/R/L over known letter time; hub: posting_pct
    dialing_secs: int                  # letter C — parent dialing, no audio
    unlisted_secs: int                 # letter '-' — parent does not list it
    unknown_secs: int                  # letter '?' or nothing recorded
    registered_pct: Optional[float]
    posting_pct: Optional[float]
    end_registered: Optional[str]      # '1' | '0' | '?' | None
    end_posting: Optional[str]
    end_letter: Optional[str]
    since_registered: Optional[datetime]
    since_posting: Optional[datetime]
    since_letter: Optional[datetime]


@dataclass
class NodeHealthTransition:
    ts: datetime
    node_id: int
    field: str
    old: Optional[str]
    new: str


def _z(dt: datetime) -> str:
    """The scanner's 'YYYY-MM-DDTHH:MM:SSZ' form, for lexical ts comparisons."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _health_intervals(conn, node_id: int, fld: str, start, end):
    """[(t0, t1, value)] covering [start, end] for one (node, field),
    reconstructed from the baseline/transition rows; plus (value at end,
    instant that value began — None when it began before any row). value
    None = nothing recorded for that stretch."""
    prior = conn.execute(
        "SELECT ts, new, baseline FROM node_health_events WHERE node_id = ? AND field = ? "
        "AND ts < ? ORDER BY ts DESC, id DESC LIMIT 1", (node_id, fld, _z(start))).fetchone()
    rows = conn.execute(
        "SELECT ts, old, new FROM node_health_events WHERE node_id = ? AND field = ? "
        "AND ts >= ? AND ts <= ? ORDER BY ts, id", (node_id, fld, _z(start), _z(end))).fetchall()
    if prior:
        state, since = prior[1], _parse(prior[0])
        if prior[2]:
            # A restart baseline re-stamps a state that began EARLIER (audit
            # S5): the real start is the latest transition before the window
            # if it set this value, else the live table's since_<field>.
            since = None
            last_tr = conn.execute(
                "SELECT ts, new FROM node_health_events WHERE node_id = ? AND field = ? "
                "AND ts < ? AND baseline = 0 ORDER BY ts DESC, id DESC LIMIT 1",
                (node_id, fld, _z(start))).fetchone()
            if last_tr and last_tr[1] == state:
                since = _parse(last_tr[0])
            elif _table_exists(conn, "current_node_health"):
                cur = conn.execute(
                    f"SELECT {fld}, since_{fld} FROM current_node_health WHERE node_id = ?",
                    (node_id,)).fetchone()
                if cur and cur[0] == state and cur[1]:
                    cand = _parse(cur[1])
                    if cand <= start:            # a later 'since' belongs to a later window
                        since = cand
    elif rows and rows[0][1] is not None:
        # The first in-window row is a transition: its `old` held before it.
        state, since = rows[0][1], None
    else:
        state, since = None, None
    ivs = []
    cur_t = start
    for ts_s, _old, new in rows:
        t = _parse(ts_s)
        if new != state:
            ivs.append((cur_t, t, state))
            cur_t, state, since = t, new, t
    ivs.append((cur_t, end, state))
    return ivs, state, since


def _sum_monitored(ivs, downs, start, end) -> dict:
    """value -> seconds inside [start, end] minus monitor-down overlap."""
    tot: dict = {}
    for t0, t1, v in ivs:
        secs = _overlap(t0, t1, start, end) - sum(_overlap(t0, t1, s, e) for s, e in downs)
        tot[v] = tot.get(v, 0) + max(0, secs)
    return tot


def _pct(num: int, den: int) -> Optional[float]:
    return (num / den) if den > 0 else None


def _node_health_summary(conn, node_id: int, parent, start, end, downs) -> NodeHealthSummary:
    reg_ivs, reg_end, reg_since = _health_intervals(conn, node_id, "registered", start, end)
    post_ivs, post_end, post_since = _health_intervals(conn, node_id, "posting", start, end)
    let_ivs, let_end, let_since = _health_intervals(conn, node_id, "letter", start, end)
    reg = _sum_monitored(reg_ivs, downs, start, end)
    post = _sum_monitored(post_ivs, downs, start, end)
    let = _sum_monitored(let_ivs, downs, start, end)
    registered_pct = _pct(reg.get("1", 0), reg.get("1", 0) + reg.get("0", 0))
    posting_pct = _pct(post.get("1", 0), post.get("1", 0) + post.get("0", 0))
    known = sum(let.get(k, 0) for k in _KNOWN_LETTERS)
    linked_pct = _pct(sum(let.get(k, 0) for k in _LINKED_LETTERS), known)
    if parent == "self" or let_end == "self" or "self" in let:
        parent = "self"
        linked_pct = posting_pct            # the hub: "linked" = hub up = posting
    has_data = any(v is not None for _a, _b, v in reg_ivs + post_ivs + let_ivs)
    unknown = let.get("?", 0) + let.get(None, 0)
    return NodeHealthSummary(node_id, parent, has_data, linked_pct, let.get("C", 0),
                             let.get("-", 0), unknown, registered_pct, posting_pct,
                             reg_end, post_end, let_end, reg_since, post_since, let_since)


def _node_health_transitions(conn, start, end) -> list[NodeHealthTransition]:
    rows = conn.execute(
        "SELECT ts, node_id, field, old, new FROM node_health_events WHERE baseline = 0 "
        "AND ts >= ? AND ts <= ? ORDER BY ts, id", (_z(start), _z(end))).fetchall()
    return [NodeHealthTransition(_parse(r[0]), int(r[1]), r[2], r[3], r[4]) for r in rows]


def _parse_parent(v):
    if v is None:
        return None
    s = str(v).strip().lower()
    if s == "self":
        return "self"
    try:
        return int(s)
    except ValueError:
        return None


def _node_health_block(conn, health_nodes, start, end, downs):
    """(summaries, hub first then by node id; transitions). Nodes = the
    configured node_health nodes ∪ nodes with rows inside the window (so a
    node retired from the config shows once, in the window of its closing
    rows, and then drops out — audit S4). Without a config map (ad-hoc
    report) the live table supplies the node list and parents."""
    parents: dict = {}
    for k, v in (health_nodes or {}).items():
        try:
            parents[int(k)] = v
        except (TypeError, ValueError):
            continue
    if _table_exists(conn, "current_node_health"):
        for nid, par in conn.execute("SELECT node_id, parent FROM current_node_health"):
            if not health_nodes:
                parents.setdefault(int(nid), _parse_parent(par))
            elif int(nid) in parents and parents[int(nid)] is None:
                parents[int(nid)] = _parse_parent(par)
    for (nid,) in conn.execute(
            "SELECT DISTINCT node_id FROM node_health_events WHERE ts >= ? AND ts <= ?",
            (_z(start), _z(end))):
        if int(nid) not in parents:
            # parent from the row detail is not worth a JSON parse here; the
            # latest row's detail is tiny, so read it once.
            det = conn.execute(
                "SELECT detail FROM node_health_events WHERE node_id = ? AND ts >= ? AND ts <= ? "
                "ORDER BY ts DESC, id DESC LIMIT 1", (int(nid), _z(start), _z(end))).fetchone()
            par = None
            try:
                par = _parse_parent((json.loads(det[0]) or {}).get("parent")) if det and det[0] else None
            except Exception:
                par = None
            parents[int(nid)] = par
    order = sorted(parents, key=lambda n: (0 if parents[n] == "self" else 1, n))
    summaries = [_node_health_summary(conn, n, parents[n], start, end, downs) for n in order]
    return summaries, _node_health_transitions(conn, start, end)


def _fact_text(fld: str, value: Optional[str]) -> str:
    """One wording for a recorded value (text + HTML + transitions)."""
    if value is None:
        return "no data"
    if fld == "registered":
        return {"1": "registered", "0": "not registered"}.get(value, "registration unknown")
    if fld == "posting":
        return {"1": "posting", "0": "not posting"}.get(value, "posting unknown")
    if value == "self":
        return "hub"
    return f"{'—' if value == '-' else value} {_LETTER_TEXT.get(value, '')}".rstrip()


def _pct_text(p: Optional[float]) -> str:
    return "n/a" if p is None else f"{p * 100:.1f}%"


NODE_HEALTH_LEGEND = (
    "Legend: Registered = the node checked in with AllStar within 90 min. "
    "Posting = it sent its own stats post within 10 min. Link = the letter its "
    "parent node's record carries for it: T live · R rx-only · L local monitor · "
    "C dialing, no audio · — not listed · ? parent data unavailable. "
    "Linked = T/R/L (the hub: posting). Percentages are over the time the fact "
    "was known while monitoring was up; a change counts after two consecutive scans. "
    "A node the scan cannot reach directly is judged from a record read up to 25 min "
    "earlier, so its changes can show up to that much late."
)


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


def _presence_sessions(conn, node_id, start, end) -> list[PresenceSession]:
    """Contiguous present-intervals for a node over [start, end], for the
    arrived/left/dwell view. Complement of _absences, but it also looks back
    before `start` to recover the true arrival time of a session already in
    progress at the window edge (so a bridge that connected before the period
    still shows its real arrival)."""
    events = conn.execute(
        "SELECT ts, event FROM node_state_events WHERE node_id = ? "
        "AND ts >= ? AND ts <= ? ORDER BY ts", (node_id, start.isoformat(), end.isoformat()),
    ).fetchall()
    state = _state_at_start(conn, node_id, start)
    # If present at the window start, recover the true arrival (last 'appeared'
    # before start). None => present from before any recorded event.
    arrived: Optional[datetime] = None
    if state == "present":
        prior = conn.execute(
            "SELECT ts FROM node_state_events WHERE node_id = ? AND event = 'appeared' "
            "AND ts < ? ORDER BY ts DESC LIMIT 1", (node_id, start.isoformat()),
        ).fetchone()
        arrived = _parse(prior[0]) if prior else None

    sessions: list[PresenceSession] = []
    for ts_s, event in events:
        etime = _parse(ts_s)
        if event == "disappeared" and state == "present":
            dwell = int((etime - arrived).total_seconds()) if arrived else None
            sessions.append(PresenceSession(arrived, etime, dwell))
            state, arrived = "absent", None
        elif event == "appeared" and state == "absent":
            state, arrived = "present", etime
    if state == "present":
        # Ongoing at window end (left=None); dwell shown as "ongoing".
        sessions.append(PresenceSession(arrived, None, None))
    return sessions


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


def _in_quiet_hours(dt: datetime, quiet_cfg: Optional[dict]) -> bool:
    """True if `dt` falls inside the configured quiet-hours window (the window
    during which real-time VIOLATION_SYSADMIN alerts are suppressed). Handles
    windows that cross midnight (e.g. 22:00-07:00). Fail-safe: any config
    problem returns False (no annotation, never a crash)."""
    try:
        if not quiet_cfg or not quiet_cfg.get("enabled", False):
            return False
        tz = ZoneInfo(quiet_cfg.get("timezone", "UTC"))
        local = dt.astimezone(tz)
        sh, sm = map(int, str(quiet_cfg.get("start", "22:00")).split(":"))
        eh, em = map(int, str(quiet_cfg.get("end", "07:00")).split(":"))
        t = local.hour * 60 + local.minute
        s, e = sh * 60 + sm, eh * 60 + em
        if s <= e:
            return s <= t < e
        return t >= s or t < e               # window crosses midnight
    except Exception:
        return False


# A violation persisting across scans is one episode; a gap longer than this
# without a detection of that offender closes the episode. Comfortably above
# the 300s normal scan interval so a missed scan doesn't split an episode.
EPISODE_GAP_S = 900


def _violation_episodes(conn, start, end,
                        quiet_cfg: Optional[dict]) -> list[ViolationEpisode]:
    """Cluster violation_events rows in [start, end] into per-offender
    episodes by TIME GAP, not by path string (audit 2026-07-03 #3, S2):
    grouping by path both merged non-contiguous incidents hours apart AND
    fragmented one incident whose deep-path churned scan-to-scan. Callsign is
    the latest real one seen — never the literal 'Unknown' placeholder unless
    nothing better exists (S1: MAX() preferred 'Unknown' over K/N/A calls)."""
    if not _table_exists(conn, "violation_events"):
        return []
    rows = conn.execute(
        "SELECT ts, offending_node, offending_callsign, path "
        "FROM violation_events WHERE ts >= ? AND ts <= ? ORDER BY ts",
        (start.isoformat(), end.isoformat()),
    ).fetchall()
    open_eps: dict[int, dict] = {}
    closed: list[dict] = []
    for ts_s, node, callsign, path in rows:
        t = _parse(ts_s)
        ep = open_eps.get(node)
        if ep is not None and (t - ep["last"]).total_seconds() > EPISODE_GAP_S:
            closed.append(ep)
            ep = None
        if ep is None:
            ep = {"node": node, "first": t, "last": t, "scans": 0,
                  "paths": [], "callsign": ""}
            open_eps[node] = ep
        ep["last"] = t
        ep["scans"] += 1
        if path and path not in ep["paths"]:
            ep["paths"].append(path)
        if callsign and callsign != "Unknown":
            ep["callsign"] = callsign
    closed.extend(open_eps.values())
    closed.sort(key=lambda e: e["first"])
    episodes = []
    for e in closed:
        path = e["paths"][-1] if e["paths"] else ""
        if len(e["paths"]) > 1:
            path += "  (path varied during the episode)"
        episodes.append(ViolationEpisode(
            offender=e["node"], callsign=e["callsign"] or "Unknown",
            first=e["first"], last=e["last"], scans=e["scans"], path=path,
            quiet_suppressed=_in_quiet_hours(e["first"], quiet_cfg)))
    return episodes


def _link_report_episodes(conn, start, end) -> list[LinkReportEpisode]:
    """Cluster link_report_events rows in [start, end] into per-(node, kind)
    episodes by TIME GAP (EPISODE_GAP_S), like violations. Callsign is the
    latest real one seen; attach node the latest seen. Guarded: a DB written
    by an older analytics_db has no such table yet."""
    if not _table_exists(conn, "link_report_events"):
        return []
    rows = conn.execute(
        "SELECT ts, node_id, kind, attached_to, attachment, callsign, post_age_seconds "
        "FROM link_report_events WHERE ts >= ? AND ts <= ? ORDER BY ts, id",
        (start.isoformat(), end.isoformat()),
    ).fetchall()
    open_eps: dict[tuple[int, str], dict] = {}
    closed: list[dict] = []
    for ts_s, node, kind, att, attachment, callsign, age in rows:
        try:
            t = _parse(ts_s)
        except Exception:
            continue
        key = (int(node), str(kind))
        ep = open_eps.get(key)
        if ep is not None and (t - ep["last"]).total_seconds() > EPISODE_GAP_S:
            closed.append(ep)
            ep = None
        if ep is None:
            ep = {"node": key[0], "kind": key[1], "first": t, "last": t, "scans": 0,
                  "attached_to": None, "attachment": "", "callsign": "", "age": None}
            open_eps[key] = ep
        ep["last"] = t
        ep["scans"] += 1
        if att is not None:
            ep["attached_to"] = int(att)
        if attachment:
            ep["attachment"] = str(attachment)
        if callsign and callsign != "Unknown":
            ep["callsign"] = callsign
        ep["age"] = int(age) if age is not None else ep["age"]
    closed.extend(open_eps.values())
    closed.sort(key=lambda e: (e["first"], e["node"]))
    # "still so" is judged against the period end, or now when the caller
    # asked for a period that has not finished yet (audit 2026-09-08 A3).
    horizon = min(end, datetime.now(timezone.utc))
    return [LinkReportEpisode(
        node=e["node"], kind=e["kind"], callsign=e["callsign"] or "Unknown",
        attached_to=e["attached_to"], attachment=e["attachment"],
        first=e["first"], last=e["last"], scans=e["scans"],
        ongoing=(horizon - e["last"]).total_seconds() <= EPISODE_GAP_S,
        post_age_seconds=e["age"])
        for e in closed]


def generate_report(db_path, start: datetime, end: datetime,
                    focus_node: int, core_nodes: set[int], bridge_nodes: set[int],
                    gap_threshold: int = DEFAULT_MONITOR_GAP_THRESHOLD_S,
                    quiet_cfg: Optional[dict] = None,
                    health_nodes: Optional[dict] = {}) -> ReportData:  # noqa: B006 (read-only)
    conn = sqlite3.connect(str(db_path))
    try:
        # Read-only in WAL, but a daemon restart's schema executescript could
        # briefly hold the lock at exactly 07:00 — wait instead of failing.
        conn.execute("PRAGMA busy_timeout=5000;")
        downs = _monitor_down_intervals(conn, start, end, gap_threshold)
        monitor_down = sum(_overlap(s, e, start, end) for s, e in downs)

        all_core = sorted({focus_node} | core_nodes)
        core = [_node_availability(conn, n, ROLE_CORE, start, end, downs) for n in all_core]
        bridges = [_node_availability(conn, n, ROLE_BRIDGE, start, end, downs)
                   for n in sorted(bridge_nodes)]
        # Bridges additionally carry arrived/left/dwell presence sessions.
        for nav in bridges:
            nav.sessions = _presence_sessions(conn, nav.node_id, start, end)

        # Guest sessions overlapping the period.
        rows = conn.execute(
            "SELECT node_id, attached_to, connected_ts, left_ts, dwell_secs "
            "FROM guest_sessions WHERE connected_ts <= ? AND (left_ts IS NULL OR left_ts >= ?) "
            "ORDER BY connected_ts", (end.isoformat(), start.isoformat()),
        ).fetchall()
        all_guests = [GuestSession(r[0], r[1], _parse(r[2]),
                                   _parse(r[3]) if r[3] else None, r[4])
                      for r in rows]
        # Split ordinary guests from UNWITTING drag-ins (2026-07-17): a guest
        # attached to a member node (focus/core/bridge) chose to visit us; a
        # guest attached to any OTHER node is hanging off a guest chain, which
        # only exists during unauthorized bridging — it was dragged in.
        members = {focus_node} | core_nodes | bridge_nodes
        guests = [g for g in all_guests
                  if g.attached_to is None or g.attached_to in members]
        unwitting = [g for g in all_guests
                     if g.attached_to is not None and g.attached_to not in members]

        # External leaf clients overlapping the period. Guarded: a DB written by
        # an older analytics_db (pre-external-tracking) has no such table yet.
        externals = []
        if _table_exists(conn, "external_sessions"):
            erows = conn.execute(
                "SELECT host_node, client_type, ext_name, connected_ts, left_ts, dwell_secs "
                "FROM external_sessions WHERE connected_ts <= ? AND (left_ts IS NULL OR left_ts >= ?) "
                "ORDER BY connected_ts", (end.isoformat(), start.isoformat()),
            ).fetchall()
            externals = [ExternalSession(r[0], r[1], r[2], _parse(r[3]),
                                         _parse(r[4]) if r[4] else None, r[5]) for r in erows]

        violations = _violation_episodes(conn, start, end, quiet_cfg)
        link_reports = _link_report_episodes(conn, start, end)

        # Three-state node health (2026-10-18). Guarded like externals: a DB
        # written by an older daemon has no such table.
        # `health_nodes`: a dict = the configured node map ({} = no config at
        # hand → ad-hoc report from the live table); None = the config was read
        # and node health is NOT enabled there (audit S4 pass 2: say so rather
        # than carry the live table's last state into every digest).
        nh_summaries, nh_transitions, nh_available = [], [], False
        nh_enabled = health_nodes is not None
        if _table_exists(conn, "node_health_events"):
            nh_available = True
            if nh_enabled:
                nh_summaries, nh_transitions = _node_health_block(
                    conn, health_nodes, start, end, downs)

        return ReportData(start, end, monitor_down, core, bridges, guests,
                          externals, violations, unwitting, link_reports,
                          node_health=nh_summaries,
                          node_health_transitions=nh_transitions,
                          node_health_available=nh_available,
                          node_health_enabled=nh_enabled)
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Rendering (trustee-appropriate)
# --------------------------------------------------------------------------- #
def _label(node_id: int, labels: dict[int, str]) -> str:
    return labels.get(node_id, f"Node {node_id}")


def load_node_info(config_path: str) -> tuple[dict[int, str], dict[int, str]]:
    """(callsigns, owners) from the bubble-map NodeInfoCache (populated by
    the daemon's scans, 30d TTL) — zero API/QRZ lookups at report time.
    Owner = the registry User_ID (owning account), which can differ from the
    broadcast callsign (Bennett, 2026-07-18: a bridge keyed as a club call
    but owned by an individual). Tolerant: any problem returns ({}, {}) and
    the report renders without either."""
    try:
        import yaml
        cfg = yaml.safe_load(open(config_path)) or {}
        out = (cfg.get("bubble_map") or {}).get(
            "output", "bubble_maps_local/current.png")
        p = Path(out)
        if not p.is_absolute():
            p = Path(__file__).resolve().parent / p
        cache = json.loads((p.parent / "node_info_cache.json").read_text())
        callsigns = {int(k): str(v.get("callsign", ""))
                     for k, v in cache.items()
                     if str(k).isdigit() and v.get("callsign")}
        owners = {int(k): str(v.get("owner", ""))
                  for k, v in cache.items()
                  if str(k).isdigit() and v.get("owner")}
        return callsigns, owners
    except Exception as e:
        logger.info("node callsigns unavailable (%s) — rendering without", e)
        return {}, {}


def render_text(r: ReportData, labels: Optional[dict[int, str]] = None,
                system_name: str = "", tz: Optional[ZoneInfo] = None,
                callsigns: Optional[dict[int, str]] = None,
                owners: Optional[dict[int, str]] = None) -> str:
    labels = labels or {}
    callsigns = callsigns or {}
    owners = owners or {}

    def _ncs(node_id) -> str:
        """Node + callsign (+ owner when it differs) for text lines."""
        cs = callsigns.get(node_id)
        ow = owners.get(node_id)
        if cs and ow and ow != cs:
            return f"{_label(node_id, labels)} [{cs}, owner {ow}]"
        if cs:
            return f"{_label(node_id, labels)} [{cs}]"
        if ow:
            return f"{_label(node_id, labels)} [owner {ow}]"
        return _label(node_id, labels)
    def _fmt_local(dt): return _fmt_ts(dt, tz)   # shadow: bind report tz
    L = []
    L.append(f"{system_name} AllStar Stats Summary".strip())
    L.append(f"Period: {_fmt_local(r.start)} — {_fmt_local(r.end)} ({_tz_label(r.end, tz)})")
    if r.monitor_down_secs > 0:
        L.append(f"(Monitoring offline {_fmt_dur(r.monitor_down_secs)} during this period; "
                 f"excluded from availability.)")
    L.append("")
    # "Seen in topology" = present in the hub's link list (the original
    # availability measure). Node health (2026-10-18) adds the parent's view:
    # when a node was listed but the parent was only DIALING it (C), it was
    # seen yet not linked — say so on the line.
    nh_by_node = {s.node_id: s for s in r.node_health}
    L.append("Core infrastructure (target: always on)")
    for n in r.core:
        av = "n/a" if n.availability is None else f"{n.availability * 100:.1f}%"
        lo = n.longest_outage
        lo_s = f"; longest {_fmt_dur(lo.secs)} ({_fmt_local(lo.start)})" if lo else ""
        suffix = ""
        s = nh_by_node.get(n.node_id)
        if (s is not None and s.has_data and s.parent != "self"
                and s.linked_pct is not None and n.availability is not None
                and s.linked_pct < n.availability - 0.0005):
            suffix = f" — but linked (parent's view) only {_pct_text(s.linked_pct)}"
            if s.dialing_secs:
                suffix += f"; parent dialing {_fmt_dur(s.dialing_secs)} of that"
        L.append(f"  - {_ncs(n.node_id)}: {av} seen in topology, "
                 f"{len(n.outages)} outage(s){lo_s}{suffix}")
    L.append("")
    L.append("Designated bridge nodes (expected to come and go)")
    if not r.bridges:
        L.append("  - (none configured)")
    for n in r.bridges:
        av = "n/a" if n.availability is None else f"{n.availability * 100:.1f}%"
        L.append(f"  - {_ncs(n.node_id)}: {av} present, {len(n.outages)} gap(s)")
        if not n.sessions:
            L.append("      (no presence recorded this period)")
        for s in n.sessions:
            arrived = _fmt_local(s.arrived) if s.arrived else "(before period)"
            if s.ongoing:
                left, dwell = "—", "ongoing"
            else:
                left = _fmt_local(s.left)
                dwell = _fmt_dur(s.dwell_secs) if s.dwell_secs is not None else "—"
            L.append(f"      arrived {arrived} → left {left} ({dwell})")
    L.append("")
    L.append(f"Guest activity: {len(r.guest_sessions)} session(s), "
             f"{len({g.node_id for g in r.guest_sessions})} distinct node(s)")
    violators = r.violator_nodes
    # Witting guests split by attachment point (Bennett, 2026-07-17): via a
    # designated bridge (the preferred front door) vs. directly to the hub
    # (candidates for future "please use a designated bridge" guidance).
    bridge_ids = {n.node_id for n in r.bridges}
    via_bridge = [g for g in r.guest_sessions if g.attached_to in bridge_ids]
    direct_hub = [g for g in r.guest_sessions if g.attached_to not in bridge_ids]

    def _guest_lines(sessions):
        for g in sorted(sessions, key=lambda g: g.connected):
            when = _fmt_local(g.connected)
            if g.ongoing:
                dwell, left = "ongoing", "—"
            else:
                dwell = _fmt_dur(g.dwell_secs
                                 or int((g.left - g.connected).total_seconds()))
                left = _fmt_local(g.left)
            flag = ("  ** VIOLATION — see Unauthorized bridging section **"
                    if g.node_id in violators else "")
            L.append(f"  - {_ncs(g.node_id)} on {_label(g.attached_to, labels)}: "
                     f"{when} → {left} ({dwell}){flag}")

    L.append(f"  Via designated bridge nodes ({len(via_bridge)} session(s)):")
    if not via_bridge:
        L.append("    (none this period)")
    _guest_lines(via_bridge)
    L.append(f"  Directly to the hub ({len(direct_hub)} session(s)) — "
             f"may merit a courtesy suggestion to use a designated bridge:")
    if not direct_hub:
        L.append("    (none this period)")
    _guest_lines(direct_hub)
    if r.unwitting_sessions:
        L.append("")
        L.append(f"Unwitting guests ({len(r.unwitting_sessions)} session(s)) — "
                 f"dragged in through unauthorized bridging, not visitors "
                 f"by choice:")
        for g in sorted(r.unwitting_sessions, key=lambda g: g.connected):
            when = _fmt_local(g.connected)
            if g.ongoing:
                dwell, left = "ongoing", "—"
            else:
                dwell = _fmt_dur(g.dwell_secs
                                 or int((g.left - g.connected).total_seconds()))
                left = _fmt_local(g.left)
            L.append(f"  - Node {g.node_id} via Node {g.attached_to}: "
                     f"{when} → {left} ({dwell})")
    L.append("")
    L.append(f"External / IAX2 leaf clients (RepeaterPhone / WebTransceiver / "
             f"EchoLink): {len(r.external_sessions)} session(s)")
    if not r.external_sessions:
        L.append("  - (none this period)")
    for e in sorted(r.external_sessions, key=lambda e: e.connected):
        when = _fmt_local(e.connected)
        if e.ongoing:
            left, dwell = "—", "ongoing"
        else:
            left = _fmt_local(e.left)
            dwell = _fmt_dur(e.dwell_secs) if e.dwell_secs is not None else "—"
        L.append(f"  - {e.ext_name} ({e.type_label}) on {_label(e.host_node, labels)}: "
                 f"{when} → {left} ({dwell})")
    L.append("")
    # Change 2 (2026-09-08): nodes that did not report their links.
    dark_eps, lkl_eps = r.dark_episodes, r.linkless_episodes
    unc_eps = r.unconfirmed_episodes
    L.append(f"Nodes not reporting their links: "
             f"{len({e.node for e in dark_eps})} dark, "
             f"{len({e.node for e in lkl_eps})} linkless, "
             f"{len({e.node for e in unc_eps})} on a pre-join record "
             f"(distinct nodes this period)")

    def _report_lines(eps, none_text):
        if not eps:
            L.append(f"    {none_text}")
        for e in eps:
            span = (f"{_fmt_local(e.first)}" if e.first == e.last
                    else f"{_fmt_local(e.first)} → {_fmt_local(e.last)}")
            tail = ", still so at period end" if e.ongoing else ""
            if e.kind == "linkless" and e.post_age_seconds is not None:
                tail += f" (its last post was {e.post_age_seconds} s old — it IS reporting)"
            elif e.kind == "unconfirmed" and e.post_age_seconds is not None:
                tail += f" (record {e.post_age_seconds} s old at last sight)"
            where = (f" on {_label(e.attached_to, labels)}"
                     if e.attached_to is not None else "")
            # Callsign: the registry cache first, else the one the scan saw.
            if e.node in callsigns:
                who = _ncs(e.node)
            else:
                cs = f" [{e.callsign}]" if e.callsign and e.callsign != "Unknown" else ""
                who = _label(e.node, labels) + cs
            L.append(f"    - {who}{where}: {span}, {e.scans} scan(s){tail}")

    L.append("  Dark — online but posting nothing to AllStar stats, so their "
             "outside links are invisible (checked against our own link tables):")
    _report_lines(dark_eps, "(none this period)")
    L.append("  Linkless — posting, but reporting NO links while we still list "
             "them: the link on our side is stuck (usually after the node's "
             "address changed); no audio path until that node re-links or reboots:")
    _report_lines(lkl_eps, "(none this period)")
    L.append("  Pre-join record — the guest's own stats post named outside links but "
             "not the node it was attached to (the post predates the join, e.g. after "
             "a disconnect-before-connect switch); not judged, never cut; one "
             "delayed re-look each:")
    _report_lines(unc_eps, "(none this period)")
    L.append("")
    # Three-state node health (2026-10-18): registered / posting / parent letter.
    L.append("Registration & link state (three facts per node; legend below)")
    if not r.node_health_available:
        L.append("  (not recorded by this daemon version)")
    elif not r.node_health_enabled:
        L.append("  (node health is not enabled in config.yaml)")
    elif not r.node_health:
        L.append("  (no node-health rows this period)")
    for s in r.node_health:
        if not s.has_data:
            L.append(f"  - {_ncs(s.node_id)}: (no data this period)")
            continue
        if s.parent == "self":
            L.append(f"  - {_ncs(s.node_id)} (hub): posting {_pct_text(s.posting_pct)} · "
                     f"registered {_pct_text(s.registered_pct)} · at period end: "
                     f"{_fact_text('posting', s.end_posting)}, "
                     f"{_fact_text('registered', s.end_registered)}")
            continue
        via = f" (via {_label(s.parent, labels)})" if isinstance(s.parent, int) else ""
        extras = []
        if s.dialing_secs:
            extras.append(f"parent dialing {_fmt_dur(s.dialing_secs)}")
        if s.unlisted_secs:
            extras.append(f"not listed {_fmt_dur(s.unlisted_secs)}")
        if s.unknown_secs:
            extras.append(f"parent data unavailable {_fmt_dur(s.unknown_secs)}")
        ex = f" ({'; '.join(extras)})" if extras else ""
        end_letter = _fact_text("letter", s.end_letter)
        if s.end_letter not in (None, "T", "R", "L") and s.since_letter is not None:
            end_letter += f" since {_fmt_local(s.since_letter)}"
        end_reg = _fact_text("registered", s.end_registered)
        if s.end_registered == "0" and s.since_registered is not None:
            end_reg += f" since {_fmt_local(s.since_registered)}"
        L.append(f"  - {_ncs(s.node_id)}{via}: linked {_pct_text(s.linked_pct)}{ex} · "
                 f"registered {_pct_text(s.registered_pct)} · posting {_pct_text(s.posting_pct)}")
        L.append(f"      at period end: {end_letter}, {end_reg}, "
                 f"{_fact_text('posting', s.end_posting)}")
    if r.node_health_available and r.node_health_enabled:
        trs = r.node_health_transitions
        L.append(f"  Transitions this period: {len(trs)}" + ("" if trs else " (none)"))
        for t in trs[:NODE_HEALTH_MAX_TRANSITIONS]:
            L.append(f"    {_fmt_local(t.ts)}  {_label(t.node_id, labels)} {t.field}: "
                     f"{_fact_text(t.field, t.old)} -> {_fact_text(t.field, t.new)}")
        if len(trs) > NODE_HEALTH_MAX_TRANSITIONS:
            L.append(f"    (+{len(trs) - NODE_HEALTH_MAX_TRANSITIONS} more)")
        L.append(f"  {NODE_HEALTH_LEGEND}")
    L.append("")
    longest = max((g for g in r.guest_sessions if not g.ongoing),
                  key=lambda g: g.dwell_secs or 0, default=None)
    if longest:
        L.append(f"Highlights: longest guest visit {_label(longest.node_id, labels)} "
                 f"({_fmt_dur(longest.dwell_secs or 0)}).")
    if not r.violations:
        L.append("No unauthorized bridging events occurred during this period. "
                 "(Violations, when they occur, are reported separately and in "
                 "real time.)")
    else:
        L.append("")
        L.append(f"** UNAUTHORIZED BRIDGING: {len(r.violations)} episode(s) "
                 f"this period **")
        for v in r.violations:
            span = (f"{_fmt_local(v.first)}"
                    if v.first == v.last
                    else f"{_fmt_local(v.first)} → {_fmt_local(v.last)}")
            L.append(f"  - {_label(v.offender, labels)} ({v.callsign}): {span}, "
                     f"detected on {v.scans} scan(s)")
            if v.path:
                L.append(f"      path: {v.path}")
            if v.quiet_suppressed:
                L.append("      (began during quiet hours — the real-time "
                         "sysadmin alert was held and delivered when quiet "
                         "hours ended; also reported here per the "
                         "morning-digest policy)")
        L.append("  Note: scan counts reflect full topology scans only; "
                 "rapid re-offenses inside a post-violation watch window are "
                 "enforced and alerted separately and may not add scans here.")
    L.append("")
    L.append(TIMING_DISCLAIMER)
    return "\n".join(L)


def render_html(r: ReportData, labels: Optional[dict[int, str]] = None,
                system_name: str = "", tz: Optional[ZoneInfo] = None,
                callsigns: Optional[dict[int, str]] = None,
                owners: Optional[dict[int, str]] = None) -> str:
    labels = labels or {}
    callsigns = callsigns or {}
    owners = owners or {}
    def _fmt_local(dt): return _fmt_ts(dt, tz)   # shadow: bind report tz
    # HTML-escape any free-text that flows into markup — callsigns/owners
    # come from the NodeInfoCache, whose values are remote-controlled
    # registry strings.
    def H(node_id):
        return html.escape(_label(node_id, labels))
    def CS(node_id):
        """Callsign cell for the node in a table's first column."""
        return html.escape(callsigns.get(node_id, "")) or "&mdash;"
    def OW(node_id):
        """Owner cell (registry User_ID — the owning account)."""
        return html.escape(owners.get(node_id, "")) or "&mdash;"
    title = html.escape(f"{system_name} AllStar Stats Summary".strip())

    nh_by_node = {s.node_id: s for s in r.node_health}

    def rows_avail(nodes, third_label, health: bool = False):
        out = []
        for n in nodes:
            av = "n/a" if n.availability is None else f"{n.availability * 100:.1f}%"
            lo = n.longest_outage
            extra = f"{_fmt_dur(lo.secs)} ({_fmt_local(lo.start)})" if lo else "—"
            cells = (f"<tr><td>{H(n.node_id)}</td><td>{CS(n.node_id)}</td>"
                     f"<td>{OW(n.node_id)}</td>"
                     f"<td>{av}</td>"
                     f"<td>{len(n.outages)}</td><td>{extra}</td>")
            if health:
                # Node health (2026-10-18): the parent's view of the link.
                s = nh_by_node.get(n.node_id)
                if s is not None and s.has_data and s.parent == "self":
                    lk = f"hub: posting {_pct_text(s.posting_pct)}"
                elif s is not None and s.has_data:
                    lk = _pct_text(s.linked_pct)
                    if s.dialing_secs:
                        lk += f" (parent dialing {_fmt_dur(s.dialing_secs)})"
                else:
                    lk = "&mdash;"
                cells += f"<td>{lk}</td>"
            out.append(cells + "</tr>")
        return "\n".join(out)
    core_health_th = ("<th>Linked (parent's view)</th>"
                      if (r.node_health_available and r.node_health_enabled) else "")

    violators = r.violator_nodes
    # Witting guests split by attachment point (Bennett, 2026-07-17).
    bridge_ids = {n.node_id for n in r.bridges}
    via_bridge = [g for g in r.guest_sessions if g.attached_to in bridge_ids]
    direct_hub = [g for g in r.guest_sessions if g.attached_to not in bridge_ids]

    def _guest_rows(sessions):
        rows = []
        for g in sorted(sessions, key=lambda g: g.connected):
            left = "—" if g.ongoing else _fmt_local(g.left)
            dwell = "ongoing" if g.ongoing else _fmt_dur(
                g.dwell_secs or int((g.left - g.connected).total_seconds()))
            if g.node_id in violators:
                guest_cell = (f"{H(g.node_id)} <b style=\"color:#b00020\">"
                              f"&#9888; VIOLATION</b>")
            else:
                guest_cell = H(g.node_id)
            rows.append(f"<tr><td>{guest_cell}</td><td>{CS(g.node_id)}</td>"
                        f"<td>{OW(g.node_id)}</td>"
                        f"<td>{H(g.attached_to)}</td>"
                        f"<td>{_fmt_local(g.connected)}</td>"
                        f"<td>{left}</td><td>{dwell}</td></tr>")
        if not rows:
            rows.append('<tr><td colspan="7">(none this period)</td></tr>')
        return rows

    grows_bridge = _guest_rows(via_bridge)
    grows_hub = _guest_rows(direct_hub)

    # Unwitting drag-ins (2026-07-17): separate table, deliberately WITHOUT
    # callsigns — these operators didn't choose to visit, and skipping the
    # column avoids lookups for foreign-mesh nodes.
    urows = []
    for g in sorted(r.unwitting_sessions, key=lambda g: g.connected):
        left = "—" if g.ongoing else _fmt_local(g.left)
        dwell = "ongoing" if g.ongoing else _fmt_dur(
            g.dwell_secs or int((g.left - g.connected).total_seconds()))
        urows.append(f"<tr><td>Node {g.node_id}</td><td>Node {g.attached_to}</td>"
                     f"<td>{_fmt_local(g.connected)}</td><td>{left}</td><td>{dwell}</td></tr>")
    unwitting_html = "" if not urows else f"""<h3>Unwitting guests ({len(r.unwitting_sessions)} sessions)</h3>
<p style="margin:0 0 4px"><small>Dragged in through unauthorized bridging —
not visitors by choice. See the Unauthorized bridging section.</small></p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Dragged in via</th><th>Arrived</th><th>Left</th><th>Dwell</th></tr>
{''.join(urows)}
</table>"""

    # Unauthorized-bridging episodes (2026-07-02 decision: violations appear
    # in the digest as a dedicated section AND as a flag on the guest rows).
    vrows = []
    for v in r.violations:
        span = (_fmt_local(v.first) if v.first == v.last
                else f"{_fmt_local(v.first)} &rarr; {_fmt_local(v.last)}")
        quiet_note = ("<br><small>(began during quiet hours — real-time "
                      "sysadmin alert held and delivered when quiet hours "
                      "ended; also reported here per the morning-digest "
                      "policy)</small>"
                      if v.quiet_suppressed else "")
        vrows.append(
            f"<tr><td>{H(v.offender)} ({html.escape(v.callsign)})</td>"
            f"<td>{span}{quiet_note}</td><td>{v.scans}</td>"
            f"<td>{html.escape(v.path)}</td></tr>")
    if r.violations:
        violations_html = f"""<h3 style="color:#b00020">&#9888; Unauthorized bridging ({len(r.violations)} episode{'s' if len(r.violations) != 1 else ''})</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Offending node</th><th>When</th><th>Scans</th><th>Path</th></tr>
{''.join(vrows)}
</table>
<p style="margin:4px 0 0"><small>Scan counts reflect full topology scans only;
rapid re-offenses inside a post-violation watch window are enforced and
alerted separately and may not add scans here.</small></p>"""
        closing_html = ""
    else:
        violations_html = ""
        closing_html = ("<p><em>No unauthorized bridging events occurred "
                        "during this period. Violations, when they occur, are "
                        "reported separately and in real time.</em></p>")

    # Bridge presence sessions (arrived/left/dwell), one row per session.
    brows = []
    for n in r.bridges:
        if not n.sessions:
            brows.append(f"<tr><td>{H(n.node_id)}</td><td>{CS(n.node_id)}</td>"
                         f"<td>{OW(n.node_id)}</td>"
                         f"<td colspan=\"3\">"
                         f"(no presence recorded this period)</td></tr>")
            continue
        for s in n.sessions:
            arrived = _fmt_local(s.arrived) if s.arrived else "(before period)"
            left = "—" if s.ongoing else _fmt_local(s.left)
            dwell = "ongoing" if s.ongoing else (
                _fmt_dur(s.dwell_secs) if s.dwell_secs is not None else "—")
            brows.append(f"<tr><td>{H(n.node_id)}</td><td>{CS(n.node_id)}</td>"
                         f"<td>{OW(n.node_id)}</td>"
                         f"<td>{arrived}</td><td>{left}</td><td>{dwell}</td></tr>")

    # External / IAX2 leaf clients.
    erows = []
    for e in sorted(r.external_sessions, key=lambda e: e.connected):
        left = "—" if e.ongoing else _fmt_local(e.left)
        dwell = "ongoing" if e.ongoing else (
            _fmt_dur(e.dwell_secs) if e.dwell_secs is not None else "—")
        erows.append(f"<tr><td>{html.escape(e.ext_name)}</td>"
                     f"<td>{html.escape(e.type_label)}</td>"
                     f"<td>{H(e.host_node)}</td>"
                     f"<td>{_fmt_local(e.connected)}</td><td>{left}</td><td>{dwell}</td></tr>")
    if not erows:
        erows.append('<tr><td colspan="6">(none this period)</td></tr>')

    # Change 2 (2026-09-08): nodes that did not report their links. Callsign
    # falls back to the one the scan recorded (escaped: remote-controlled).
    def _lr_rows(eps):
        out = []
        for e in eps:
            span = (_fmt_local(e.first) if e.first == e.last
                    else f"{_fmt_local(e.first)} &rarr; {_fmt_local(e.last)}")
            if e.ongoing:
                span += " (still so at period end)"
            if e.kind == "linkless" and e.post_age_seconds is not None:
                span += f"; last post {e.post_age_seconds} s old"
            elif e.kind == "unconfirmed" and e.post_age_seconds is not None:
                span += f"; record {e.post_age_seconds} s old at last sight"
            cs = callsigns.get(e.node) or (e.callsign if e.callsign != "Unknown" else "")
            where = H(e.attached_to) if e.attached_to is not None else "&mdash;"
            out.append(f"<tr><td>{H(e.node)}</td><td>{html.escape(cs) or '&mdash;'}</td>"
                       f"<td>{where}</td><td>{span}</td><td>{e.scans}</td></tr>")
        if not out:
            out.append('<tr><td colspan="5">(none this period)</td></tr>')
        return "".join(out)
    link_reports_html = f"""
<h3>Nodes not reporting their links</h3>
<h4 style="margin:8px 0 2px">Dark ({len({e.node for e in r.dark_episodes})} nodes)</h4>
<p style="margin:0 0 4px"><small>Online but posting nothing to AllStar stats, so their
outside links are invisible; checked against our own link tables.</small></p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Callsign</th><th>Listed by</th><th>When</th><th>Scans</th></tr>
{_lr_rows(r.dark_episodes)}
</table>
<h4 style="margin:10px 0 2px">Linkless ({len({e.node for e in r.linkless_episodes})} nodes)</h4>
<p style="margin:0 0 4px"><small>Posting, but reporting no links while we still list them:
the link on our side is stuck (usually after the node's address changed); no audio path
until that node re-links or reboots.</small></p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Callsign</th><th>Listed by</th><th>When</th><th>Scans</th></tr>
{_lr_rows(r.linkless_episodes)}
</table>
<h4 style="margin:10px 0 2px">Pre-join record ({len({e.node for e in r.unconfirmed_episodes})} nodes)</h4>
<p style="margin:0 0 4px"><small>The guest's own stats post named outside links but not the
node it was attached to: the post predates the join (e.g. after a disconnect-before-connect
switch). Not judged, never cut; one delayed re-look each.</small></p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Callsign</th><th>Listed by</th><th>When</th><th>Scans</th></tr>
{_lr_rows(r.unconfirmed_episodes)}
</table>"""

    # Three-state node health (2026-10-18).
    def _nh_rows():
        out = []
        for s in r.node_health:
            if not s.has_data:
                out.append(f"<tr><td>{H(s.node_id)}</td><td>{CS(s.node_id)}</td>"
                           f'<td colspan="7">(no data this period)</td></tr>')
                continue
            if s.parent == "self":
                par, linked, dial, unk = "hub", f"posting {_pct_text(s.posting_pct)}", "&mdash;", "&mdash;"
            else:
                par = H(s.parent) if isinstance(s.parent, int) else "&mdash;"
                linked = _pct_text(s.linked_pct)
                dial = _fmt_dur(s.dialing_secs) if s.dialing_secs else "&mdash;"
                unk = _fmt_dur(s.unknown_secs) if s.unknown_secs else "&mdash;"
            end = html.escape(", ".join([_fact_text("letter", s.end_letter),
                                         _fact_text("registered", s.end_registered),
                                         _fact_text("posting", s.end_posting)]))
            out.append(f"<tr><td>{H(s.node_id)}</td><td>{CS(s.node_id)}</td><td>{par}</td>"
                       f"<td>{linked}</td><td>{dial}</td><td>{unk}</td>"
                       f"<td>{_pct_text(s.registered_pct)}</td><td>{_pct_text(s.posting_pct)}</td>"
                       f"<td>{end}</td></tr>")
        if not out:
            out.append('<tr><td colspan="9">(no node-health rows this period)</td></tr>')
        return "".join(out)

    def _nh_trows():
        out = []
        trs = r.node_health_transitions
        for t in trs[:NODE_HEALTH_MAX_TRANSITIONS]:
            out.append(f"<tr><td>{_fmt_local(t.ts)}</td><td>{H(t.node_id)}</td>"
                       f"<td>{html.escape(t.field)}</td>"
                       f"<td>{html.escape(_fact_text(t.field, t.old))}</td>"
                       f"<td>{html.escape(_fact_text(t.field, t.new))}</td></tr>")
        if len(trs) > NODE_HEALTH_MAX_TRANSITIONS:
            out.append(f'<tr><td colspan="5">(+{len(trs) - NODE_HEALTH_MAX_TRANSITIONS} more)</td></tr>')
        if not out:
            out.append('<tr><td colspan="5">(none this period)</td></tr>')
        return "".join(out)
    if r.node_health_available and not r.node_health_enabled:
        node_health_html = ('<h3>Registration &amp; link state</h3>'
                            '<p><small>(node health is not enabled in config.yaml)</small></p>')
    elif r.node_health_available:
        node_health_html = f"""
<h3>Registration &amp; link state</h3>
<p style="margin:0 0 4px"><small>{html.escape(NODE_HEALTH_LEGEND)}</small></p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Callsign</th><th>Parent</th><th>Linked</th><th>Parent dialing (C)</th><th>Parent data unavailable</th><th>Registered</th><th>Posting</th><th>At period end</th></tr>
{_nh_rows()}
</table>
<h4 style="margin:8px 0 2px">Transitions this period ({len(r.node_health_transitions)})</h4>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>When</th><th>Node</th><th>Fact</th><th>From</th><th>To</th></tr>
{_nh_trows()}
</table>"""
    else:
        node_health_html = ('<h3>Registration &amp; link state</h3>'
                            '<p><small>(not recorded by this daemon version)</small></p>')

    return f"""<html><body style="font-family:sans-serif">
<h2>{title}</h2>
<p>Period: {_fmt_local(r.start)} — {_fmt_local(r.end)} ({_tz_label(r.end, tz)})</p>
{violations_html}
<h3>Core infrastructure (target: always on)</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Callsign</th><th>Owner</th><th>Seen in topology</th><th>Outages</th><th>Longest outage</th>{core_health_th}</tr>
{rows_avail(r.core, 'Outages', health=(r.node_health_available and r.node_health_enabled))}
</table>
<h3>Designated bridge nodes (expected to come and go)</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Callsign</th><th>Owner</th><th>Present</th><th>Gaps</th><th>Longest gap</th></tr>
{rows_avail(r.bridges, 'Gaps')}
</table>
<table border="1" cellpadding="4" cellspacing="0" style="margin-top:6px">
<tr><th>Node</th><th>Callsign</th><th>Owner</th><th>Arrived</th><th>Left</th><th>Dwell</th></tr>
{''.join(brows)}
</table>
<h3>Guest activity ({len(r.guest_sessions)} sessions)</h3>
<h4 style="margin:8px 0 2px">Via designated bridge nodes ({len(via_bridge)} sessions)</h4>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Guest</th><th>Callsign</th><th>Owner</th><th>Visited</th><th>Arrived</th><th>Left</th><th>Dwell</th></tr>
{''.join(grows_bridge)}
</table>
<h4 style="margin:10px 0 2px">Directly to the hub ({len(direct_hub)} sessions)</h4>
<p style="margin:0 0 4px"><small>Guests connecting straight to the hub rather
than a designated bridge — possible future candidates for a courtesy note
suggesting the designated bridges.</small></p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Guest</th><th>Callsign</th><th>Owner</th><th>Visited</th><th>Arrived</th><th>Left</th><th>Dwell</th></tr>
{''.join(grows_hub)}
</table>
{unwitting_html}
<h3>External / IAX2 leaf clients ({len(r.external_sessions)} sessions)</h3>
<p style="margin:0 0 4px"><small>RepeaterPhone / WebTransceiver / AllScan (IAX2) and EchoLink endpoints —
permitted single-user leaves; not AllStar nodes.</small></p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Client</th><th>Type</th><th>Host node</th><th>Arrived</th><th>Left</th><th>Dwell</th></tr>
{''.join(erows)}
</table>
{link_reports_html}
{node_health_html}
{closing_html}
<p><em>{html.escape(TIMING_DISCLAIMER)}</em></p>
</body></html>"""


def send_report(subject: str, text_body: str, html_body: str,
                config_path: str = "config.yaml") -> bool:
    """Email the analytics digest to Bennett only.

    Routes through notifier.Notifier under EmailCategory.ANALYTICS:
    internal_recipients only (never external), not rate-limited against
    alert traffic, sends regardless of quiet hours / monitor_only. Recipients
    and SMTP credentials are resolved by the Notifier from config + secrets —
    we do NOT pass a recipient list here (fail-closed: the Notifier refuses to
    construct without an explicit internal_recipients list in secrets.yaml).

    Reuses asl_link_detector.load_config so the config+secrets merge logic has
    a single source of truth. Returns True iff the send succeeded.

    DB isolation: the Notifier's NotificationTracker is pinned to a DEDICATED
    `analytics_notifications.db` (top-level db_path), NOT the live daemon's
    `notifications.db`. This keeps the standalone reporter from writing the
    daemon's rate-limit/dedup state (DDL, orphan-pending cleanup, send rows) —
    making the "cannot touch the monitor/detection path" guarantee literally
    true. Safe because ANALYTICS has no external recipients and is not
    rate-limited, so it never needs to share the daemon's tracker state.
    """
    from asl_link_detector import load_config   # reuse the secrets-merge path
    from notifier import Notifier

    config = load_config(config_path)
    config = dict(config)   # shallow copy — don't mutate the loaded mapping
    config["db_path"] = str(Path(__file__).resolve().parent / "analytics_notifications.db")
    notifier = Notifier(config)
    ok = notifier.send_analytics_report(
        subject=subject, text_body=text_body, html_body=html_body)
    if ok:
        logger.info("Analytics report emailed: %s", subject)
    else:
        logger.error("Analytics report send FAILED (see notifier log): %s", subject)
    return ok


# --------------------------------------------------------------------------- #
# Team page digest (2026-10-20): public_export/digest.json -> blob status/digest.json
# --------------------------------------------------------------------------- #
DIGEST_CONTRACT_V = 1
DIGEST_MAX_BYTES = 256 * 1024          # a digest is ~6 KB; anything bigger is a bug
DIGEST_PUSH_ATTEMPTS = 3
DIGEST_RETRY_SLEEPS_S = (2.0, 4.0)     # between attempts (5xx / transport errors only)
DIGEST_FILES = {"daily": "digest.json", "weekly": "digest-week.json"}
DIGEST_MAX_TEXT_CHARS = 190_000       # the page refuses text > 200 000 chars; cut below that, visibly
DIGEST_TRUNCATED_LINE = "\n[… digest truncated for the team page — the full report is in the email …]\n"
# Control characters (except \n) and Unicode bidi overrides/isolates could spoof
# lines in the page's <pre>; textContent rules out XSS, this rules out spoofing.
_DIGEST_STRIP_RE = __import__("re").compile(
    "[\x00-\x09\x0b-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩]")


def _utc_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- v2.1 (2026-10-21): the email HTML -> generic "blocks" for the team page ---
# render_html() emits a closed, tiny grammar (html body h2 h3 h4 p small em b br
# table tr th td; nesting no deeper than p>small, p>em, td>b, td>br, td>small).
# Rather than format the report a second time (drift) or refactor render_html
# (regression risk to the email), the already-rendered HTML is TRANSCRIBED into
# a list of generic blocks the page renders with DOM APIs under its CSP:
#   {"t":"h2"|"h3"|"h4"|"p", "text":…, "mark"?:true, "small"?:true, "em"?:true}
#   {"t":"table", "head":[…], "rows":[[{"text":…, "span"?:n, "mark"?:true, "note"?:…}, …], …]}
# The transcriber is a strict whitelist state machine: ANY tag, attribute or
# structure it does not know raises DigestBlocksError, and the publisher then
# ships the text-only document (never a broken page, never a failed publish).
class DigestBlocksError(ValueError):
    """The email HTML contained something outside the transcriber's whitelist."""


_BLK_HEADINGS = ("h2", "h3", "h4", "p")
_BLK_ATTRS = {                      # tag -> attributes allowed (all are dropped; style only decides `mark`)
    "html": set(), "body": {"style"}, "h2": set(), "h3": {"style"}, "h4": {"style"},
    "p": {"style"}, "small": set(), "em": set(), "b": {"style"}, "br": set(),
    "table": {"border", "cellpadding", "cellspacing", "style"},
    "tr": set(), "th": set(), "td": {"colspan"},
}
_BLK_BR = "\x00BR\x00"              # sentinel for <br> while whitespace is being collapsed (\x00 can never
                                    # come from data: handle_data strips control characters first)
_BLK_WS_RE = __import__("re").compile(r"\s+")
_BLK_COLOR_RE = __import__("re").compile(r"(^|;)\s*color\s*:")   # `color:` itself, not background-color
# The page's limits (site/digest-blocks.js) mirrored here so an over-limit email fails loudly at
# dev time (selftest) instead of silently sending the page back to text.
_BLK_MAX_BLOCKS, _BLK_MAX_TEXT, _BLK_MAX_COLS, _BLK_MAX_CELLS = 1000, 4000, 60, 50_000


def _blk_safe(s) -> str:
    """Input-derived fragment for an error message: ASCII-only, short."""
    return ascii(str(s))[:40]


def _blk_text(parts) -> str:
    """HTML whitespace rules: runs of whitespace -> one space; only <br> makes a newline."""
    s = _BLK_WS_RE.sub(" ", "".join(parts))
    s = "\n".join(seg.strip() for seg in s.split(_BLK_BR))
    return s.strip()


class _DigestBlocksParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks: list = []
        self.stack: list = []
        self.block = None          # open heading/paragraph: {"t", "parts": [(text, in_small, in_em)], "mark"}
        self.table = None          # open table: {"t":"table","head":[],"rows":[],"has_data":False}
        self.row = None            # open row: {"kind": "th"|"td"|None, "cells": []}
        self.cell = None           # open cell: {"text": [], "note": [], "mark": bool, "span": int|None}
        self.in_small = self.in_em = self.in_note = False
        self.seen_html = False

    def _err(self, msg: str):
        raise DigestBlocksError(msg)

    def _parent(self):
        return self.stack[-1] if self.stack else None

    # -- structure --
    def handle_startendtag(self, tag, attrs):             # <x/> — only <br/> is meaningful
        if tag != "br":
            self._err(f"unexpected self-closing tag <{_blk_safe(tag)}/>")
        self.handle_starttag(tag, attrs)

    def handle_starttag(self, tag, attrs):
        allowed = _BLK_ATTRS.get(tag)
        if allowed is None:
            self._err(f"unexpected tag <{_blk_safe(tag)}>")
        raw = self.get_starttag_text() or ""
        if raw != raw.lower():                              # HTMLParser lowercases names; our renderer never uppercases
            self._err(f"uppercase in tag <{_blk_safe(tag)}>")
        seen = set()
        for name, value in attrs:
            if name not in allowed:
                self._err(f"unexpected attribute on <{tag}>: {_blk_safe(name)}")
            if value is None:
                self._err(f"attribute without value on <{tag}>: {name}")
            if name in seen:
                self._err(f"duplicate attribute on <{tag}>: {name}")
            seen.add(name)
        a = dict(attrs)
        mark = bool(_BLK_COLOR_RE.search(a.get("style") or ""))
        parent = self._parent()
        if tag == "br":                                     # void element: only inside a <td> (or its <small> note)
            if parent != "td" and not (parent == "small" and self.in_note):
                self._err("<br> outside a <td>")
            (self.cell["note"] if self.in_note else self.cell["text"]).append(_BLK_BR)
            return
        if tag == "html":
            if parent is not None or self.seen_html:
                self._err("<html> nested or repeated")
            self.seen_html = True
        elif tag == "body":
            if parent != "html":
                self._err("<body> outside <html>")
        elif tag in _BLK_HEADINGS:
            if parent != "body":
                self._err(f"<{tag}> not directly in <body>")
            self.block = {"t": tag, "parts": [], "mark": mark}
        elif tag == "table":
            if parent != "body":
                self._err("<table> not directly in <body>")
            self.table = {"t": "table", "head": [], "rows": [], "has_data": False}
        elif tag == "tr":
            if parent != "table":
                self._err("<tr> outside <table>")
            self.row = {"kind": None, "cells": []}
        elif tag in ("th", "td"):
            if parent != "tr":
                self._err(f"<{tag}> outside <tr>")
            if self.row["kind"] is None:
                self.row["kind"] = tag
            elif self.row["kind"] != tag:
                self._err("a row mixes <th> and <td>")
            if tag == "th" and self.table["has_data"]:
                self._err("header row after data rows")
            span = None
            if tag == "td" and a.get("colspan") is not None:
                cs = a["colspan"]
                if not (cs.isascii() and cs.isdigit() and 2 <= int(cs) <= 30):
                    self._err(f"bad colspan {_blk_safe(cs)}")
                span = int(cs)
            self.cell = {"text": [], "note": [], "mark": False, "span": span}
        elif tag == "small":
            if parent == "p":
                self.in_small = True
            elif parent == "td":
                self.in_note = True
            else:
                self._err(f"<small> inside <{parent}>")
        elif tag == "em":
            if parent != "p":
                self._err(f"<em> inside <{parent}>")
            self.in_em = True
        elif tag == "b":
            if parent != "td":
                self._err(f"<b> inside <{parent}>")
            if mark:
                self.cell["mark"] = True
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag == "br":
            self._err("unexpected </br>")
        if not self.stack or self.stack[-1] != tag:
            self._err(f"unexpected </{_blk_safe(tag)}>")
        self.stack.pop()
        if tag in _BLK_HEADINGS:
            b = self.block
            self.block = None
            nonblank = [p for p in b["parts"] if p[0].strip()]
            out = {"t": b["t"], "text": _blk_text(p[0] for p in b["parts"])}
            if b["mark"]:
                out["mark"] = True
            if b["t"] == "p" and nonblank:
                if all(p[1] for p in nonblank):
                    out["small"] = True
                if all(p[2] for p in nonblank):
                    out["em"] = True
            self.blocks.append(out)
        elif tag == "table":
            t = self.table
            self.table = None
            self.blocks.append({"t": "table", "head": t["head"], "rows": t["rows"]})
        elif tag == "tr":
            row = self.row
            self.row = None
            if row["kind"] is None:
                self._err("empty <tr>")
            if row["kind"] == "th":
                if self.table["head"]:
                    self._err("second header row")
                self.table["head"] = [c["text"] for c in row["cells"]]
            else:
                self.table["rows"].append(row["cells"])
                self.table["has_data"] = True
        elif tag in ("th", "td"):
            c = self.cell
            self.cell = None
            out = {"text": _blk_text(c["text"])}
            if c["span"]:
                out["span"] = c["span"]
            if c["mark"]:
                out["mark"] = True
            note = _blk_text(c["note"])
            if note:
                out["note"] = note
            self.row["cells"].append(out)
        elif tag == "small":
            self.in_small = self.in_note = False
        elif tag == "em":
            self.in_em = False

    # -- content --
    def handle_data(self, data):
        data = _DIGEST_STRIP_RE.sub("", data)      # remote text (callsigns/owners) is raw again after entity
        if self.cell is not None:                   # decoding: strip control/bidi chars BEFORE the \x00 sentinel logic
            (self.cell["note"] if self.in_note else self.cell["text"]).append(data)
        elif self.block is not None:
            self.block["parts"].append((data, self.in_small, self.in_em))
        elif data.strip():
            self._err("text outside a heading, paragraph or cell")

    def handle_comment(self, data): self._err("unexpected comment")
    def handle_decl(self, decl): self._err("unexpected declaration")
    def handle_pi(self, data): self._err("unexpected processing instruction")
    def unknown_decl(self, data): self._err("unexpected declaration")

    def close(self):
        super().close()
        if self.stack:
            self._err(f"unclosed <{self.stack[-1]}>")


def _blk_sanitize(obj):
    """Apply the control/bidi strip to every string (callsigns/owners are remote text)."""
    if isinstance(obj, str):
        return _DIGEST_STRIP_RE.sub("", obj)
    if isinstance(obj, list):
        return [_blk_sanitize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _blk_sanitize(v) for k, v in obj.items()}
    return obj


def digest_blocks_from_html(html_text: str) -> list:
    """Transcribe render_html() output into generic blocks (see above). Pure.
    Raises DigestBlocksError on anything outside the whitelist or over the
    page's limits (so an over-limit email is caught by the selftest, not by a
    silent fall-back to text on the page)."""
    p = _DigestBlocksParser()
    p.feed(html_text)
    p.close()
    blocks = _blk_sanitize(p.blocks)
    if len(blocks) > _BLK_MAX_BLOCKS:
        raise DigestBlocksError(f"too many blocks ({len(blocks)})")
    cells = 0
    for b in blocks:
        if b["t"] == "table":
            if len(b["head"]) > _BLK_MAX_COLS or any(len(row) > _BLK_MAX_COLS for row in b["rows"]):
                raise DigestBlocksError("a table has more than %d columns" % _BLK_MAX_COLS)
            cells += sum(max(1, len(row)) for row in b["rows"])
            texts = list(b["head"]) + [c.get("text", "") for row in b["rows"] for c in row] + \
                    [c.get("note", "") for row in b["rows"] for c in row]
        else:
            texts = [b["text"]]
        if any(len(s) > _BLK_MAX_TEXT for s in texts):
            raise DigestBlocksError("a block text exceeds %d characters" % _BLK_MAX_TEXT)
    if cells > _BLK_MAX_CELLS:
        raise DigestBlocksError(f"too many table cells ({cells})")
    return blocks


def build_digest_doc(r: ReportData, text: str, subject: str, kind: str,
                     tzname: str, system_name: str,
                     now: Optional[datetime] = None,
                     html_body: Optional[str] = None) -> dict:
    """The team-page digest document, contract v1 (rev 2): the rendered TEXT
    report (always; the fallback), a few counts for the page banner and —
    when `html_body` (render_html output) is given — the optional `blocks`
    transcription of it for the page's tables. Pure — no I/O. `kind` is
    'daily' or 'weekly'. Text is sanitised (control / bidi characters) and,
    if absurdly long, truncated with a visible marker (then no blocks) so the
    page never refuses the document. Blocks are presentation: a transcription
    failure is logged and the text-only document is returned."""
    now = now or datetime.now(timezone.utc)
    text = _DIGEST_STRIP_RE.sub("", text or "")
    truncated = len(text) > DIGEST_MAX_TEXT_CHARS
    if truncated:
        text = text[:DIGEST_MAX_TEXT_CHARS - len(DIGEST_TRUNCATED_LINE)] + DIGEST_TRUNCATED_LINE
    text = text if text.endswith("\n") else text + "\n"
    doc = {
        "v": DIGEST_CONTRACT_V,
        "kind": kind,
        "generated": _utc_z(now),
        "period_start": _utc_z(r.start),
        "period_end": _utc_z(r.end),
        "tz": tzname or "UTC",
        "system": system_name or "",
        "subject": subject,
        "text": text,
        "summary": {
            "core_nodes": len(r.core),
            "bridge_nodes": len(r.bridges),
            "guest_sessions": len(r.guest_sessions),
            "violations": len(r.violations),
            "monitor_down_s": int(r.monitor_down_secs),
            "lines": text.count("\n"),
            "truncated": truncated,
        },
    }
    if html_body is not None and not truncated:
        try:
            blocks = digest_blocks_from_html(html_body)
            size = len(json.dumps(dict(doc, blocks=blocks), ensure_ascii=False).encode("utf-8"))
            if size <= DIGEST_MAX_BYTES:
                doc["blocks"] = blocks
            else:
                logger.warning("DIGEST BLOCKS: document with tables would be %d bytes — publishing text only", size)
        except DigestBlocksError as e:                      # our own tag names only — safe to log
            logger.error("DIGEST BLOCKS: %s — publishing text only", e)
        except Exception as e:                              # noqa: BLE001 — type only
            logger.error("DIGEST BLOCKS: unexpected %s — publishing text only", type(e).__name__)
    return doc


def digest_publish_cfg(cfg: dict, kind: str = "daily") -> dict:
    """`public_export.digest` from a loaded config.yaml -> a flat dict
    {enabled, dir, blob_url, item, timeout}. Tolerant: a missing or malformed
    block = disabled (local file still written). The daily blob is `blob_url`;
    other kinds use `<kind>_blob_url` so a weekly run can never overwrite the
    daily blob. Pure (the URL check is import-free)."""
    pe = cfg.get("public_export") if isinstance(cfg, dict) else None
    pe = pe if isinstance(pe, dict) else {}
    d = pe.get("digest")
    d = d if isinstance(d, dict) else {}
    url_key = "blob_url" if kind == "daily" else f"{kind}_blob_url"
    blob_url = str(d.get(url_key) or "").strip() or None
    import math
    try:
        timeout = float(d.get("timeout_seconds") or 10)
        if not math.isfinite(timeout):
            timeout = 10.0
    except (TypeError, ValueError, OverflowError):
        timeout = 10.0
    return {
        "enabled": d.get("enabled") is True,          # strict, like public_export_cfg: "false" is not True
        "dir": str(pe.get("dir") or "public_export"),
        "blob_url": blob_url,
        "item": str(d.get("sas_keychain_item") or "ASL_TEAM_DIGEST_SAS"),
        "timeout": min(max(timeout, 2.0), 60.0),
    }


def publish_digest(doc: dict, config_path: str, *, _push=None, _sas_reader=None,
                   _sleep=None) -> bool:
    """Write the digest file atomically under <public_export.dir>/ and PUT it
    to the configured blob. Returns True iff everything that was configured
    succeeded (disabled / no blob_url = local file only = True). Never raises;
    never logs the SAS (push() errors are SAS-free by construction). Reads
    nothing but config.yaml; writes nothing but the digest file.
    The keyword-only hooks exist for the selftest."""
    import time as _time
    try:
        import yaml
        with open(config_path) as fh:
            cfg = yaml.safe_load(fh) or {}
    except Exception as e:                                       # noqa: BLE001
        logger.error("DIGEST NOT PUBLISHED: config %s unreadable (%s)", config_path, type(e).__name__)
        return False
    try:
        from public_export import encode, write_atomic, read_sas, push, _retryable, _valid_blob_url
    except Exception as e:                                       # noqa: BLE001 — ImportError, SyntaxError, …
        logger.error("DIGEST NOT PUBLISHED: public_export module not importable (%s)", type(e).__name__)
        return False

    def retryable(err):                      # 408/429 are transient too; push()'s rule says 4xx = permanent
        return _retryable(err) or err in ("HTTP 408", "HTTP 429")

    try:
        kind = str(doc.get("kind") or "daily")
        c = digest_publish_cfg(cfg, kind)
        data = encode(doc)
        if len(data) > DIGEST_MAX_BYTES:
            logger.error("DIGEST NOT PUBLISHED: document is %d bytes (> %d) — refusing", len(data), DIGEST_MAX_BYTES)
            return False
        path = str(Path(__file__).resolve().parent / c["dir"] / DIGEST_FILES.get(kind, f"digest-{kind}.json"))
        write_atomic(path, data)
        logger.info("digest written: %s (%d bytes)", path, len(data))
        if not c["enabled"]:
            logger.info("digest publish disabled in config (public_export.digest.enabled) — local file only")
            return True
        if not c["blob_url"]:
            logger.warning("digest publish: no blob URL configured for kind=%s — local file only", kind)
            return True
        if not _valid_blob_url(c["blob_url"]):
            logger.error("DIGEST NOT PUBLISHED: public_export.digest blob URL must be "
                         "https://<account>.blob.core.windows.net/<container>/<blob> with NO query string")
            return False
        sas = (_sas_reader or read_sas)(c["item"])
        if not sas:
            logger.error("DIGEST NOT PUBLISHED: SAS absent — keychain item %r missing/unreadable "
                         "(install: security add-generic-password -a \"$USER\" -s %s -T /usr/bin/security -U -w)",
                         c["item"], c["item"])
            return False
        do_push = _push or push
        sleep = _sleep or _time.sleep
        err = None
        for attempt in range(1, DIGEST_PUSH_ATTEMPTS + 1):
            ok, err = do_push(data, c["blob_url"], sas, timeout=c["timeout"])
            if ok:
                logger.info("digest published: %d bytes -> %s (attempt %d)", len(data), c["blob_url"], attempt)
                return True
            if not retryable(err):
                logger.error("DIGEST NOT PUBLISHED: %s (permanent — bad/expired/mis-scoped SAS or URL; not retried)", err)
                return False
            logger.warning("digest push attempt %d/%d failed: %s", attempt, DIGEST_PUSH_ATTEMPTS, err)
            if attempt < DIGEST_PUSH_ATTEMPTS:
                sleep(DIGEST_RETRY_SLEEPS_S[min(attempt - 1, len(DIGEST_RETRY_SLEEPS_S) - 1)])
        logger.error("DIGEST NOT PUBLISHED after %d attempts: %s", DIGEST_PUSH_ATTEMPTS, err)
        return False
    except Exception as e:                                       # noqa: BLE001 — type only, never str(e)
        logger.error("DIGEST NOT PUBLISHED: unexpected %s", type(e).__name__)
        return False


def deliver(send: bool, publish: bool, send_fn, publish_fn) -> bool:
    """Run the two deliveries independently — an exception or failure in one
    never prevents the other (2026-10-20). Returns True iff everything that
    was requested succeeded. Exceptions are logged by type only."""
    ok_mail = True
    if send:
        try:
            ok_mail = bool(send_fn())
        except Exception as e:                                   # noqa: BLE001
            logger.error("EMAIL NOT SENT: unexpected %s in send_report", type(e).__name__)
            ok_mail = False
    ok_pub = True
    if publish:
        try:
            ok_pub = bool(publish_fn())
        except Exception as e:                                   # noqa: BLE001
            logger.error("DIGEST NOT PUBLISHED: unexpected %s", type(e).__name__)
            ok_pub = False
    return ok_mail and ok_pub


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
    Also returns the quiet_hours dict (for the violations section's
    "alert was suppressed overnight" annotation).
    Tolerant: returns empty roles if the config is missing/unreadable."""
    try:
        import yaml
        cfg = yaml.safe_load(open(path)) or {}
    except Exception:
        return None, set(), set(), "analytics.db", "", "UTC", None, {}
    focus = cfg.get("focus_node")
    acfg = cfg.get("analytics") or {}
    if not isinstance(acfg, dict):
        acfg = {}
    core = set(acfg.get("core_nodes") or ([focus] if focus is not None else []))
    bridges = set(acfg.get("bridge_nodes") or cfg.get("bridge_nodes", []))
    # Report display timezone: analytics.timezone, else the quiet_hours zone,
    # else UTC.
    tzname = (acfg.get("timezone")
              or (cfg.get("quiet_hours") or {}).get("timezone")
              or "UTC")
    quiet = cfg.get("quiet_hours") if isinstance(cfg.get("quiet_hours"), dict) else None
    # Node health (2026-10-18): the configured node -> expected-parent map,
    # so the section lists every monitored node even before it has rows.
    # None = the config has no enabled node_health block (section says so);
    # {} only when the module itself cannot be imported (ad-hoc fallback).
    health_nodes: Optional[dict] = None
    try:
        from node_health import node_health_cfg
    except ImportError as e:
        logger.info("node_health module not available (%s) — section uses recorded nodes only", e)
        health_nodes = {}
    else:
        try:
            hc = node_health_cfg(cfg)
            if hc:
                health_nodes = dict(hc["nodes"])
        except Exception as e:                 # a bad block: say "not enabled", never replay
            logger.warning("node_health config did not parse (%s) — section disabled", e)
            health_nodes = None
    return (focus, core, bridges, acfg.get("db_path", "analytics.db"),
            acfg.get("system_name", ""), tzname, quiet, health_nodes)


def _selftest() -> int:
    """Offline: change 2 (non-reporting nodes) end to end on a scratch DB —
    recorder rows -> episodes -> text/HTML. No config, no email."""
    import os
    import tempfile
    from datetime import timedelta
    from analytics_db import init_db, Recorder

    td = tempfile.mkdtemp()
    db = os.path.join(td, "a.db")
    conn = init_db(db)
    rec = Recorder(conn)
    end = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
    start = end - timedelta(days=1)
    t0 = start + timedelta(hours=1)
    ts = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731 (scanner format)
    # dark 4000 on bridge 2000: 3 scans 5 min apart, a 2 h gap, then 1 more scan
    n = 0
    for i in range(3):
        n += rec.record_link_reports(
            [{"node": 4000, "attached_to": 2000, "attachment": "bridge", "callsign": "C4000"}],
            [], ts=ts(t0 + timedelta(minutes=5 * i)))
    n += rec.record_link_reports(
        [{"node": 4000, "attached_to": 2000, "attachment": "bridge", "callsign": "Unknown"}],
        [], ts=ts(t0 + timedelta(hours=3)))
    # linkless 3000 on hub 1000: 2 scans, the last one 5 min before period end
    for i in range(2):
        n += rec.record_link_reports(
            [], [{"node": 3000, "attached_to": 1000, "attachment": "hub",
                  "callsign": "<b>X</b>", "post_age_seconds": 4.6}],
            ts=ts(end - timedelta(minutes=10 - 5 * i)))
    # malformed entries are skipped, not raised; a row before the period is excluded
    n_bad = rec.record_link_reports([{"node": "junk"}, {"attached_to": 1}], [{"node": None}],
                                    ts=ts(t0))
    rec.record_link_reports([{"node": 9999, "attached_to": 1000}], [], ts=ts(start - timedelta(hours=2)))
    age_row = conn.execute("SELECT post_age_seconds FROM link_report_events "
                           "WHERE node_id=3000 LIMIT 1").fetchone()
    # sanitizing (audit A2): control chars stripped, callsign truncated
    rec.record_link_reports([{"node": 7000, "attached_to": 1000, "attachment": "hub",
                              "callsign": "AB\r\nCD"},
                             {"node": 7001, "attached_to": 1000, "callsign": "x" * 40}],
                            [], ts=ts(start - timedelta(days=2)))
    cs_row = tuple(r[0] for r in conn.execute(
        "SELECT callsign FROM link_report_events WHERE node_id IN (7000, 7001) ORDER BY node_id"))
    # rollback discipline (audit S1): a failing INSERT mid-list leaves no rows
    raised = False
    before = conn.execute("SELECT COUNT(*) FROM link_report_events").fetchone()[0]
    try:
        rec.record_link_reports(
            [{"node": 8000, "attached_to": 1000}, {"node": 2 ** 70, "attached_to": 1000}],
            [], ts=ts(t0))
    except Exception:
        raised = True
    left_rows = conn.execute("SELECT COUNT(*) FROM link_report_events").fetchone()[0] - before
    # retention (audit S2): rows older than the window go, newer stay
    from analytics_db import purge_link_reports, LINK_REPORT_RETENTION_DAYS
    old_ts = ts(end - timedelta(days=LINK_REPORT_RETENTION_DAYS + 1))
    rec.record_link_reports([{"node": 9001, "attached_to": 1000}], [], ts=old_ts)
    purged = purge_link_reports(conn, now=end)
    kept = conn.execute("SELECT COUNT(*) FROM link_report_events WHERE node_id=7000").fetchone()[0]
    conn.close()

    r = generate_report(db, start, end, focus_node=1000, core_nodes={1000}, bridge_nodes={2000})
    dark, lkl = r.dark_episodes, r.linkless_episodes
    text = render_text(r, system_name="T", callsigns={4000: "C4000"})
    page = render_html(r, system_name="T", callsigns={4000: "C4000"})
    # an older DB with no such table -> no episodes, no crash
    old = os.path.join(td, "old.db")
    c2 = init_db(old)
    c2.execute("DROP TABLE link_report_events")
    c2.execute("DROP TABLE node_health_events")
    c2.execute("DROP TABLE current_node_health")
    c2.commit()
    c2.close()
    r_old = generate_report(old, start, end, focus_node=1000, core_nodes=set(), bridge_nodes=set())

    # --- three-state node health (2026-10-18) on its own scratch DB ---------
    from analytics_db import PresentNode, ROLE_CORE as _RC
    db2 = os.path.join(td, "nh.db")
    c3 = init_db(db2)
    rec3 = Recorder(c3)
    # presence: hub 1000 + core 3000 present for the whole window (core-line suffix case)
    rec3.reconcile_scan([PresentNode(1000, _RC), PresentNode(3000, _RC)],
                        ts=ts(start - timedelta(hours=1)))
    # heartbeats every 5 min, with a 2 h monitoring gap +18h..+20h (gated scans
    # write no heartbeat — this is what a gated stretch looks like)
    t = start
    while t <= end:
        if not (start + timedelta(hours=18) < t < start + timedelta(hours=20)):
            rec3.heartbeat(ts(t), 5)
        t += timedelta(minutes=5)
    c3.commit()
    H0 = lambda h: ts(start + timedelta(hours=h))  # noqa: E731
    det = {"parent": 1000}
    nh_rows = [
        # hub 1000: baselines 2 h before the window; posting off +20h..+21h
        (ts(start - timedelta(hours=2)), 1000, "registered", None, "1", 1, det),
        (ts(start - timedelta(hours=2)), 1000, "posting", None, "1", 1, det),
        (ts(start - timedelta(hours=2)), 1000, "letter", None, "self", 1, det),
        (H0(20), 1000, "posting", "1", "0", 0, det),
        (H0(21), 1000, "posting", "0", "1", 0, det),
        # core 3000 via the hub: T, then C from +12h (overlapping the monitor
        # gap); registration lost at +6h; posting all along
        (ts(start - timedelta(hours=2)), 3000, "registered", None, "1", 1, det),
        (ts(start - timedelta(hours=2)), 3000, "posting", None, "1", 1, det),
        (ts(start - timedelta(hours=2)), 3000, "letter", None, "T", 1, det),
        (H0(6), 3000, "registered", "1", "0", 0, det),
        (H0(12), 3000, "letter", "T", "C", 0, det),
        # 4000 via bridge 2000: first observed at +2h (restart boundary —
        # baseline rows only, nothing before them)
        (H0(2), 4000, "registered", None, "1", 1, {"parent": 2000}),
        (H0(2), 4000, "posting", None, "1", 1, {"parent": 2000}),
        (H0(2), 4000, "letter", None, "T", 1, {"parent": 2000}),
        # 5000 via the hub: T -> C five hours BEFORE the window, then a restart
        # baseline 2 h before it (audit S5: "since" must be the real -5h, not
        # the restart); registered/posting baselines only
        (ts(start - timedelta(hours=6)), 5000, "letter", None, "T", 1, det),
        (ts(start - timedelta(hours=5)), 5000, "letter", "T", "C", 0, det),
        (ts(start - timedelta(hours=2)), 5000, "letter", None, "C", 1, det),
        (ts(start - timedelta(hours=2)), 5000, "registered", None, "1", 1, det),
        (ts(start - timedelta(hours=2)), 5000, "posting", None, "1", 1, det),
    ]
    nh_cur = [
        {"node_id": 1000, "parent": "self", "registered": "1", "posting": "1", "letter": "self",
         "since_registered": None, "since_posting": H0(21), "since_letter": None, "updated": H0(21)},
        {"node_id": 3000, "parent": "1000", "registered": "0", "posting": "1", "letter": "C",
         "since_registered": H0(6), "since_posting": None, "since_letter": H0(12), "updated": H0(12)},
        {"node_id": 4000, "parent": "2000", "registered": "1", "posting": "1", "letter": "T",
         "since_registered": H0(2), "since_posting": H0(2), "since_letter": H0(2), "updated": H0(2)},
        {"node_id": 5000, "parent": "1000", "registered": "1", "posting": "1", "letter": "C",
         "since_registered": None, "since_posting": None,
         "since_letter": ts(start - timedelta(hours=5)), "updated": H0(0)},
        # 6000: only in the live table, NOT configured, no rows in the window
        # (a stale leftover) -> must not appear (audit S4)
        {"node_id": 6000, "parent": "1000", "registered": "1", "posting": "1", "letter": "T",
         "since_registered": None, "since_posting": None, "since_letter": None, "updated": H0(0)},
    ]
    n_nh = rec3.record_node_health(nh_rows, nh_cur)
    nh_loaded = {d["node_id"]: d["letter"] for d in rec3.load_current_node_health()}
    c3.close()
    rh = generate_report(db2, start, end, focus_node=1000, core_nodes={1000, 3000},
                         bridge_nodes={2000},
                         health_nodes={1000: "self", 3000: 1000, 4000: 2000, 5000: 1000})
    nh = {s.node_id: s for s in rh.node_health}
    nh_text = render_text(rh, system_name="T")
    nh_page = render_html(rh, system_name="T")

    checks = [
        ("recorder: one row per node per scan (6), malformed skipped (0)", n == 6 and n_bad == 0),
        ("recorder: post age stored as an integer", age_row is not None and age_row[0] == 5),
        ("episodes: dark node splits into 2 episodes by the 15 min gap (3 scans + 1)",
         [(e.node, e.scans) for e in dark] == [(4000, 3), (4000, 1)]),
        ("episodes: dark callsign keeps the real one, 'Unknown' never wins",
         all(e.callsign == "C4000" or e.scans == 1 for e in dark)
         and dark[0].callsign == "C4000" and dark[1].callsign == "Unknown"),
        ("episodes: linkless node is one episode of 2 scans, ongoing at period end",
         [(e.node, e.scans, e.ongoing, e.attached_to) for e in lkl] == [(3000, 2, True, 1000)]),
        ("episodes: the dark episodes are not ongoing; the pre-period row is excluded",
         not any(e.ongoing for e in dark) and all(e.node != 9999 for e in r.link_reports)),
        ("text: header counts distinct nodes",
         "Nodes not reporting their links: 1 dark, 1 linkless" in text),
        ("text: dark line names node, bridge, scans", "Node 4000 [C4000] on Node 2000" in text
         and "3 scan(s)" in text),
        ("text: linkless line marks still-so-at-end", "Node 3000" in text
         and "2 scan(s), still so at period end" in text),
        ("html: section + tables present with rows", "Nodes not reporting their links" in page
         and "<td>Node 4000</td><td>C4000</td><td>Node 2000</td>" in page
         and "<td>Node 3000</td><td>&lt;b&gt;X&lt;/b&gt;</td><td>Node 1000</td>" in page
         and "last post 5 s old</td><td>2</td></tr>" in page),
        ("html: recorded callsign is escaped", "<b>X</b>" not in page),
        ("text: linkless line carries the last post age", "last post was 5 s old" in text),
        ("old DB without the table: no episodes, section renders empty",
         r_old.link_reports == [] and
         "Nodes not reporting their links: 0 dark, 0 linkless" in render_text(r_old)),
        ("recorder: control characters stripped, callsign truncated to 20",
         cs_row == ("ABCD", "x" * 20)),
        ("recorder: an INSERT failure rolls back this call's rows and re-raises",
         raised and left_rows == 0),
        ("purge: rows older than the retention window are deleted, newer kept",
         purged == 1 and kept == 1),
        # three-state node health (2026-10-18)
        ("node health: recorder wrote 18 rows + 5 current rows; load_current reads them back",
         n_nh == 18 and nh_loaded == {1000: "self", 3000: "C", 4000: "T", 5000: "C", 6000: "T"}),
        ("node health S5: 'since' behind a restart baseline = the real transition (-5h), "
         "dialing the whole monitored window",
         5000 in nh and nh[5000].since_letter == start - timedelta(hours=5)
         and nh[5000].dialing_secs == 79200 and nh[5000].linked_pct == 0.0),
        ("node health S4: a node only in the live table (not configured, no rows) is not listed",
         6000 not in nh),
        ("node health S4 pass 2: config read but node health disabled -> section says so, "
         "no live-table replay; no config at hand ({}) -> live-table fallback lists them",
         "(node health is not enabled in config.yaml)" in render_text(
             generate_report(db2, start, end, 1000, {1000, 3000}, {2000}, health_nodes=None))
         and 6000 in {s.node_id for s in generate_report(
             db2, start, end, 1000, {1000, 3000}, {2000}, health_nodes={}).node_health}),
        ("node health: 3000 linked 54.5% over KNOWN time; C overlapping the 2 h monitor gap "
         "excluded (10 h dialing)",
         3000 in nh and abs(nh[3000].linked_pct - 43200 / 79200) < 1e-6
         and nh[3000].dialing_secs == 36000),
        ("node health: 3000 registered 27.3%, posting 100%",
         abs(nh[3000].registered_pct - 6 / 22) < 1e-6 and nh[3000].posting_pct == 1.0),
        ("node health: hub linked = posting 95.5%",
         nh[1000].parent == "self" and abs(nh[1000].linked_pct - 21 / 22) < 1e-6),
        ("node health: restart-boundary baseline -> 2 h unknown, 100% linked over known time",
         nh[4000].linked_pct == 1.0 and nh[4000].unknown_secs == 7200),
        ("node health: 4 transitions in the window, baselines excluded; hub ordered first",
         len(rh.node_health_transitions) == 4 and rh.node_health[0].node_id == 1000),
        ("node health: end state 3000 = C since +12h, not registered since +6h",
         nh[3000].end_letter == "C" and nh[3000].since_letter == start + timedelta(hours=12)
         and nh[3000].end_registered == "0"
         and nh[3000].since_registered == start + timedelta(hours=6)),
        ("text: node-health section, 3000 line, transitions count",
         "Registration & link state" in nh_text
         and "linked 54.5% (parent dialing 10 h)" in nh_text
         and "Transitions this period: 4" in nh_text
         and "parent data unavailable 2 h" in nh_text),
        ("text: core line says 'seen in topology' and carries the dialing suffix",
         "100.0% seen in topology" in nh_text and "parent dialing 10 h of that" in nh_text),
        ("html: section, 3000 row, core 'Linked (parent's view)' column",
         "<h3>Registration &amp; link state</h3>" in nh_page
         and "C dialing, no audio" in nh_page and "<td>54.5%</td><td>10 h</td>" in nh_page
         and "<th>Linked (parent's view)</th>" in nh_page),
        ("old DB without the tables: 'not recorded' in text + HTML, no crash",
         not r_old.node_health_available
         and "(not recorded by this daemon version)" in render_text(r_old)
         and "(not recorded by this daemon version)" in render_html(r_old)),
    ]

    # ---- team page digest (2026-10-20): contract, config, publish paths ----
    import json as _json
    import yaml as _yaml
    from public_export import encode as _encode
    doc = build_digest_doc(r, text, "SYS AllStar Stats — Daily (2026-09-08)", "daily",
                           "America/Chicago", "SYS", now=end, html_body=page)   # v2.1: with blocks
    good_url = "https://example.blob.core.windows.net/status/digest.json"
    pe_dir = os.path.join(td, "pe")
    daily_path = os.path.join(pe_dir, "digest.json")
    SAS = "sv=1&sr=b&sp=cw&sig=SECRETSASVALUE"
    calls: list = []
    sleeps: list = []
    log_lines: list = []

    class _Cap(logging.Handler):
        def emit(self, record):
            log_lines.append(record.getMessage())
    cap = _Cap()
    logger.addHandler(cap)
    cfg_n = [0]

    def _cfg(**digest):
        cfg_n[0] += 1
        p = os.path.join(td, f"cfg_{cfg_n[0]}.yaml")
        with open(p, "w") as fh:
            _yaml.safe_dump({"public_export": {"dir": pe_dir, "digest": digest}}, fh)
        return p

    def _pusher(results):
        it = iter(results)
        def _p(data, url, sas, timeout):
            calls.append((len(data), url, sas, timeout))
            res = next(it)
            if isinstance(res, Exception):
                raise res
            return res
        return _p

    def _written():
        """(file exists and equals doc, no temp files left) for the LAST run."""
        if not os.path.exists(daily_path):
            return False
        same = _json.loads(open(daily_path, "rb").read().decode("utf-8")) == doc
        tmps = [f for f in os.listdir(pe_dir) if f.endswith(".tmp")]
        return same and not tmps

    def _run(results, sas=SAS, the_doc=None, **digest):
        del calls[:], sleeps[:], log_lines[:]
        if os.path.exists(daily_path):
            os.unlink(daily_path)
        reader = sas if callable(sas) else (lambda item: sas)
        return publish_digest(the_doc or doc, _cfg(**digest), _push=_pusher(results),
                              _sas_reader=reader, _sleep=sleeps.append)

    pub_ok = _run([(True, None)], enabled=True, blob_url=good_url)
    pub_ok_calls, pub_ok_written, pub_ok_log = list(calls), _written(), list(log_lines)
    pub_403 = _run([(False, "HTTP 403"), (True, None)], enabled=True, blob_url=good_url)
    pub_403_calls, pub_403_sleeps, pub_403_written = len(calls), list(sleeps), _written()
    pub_5xx = _run([(False, "HTTP 503"), (False, "ConnectTimeout"), (False, "HTTP 500")],
                   enabled=True, blob_url=good_url)
    pub_5xx_calls, pub_5xx_sleeps = len(calls), list(sleeps)
    pub_429 = _run([(False, "HTTP 429"), (True, None)], enabled=True, blob_url=good_url)
    pub_429_calls = len(calls)
    pub_recover = _run([(False, "HTTP 503"), (True, None)], enabled=True, blob_url=good_url)
    pub_recover_calls = len(calls)
    pub_nosas = _run([(True, None)], sas=None, enabled=True, blob_url=good_url)
    pub_nosas_calls, pub_nosas_written, pub_nosas_log = len(calls), _written(), list(log_lines)
    pub_disabled = _run([(True, None)], enabled=False, blob_url=good_url)
    pub_disabled_calls, pub_disabled_written = len(calls), _written()
    pub_strfalse = _run([(True, None)], enabled="false", blob_url=good_url)
    pub_strfalse_calls = len(calls)
    pub_nourl = _run([(True, None)], enabled=True)
    pub_nourl_calls = len(calls)
    pub_badurl = _run([(True, None)], enabled=True,
                      blob_url="https://example.blob.core.windows.net/status/digest.json?sv=1&sig=x")
    pub_badurl_calls, pub_badurl_written = len(calls), _written()
    pub_push_raises = _run([RuntimeError("boom " + SAS)], enabled=True, blob_url=good_url)
    pub_push_raises_log = list(log_lines)

    def _raising_reader(item):
        raise OSError("keychain exploded " + SAS)
    pub_sas_raises = _run([(True, None)], sas=_raising_reader, enabled=True, blob_url=good_url)
    pub_bad_cfg = publish_digest(doc, os.path.join(td, "missing.yaml"), _push=_pusher([(True, None)]),
                                 _sas_reader=lambda item: SAS, _sleep=sleeps.append)
    # weekly end to end: its own file, the daily blob URL is never used, digest.json untouched
    doc_week = build_digest_doc(r, text, "SYS AllStar Stats — Weekly (2026-09-08)", "weekly",
                                "America/Chicago", "SYS", now=end)
    pub_week = _run([(True, None)], the_doc=doc_week, enabled=True, blob_url=good_url)
    pub_week_calls = len(calls)
    week_written = os.path.exists(os.path.join(pe_dir, "digest-week.json")) and not os.path.exists(daily_path)
    pub_week_url = _run([(True, None)], the_doc=doc_week, enabled=True, blob_url=good_url,
                        weekly_blob_url="https://example.blob.core.windows.net/status/digest-week.json")
    pub_week_url_calls = list(calls)
    leaked =[ln for ln in (pub_ok_log + pub_nosas_log + pub_push_raises_log + log_lines)
              if "SECRETSASVALUE" in ln or "sig=" in ln]
    logger.removeHandler(cap)
    weekly_cfg = digest_publish_cfg({"public_export": {"digest": {"enabled": True, "blob_url": good_url}}}, "weekly")
    nan_cfg = digest_publish_cfg({"public_export": {"digest": {"enabled": True, "timeout_seconds": float("nan")}}})
    huge_cfg = digest_publish_cfg({"public_export": {"digest": {"enabled": True, "timeout_seconds": 10**400}}})
    # text sanitising + truncation
    doc_dirty = build_digest_doc(r, "a\x00b\x1bc‮d\r\n" + "x" * 250_000, "s", "daily", "UTC", "SYS", now=end)
    # deliver(): the two deliveries are independent, exceptions included
    seq: list = []

    def _s_ok(): seq.append("send"); return True
    def _s_raise(): seq.append("send"); raise RuntimeError("smtp")
    def _s_fail(): seq.append("send"); return False
    def _p_ok(): seq.append("pub"); return True
    def _p_fail(): seq.append("pub"); return False
    d_both_ok = deliver(True, True, _s_ok, _p_ok); del seq[:]
    d_send_raises = deliver(True, True, _s_raise, _p_ok); d_send_raises_seq = list(seq); del seq[:]
    d_send_fail = deliver(True, True, _s_fail, _p_ok); del seq[:]
    d_pub_fail = deliver(True, True, _s_ok, _p_fail); del seq[:]
    d_neither = deliver(False, False, _s_raise, _p_fail); d_neither_seq = list(seq)
    checks += [
        ("digest doc: contract v1 keys (+ optional blocks), UTC Z stamps, text ends with newline, line count",
         set(doc) == {"v", "kind", "generated", "period_start", "period_end", "tz", "system",
                      "subject", "text", "summary", "blocks"}
         and doc["v"] == 1 and doc["kind"] == "daily"
         and doc["generated"] == "2026-09-08T12:00:00Z" and doc["period_start"] == "2026-09-07T12:00:00Z"
         and doc["text"].endswith("\n") and doc["summary"]["lines"] == doc["text"].count("\n")
         and doc["summary"]["core_nodes"] == len(r.core) and doc["summary"]["violations"] == len(r.violations)),
        ("digest doc: encode round-trips, no NaN, well under the size cap",
         _json.loads(_encode(doc)) == doc and len(_encode(doc)) < DIGEST_MAX_BYTES),
        ("digest cfg: weekly kind reads weekly_blob_url (absent -> None), daily URL never reused",
         weekly_cfg["blob_url"] is None and weekly_cfg["enabled"] is True
         and digest_publish_cfg({})["enabled"] is False and digest_publish_cfg({})["dir"] == "public_export"),
        ("digest publish: 201 -> True, one PUT of the encoded bytes to the configured URL with the SAS",
         pub_ok and pub_ok_calls == [(len(_encode(doc)), good_url, SAS, 10.0)]),
        ("digest publish: the local file is written (atomically, no .tmp left) and equals the document",
         pub_ok_written),
        ("digest publish: 403 is permanent — one attempt, False, no sleep, file still written",
         pub_403 is False and pub_403_calls == 1 and pub_403_sleeps == [] and pub_403_written),
        ("digest publish: 5xx/transport errors -> 3 attempts with 2 s / 4 s sleeps, then False",
         pub_5xx is False and pub_5xx_calls == 3 and pub_5xx_sleeps == [2.0, 4.0]),
        ("digest publish: 429 is transient -> retried, then 201 -> True",
         pub_429 is True and pub_429_calls == 2),
        ("digest publish: 503 then 201 -> True after 2 attempts",
         pub_recover is True and pub_recover_calls == 2),
        ("digest publish: SAS absent -> False, no PUT, file still written, LOUD log line names the item",
         pub_nosas is False and pub_nosas_calls == 0 and pub_nosas_written
         and any("DIGEST NOT PUBLISHED: SAS absent" in ln and "ASL_TEAM_DIGEST_SAS" in ln for ln in pub_nosas_log)),
        ("digest publish: disabled -> True, no PUT, file written; enabled:'false' (string) is NOT enabled",
         pub_disabled is True and pub_disabled_calls == 0 and pub_disabled_written
         and pub_strfalse is True and pub_strfalse_calls == 0),
        ("digest publish: no blob_url -> True, no PUT",
         pub_nourl is True and pub_nourl_calls == 0),
        ("digest publish: a blob_url carrying a query string is refused -> False, no PUT, file written",
         pub_badurl is False and pub_badurl_calls == 0 and pub_badurl_written),
        ("digest publish: a raising push or SAS reader -> False, never raises",
         pub_push_raises is False and pub_sas_raises is False),
        ("digest publish: unreadable config -> False, never raises",
         pub_bad_cfg is False),
        ("digest publish: NO log line ever carries the SAS or any sig= fragment",
         leaked == []),
        ("digest publish weekly: writes digest-week.json, never digest.json; no weekly URL -> no PUT; "
         "weekly_blob_url -> PUT there only",
         pub_week is True and pub_week_calls == 0 and week_written
         and pub_week_url is True and [c[1] for c in pub_week_url_calls]
         == ["https://example.blob.core.windows.net/status/digest-week.json"]),
        ("digest cfg: NaN / absurd timeout_seconds fall back to 10 s",
         nan_cfg["timeout"] == 10.0 and huge_cfg["timeout"] == 10.0),
        ("digest doc: control + bidi characters stripped, 250k text truncated below the page limit with a marker",
         "\x00" not in doc_dirty["text"] and "\x1b" not in doc_dirty["text"] and "‮" not in doc_dirty["text"]
         and doc_dirty["text"].startswith("abcd\n") and len(doc_dirty["text"]) <= DIGEST_MAX_TEXT_CHARS + 1
         and DIGEST_TRUNCATED_LINE.strip() in doc_dirty["text"] and doc_dirty["summary"]["truncated"] is True
         and doc["summary"]["truncated"] is False),
        ("deliver(): both ok -> True; send raises -> False but publish still runs; send/publish False -> False; "
         "neither requested -> True and nothing runs",
         d_both_ok is True and d_send_raises is False and d_send_raises_seq == ["send", "pub"]
         and d_send_fail is False and d_pub_fail is False and d_neither is True and d_neither_seq == []),
    ]

    # ---- v2.1 blocks: the email HTML transcribed into generic blocks ----
    def _blk_counts(src):
        bl = digest_blocks_from_html(src)
        tabs = [b for b in bl if b["t"] == "table"]
        got = {"table": len(tabs),
               "tr": sum(len(t["rows"]) + (1 if t["head"] else 0) for t in tabs),
               "th": sum(len(t["head"]) for t in tabs),
               "td": sum(len(row) for t in tabs for row in t["rows"]),
               "h2": sum(b["t"] == "h2" for b in bl), "h3": sum(b["t"] == "h3" for b in bl),
               "h4": sum(b["t"] == "h4" for b in bl), "p": sum(b["t"] == "p" for b in bl)}
        exp = {"table": src.count("<table"), "tr": src.count("<tr>"), "th": src.count("<th>"),
               "td": src.count("<td"), "h2": src.count("<h2"),
               "h3": src.count("<h3"), "h4": src.count("<h4"), "p": src.count("<p")}
        return bl, got, exp
    # a report WITH violations (quiet-hours note), violator + hub guests, an unwitting drag-in and
    # an external client — the branches the scratch-DB fixtures never exercise (audit S2)
    r_viol = ReportData(
        start=start, end=end, monitor_down_secs=0,
        core=[NodeAvailability(1000, "core", 1.0)],
        bridges=[NodeAvailability(2000, "bridge", 1.0, sessions=[PresenceSession(None, None, None)])],
        guest_sessions=[GuestSession(4000, 2000, start + timedelta(hours=2), start + timedelta(hours=3), 3600),
                        GuestSession(4100, 1000, start + timedelta(hours=4), None, None)],
        external_sessions=[ExternalSession(1000, "echolink", "N0CALL-L", start + timedelta(hours=1), None, None)],
        violations=[ViolationEpisode(4000, "C4000", start + timedelta(hours=2), start + timedelta(hours=2, minutes=10),
                                     3, "1000 -> 2000 -> 4000 -> 5000", quiet_suppressed=True)],
        unwitting_sessions=[GuestSession(5000, 4000, start + timedelta(hours=2), start + timedelta(hours=2, minutes=10), 600)])
    viol_page = render_html(r_viol, callsigns={4000: "C4000"}, owners={4000: "O4000"})
    blk_results = {nm: _blk_counts(src) for nm, src in
                   (("page", page), ("nh_page", nh_page), ("old", render_html(r_old)), ("viol", viol_page))}
    blk_structure_ok = all(got == exp for _, got, exp in blk_results.values())
    vb = blk_results["viol"][0]
    v_h3 = [b for b in vb if b["t"] == "h3" and b.get("mark")]
    v_cells = [c for b in vb if b["t"] == "table" for row in b["rows"] for c in row]
    v_mark = [c for c in v_cells if c.get("mark")]
    v_note = [c for c in v_cells if c.get("note")]
    v_unwit = [b for b in vb if b["t"] == "table" and b["head"][:2] == ["Node", "Dragged in via"]]
    v_ext = [c for c in v_cells if c["text"] == "N0CALL-L"]
    blocks_page = blk_results["page"][0]
    tables_page = [b for b in blocks_page if b["t"] == "table"]
    linkless = [row for t in tables_page for row in t["rows"]
                if len(row) == 5 and row[0]["text"] == "Node 3000" and row[1]["text"] == "<b>X</b>"]
    span7 = [c for t in tables_page for row in t["rows"] for c in row if c.get("span") == 7]
    disclaimer = [b for b in blocks_page if b["t"] == "p" and b.get("em") and b["text"].startswith("Disclaimer:")]
    legend_small = [b for b in blk_results["nh_page"][0] if b["t"] == "p" and b.get("small")]
    core_head = tables_page[0]["head"][:6] if tables_page else None
    syn = ('<html><body style="font-family:sans-serif">\n<h3 style="color:#b00020">&#9888; X</h3>\n'
           '<table border="1" cellpadding="4" cellspacing="0">\n<tr><th>A</th><th>B</th></tr>\n'
           '<tr><td>Node 1 <b style="color:#b00020">&#9888; VIOLATION</b></td>'
           '<td>a &rarr; b<br><small>(note\n  here)</small></td></tr>\n'
           '<tr><td colspan="2">(none this period)</td></tr>\n</table>\n'
           '<p style="margin:0 0 4px"><small>hint\nwrapped</small></p><p><em>disc</em></p>'
           '<p>mixed <small>x</small></p><h4 style="margin:8px 0 2px">Sub</h4></body></html>')
    sb = digest_blocks_from_html(syn)
    bad_snippets = ['<a href="x">y</a>', '<img src="x">', '<script>1</script>',
                    '<table><tr><td onclick="">x</td></tr></table>', '<span>x</span>', 'bare text',
                    '<td>x</td>', '<table><tr><th>A</th><td>B</td></tr></table>',
                    '<table><tr><td>A</td></tr><tr><th>B</th></tr></table>',
                    '<table><tr><td colspan="x">A</td></tr></table>',
                    '<table><tr><td colspan="1">A</td></tr></table>',
                    '<table><tr><td colspan="99">A</td></tr></table>',
                    '<table><tr><td>A</td></tr>', '<!-- c --><p>x</p>', '<p><b>x</b></p>',
                    '<table><tr><td><p>x</p></td></tr></table>', '<table><tr></tr></table>',
                    # audit additions: case, self-closing, misplaced inline tags, declarations, odd attrs
                    '<table><tr><th colspan="2">A</th></tr></table>', '<table><tr><td style="x">A</td></tr></table>',
                    '<TABLE><tr><td>A</td></tr></TABLE>', '<table><tr><TD>A</TD></tr></table>', '<p>a<br>b</p>',
                    '<table><tr><th><small>A</small></th></tr></table>', '<table><tr><td><em>A</em></td></tr></table>',
                    '<table><tr><td><b><b>A</b></b></td></tr></table>', '<table><tr>text<td>A</td></tr></table>',
                    '<table><tr><td/></tr></table>', '<p/>', '<!DOCTYPE html><p>x</p>', '<![CDATA[x]]><p>x</p>',
                    '<?x?><p>x</p>', '<table><tr><td colspan>A</td></tr></table>',
                    '<table><tr><td colspan="2" colspan="3">A</td></tr></table>',
                    '<table><tr><td colspan="²">A</td></tr></table>', '<p>x</br></p>',
                    '<table><tr><td><b>x<br>y</b></td></tr></table>',
                    '<p>' + 'x' * 4001 + '</p>',
                    '<table><tr>' + '<td>a</td>' * 61 + '</tr></table>']
    html_repeat = '<html><body><p>x</p></body></html><html><body><p>y</p></body></html>'

    def _raises(s, wrap=True):
        try:
            digest_blocks_from_html(("<html><body>" + s + "</body></html>") if wrap else s)
            return False
        except DigestBlocksError:
            return True
        except Exception:                      # any other exception is a bug, not a pass
            return False
    all_raise = [s[:40] for s in bad_snippets if not _raises(s)] + ([] if _raises(html_repeat, wrap=False) else ["html_repeat"])
    bg_color_ok = digest_blocks_from_html('<html><body><h3 style="background-color:#fff">X</h3>'
                                          '<h3 style="margin:0; color:#b00020">Y</h3></body></html>')
    sentinel_ok = digest_blocks_from_html('<html><body><table><tr><td>a\x00BR\x00b</td></tr></table></body></html>')

    def _strings(o):
        if isinstance(o, str):
            yield o
        elif isinstance(o, list):
            for x in o:
                yield from _strings(x)
        elif isinstance(o, dict):
            for v in o.values():
                yield from _strings(v)
    doc_plain = build_digest_doc(r, text, "SYS AllStar Stats — Daily (2026-09-08)", "daily",
                                 "America/Chicago", "SYS", now=end)
    page_bidi = render_html(r, callsigns={3000: "AB‮CD\x07"})
    doc_bidi = build_digest_doc(r, text, "s", "daily", "UTC", "SYS", now=end, html_body=page_bidi)
    bidi_clean = ("blocks" in doc_bidi and not any(_DIGEST_STRIP_RE.search(s) for s in _strings(doc_bidi["blocks"]))
                  and any("ABCD" in s for s in _strings(doc_bidi["blocks"])))
    logger.addHandler(cap)
    del log_lines[:]
    doc_badhtml = build_digest_doc(r, text, "s", "daily", "UTC", "SYS", now=end,
                                   html_body='<html><body><a href="x">y</a></body></html>')
    badhtml_logged = any(ln.startswith("DIGEST BLOCKS:") for ln in log_lines)
    logger.removeHandler(cap)
    doc_trunc_html = build_digest_doc(r, "x" * 250_000, "s", "daily", "UTC", "SYS", now=end, html_body=page)
    checks += [
        ("blocks: every table/tr/th/td/h2/h3/h4/p of four rendered emails is transcribed (count equality)",
         blk_structure_ok),
        ("blocks viol: marked ⚠ h3, marked VIOLATION guest cell, quiet-hours note cell, unwitting table, external row",
         len(v_h3) == 1 and v_h3[0]["text"].startswith("⚠ Unauthorized bridging (1 episode)")
         and len(v_mark) == 1 and v_mark[0]["text"].endswith("⚠ VIOLATION")
         and len(v_note) == 1 and v_note[0]["note"].startswith("(began during quiet hours")
         and "→" in v_note[0]["text"] and len(v_unwit) == 1 and len(v_unwit[0]["rows"]) == 1 and len(v_ext) == 1),
        ("blocks: background-color is not a mark, color: is; a literal sentinel in data cannot inject a line break",
         bg_color_ok[0] == {"t": "h3", "text": "X"} and bg_color_ok[1] == {"t": "h3", "text": "Y", "mark": True}
         and sentinel_ok[0]["rows"][0][0]["text"] == "aBRb"),
        ("blocks: core table head = Node/Callsign/Owner/Seen in topology/Outages/Longest outage",
         core_head == ["Node", "Callsign", "Owner", "Seen in topology", "Outages", "Longest outage"]),
        ("blocks: linkless row cells are literal text (escaping undone, no markup), '(none)' row has span 7",
         len(linkless) == 1 and linkless[0][2]["text"] == "Node 1000" and linkless[0][4]["text"] == "2"
         and linkless[0][3]["text"].endswith("last post 5 s old") and len(span7) >= 1
         and span7[0]["text"] == "(none this period)"),
        ("blocks: disclaimer is a p with em; node-health legend is a p with small",
         len(disclaimer) == 1 and len(legend_small) >= 1),
        ("blocks synthetic: marked h3 with entity, marked cell text, arrow + note cell, span 2, small/em/mixed p, h4",
         sb[0] == {"t": "h3", "text": "⚠ X", "mark": True}
         and sb[1]["head"] == ["A", "B"]
         and sb[1]["rows"][0][0] == {"text": "Node 1 ⚠ VIOLATION", "mark": True}
         and sb[1]["rows"][0][1] == {"text": "a → b", "note": "(note here)"}
         and sb[1]["rows"][1][0] == {"text": "(none this period)", "span": 2}
         and sb[2] == {"t": "p", "text": "hint wrapped", "small": True}
         and sb[3] == {"t": "p", "text": "disc", "em": True}
         and sb[4] == {"t": "p", "text": "mixed x"} and sb[5] == {"t": "h4", "text": "Sub"}),
        ("blocks: every off-whitelist snippet raises DigestBlocksError (%d cases)" % len(bad_snippets),
         all_raise == []),
        ("blocks doc: html_body=None gives exactly today's document (blocks optional, additive)",
         doc_plain == {k: v for k, v in doc.items() if k != "blocks"} and "blocks" not in doc_plain),
        ("blocks doc: bidi/control characters in a callsign (raw and entity-encoded) never reach the blocks",
         bidi_clean and not any(_DIGEST_STRIP_RE.search(s) for s in _strings(digest_blocks_from_html(
             '<html><body><p>a&#x202e;b&#7;c&#x200f;d</p></body></html>')))),
        ("blocks doc: off-whitelist HTML -> no blocks, text intact, 'DIGEST BLOCKS:' logged; truncated text -> no blocks",
         "blocks" not in doc_badhtml and doc_badhtml["text"] == doc["text"] and badhtml_logged
         and "blocks" not in doc_trunc_html and doc_trunc_html["summary"]["truncated"] is True),
        ("blocks doc: encode round-trips with blocks and stays far below the size cap",
         _json.loads(_encode(doc)) == doc and len(_encode(doc)) < DIGEST_MAX_BYTES // 4),
    ]
    failed = [nm for nm, ok in checks if not ok]
    for nm, ok in checks:
        print(f"  [{'OK' if ok else 'FAIL'}] {nm}")
    print(f"analytics_report selftest: {len(checks) - len(failed)}/{len(checks)} passed")
    import shutil
    shutil.rmtree(td, ignore_errors=True)
    return 1 if failed else 0


def main() -> None:
    if "--selftest" in sys.argv:
        logging.basicConfig(level=logging.WARNING)
        raise SystemExit(_selftest())
    # Timestamped so the 07:00 runs can be told apart in analytics_report.log (launchd appends).
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
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
    ap.add_argument("--send", action="store_true",
                    help="email the digest to Bennett (ANALYTICS category, "
                         "internal-only). Builds both text+HTML regardless of "
                         "--format.")
    ap.add_argument("--publish", action="store_true",
                    help="write <public_export.dir>/digest.json and PUT it to the "
                         "team page blob (public_export.digest in config.yaml). "
                         "Independent of --send.")
    args = ap.parse_args()

    def _ids(s): return {int(x) for x in s.split(",") if x.strip()}
    (focus, core, bridges, cfg_db, system_name, tzname,
     quiet_cfg, health_nodes) = _load_roles_from_config(args.config)
    if args.focus is not None:
        focus = args.focus
    if args.core is not None:
        core = _ids(args.core)
    if args.bridges is not None:
        bridges = _ids(args.bridges)
    db = args.db or cfg_db
    try:
        tz = ZoneInfo(tzname) if tzname and tzname != "UTC" else None
    except Exception:
        tz = None
    start, end = _period_bounds(args)
    r = generate_report(db, start, end, focus, core, bridges,
                        quiet_cfg=quiet_cfg, health_nodes=health_nodes)
    callsigns, owners = load_node_info(args.config)
    rendered = (render_html(r, system_name=system_name, tz=tz,
                            callsigns=callsigns, owners=owners) if args.format == "html"
                else render_text(r, system_name=system_name, tz=tz,
                                 callsigns=callsigns, owners=owners))

    period_word = "Daily" if args.period == "day" else "Weekly"
    # Subject date in local time so it matches the body / the reader's day.
    end_local = end.astimezone(tz) if tz is not None else end
    subject = (f"{system_name} AllStar Stats — {period_word} "
               f"({end_local.strftime('%Y-%m-%d')})").strip()
    text_body = rendered if args.format == "text" else render_text(
        r, system_name=system_name, tz=tz, callsigns=callsigns, owners=owners)

    # --send and --publish are independent deliveries (2026-10-20): an SMTP
    # outage must not stop the website update and vice versa. Each is
    # attempted (deliver() isolates exceptions too); the exit code is 1 if
    # either failed. An ad-hoc --start/--end range is never published: it
    # would overwrite the live daily blob with an arbitrary period.
    # One HTML render serves both the email body and the page's tables (v2.1). A render
    # failure here must not pre-empt deliver(): the email path re-renders inside it (and
    # fails there, isolated), the page falls back to text.
    def _html():
        return rendered if args.format == "html" else render_html(
            r, system_name=system_name, tz=tz, callsigns=callsigns, owners=owners)
    html_body = None
    if args.send or args.publish:
        try:
            html_body = _html()
        except Exception as e:                                   # noqa: BLE001
            logger.error("HTML render failed (%s) — email retries inside deliver(); page gets text only",
                         type(e).__name__)

    def _send():
        return send_report(subject, text_body, html_body if html_body is not None else _html(),
                           config_path=args.config)

    def _publish():
        if args.start or args.end:
            logger.error("DIGEST NOT PUBLISHED: --publish is refused with --start/--end "
                         "(an ad-hoc period must not overwrite the live daily blob)")
            return False
        doc = build_digest_doc(r, text_body, subject,
                               "daily" if args.period == "day" else "weekly",
                               tzname if tz is not None else "UTC", system_name,
                               html_body=html_body)
        return publish_digest(doc, args.config)

    ok = deliver(args.send, args.publish, _send, _publish)

    if args.out:
        with open(args.out, "w") as f:
            f.write(rendered)
        logger.info("wrote %s", args.out)
    elif not args.send and not args.publish:
        print(rendered)
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
