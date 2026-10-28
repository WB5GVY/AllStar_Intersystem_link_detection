"""AllStar network analytics — observation store (schema + recorder API).

See Analytics_Design_2026-06-30.md for the full design. This module is an
ISOLATED add-on: it only WRITES to its own SQLite file (`analytics.db`) and is
never imported by the detection path's hot code. The live recording hook in
`run_scan` is deferred until after the current soak commits; until then this
module is exercised only by `analytics_seed.py` (synthetic data) and unit tests.

Recording is EVENT-BASED, not snapshot-per-scan: we persist state TRANSITIONS
(a node appeared / disappeared; a guest connected to / left a managed node),
each timestamped, which is far smaller than logging every node every cycle and
yields durations directly. A `scan_heartbeat` row per scan anchors "still
present as of T" so an absence episode is bounded correctly across a daemon
restart or a monitoring gap.

Design-doc deviation: a 4th table, `current_presence`, holds the live present-set
so `reconcile_scan()` is stateless across process restarts (it diffs against the
DB, not against in-memory state). This makes reconciliation crash-safe.

All timestamps are ISO-8601 UTC strings (matching notifications.db). This module
uses `datetime.now(timezone.utc)` — never the deprecated `utcnow()`.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Role taxonomy used throughout analytics (distinct from graph_analyzer's
# focus/bridge/regular/permitted_external topology roles):
#   core     — always-on infrastructure (focus hub + key managed nodes)
#   bridge   — recognized gateway/bridge nodes that legitimately come and go
#   guest    — any other AllStar NODE (integer node id)
#   external — a non-AllStar LEAF client (IAX2 softclient: RepeaterPhone /
#              WebTransceiver / AllScan; or EchoLink). These are NOT nodes —
#              they have no node number — so they are tracked in their own
#              tables keyed by (host_node, client_type, ext_name), never in the
#              INTEGER node_id columns. classify_role() never returns this;
#              build_present_from_topology() tags them from the topology's
#              permitted_external role.
ROLE_CORE = "core"
ROLE_BRIDGE = "bridge"
ROLE_GUEST = "guest"
ROLE_EXTERNAL = "external"

SCHEMA = """
CREATE TABLE IF NOT EXISTS node_state_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL,          -- ISO-8601 UTC
    node_id      INTEGER NOT NULL,
    role         TEXT    NOT NULL,          -- 'core' | 'bridge' | 'guest'
    event        TEXT    NOT NULL,          -- 'appeared' | 'disappeared'
    attached_to  INTEGER,                   -- managed node a guest was seen on
    note         TEXT
);

CREATE TABLE IF NOT EXISTS guest_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id      INTEGER NOT NULL,
    attached_to  INTEGER NOT NULL,          -- which managed node it visited
    connected_ts TEXT    NOT NULL,
    left_ts      TEXT,                       -- NULL = still connected
    dwell_secs   INTEGER                     -- filled when the session closes
);

CREATE TABLE IF NOT EXISTS scan_heartbeat (
    ts            TEXT    PRIMARY KEY,       -- ISO-8601 UTC of the scan
    nodes_present INTEGER NOT NULL,
    mesh_count    INTEGER                    -- app_rpt mesh size seen from the
                                             -- SSH vantage node (rpt_reader);
                                             -- NULL = reader off/failed
);

-- Live present-set; lets reconcile_scan() diff against the DB (crash-safe).
CREATE TABLE IF NOT EXISTS current_presence (
    node_id     INTEGER PRIMARY KEY,
    role        TEXT    NOT NULL,
    attached_to INTEGER,
    since_ts    TEXT    NOT NULL
);

-- External (non-AllStar) leaf clients: IAX2 softclients (RepeaterPhone /
-- WebTransceiver / AllScan) and EchoLink endpoints. They have no node number,
-- so they live here keyed by (host_node, client_type, ext_name) rather than in
-- the INTEGER node_id tables above. Mirrors guest_sessions semantically.
CREATE TABLE IF NOT EXISTS external_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_node    INTEGER NOT NULL,          -- AllStar node the client is attached to
    client_type  TEXT    NOT NULL,          -- 'echolink' | 'webtransceiver_type'
    ext_name     TEXT    NOT NULL,          -- 'EchoLink-NNNNNN' | callsign / peer label
    connected_ts TEXT    NOT NULL,
    left_ts      TEXT,                       -- NULL = still connected
    dwell_secs   INTEGER
);

-- Live present-set for externals (crash-safe diff, like current_presence).
CREATE TABLE IF NOT EXISTS current_external_presence (
    host_node    INTEGER NOT NULL,
    client_type  TEXT    NOT NULL,
    ext_name     TEXT    NOT NULL,
    since_ts     TEXT    NOT NULL,
    PRIMARY KEY (host_node, client_type, ext_name)
);

-- Bridging violations, one row per (scan, event) — recorded for EVERY
-- detection, independent of whether an email went out (notifications.db only
-- sees attempts that passed can_notify). The digest aggregates rows into
-- episodes (2026-07-02 decision: violations appear in the analytics digest).
CREATE TABLE IF NOT EXISTS violation_events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 TEXT    NOT NULL,   -- scan timestamp (ISO-8601 UTC)
    offending_node     INTEGER NOT NULL,
    offending_callsign TEXT,
    path               TEXT                -- human-readable path description
);

-- Nodes that were linked to us but did not report their links, one row per
-- (scan, node): kind 'dark' = online (in DNS) but posting nothing to stats;
-- kind 'linkless' = posting a fresh record that names no links while the
-- attach node still lists it (attach-side link stuck, no audio path).
-- Recorded for EVERY scan the condition holds; the digest clusters rows into
-- episodes with a scan count (change 2, 2026-09-08 — Bennett's 09-07 ask).
CREATE TABLE IF NOT EXISTS link_report_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               TEXT    NOT NULL,   -- scan timestamp: the scanner's
                                         -- "YYYY-MM-DDTHH:MM:SSZ" form ONLY
                                         -- (ORDER BY ts is lexical; mixing
                                         -- "+00:00" forms breaks sub-second order)
    node_id          INTEGER NOT NULL,
    kind             TEXT    NOT NULL,   -- 'dark' | 'linkless' | 'unconfirmed' (2026-10-12)
    attached_to      INTEGER,            -- hub / bridge that listed the node
    attachment       TEXT,               -- 'hub' | 'bridge'
    callsign         TEXT,
    post_age_seconds INTEGER             -- linkless/unconfirmed: age of the post
);

-- Three-state node health (2026-10-18, node_health.py): per monitored node
-- the three facts registered / posting / letter (what its expected parent
-- reports: T R L C '-' '?' 'self'), TRANSITIONS only, plus one BASELINE row
-- per field (old NULL, baseline 1) the first time the daemon observes the
-- node after a (re)start, so a report window reconstructs the state at any
-- instant from the rows alone. `new` is TEXT: registered/posting '1' '0'
-- '?' (unknown this scan); letter as above. `detail` is small JSON (parent,
-- ages, DNS). 90-day purge keeps the newest row per (node, field).
CREATE TABLE IF NOT EXISTS node_health_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL,   -- scanner "YYYY-MM-DDTHH:MM:SSZ" form ONLY
    node_id   INTEGER NOT NULL,
    field     TEXT    NOT NULL,   -- 'registered' | 'posting' | 'letter'
    old       TEXT,               -- NULL on a baseline row
    new       TEXT    NOT NULL,
    baseline  INTEGER NOT NULL DEFAULT 0,
    detail    TEXT
);

-- Live debounced state (crash-safe seed for the tracker after a restart).
CREATE TABLE IF NOT EXISTS current_node_health (
    node_id          INTEGER PRIMARY KEY,
    parent           TEXT,       -- node number as text, or 'self'
    registered       TEXT,
    posting          TEXT,
    letter           TEXT,
    since_registered TEXT,
    since_posting    TEXT,
    since_letter     TEXT,
    updated          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nhe_node_field_ts ON node_health_events(node_id, field, ts);
CREATE INDEX IF NOT EXISTS idx_nhe_ts ON node_health_events(ts);
CREATE INDEX IF NOT EXISTS idx_lre_ts  ON link_report_events(ts);
CREATE INDEX IF NOT EXISTS idx_lre_node ON link_report_events(node_id, ts);
CREATE INDEX IF NOT EXISTS idx_ve_ts   ON violation_events(ts);
CREATE INDEX IF NOT EXISTS idx_nse_ts   ON node_state_events(ts);
CREATE INDEX IF NOT EXISTS idx_nse_node ON node_state_events(node_id);
CREATE INDEX IF NOT EXISTS idx_gs_node  ON guest_sessions(node_id);
CREATE INDEX IF NOT EXISTS idx_gs_open  ON guest_sessions(node_id, left_ts);
CREATE INDEX IF NOT EXISTS idx_es_open  ON external_sessions(host_node, client_type, ext_name, left_ts);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(path: str | Path) -> sqlite3.Connection:
    """Create (if needed) and open the analytics database."""
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL;")
    # Don't fail instantly with SQLITE_BUSY if another process briefly holds
    # the write lock (e.g. the reporter) while we ALTER/insert.
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.executescript(SCHEMA)
    # Migration (2026-07-03): per-scan app_rpt mesh link count from the SSH
    # vantage reader (rpt_reader.py). NULL when the reader is disabled or the
    # read failed that scan. CREATE TABLE IF NOT EXISTS won't add columns to
    # a pre-existing table, so ALTER in place for DBs created before this.
    cols = {row[1] for row in conn.execute("PRAGMA table_info(scan_heartbeat)")}
    if "mesh_count" not in cols:
        conn.execute("ALTER TABLE scan_heartbeat ADD COLUMN mesh_count INTEGER")
    conn.commit()
    purge_link_reports(conn)
    purge_node_health(conn)
    return conn


# link_report_events is the schema's only per-scan-per-node table (~1,650
# rows/day per persistently non-reporting node at the 15 s top-of-hour burst
# + 300 s cadence); everything else is transition-based. Keep 90 days — the
# digest looks back a week at most (audit 2026-09-08 S2).
LINK_REPORT_RETENTION_DAYS = 90


def purge_link_reports(conn: sqlite3.Connection,
                       now: Optional[datetime] = None) -> int:
    """Delete link_report_events rows older than LINK_REPORT_RETENTION_DAYS.
    Fail-safe (logs, never raises); returns the rows deleted. Runs at
    init_db and once a day from the recorder."""
    try:
        from datetime import timedelta
        cutoff = ((now or datetime.now(timezone.utc)) -
                  timedelta(days=LINK_REPORT_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cur = conn.execute("DELETE FROM link_report_events WHERE ts < ?", (cutoff,))
        conn.commit()
        n = cur.rowcount if cur.rowcount is not None else 0
        if n > 0:
            logger.info("analytics: purged %d link_report_events rows older than %d days",
                        n, LINK_REPORT_RETENTION_DAYS)
        return n
    except Exception as e:
        logger.warning("analytics: link_report_events purge failed (non-fatal): %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
        return 0


NODE_HEALTH_RETENTION_DAYS = 90


def purge_node_health(conn: sqlite3.Connection,
                      now: Optional[datetime] = None) -> int:
    """Delete node_health_events rows older than NODE_HEALTH_RETENTION_DAYS,
    but ALWAYS keep the newest row per (node, field): a state that has not
    changed for months must still be reconstructible at a window start.
    Fail-safe (logs, never raises); returns the rows deleted."""
    try:
        from datetime import timedelta
        cutoff = ((now or datetime.now(timezone.utc)) -
                  timedelta(days=NODE_HEALTH_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Keep the newest row OLDER than the cutoff per (node, field) too: it
        # is the anchor a report window reconstructs the state from when the
        # state has not changed since (audit S3 — a restart baseline written
        # just before the purge must not strand the window start).
        cur = conn.execute(
            "DELETE FROM node_health_events WHERE ts < ? AND id NOT IN "
            "(SELECT MAX(id) FROM node_health_events WHERE ts < ? GROUP BY node_id, field)",
            (cutoff, cutoff))
        conn.commit()
        n = cur.rowcount if cur.rowcount is not None else 0
        if n > 0:
            logger.info("analytics: purged %d node_health_events rows older than %d days",
                        n, NODE_HEALTH_RETENTION_DAYS)
        return n
    except Exception as e:
        logger.warning("analytics: node_health_events purge failed (non-fatal): %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
        return 0


def classify_role(node_id: int, focus_node: int,
                  core_nodes: set[int], bridge_nodes: set[int]) -> str:
    """Map a node to the analytics role taxonomy.

    The focus hub and any explicitly-listed core infrastructure are 'core';
    recognized gateway/bridge nodes are 'bridge'; everything else is 'guest'.
    """
    if node_id == focus_node or node_id in core_nodes:
        return ROLE_CORE
    if node_id in bridge_nodes:
        return ROLE_BRIDGE
    return ROLE_GUEST


@dataclass
class PresentNode:
    """One entity observed present in a scan (what the run_scan hook emits).

    For an AllStar node, `node_id` is the integer node number and `is_external`
    is False. For a non-AllStar leaf client (IAX2 softclient / EchoLink),
    `is_external` is True, `node_id` carries the topology's opaque string key
    (used only for dedup within a scan — NEVER written to an INTEGER column),
    `attached_to` is the host node, and client_type/ext_name identify it. The
    recorder routes externals to external_sessions, keeping them out of the
    integer node_id tables (which would otherwise raise 'datatype mismatch')."""
    node_id: object                 # int for nodes; str topology-key for externals
    role: str                       # classify_role() result, or ROLE_EXTERNAL
    attached_to: Optional[int] = None
    is_external: bool = False
    client_type: Optional[str] = None
    ext_name: Optional[str] = None


def build_present_from_topology(topology: dict, focus_node: int,
                               core_nodes: set[int],
                               bridge_nodes: set[int]) -> list["PresentNode"]:
    """Convert a graph_analyzer ScanResult.topology dict into PresentNodes.

    `topology` is {key: {"depth", "parent", "role", ...}}. Every entry was
    observed present this scan. For AllStar nodes the key is the integer node
    id and attached_to = its immediate upstream node (parent). External leaf
    clients (RepeaterPhone / WebTransceiver / EchoLink) are added by
    graph_analyzer with role 'permitted_external' and a STRING key (e.g.
    'ext_<node>_EchoLink-NNNNNN' or 'ext_<callsign>'); we tag those as external
    and carry host_node (parent) + client_type + ext_name so the recorder can file
    them in external_sessions instead of the integer node tables. A non-integer
    key is also treated as external defensively, so a string id can never reach
    an INTEGER column. Kept as a plain-dict input so this module needs no
    graph_analyzer import.
    """
    present = []
    for nid, info in topology.items():
        if info.get("role") == "permitted_external" or not isinstance(nid, int):
            present.append(PresentNode(
                node_id=nid,
                role=ROLE_EXTERNAL,
                attached_to=info.get("parent"),
                is_external=True,
                client_type=info.get("client_type", "webtransceiver_type"),
                ext_name=str(info.get("callsign")
                             or info.get("external_name") or nid),
            ))
            continue
        role = classify_role(nid, focus_node, core_nodes, bridge_nodes)
        present.append(PresentNode(nid, role, attached_to=info.get("parent")))
    return present


def _clean_text(value, max_len: int) -> Optional[str]:
    """Registry-sourced free text for storage: control characters stripped
    (the plain-text digest prints it raw — no line injection), truncated.
    None for empty (audit 2026-09-08 A2)."""
    if value is None:
        return None
    s = "".join(ch for ch in str(value) if ch.isprintable())
    s = s.strip()[:max_len]
    return s or None


@dataclass
class Recorder:
    """Writes observations to analytics.db. Thread-confine one Recorder per conn."""
    conn: sqlite3.Connection
    _last_purge: Optional[datetime] = None

    # --- low-level writers -------------------------------------------------
    def _event(self, ts: str, node_id: int, role: str, event: str,
               attached_to: Optional[int] = None, note: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT INTO node_state_events (ts, node_id, role, event, attached_to, note) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, node_id, role, event, attached_to, note),
        )

    def _open_guest_session(self, node_id: int, attached_to: int, ts: str) -> None:
        self.conn.execute(
            "INSERT INTO guest_sessions (node_id, attached_to, connected_ts) "
            "VALUES (?, ?, ?)",
            (node_id, attached_to, ts),
        )

    def _close_guest_session(self, node_id: int, ts: str) -> None:
        """Close the most recent open session for node_id (if any)."""
        row = self.conn.execute(
            "SELECT id, connected_ts FROM guest_sessions "
            "WHERE node_id = ? AND left_ts IS NULL ORDER BY id DESC LIMIT 1",
            (node_id,),
        ).fetchone()
        if row is None:
            return
        sess_id, connected_ts = row
        dwell = _delta_secs(connected_ts, ts)
        self.conn.execute(
            "UPDATE guest_sessions SET left_ts = ?, dwell_secs = ? WHERE id = ?",
            (ts, dwell, sess_id),
        )

    def record_violations(self, events: list, ts: str) -> None:
        """Persist this scan's bridging events (duck-typed BridgingEvent:
        offending_node / offending_callsign / path_description). One row per
        event per scan; the reporter aggregates rows into episodes. Commits
        itself. Caller wraps in try (fail-safe like all analytics writes)."""
        try:
            for ev in events:
                self.conn.execute(
                    "INSERT INTO violation_events "
                    "(ts, offending_node, offending_callsign, path) "
                    "VALUES (?, ?, ?, ?)",
                    (ts, int(ev.offending_node),
                     str(getattr(ev, "offending_callsign", "") or ""),
                     str(getattr(ev, "path_description", "") or "")),
                )
            if events:
                self.conn.commit()
        except Exception:
            # Same rollback discipline as record_link_reports (audit 2026-09-08
            # S1 noted this writer had the identical hole).
            try:
                self.conn.rollback()
            except Exception:
                pass
            raise

    def record_link_reports(self, dark_guests: list, linkless: list, ts: str,
                            unconfirmed: Optional[list] = None) -> int:
        """Persist this scan's non-reporting nodes (change 2, 2026-09-08):
        `dark_guests` and `linkless` are the analyzer's ScanResult lists of
        dicts ({node, attached_to, attachment, callsign[, post_age_seconds]}).
        Coherence (2026-10-12): `unconfirmed` rows (kind 'unconfirmed') are
        guests seen on a pre-join record — same columns, post age kept.
        One row per node per scan; the reporter clusters rows into episodes.
        Commits itself; returns the row count. Caller wraps in try (fail-safe
        like all analytics writes). Malformed entries are skipped, never
        raised — one bad dict must not drop the rest."""
        n = 0
        try:
            for kind, entries in (("dark", dark_guests), ("linkless", linkless),
                                  ("unconfirmed", unconfirmed)):
                for g in (entries or []):
                    try:
                        node = int(g["node"])
                    except (KeyError, TypeError, ValueError, AttributeError):
                        continue
                    att = g.get("attached_to")
                    try:
                        att = int(att) if att is not None else None
                    except (TypeError, ValueError):
                        att = None
                    age = (g.get("post_age_seconds")
                           if kind in ("linkless", "unconfirmed") else None)
                    try:
                        age = int(round(float(age))) if age is not None else None
                    except (TypeError, ValueError):
                        age = None
                    self.conn.execute(
                        "INSERT INTO link_report_events "
                        "(ts, node_id, kind, attached_to, attachment, callsign, post_age_seconds) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (ts, node, kind, att,
                         _clean_text(g.get("attachment"), 16),
                         _clean_text(g.get("callsign"), 20), age),
                    )
                    n += 1
            if n:
                self.conn.commit()
        except Exception:
            # Never leave a write transaction open for the next scan to
            # inherit (audit 2026-09-08 S1): roll back this call's rows.
            try:
                self.conn.rollback()
            except Exception:
                pass
            raise
        # Retention: once a day (audit S2). Cheap; fail-safe inside.
        now = datetime.now(timezone.utc)
        if (self._last_purge is None
                or (now - self._last_purge).total_seconds() >= 86400):
            self._last_purge = now
            purge_link_reports(self.conn, now)
        return n

    # --- three-state node health (2026-10-18) ------------------------------
    _last_nh_purge: Optional[datetime] = None

    def record_node_health(self, rows: list, current: list) -> int:
        """Persist node-health transition/baseline rows and upsert the live
        state of the nodes they belong to. `rows`: (ts, node_id, field, old,
        new, baseline, detail_dict); `current`: dicts shaped like
        node_health.NodeHealthTracker._current_row(). Commits itself; rolls
        back this call's writes on any error and re-raises (the caller is
        fail-safe). Returns the rows written."""
        import json
        n = 0
        try:
            for (ts, node, field, old, new, baseline, detail) in rows:
                try:
                    det = (json.dumps(detail, separators=(",", ":"), default=str)
                           if detail else None)
                    if det is not None and len(det) > 1000:
                        # Never slice JSON (audit A3): keep the one key that matters.
                        det = json.dumps({"parent": (detail or {}).get("parent"),
                                          "truncated": True}, default=str)
                except Exception:
                    det = None
                self.conn.execute(
                    "INSERT INTO node_health_events "
                    "(ts, node_id, field, old, new, baseline, detail) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (ts, int(node), str(field),
                     None if old is None else str(old), str(new),
                     1 if baseline else 0, det))
                n += 1
            for c in current:
                self.conn.execute(
                    "INSERT OR REPLACE INTO current_node_health "
                    "(node_id, parent, registered, posting, letter, since_registered, "
                    "since_posting, since_letter, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (int(c["node_id"]), c.get("parent"), c.get("registered"),
                     c.get("posting"), c.get("letter"), c.get("since_registered"),
                     c.get("since_posting"), c.get("since_letter"), c["updated"]))
            self.conn.commit()
        except Exception:
            try:
                self.conn.rollback()
            except Exception:
                pass
            raise
        now = datetime.now(timezone.utc)
        if (self._last_nh_purge is None
                or (now - self._last_nh_purge).total_seconds() >= 86400):
            self._last_nh_purge = now
            purge_node_health(self.conn, now)
        return n

    def retire_node_health(self, node_ids: list, ts: str) -> int:
        """A node no longer in the node_health config (audit S4): close each
        recorded fact with a transition to '?' and drop its live row, so the
        digest stops carrying its last state forward. Commits; rolls back and
        re-raises on error. Returns the rows written."""
        n = 0
        try:
            for nid in node_ids:
                row = self.conn.execute(
                    "SELECT parent, registered, posting, letter FROM current_node_health "
                    "WHERE node_id = ?", (int(nid),)).fetchone()
                if row is None:
                    continue
                parent, cur = row[0], {"registered": row[1], "posting": row[2], "letter": row[3]}
                for fld in ("registered", "posting", "letter"):
                    if cur[fld] is None or cur[fld] == "?":
                        continue
                    self.conn.execute(
                        "INSERT INTO node_health_events "
                        "(ts, node_id, field, old, new, baseline, detail) VALUES (?, ?, ?, ?, ?, 0, ?)",
                        (ts, int(nid), fld, cur[fld], "?",
                         '{"parent":%s,"reason":"removed from node_health config"}'
                         % (parent if str(parent).isdigit() else '"%s"' % parent)))
                    n += 1
                self.conn.execute("DELETE FROM current_node_health WHERE node_id = ?", (int(nid),))
            self.conn.commit()
        except Exception:
            try:
                self.conn.rollback()
            except Exception:
                pass
            raise
        return n

    def load_current_node_health(self) -> list[dict]:
        """Live debounced state per node (seed after a restart). Empty list
        for a DB created before the table existed."""
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='current_node_health'").fetchone()
        if row is None:
            return []
        cols = ("node_id", "parent", "registered", "posting", "letter",
                "since_registered", "since_posting", "since_letter", "updated")
        rows = self.conn.execute(
            "SELECT " + ", ".join(cols) + " FROM current_node_health").fetchall()
        return [dict(zip(cols, r)) for r in rows]

    def heartbeat(self, ts: str, nodes_present: int,
                  mesh_count: Optional[int] = None) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_heartbeat "
            "(ts, nodes_present, mesh_count) VALUES (?, ?, ?)",
            (ts, nodes_present, mesh_count),
        )

    def _close_external_session(self, host_node: int, client_type: str,
                                ext_name: str, ts: str) -> None:
        """Close the most recent open external session for this client."""
        row = self.conn.execute(
            "SELECT id, connected_ts FROM external_sessions "
            "WHERE host_node = ? AND client_type = ? AND ext_name = ? "
            "AND left_ts IS NULL ORDER BY id DESC LIMIT 1",
            (host_node, client_type, ext_name),
        ).fetchone()
        if row is None:
            return
        sess_id, connected_ts = row
        dwell = _delta_secs(connected_ts, ts)
        self.conn.execute(
            "UPDATE external_sessions SET left_ts = ?, dwell_secs = ? WHERE id = ?",
            (ts, dwell, sess_id),
        )

    def _reconcile_externals(self, externals: list["PresentNode"], ts: str) -> dict[str, int]:
        """Diff the external leaf-client present-set against the DB. Keyed by
        (host_node, client_type, ext_name); a client moving to a different host
        naturally reads as one disappearing and another appearing (the host is
        part of the key). Externals never touch the integer node_id tables."""
        cur = {(e.attached_to, e.client_type, e.ext_name): e
               for e in externals if e.attached_to is not None}
        prev_rows = self.conn.execute(
            "SELECT host_node, client_type, ext_name FROM current_external_presence"
        ).fetchall()
        prev = {(r[0], r[1], r[2]) for r in prev_rows}
        counts = {"ext_appeared": 0, "ext_disappeared": 0}

        for key in cur:
            if key not in prev:
                host, ct, name = key
                self.conn.execute(
                    "INSERT INTO external_sessions "
                    "(host_node, client_type, ext_name, connected_ts) VALUES (?, ?, ?, ?)",
                    (host, ct, name, ts),
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO current_external_presence "
                    "(host_node, client_type, ext_name, since_ts) VALUES (?, ?, ?, ?)",
                    (host, ct, name, ts),
                )
                counts["ext_appeared"] += 1

        for key in prev:
            if key not in cur:
                host, ct, name = key
                self._close_external_session(host, ct, name, ts)
                self.conn.execute(
                    "DELETE FROM current_external_presence "
                    "WHERE host_node = ? AND client_type = ? AND ext_name = ?",
                    (host, ct, name),
                )
                counts["ext_disappeared"] += 1
        return counts

    # --- the function the run_scan hook calls -------------------------------
    def reconcile_scan(self, present: list[PresentNode],
                       ts: Optional[str] = None,
                       mesh_count: Optional[int] = None) -> dict[str, int]:
        """Diff this scan's present-set against the DB and emit transitions.

        Returns a small counter dict for logging. Commits once at the end.
        """
        ts = ts or _now_iso()
        # Discard any uncommitted state left by a previously-FAILED reconcile, so
        # we never read or re-commit partial writes. Each successful call commits
        # at the end, so between calls there is normally nothing to roll back;
        # this only clears the wreckage of a mid-call exception (audit 2026-06-30).
        try:
            self.conn.rollback()
        except Exception:
            pass

        # Split AllStar nodes (integer ids) from external leaf clients. The node
        # logic below only ever sees integer node_ids, so a string external id
        # can never reach an INTEGER column (the 2026-06-30 'datatype mismatch'
        # that silently blanked a whole scan whenever an IAX2/EchoLink client
        # was connected). Externals are reconciled separately into their own
        # tables.
        nodes = [p for p in present if not p.is_external]
        externals = [p for p in present if p.is_external]
        cur = {p.node_id: p for p in nodes}

        prev_rows = self.conn.execute(
            "SELECT node_id, role, attached_to, since_ts FROM current_presence"
        ).fetchall()
        prev = {r[0]: {"role": r[1], "attached_to": r[2], "since_ts": r[3]}
                for r in prev_rows}

        counts = {"appeared": 0, "disappeared": 0, "moved": 0}

        # Appeared
        for nid, p in cur.items():
            if nid not in prev:
                self._event(ts, nid, p.role, "appeared", p.attached_to)
                self.conn.execute(
                    "INSERT OR REPLACE INTO current_presence "
                    "(node_id, role, attached_to, since_ts) VALUES (?, ?, ?, ?)",
                    (nid, p.role, p.attached_to, ts),
                )
                if p.role == ROLE_GUEST and p.attached_to is not None:
                    self._open_guest_session(nid, p.attached_to, ts)
                counts["appeared"] += 1

        # Disappeared
        for nid, info in prev.items():
            if nid not in cur:
                self._event(ts, nid, info["role"], "disappeared", info["attached_to"])
                if info["role"] == ROLE_GUEST:
                    self._close_guest_session(nid, ts)
                self.conn.execute("DELETE FROM current_presence WHERE node_id = ?", (nid,))
                counts["disappeared"] += 1

        # Still-present but attachment/role changed (e.g., guest moved managed node)
        for nid, p in cur.items():
            if nid in prev:
                old = prev[nid]
                if old["attached_to"] != p.attached_to or old["role"] != p.role:
                    # Treat a guest moving to a different managed node as a new visit.
                    if old["role"] == ROLE_GUEST:
                        self._close_guest_session(nid, ts)
                    self._event(ts, nid, p.role, "disappeared", old["attached_to"],
                                note="role/attachment change")
                    self._event(ts, nid, p.role, "appeared", p.attached_to,
                                note="role/attachment change")
                    if p.role == ROLE_GUEST and p.attached_to is not None:
                        self._open_guest_session(nid, p.attached_to, ts)
                    self.conn.execute(
                        "UPDATE current_presence SET role = ?, attached_to = ?, since_ts = ? "
                        "WHERE node_id = ?", (p.role, p.attached_to, ts, nid))
                    counts["moved"] += 1

        # Commit node transitions + heartbeat FIRST, so an external-client
        # reconcile failure can NEVER roll them back. Externals are a
        # non-critical add-on: writing them in their own transaction means a
        # throw there is logged and isolated, never re-introducing the
        # silent-blanking of node/heartbeat data that this whole change exists
        # to fix (audit 2026-06-30, Significant-1).
        self.heartbeat(ts, len(cur) + len(externals), mesh_count)
        self.conn.commit()
        try:
            counts.update(self._reconcile_externals(externals, ts))
            self.conn.commit()
        except Exception as e:
            logger.error("External-client reconcile failed (non-fatal; node "
                         "transitions + heartbeat already committed): %s", e)
            try:
                self.conn.rollback()
            except Exception:
                pass
        return counts


def _delta_secs(start_iso: str, end_iso: str) -> int:
    # Tolerate the trailing 'Z' the scanner emits (graph_analyzer uses
    # "...%SZ"); datetime.fromisoformat only accepts 'Z' on Python 3.11+, and
    # this path runs on every session close, so normalize for the 3.10 floor.
    a = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
    b = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    return int((b - a).total_seconds())


# Time-gap that separates violation_events rows into distinct offense
# episodes. MUST match analytics_report.EPISODE_GAP_S so both views cluster
# rows by the same rule. (The absolute counts still legitimately differ:
# the email counts all-time priors minus the ongoing episode; the digest
# counts episodes inside its reporting window.)
EPISODE_GAP_S = 900


def prior_offense_episodes(db_path: str | Path, node: int,
                           before_ts: str,
                           gap_s: int = EPISODE_GAP_S) -> list[dict]:
    """Recorded offense episodes by `node` strictly BEFORE the event at
    `before_ts` (ISO-8601 UTC, 'Z' tolerated), for the violation email's
    repeat-offender annotation (Bennett, 2026-07-17).

    Opens its OWN read-only connection (URI mode=ro) so it is safe to call
    from any thread and can never write or lock out the recorder. Rows are
    clustered into episodes by `gap_s` (same rule as the digest); a trailing
    cluster whose last row is within `gap_s` of `before_ts` is the CURRENT
    episode's earlier scans and is dropped, so the caller can phrase the
    result as "prior episodes". Callsign per episode is the latest non-empty,
    non-'Unknown' value seen (same S1 lesson as the reporter).

    Returns oldest-first: [{"first": datetime, "last": datetime,
    "callsign": str, "scans": int}, ...]. Raises on unexpected errors —
    callers must treat this as fail-safe optional data. A missing DB file or
    table returns [] (fresh deployments)."""
    p = Path(db_path)
    if not p.is_file():
        return []
    cutoff = datetime.fromisoformat(before_ts.replace("Z", "+00:00"))
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='violation_events'").fetchone()
        if row is None:
            return []
        rows = conn.execute(
            "SELECT ts, offending_callsign FROM violation_events "
            "WHERE offending_node = ? AND ts < ? ORDER BY ts",
            (int(node), before_ts),
        ).fetchall()
    finally:
        conn.close()

    episodes: list[dict] = []
    for ts_s, callsign in rows:
        t = datetime.fromisoformat(ts_s.replace("Z", "+00:00"))
        if t >= cutoff:            # belt-and-braces vs. string-compare edge
            continue
        ep = episodes[-1] if episodes else None
        if ep is None or (t - ep["last"]).total_seconds() > gap_s:
            ep = {"first": t, "last": t, "callsign": "", "scans": 0}
            episodes.append(ep)
        ep["last"] = t
        ep["scans"] += 1
        cs = (callsign or "").strip()
        if cs and cs != "Unknown":
            ep["callsign"] = cs
    # Drop the current episode's own earlier scans (violation persisting
    # across scans inserts one row per scan before the email goes out).
    if episodes and (cutoff - episodes[-1]["last"]).total_seconds() <= gap_s:
        episodes.pop()
    return episodes
