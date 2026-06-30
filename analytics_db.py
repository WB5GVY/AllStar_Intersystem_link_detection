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
#   core   — always-on infrastructure (focus hub + key managed nodes)
#   bridge — recognized gateway/bridge nodes that legitimately come and go
#   guest  — everything else
ROLE_CORE = "core"
ROLE_BRIDGE = "bridge"
ROLE_GUEST = "guest"

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
    nodes_present INTEGER NOT NULL
);

-- Live present-set; lets reconcile_scan() diff against the DB (crash-safe).
CREATE TABLE IF NOT EXISTS current_presence (
    node_id     INTEGER PRIMARY KEY,
    role        TEXT    NOT NULL,
    attached_to INTEGER,
    since_ts    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nse_ts   ON node_state_events(ts);
CREATE INDEX IF NOT EXISTS idx_nse_node ON node_state_events(node_id);
CREATE INDEX IF NOT EXISTS idx_gs_node  ON guest_sessions(node_id);
CREATE INDEX IF NOT EXISTS idx_gs_open  ON guest_sessions(node_id, left_ts);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(path: str | Path) -> sqlite3.Connection:
    """Create (if needed) and open the analytics database."""
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


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
    """One node observed present in a scan (what the run_scan hook emits)."""
    node_id: int
    role: str                       # already classified via classify_role()
    attached_to: Optional[int] = None


def build_present_from_topology(topology: dict, focus_node: int,
                               core_nodes: set[int],
                               bridge_nodes: set[int]) -> list["PresentNode"]:
    """Convert a graph_analyzer ScanResult.topology dict into PresentNodes.

    `topology` is {node_id: {"depth", "parent", "role", ...}}. Every node in it
    was observed present this scan. attached_to = the immediate upstream node
    (its parent); for a guest directly on a managed node that IS the managed
    node. Kept as a plain-dict input so this module needs no graph_analyzer
    import.
    """
    present = []
    for nid, info in topology.items():
        role = classify_role(nid, focus_node, core_nodes, bridge_nodes)
        present.append(PresentNode(nid, role, attached_to=info.get("parent")))
    return present


@dataclass
class Recorder:
    """Writes observations to analytics.db. Thread-confine one Recorder per conn."""
    conn: sqlite3.Connection

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

    def heartbeat(self, ts: str, nodes_present: int) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_heartbeat (ts, nodes_present) VALUES (?, ?)",
            (ts, nodes_present),
        )

    # --- the function the future run_scan hook calls -----------------------
    def reconcile_scan(self, present: list[PresentNode],
                       ts: Optional[str] = None) -> dict[str, int]:
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
        cur = {p.node_id: p for p in present}

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

        self.heartbeat(ts, len(cur))
        self.conn.commit()
        return counts


def _delta_secs(start_iso: str, end_iso: str) -> int:
    a = datetime.fromisoformat(start_iso)
    b = datetime.fromisoformat(end_iso)
    return int((b - a).total_seconds())
