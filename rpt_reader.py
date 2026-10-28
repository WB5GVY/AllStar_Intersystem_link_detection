"""Read-only app_rpt link-state reader (the "SSH vantage" data source).

SSHes into a vantage node we administer (config: rpt_reader.vantage_node) and
parses `asterisk -rx "rpt xnode <node>"`. From that single command we get:

  1. The ADJACENT links (name, peer IP, reconnects, direction, uptime, state)
     — the same rows `rpt lstats` prints, so no second command is needed.
  2. The full MESH node list as app_rpt itself sees it — including nodes the
     AllStarLink stats API cannot see (unregistered nodes, EchoLink leaves
     `3NNNNNN`, named IAX2 leaf clients). This closes the stats-API blind spot.
  3. The RPT_* channel variables (RPT_NUMLINKS / RPT_LINKS / RPT_NUMALINKS...)
     as a cross-check on the parsed mesh list.

Scale note (verified against the public app_rpt 0.327 baseline, 2026-07-03):
the xnode/nodes mesh list and the RPT_LINKS/RPT_NUMLINKS variables are built
by __mklinklist() into MAXLINKLIST=5120-char buffers — they are NOT capped by
MAX_STAT_LINKS(32), which only limits the `rpt stats` display and the voter
code. Effective ceiling is ~550-700 mesh nodes (silent truncation beyond), far
above any threshold this project cares about.

READ-ONLY GUARANTEE: this module only ever executes the whitelisted commands
in _ALLOWED_RPT_COMMANDS over SSH. It never mutates node state. (The
force-disconnect path lives in auto_disconnect.py and is deliberately not
reachable from here.)

Flat-view caveat: the mesh list has no depth/topology information, so this
source complements — never replaces — the stats-API walk that depth-based
detection needs. Its jobs are (a) the link-count tripwire and (b) seeing
API-invisible leaves.

Standalone use:
    python3 rpt_reader.py --config config.yaml [--json]
    python3 rpt_reader.py --selftest
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# The ONLY commands this module may run on the node. Read-only by construction.
_ALLOWED_RPT_COMMANDS = ("rpt xnode", "rpt lstats", "rpt nodes")

# Mode prefixes app_rpt puts on mesh-list entries (Transceive / RX-only /
# Local monitor / Connecting — ASL3 rpt_link.c __mklinklist). Anything else
# is kept verbatim with mode '?'.
_MODE_CHARS = "TRLC"


@dataclass
class AdjacentLink:
    """One directly-connected peer (an lstats row)."""
    node: str                # node number, or EchoLink 3NNNNNN / IAX2 name
    peer_ip: str
    reconnects: int
    direction: str           # 'IN' | 'OUT'
    connect_time: str        # app_rpt's cumulative hh:mm:ss string, verbatim
    state: str               # 'ESTABLISHED' | 'CONNECTING'


@dataclass
class RptSnapshot:
    """Parsed result of one `rpt xnode` read."""
    vantage_node: int
    adjacent: list[AdjacentLink] = field(default_factory=list)
    mesh_nodes: list[str] = field(default_factory=list)   # mode prefix stripped
    mesh_modes: dict[str, str] = field(default_factory=dict)  # node -> T/R/C
    variables: dict[str, str] = field(default_factory=dict)   # RPT_* channel vars
    states: dict[str, str] = field(default_factory=dict)      # parrot_ena etc.
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        # The mesh list is the payload this reader exists for; a read that
        # produced errors but still yielded a mesh list is degraded-but-usable.
        return not self.errors or bool(self.mesh_nodes)

    @property
    def mesh_count(self) -> int:
        """Number of mesh nodes visible from the vantage (excludes the vantage
        node itself, matching RPT_NUMLINKS semantics)."""
        return len(self.mesh_nodes)

    @property
    def reported_numlinks(self) -> Optional[int]:
        """RPT_NUMLINKS as app_rpt last computed it (may lag the live list)."""
        v = self.variables.get("RPT_NUMLINKS")
        try:
            return int(v) if v is not None else None
        except ValueError:
            return None

    def to_dict(self) -> dict:
        return {
            "vantage_node": self.vantage_node,
            "mesh_count": self.mesh_count,
            "reported_numlinks": self.reported_numlinks,
            "mesh_nodes": self.mesh_nodes,
            "mesh_modes": self.mesh_modes,
            "adjacent": [vars(a) for a in self.adjacent],
            "variables": self.variables,
            "states": self.states,
            "errors": self.errors,
        }


def parse_xnode(text: str, vantage_node: int) -> RptSnapshot:
    """Parse `rpt xnode <node>` output into an RptSnapshot.

    Sections are identified by CONTENT, not position, because app_rpt omits
    the adjacent-links block entirely when nothing is connected (the output
    then starts with the mesh list):
      A) adjacent links  — rows terminated by '~'
      B) mesh node list  — comma-separated [TRC]-prefixed entries, or <NONE>
      C) channel vars    — NAME=value lines including RPT_*
      D) status states   — key=value lines (parrot_ena, sys_ena, ...)
    """
    snap = RptSnapshot(vantage_node=vantage_node)
    blocks = [b for b in re.split(r"\n\s*\n", text) if b.strip()]
    if not blocks:
        snap.errors.append("empty xnode output")
        return snap

    mesh_block = None
    for block in blocks:
        stripped = block.strip()
        if "~" in stripped and "=" not in stripped:
            _parse_adjacent(stripped, snap)
        elif re.search(r"^\s*\w+=", stripped, re.MULTILINE):
            # vars (C) and states (D) share NAME=value shape; split by content
            for line in stripped.splitlines():
                line = line.strip()
                if not line or "=" not in line:
                    continue
                name, _, value = line.partition("=")
                if name.startswith("RPT_"):
                    snap.variables[name] = value.strip()
                else:
                    snap.states[name] = value.strip()
        elif mesh_block is None:
            mesh_block = stripped
        else:
            snap.errors.append(f"unrecognized xnode block: {stripped[:60]!r}")

    if mesh_block is None:
        snap.errors.append("mesh node list block not found in xnode output")
        return snap

    raw_entries = 0
    if mesh_block != "<NONE>":
        for entry in mesh_block.split(","):
            entry = entry.strip()
            if not entry:
                continue
            raw_entries += 1
            if (entry[0] in _MODE_CHARS and len(entry) > 1
                    # L (local monitor) is stripped only from NUMERIC names:
                    # many callsigns begin with L (LU..., LA...), and
                    # mangling a named softclient would break roster
                    # matching. T/R/C keep today's behavior unchanged.
                    and (entry[0] != "L" or entry[1:].isdigit())):
                mode, node = entry[0], entry[1:]
            else:
                mode, node = "?", entry
            # DEDUP: __mklinklist appends each neighbor's own linklist with no
            # dedup, so a node reachable via two paths appears twice. The
            # deduped count is the meaningful metric (tripwire input).
            if node not in snap.mesh_modes:
                snap.mesh_nodes.append(node)
            snap.mesh_modes[node] = mode

    # Cross-check the raw (pre-dedup) entry count against app_rpt's own
    # counter, which is likewise built without dedup.
    rep = snap.reported_numlinks
    if rep is not None and rep != raw_entries:
        snap.errors.append(
            f"mesh list has {raw_entries} raw entries "
            f"({snap.mesh_count} unique) but RPT_NUMLINKS={rep} "
            "(vars can lag the live list; transient skew is normal)")
    return snap


def _parse_adjacent(block: str, snap: RptSnapshot) -> None:
    """Parse section A: '~'-terminated fixed-width rows, 6 fields each."""
    for row in block.replace("\n", " ").split("~"):
        fields = row.split()
        if not fields:
            continue
        if len(fields) != 6:
            snap.errors.append(f"unparseable adjacent-link row: {row.strip()!r}")
            continue
        try:
            reconnects = int(fields[2])
        except ValueError:
            snap.errors.append(f"bad reconnect count in row: {row.strip()!r}")
            continue
        snap.adjacent.append(AdjacentLink(
            node=fields[0], peer_ip=fields[1], reconnects=reconnects,
            direction=fields[3], connect_time=fields[4], state=fields[5]))


@dataclass
class RptReader:
    """Reads link state from one vantage node over SSH. Read-only."""
    node_id: int
    ssh_host: str
    ssh_user: str
    ssh_key: str
    ssh_port: int = 22
    timeout_seconds: int = 15

    def read(self, timeout_seconds: Optional[int] = None) -> RptSnapshot:
        """Run `rpt xnode` on the vantage node and parse it. Never raises for
        remote/parse trouble — failures come back in snapshot.errors.
        timeout_seconds overrides the configured timeout for this one read
        (used by the routine per-scan read, which must stay well under the
        15s top-of-hour scan cadence)."""
        raw = self._run_rpt_command(f"rpt xnode {self.node_id}",
                                    timeout_seconds=timeout_seconds)
        if raw is None:
            snap = RptSnapshot(vantage_node=self.node_id)
            snap.errors.append(
                f"SSH read from {self.ssh_host} failed (see log)")
            return snap
        return parse_xnode(raw, self.node_id)

    def _run_rpt_command(self, rpt_cmd: str,
                         timeout_seconds: Optional[int] = None) -> Optional[str]:
        """Execute one whitelisted read-only rpt CLI command; None on failure."""
        if not rpt_cmd.startswith(_ALLOWED_RPT_COMMANDS):
            # Defense in depth: this module must never grow a write path.
            raise ValueError(f"rpt command not in read-only whitelist: {rpt_cmd!r}")
        timeout = timeout_seconds or self.timeout_seconds
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "-p", str(self.ssh_port),
            "-i", str(Path(self.ssh_key).expanduser()),
            f"{self.ssh_user}@{self.ssh_host}",
            f'/usr/sbin/asterisk -rx "{rpt_cmd}"',
        ]
        try:
            result = subprocess.run(
                ssh_cmd, capture_output=True, text=True,
                timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("rpt_reader: SSH to %s timed out after %ss",
                           self.ssh_host, timeout)
            return None
        except Exception as e:
            logger.warning("rpt_reader: SSH to %s failed: %s", self.ssh_host, e)
            return None
        if result.returncode != 0:
            logger.warning("rpt_reader: SSH rc=%d stderr=%s",
                           result.returncode, result.stderr.strip()[:200])
            return None
        return result.stdout


def build_rpt_reader(config: dict) -> Optional[RptReader]:
    """Build an RptReader from config, or None if disabled/misconfigured.

    SSH credentials are RESOLVED from the matching auto_disconnect.nodes entry
    (single source of truth — no duplicated creds in config). Never raises:
    the reader is an optional data source and must not block daemon startup.
    """
    try:
        rcfg = config.get("rpt_reader") or {}
        if not isinstance(rcfg, dict) or not rcfg.get("enabled", False):
            return None
        vantage = int(rcfg.get("vantage_node", 0))
        if not vantage:
            logger.error("rpt_reader: enabled but no vantage_node configured")
            return None
        for node_cfg in (config.get("auto_disconnect", {}) or {}).get("nodes", []):
            if node_cfg.get("node_id") == vantage:
                reader = RptReader(
                    node_id=vantage,
                    ssh_host=node_cfg["ssh_host"],
                    ssh_user=node_cfg.get("ssh_user", "root"),
                    ssh_key=node_cfg.get("ssh_key", "~/.ssh/id_rsa"),
                    ssh_port=node_cfg.get("ssh_port", 22),
                    timeout_seconds=int(rcfg.get("timeout_seconds", 15)),
                )
                logger.info("RPT reader: ENABLED (vantage=%d via %s:%d)",
                            vantage, reader.ssh_host, reader.ssh_port)
                return reader
        logger.error("rpt_reader: vantage_node %d has no matching "
                     "auto_disconnect.nodes entry (need its SSH creds)", vantage)
        return None
    except Exception as e:
        logger.error("rpt_reader init failed (reader disabled this run): %s", e)
        return None


# --- selftest fixture (placeholder node numbers; structure is a verbatim ----
# --- capture of `rpt xnode` from a HamVoIP app_rpt 0.327 node) --------------
_SELFTEST_FIXTURE = """\
12345 192.0.2.57 0 IN 68:23:14 ESTABLISHED~23456 192.0.2.122 4 OUT 32:01:09 ESTABLISHED~34567 192.0.2.46 0 IN 68:31:18 ESTABLISHED~

T11111, T12345, T22222, T23456, T33333, T34567, T3123456, TAB1CDE

RPT_TXKEYED=0
RPT_NUMLINKS=8
RPT_LINKS=8,T11111,T12345,T22222,T23456,T33333,T34567,T3123456,TAB1CDE
RPT_NUMALINKS=3
RPT_ALINKS=3,12345TU,23456TU,34567TU
RPT_RXKEYED=0

parrot_ena=0
sys_ena=1
tot_ena=1
"""


def _selftest() -> int:
    snap = parse_xnode(_SELFTEST_FIXTURE, vantage_node=99999)
    checks = [
        ("mesh_count", snap.mesh_count == 8),
        ("reported_numlinks", snap.reported_numlinks == 8),
        ("no errors", not snap.errors),
        ("adjacent rows", len(snap.adjacent) == 3),
        ("adjacent parse", snap.adjacent[1].node == "23456"
         and snap.adjacent[1].direction == "OUT"
         and snap.adjacent[1].reconnects == 4),
        ("echolink leaf in mesh", "3123456" in snap.mesh_nodes),
        ("named iax2 leaf in mesh", "AB1CDE" in snap.mesh_nodes),
        ("modes", snap.mesh_modes.get("11111") == "T"),
        ("R and L prefixes stripped and kept as modes",
         parse_xnode("R22222, L33333\n\nRPT_NUMLINKS=2\n", 1).mesh_modes
         == {"22222": "R", "33333": "L"}),
        ("L not stripped from a named client (callsign starting with L)",
         parse_xnode("LU1ABC, TLA2XYZ\n\nRPT_NUMLINKS=2\n", 1).mesh_modes
         == {"LU1ABC": "?", "LA2XYZ": "T"}),
        ("states", snap.states.get("sys_ena") == "1"),
        ("empty mesh", parse_xnode("<NONE>\n\nRPT_NUMLINKS=0   \n",
                                   1).mesh_count == 0),
        ("no-adjacent output", parse_xnode(
            "\n\nT11111\n\nRPT_NUMLINKS=1\n\nparrot_ena=0\n", 1).mesh_count == 1),
        # __mklinklist appends neighbors' lists without dedup — a node seen
        # via two paths appears twice; the count must dedup it.
        ("duplicate mesh entries deduped", parse_xnode(
            "T11111, T22222, T11111\n\nRPT_NUMLINKS=3\n", 1).mesh_count == 2),
        ("raw-count crosscheck quiet on dupes", not parse_xnode(
            "T11111, T22222, T11111\n\nRPT_NUMLINKS=3\n", 1).errors),
    ]
    failed = [name for name, passed in checks if not passed]
    for name, passed in checks:
        print(f"  [{'OK' if passed else 'FAIL'}] {name}")
    if failed:
        print(f"SELFTEST FAILED: {failed}")
        return 1
    print("SELFTEST PASSED")
    return 0


def main() -> int:
    import argparse
    import json

    import yaml

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", help="config.yaml path")
    parser.add_argument("--json", action="store_true",
                        help="print the full snapshot as JSON")
    parser.add_argument("--selftest", action="store_true",
                        help="run the embedded parser selftest and exit")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.selftest:
        return _selftest()
    if not args.config:
        parser.error("--config is required unless --selftest")

    with open(Path(args.config).expanduser()) as f:
        config = yaml.safe_load(f)
    reader = build_rpt_reader(config)
    if reader is None:
        print("rpt_reader is disabled or misconfigured (see log)")
        return 1
    snap = reader.read()
    if args.json:
        print(json.dumps(snap.to_dict(), indent=2))
    else:
        print(f"vantage={snap.vantage_node} mesh_count={snap.mesh_count} "
              f"reported_numlinks={snap.reported_numlinks} "
              f"adjacent={len(snap.adjacent)}")
        for a in snap.adjacent:
            print(f"  adj {a.node:<10} {a.direction:<4} {a.state:<12} "
                  f"up {a.connect_time} via {a.peer_ip}")
        print(f"  mesh: {', '.join(snap.mesh_nodes) or '<NONE>'}")
        for err in snap.errors:
            print(f"  [warn] {err}")
    return 0 if snap.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
