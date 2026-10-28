"""Local bubble-map generator — Graphviz rendering of our own scan data.

Replaces the dependency on AllStarLink's rendered bubble JPG for display
purposes (the HA dashboard tab) with a locally-rendered map built from data
the detector already holds:

  - Edges/depths/roles from the scan's topology walk (exact, per-scan)
  - API-invisible leaves from the SSH vantage reader (unregistered nodes,
    EchoLink endpoints, named IAX2 clients) — drawn dotted, attached to the
    vantage node (their true attachment point is not knowable from the flat
    mesh list)
  - Callsign + location + frequency + CTCSS tone + lat/lon per node
    (already in the topology, from the stats API — superset of the official
    map's bubble content as of 2026-07-04)
  - Optional operator names from QRZ.com (cached on disk with a TTL and a
    per-scan lookup budget so the map can never hammer QRZ)
  - A disk-backed per-node info cache (NodeInfoCache) so nodes that drop out
    of API visibility (or appear only in the vantage mesh) still label richly
    from their last-seen registry data

Styling encodes what the official map cannot: role coloring (focus / core
spokes vs designated bridges vs guests), UNAUTHORIZED nodes in red, external
leaf clients as dashed gray ellipses, vantage-only nodes dotted. A color
legend is drawn on the image itself (HTML-like graph label).

The renderer is pure presentation: it never affects detection, is wrapped
fail-safe by the caller, and writes its PNG atomically (render to tmp,
os.replace) so the HTTP endpoint can never serve a half-written file.
Rendering uses the Graphviz CLI (`twopi`/`dot`) via subprocess — no Python
graphviz dependency.

Two render paths (2026-07-04):
  - render(): once per scan, main-loop thread. Updates the caches and stashes
    a deep-copied topology for the refresh path.
  - request_refresh(): called from the link-watch thread when the vantage
    mesh set changes (AMI push latency). Re-renders the LAST scan's topology
    with the CURRENT vantage overlay on a short-lived daemon thread —
    debounced, single-flight, QRZ cache-read-only (the QRZ client shares the
    notifier's requests.Session, which is not thread-safe). Arrivals appear
    dotted within seconds; departures persist until the next scan (the flat
    mesh list is numeric-only, so pruning against it would falsely drop
    externals) — the caption discloses this.
"""

from __future__ import annotations

import copy
import html
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

# Custom ASL-style layout engine (2026-07-18). A missing/broken module must
# never take the daemon down — the vpsc path below works without it.
try:
    import asl_placer
except Exception as _e:                      # pragma: no cover - defensive
    asl_placer = None
    _ASL_IMPORT_ERROR = _e
else:
    _ASL_IMPORT_ERROR = None

logger = logging.getLogger(__name__)

_DEFAULT_RENDER_TIMEOUT_S = 30
_DEFAULT_REFRESH_MIN_INTERVAL_S = 10
_QRZ_CACHE_TTL_S = 30 * 86400        # operator names change rarely
_DEFAULT_NODE_INFO_TTL_S = 30 * 86400

# role -> (fillcolor, shape, extra attrs). Anything unknown gets the default.
# Ellipses throughout (2026-07-04): shape=circle forces width == height, which
# was the dominant whitespace cost vs. the official map's compact ellipses.
_ROLE_STYLE = {
    "focus":              ("#bbdefb", "ellipse", "peripheries=2"),
    "bridge":             ("#ffe082", "ellipse", ""),
    "regular":            ("#c8e6c9", "ellipse", ""),
    "guest":              ("#ffffff", "ellipse", ""),
    "unauthorized":       ("#ef9a9a", "ellipse", "penwidth=3, color=\"#b00020\""),
    "dragged_in":         ("#ffcdd2", "ellipse", "style=\"filled,dashed\""),
    "permitted_external": ("#eeeeee", "ellipse", "style=\"filled,dashed\""),
    # Phase 2: outside node a permitted listener guest monitors (one-way
    # audio INTO the guest, nothing crosses into the system).
    "monitored_by_guest": ("#ede7f6", "ellipse", "style=\"filled,dashed\""),
}
_DEFAULT_STYLE = ("#e0e0e0", "ellipse", "")

# Legend swatches: (fillcolor, text). Order is display order.
_LEGEND = [
    ("#bbdefb", "focus"),
    ("#c8e6c9", "core"),
    ("#ffe082", "bridge"),
    ("#ffffff", "guest"),
    ("#ef9a9a", "UNAUTHORIZED"),
    ("#ffcdd2", "dragged-in"),
    ("#eeeeee", "external leaf (dashed)"),
    ("#fafafa", "vantage-reported (listed)"),
    ("#e1bee7", "monitor: dashed, open arrow → listener (double = transceive/unreported)"),
]
# Phase 2 swatch, shown only when the map actually contains such a node so
# the legend is unchanged while listeners are not permitted.
_LEGEND_MONITORED = ("#ede7f6", "monitored by guest (one-way, into guest)")

# Edge colors. Violation red must win over everything else on an edge.
_EDGE_VIOLATION = "#b00020"
_EDGE_MONITOR = "#6a1b9a"
_EDGE_EXTERNAL = "#9e9e9e"

_LISTEN_MODES = ("R", "L")   # receive-only / local monitor: this end listens


def _monitor_listener(info: dict) -> Optional[str]:
    """Which end of a child->parent link is listen-only, from the link-mode
    letters graph_analyzer stamps on the child entry (each node's OWN report
    to AllStarLink stats). "child" / "parent" / "both" / None. A T on one
    side never overrides an R on the other: app_rpt records every incoming
    link as transceive, so only the node that dialed *2 ever reports R."""
    child = info.get("link_mode_to_parent") in _LISTEN_MODES
    parent = info.get("link_mode_from_parent") in _LISTEN_MODES
    if child and parent:
        return "both"
    if child:
        return "child"
    if parent:
        return "parent"
    return None


def _edge_attrs(info: dict) -> list[str]:
    """DOT attributes for the edge parent -- child, one key each (DOT is
    last-wins on duplicates). Role owns the violation look; link mode adds
    the dashed one-way rendering; a still-connecting link is dotted, no
    arrows. `len=` is appended by the caller, last."""
    role = info.get("role")
    violation = role in ("unauthorized", "dragged_in")
    listener = _monitor_listener(info)
    connecting = "C" in (info.get("link_mode_to_parent"),
                         info.get("link_mode_from_parent"))
    attrs: list[str] = []
    if violation:
        attrs.append(f'color="{_EDGE_VIOLATION}"')
    elif listener:
        attrs.append(f'color="{_EDGE_MONITOR}"')
    elif role == "permitted_external":
        attrs.append(f'color="{_EDGE_EXTERNAL}"')
    if connecting:
        attrs.append("style=dotted")
    elif listener or role == "permitted_external":
        attrs.append("style=dashed")
    if violation:
        attrs.append("penwidth=2")
    elif listener:
        attrs.append("penwidth=1.6")
    # Arrow points AT the listener. In `"parent" -- "child"` the child is the
    # head, so dir=forward/arrowhead is the child end and dir=back/arrowtail
    # the parent end (graphviz reads only the attribute for the drawn end).
    if connecting:
        attrs.append("dir=none")
    elif listener == "child":
        attrs.append("dir=forward, arrowhead=onormal")
    elif listener == "parent":
        attrs.append("dir=back, arrowtail=onormal")
    elif listener == "both":
        attrs.append("dir=both, arrowhead=onormal, arrowtail=onormal")
    return attrs


def _esc(s: str) -> str:
    """Escape a string for a double-quoted DOT label. Node callsigns and
    locations are REMOTE-controlled strings (a node self-reports them), so
    control characters are stripped, not passed through."""
    s = "".join(ch for ch in str(s) if ch >= " ")
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _esc_html(s: str) -> str:
    """Escape a string for an HTML-like Graphviz label. Unlike the quoted-DOT
    context, an unescaped '&' or '<' here is a SYNTAX ERROR that fails the
    whole render — this escaper is a hard requirement for the legend."""
    s = "".join(ch for ch in str(s) if ch >= " ")
    return html.escape(s, quote=True)


class QrzNameCache:
    """Disk-backed callsign -> operator-name cache with TTL and a per-scan
    lookup budget. A miss beyond the budget just renders without the name;
    the next scan picks it up. QRZ failures cache an empty name for a day
    so a dead account can't retry every scan.

    begin_scan(readonly=True) sets a zero budget: name_for() then serves
    cached names only — no QRZ lookups, no disk writes. Used by the refresh
    render thread (the QRZ client's requests.Session is not thread-safe)."""

    def __init__(self, qrz_client, cache_path: Path, per_scan_budget: int = 3):
        self._qrz = qrz_client
        self._path = cache_path
        self._budget = per_scan_budget
        self._cache: dict[str, dict] = {}
        try:
            if cache_path.exists():
                self._cache = json.loads(cache_path.read_text()) or {}
        except Exception as e:
            logger.warning("bubble_map: QRZ name cache unreadable (%s); "
                           "starting empty", e)
            self._cache = {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._cache))
            os.replace(tmp, self._path)
        except Exception as e:
            logger.warning("bubble_map: QRZ name cache save failed: %s", e)

    def begin_scan(self, readonly: bool = False) -> None:
        self._remaining = 0 if readonly else self._budget

    def name_for(self, callsign: str) -> str:
        """Cached operator name for a callsign, '' if unknown."""
        if not callsign or self._qrz is None:
            return ""
        cs = callsign.upper().strip()
        # Strip SSID-ish suffixes for lookup (N0CALL-R, N0CALL/P).
        base = cs.split("-")[0].split("/")[0]
        # Only spend QRZ quota on callsign-shaped strings — never on
        # EchoLink-NNNNNN remnants, IAX2 labels, or numeric node ids
        # (audit 2026-07-04, A6).
        if not re.fullmatch(r"[A-Z0-9]{1,3}\d[A-Z]{1,4}", base):
            return ""
        ent = self._cache.get(base)
        now = time.time()
        if ent is not None:
            ttl = _QRZ_CACHE_TTL_S if ent.get("name") else 86400
            if (now - ent.get("ts", 0)) < ttl:
                return ent.get("name", "")
        if getattr(self, "_remaining", 0) <= 0:
            return ent.get("name", "") if ent else ""
        self._remaining -= 1
        name = ""
        try:
            info = self._qrz.lookup(base)
            if info:
                name = f"{info.get('fname', '')} {info.get('name', '')}".strip()
        except Exception as e:
            logger.info("bubble_map: QRZ lookup failed for %s: %s", base, e)
        self._cache[base] = {"name": name, "ts": now}
        self._save()
        return name


# Adaptive label fold: 'CALLSIGN · Location' stays on one line only up to
# this many chars — wider pairs split into two lines so a long location
# cannot widen the bubble (the fold line is the width-dominant label
# element, measured 2026-07-18 D4).
_ADAPTIVE_FOLD_MAX = 26

# Callsign values that are placeholders, never worth caching or clobbering
# a cached value with.
_PLACEHOLDER_CALLSIGNS = ("", "Unknown", "Focus")
_PLACEHOLDER_LOCATIONS = ("", "Unknown", "Hub", "External Connection")


class NodeInfoCache:
    """Disk-backed per-node registry-info cache (callsign / location /
    frequency / tone / lat / lon), written through from every scan's enriched
    topology and read at render time to fill gaps:

      - vantage-only dotted nodes that were EVER API-visible label richly
      - a node whose current-scan record is missing a field keeps showing
        the last-known value

    Field-wise, non-clobbering merge: a scan record with an empty field never
    erases a previously-cached value (a momentary registry hiccup must not
    blank the map). Entries expire after ttl_s (pruned at load). Keys are
    numeric node ids only — ext_* topology entries are transport leaves with
    no registry identity."""

    _FIELDS = ("callsign", "location", "frequency", "tone", "owner",
               "lat", "lon")

    def __init__(self, cache_path: Path, ttl_s: int = _DEFAULT_NODE_INFO_TTL_S):
        self._path = cache_path
        self._ttl_s = ttl_s
        self._cache: dict[str, dict] = {}
        try:
            if cache_path.exists():
                raw = json.loads(cache_path.read_text()) or {}
                now = time.time()
                self._cache = {k: v for k, v in raw.items()
                               if isinstance(v, dict)
                               and (now - v.get("ts", 0)) < ttl_s}
        except Exception as e:
            logger.warning("bubble_map: node info cache unreadable (%s); "
                           "starting empty", e)
            self._cache = {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._cache))
            os.replace(tmp, self._path)
        except Exception as e:
            logger.warning("bubble_map: node info cache save failed: %s", e)

    @staticmethod
    def _worth_keeping(field: str, value) -> bool:
        if value is None:
            return False
        if field == "callsign":
            return value not in _PLACEHOLDER_CALLSIGNS
        if field == "owner":
            # User_ID is remote-controlled registry text; never cache a
            # placeholder for 30 days (audit 2026-07-18, parity w/ callsign).
            return value not in ("", "Unknown", "0")
        if field == "location":
            return value not in _PLACEHOLDER_LOCATIONS
        if field in ("lat", "lon"):
            return isinstance(value, (int, float))
        return bool(value)          # frequency / tone: non-empty string

    def update_from_topology(self, topology: dict) -> None:
        """Write-through from a scan's topology. ONE disk save per call."""
        now = time.time()
        dirty = False
        for nid, info in topology.items():
            key = str(nid)
            if not key.isdigit():
                continue            # ext_* keys have no registry identity
            fields = {f: info.get(f) for f in self._FIELDS
                      if self._worth_keeping(f, info.get(f))}
            if not fields:
                continue
            ent = self._cache.get(key)
            if ent is None:
                ent = {}
                self._cache[key] = ent
            ent.update(fields)      # field-wise: absent fields untouched
            ent["ts"] = now
            dirty = True
        if dirty:
            self._save()

    def get(self, nid) -> dict:
        """Last-known info for a node id, {} if absent/expired."""
        ent = self._cache.get(str(nid))
        if ent is None:
            return {}
        if (time.time() - ent.get("ts", 0)) >= self._ttl_s:
            return {}
        return ent


class BubbleMapGenerator:
    def __init__(self, engine: str, out_path: Path, system_name: str = "",
                 name_cache: Optional[QrzNameCache] = None,
                 node_cache: Optional[NodeInfoCache] = None,
                 engine_path: Optional[str] = None,
                 render_timeout_s: int = _DEFAULT_RENDER_TIMEOUT_S,
                 refresh_min_interval_s: int = _DEFAULT_REFRESH_MIN_INTERVAL_S,
                 echolink_host: Optional[str] = None,
                 landscape_out_path: Optional[Path] = None,
                 landscape_ratio: float = 0.45,
                 spread_enabled: bool = False,
                 asl_enabled: bool = False,
                 neato_path: Optional[str] = None,
                 core_nodes: Optional[set] = None,
                 asl_label_style: str = "full",
                 vantage_ghost_grace_s: int = 60,
                 vantage_list_max: int = 10):
        self.engine = engine                      # layout name for the DOT attr
        self.engine_path = engine_path or engine  # binary to execute (launchd's
                                                  # PATH lacks /opt/homebrew/bin)
        self.out_path = out_path
        self.system_name = system_name
        self.name_cache = name_cache
        self.node_cache = node_cache
        self.render_timeout_s = render_timeout_s
        self.refresh_min_interval_s = refresh_min_interval_s
        # The system's designated EchoLink gateway node (config). An
        # unconfirmed EchoLink mesh entry attaches HERE speculatively —
        # that is where EchoLink guests actually land in this system —
        # rather than to the vantage node (Bennett, 2026-07-05 00:03).
        self.echolink_host = str(echolink_host) if echolink_host else None
        # Landscape companion render (2026-07-05): same layout, graphviz
        # ratio-stretched for wide displays; served at /bubble_wide.png.
        # None disables. Stretching only widens x-gaps — no new overlaps.
        self.landscape_out_path = landscape_out_path
        self.landscape_ratio = landscape_ratio
        self.last_wide_png: Optional[Path] = None
        # Airy "spread" companions (?layout=spread — Bennett 2026-07-06).
        # Derived names: current.png -> current_spread.png etc.
        self.spread_enabled = spread_enabled
        self.spread_out_path = self._spread_name(out_path)
        self.spread_wide_out_path = (self._spread_name(landscape_out_path)
                                     if landscape_out_path else None)
        self.last_spread_png: Optional[Path] = None
        self.last_spread_wide_png: Optional[Path] = None
        # ASL-style custom layout (?layout=asl — 2026-07-18). Pin-honoring
        # `-n1` is a NEATO-ONLY behavior (D9: twopi/dot/circo/fdp all
        # silently discard pins, rc=0), so this path uses its own resolved
        # neato binary regardless of self.engine. asl_placer failures fall
        # back to the vpsc path and are counted for the /status surface.
        self.asl_enabled = bool(asl_enabled)
        self.neato_path = neato_path
        self.core_nodes = {str(n) for n in core_nodes} if core_nodes else set()
        if self.asl_enabled and asl_placer is None:
            logger.error("bubble_map: asl layout disabled — asl_placer "
                         "import failed: %s", _ASL_IMPORT_ERROR)
            self.asl_enabled = False
        if self.asl_enabled and not self.neato_path:
            logger.error("bubble_map: asl layout disabled — no neato binary "
                         "resolved (pin-honoring -n1 is neato-only)")
            self.asl_enabled = False
        if asl_label_style not in ("full", "compact", "adaptive"):
            logger.warning("bubble_map: unknown asl_label_style %r; "
                           "using 'full'", asl_label_style)
            asl_label_style = "full"
        self.asl_label_style = asl_label_style
        self.asl_out_path = out_path.with_name(
            out_path.stem + "_asl" + out_path.suffix)
        self.last_asl_png: Optional[Path] = None
        self.asl_fallback_count = 0          # lifetime (trend)
        self.asl_consecutive_fallbacks = 0   # 0 = currently healthy (7b S1)
        self.asl_last_error: Optional[str] = None   # cleared on success
        self.asl_last_error_at: Optional[str] = None
        self.asl_last_ok: Optional[str] = None
        self.asl_last_health: Optional[dict] = None
        # Vantage-overlay policy (Bennett 2026-07-21): vantage-only mesh
        # entries are NO LONGER drawn as dotted graph nodes attached to the
        # vantage node — a mass ghost union (150 phantoms, 2026-07-20) blew
        # every layout up into per-scan timeouts, and even ONE phantom edge
        # to the vantage node misstates where the client is attached. They
        # are listed in a legend row instead, and a sustained-ghost filter
        # suppresses entries the ASL API has had a chance to confirm but
        # did not: age >= grace AND at least one full API scan completed
        # since first sight (scan_on_mesh_change makes that ~immediate for
        # mass arrivals). Exception that still draws: unconfirmed EchoLink
        # at the configured gateway (Bennett 2026-07-05 00:03) while fresh.
        self.vantage_ghost_grace_s = max(0, int(vantage_ghost_grace_s))
        self.vantage_list_max = max(1, int(vantage_list_max))
        self._scan_generation = 0            # bumped per full-scan render()
        self._vantage_first_seen: dict = {}  # name -> (monotonic, generation)
        self._vantage_last_stats = {"drawn": 0, "listed": 0, "suppressed": 0}
        self._last_overlay_drawn: dict = {}  # name -> attach (set by build_dot)
        # Optional callable returning a short activity line for the caption
        # (QSO state from the AMI listener); wired by the daemon.
        self.activity_provider: Optional[callable] = None
        # _lock serializes build+subprocess+cache writes across the main loop
        # and the refresh thread. _sched_lock only guards refresh scheduling
        # state (tiny critical section — never held during a render).
        self._lock = threading.Lock()
        self._sched_lock = threading.Lock()
        self._last_topology: Optional[dict] = None   # deep copy (see render)
        self._last_ts: str = ""
        self._refresh_thread: Optional[threading.Thread] = None
        self._last_render_started = 0.0              # time.monotonic()

    @staticmethod
    def _spread_name(p: Optional[Path]) -> Optional[Path]:
        return p.with_name(p.stem + "_spread" + p.suffix) if p else None

    # --- DOT construction ----------------------------------------------------

    def _cached(self, nid) -> dict:
        return self.node_cache.get(nid) if self.node_cache is not None else {}

    def _node_label(self, nid, info: dict,
                    label_style: str = "full") -> str:
        """Build the multi-line bubble label. Superset of the official map:
        'Node <id> <freq> <tone>' / callsign (+ QRZ operator name for
        non-core roles) / location / lat lon (4 decimals). Each field falls
        back to the NodeInfoCache when the scan record lacks it.

        label_style (2026-07-18/19, ASL-style layout only):
          "full"     — the 4-line label above (Bennett's preferred style
                       for the custom layout, 2026-07-19).
          "compact"  — 3-line fold: 'CALLSIGN · Location' on one line.
          "adaptive" — fold ONLY when the folded line stays narrow
                       (<= _ADAPTIVE_FOLD_MAX chars); wide pairs split
                       into two lines (the D4 whitespace fix candidate).
        Both non-full styles: no QRZ operator-name line (never looked up —
        QRZ budget untouched); location clamped (remote-controlled free
        text; unclamped it is a per-node style kill-switch — D8); the
        UNAUTHORIZED marker line is ALWAYS kept (evidence-critical)."""
        role = info.get("role", "")
        if str(nid).startswith("ext_"):
            # Transport leaves: callsign/name only, as before.
            return _esc(info.get("callsign", nid))
        cached = self._cached(nid)

        def field(name):
            v = info.get(name)
            return v if NodeInfoCache._worth_keeping(name, v) else cached.get(name)

        parts = []
        line1 = f"Node {nid}"
        freq, tone = field("frequency"), field("tone")
        # The registry "frequency" field is free text some owners fill with a
        # whole description; unbounded it inflates the bubble (and thus every
        # branch length). Clamp for display (2026-07-04 density feedback).
        if freq and len(str(freq)) > 18:
            freq = str(freq)[:18] + "…"
        # The tone field is equally free-text (one node's literally says
        # "Open Std ASL Port"). A tone is only meaningful as a CTCSS number —
        # display it only when it is shaped like one, drop junk silently.
        if tone and not re.fullmatch(r"\d{2,3}(\.\d)?", str(tone).strip()):
            tone = ""
        if freq:
            line1 += f" {freq}"
        if tone:
            line1 += f" {tone}"
        parts.append(_esc(line1))
        cs = field("callsign")
        cs_ok = cs and cs not in _PLACEHOLDER_CALLSIGNS and str(nid) != str(cs)
        loc = field("location")
        loc_ok = loc and loc not in _PLACEHOLDER_LOCATIONS
        if label_style in ("compact", "adaptive"):
            if loc_ok and len(str(loc)) > 28:
                loc = str(loc)[:28] + "…"
            fold = cs_ok and loc_ok
            if fold and label_style == "adaptive" \
                    and len(f"{cs} · {loc}") > _ADAPTIVE_FOLD_MAX:
                fold = False        # wide pair: split, don't widen the bubble
            # Conditional fold: never a dangling separator.
            if fold:
                parts.append(_esc(f"{cs} · {loc}"))
            else:
                if cs_ok:
                    parts.append(_esc(cs))
                if loc_ok:
                    parts.append(_esc(loc))
        else:
            if cs_ok:
                parts.append(_esc(cs))
                if self.name_cache is not None and role in (
                        "guest", "unauthorized", "dragged_in"):
                    name = self.name_cache.name_for(cs)
                    if name:
                        parts.append(_esc(name))
            if loc_ok:
                parts.append(_esc(loc))
        lat, lon = field("lat"), field("lon")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            parts.append(f"{lat:.4f} {lon:.4f}")
        if role == "unauthorized":
            parts.append("UNAUTHORIZED")
        return "\\n".join(parts)

    def _legend_label(self, timestamp_text: str,
                      vantage_row: Optional[dict] = None,
                      show_monitored: bool = False) -> str:
        """HTML-like graph label: title row + color-swatch legend row, plus
        (when present) the vantage-reported list row — vantage-only mesh
        entries live HERE since 2026-07-21, not as graph nodes. vantage_row:
        {"vantage": str, "listed": [str], "suppressed": int}. Everything
        interpolated goes through _esc_html — an unescaped '&'/'<' here
        fails the entire render."""
        title = f"{self.system_name} — {timestamp_text}"
        if self.activity_provider is not None:
            try:
                act = self.activity_provider()
                if act:
                    title += f" — {act}"
            except Exception:
                pass                     # caption garnish only, never fatal
        title = _esc_html(title)
        legend = _LEGEND + ([_LEGEND_MONITORED] if show_monitored else [])
        cells = "".join(
            f'<TD BGCOLOR="{color}"><FONT POINT-SIZE="8">{_esc_html(text)}'
            f'</FONT></TD>'
            for color, text in legend)
        vrow = ""
        if vantage_row and (vantage_row["listed"] or vantage_row["suppressed"]):
            shown = vantage_row["listed"][:self.vantage_list_max]
            extra = len(vantage_row["listed"]) - len(shown)
            head = (f'Reported by vantage {vantage_row["vantage"]} '
                    '(not in stats API): ')
            body = " &#183; ".join(_esc_html(s) for s in shown)
            if extra > 0:
                body += f" (+{extra} more)"
            if vantage_row["suppressed"]:
                sup = (f'{vantage_row["suppressed"]} unconfirmed '
                       f'&#8805;{self.vantage_ghost_grace_s}s')
                # Empty list reads "138 unconfirmed >=60s — suppressed";
                # a populated list appends "— plus 138 ..., suppressed"
                # (Bennett 2026-07-21: the old "none —" placeholder was
                # confusing).
                body += (f" &#8212; plus {sup}, suppressed" if body
                         else f"{sup} &#8212; suppressed")
            # <BR/> every ~5 entries keeps the row narrower than the map.
            parts = body.split(" &#183; ")
            chunks = [" &#183; ".join(parts[i:i + 5])
                      for i in range(0, len(parts), 5)]
            vrow = (f'<TR><TD COLSPAN="{len(legend)}" BORDER="0" '
                    'ALIGN="LEFT"><FONT POINT-SIZE="8">'
                    + _esc_html(head) + "<BR/>".join(chunks)
                    + '</FONT></TD></TR>')
        return (
            '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="3">'
            f'<TR><TD COLSPAN="{len(legend)}" BORDER="0">'
            f'<FONT POINT-SIZE="10">{title}</FONT></TD></TR>'
            f'<TR>{cells}</TR>'
            f'{vrow}'
            '</TABLE>>')

    def build_dot(self, topology: dict, vantage_snapshot=None,
                  timestamp: str = "", readonly_qrz: bool = False,
                  ratio: Optional[float] = None, spread: bool = False,
                  label_style: str = "full") -> str:
        if self.name_cache is not None:
            self.name_cache.begin_scan(readonly=readonly_qrz)
        # Focus first: twopi honors root reliably when it is part of the
        # graph attribute list (a bare root statement lost to the
        # highest-degree node in testing).
        focus = next((nid for nid, info in topology.items()
                      if info.get("role") == "focus"), None)
        root_attr = f'root="{_esc(str(focus))}", ' if focus is not None else ""
        # Vantage overlay FIRST: the legend (a graph attribute in the header)
        # carries the list row, and the ASL path reuses the drawn subset.
        overlay = self._vantage_attachments(topology, vantage_snapshot,
                                            label_style=label_style)
        ov_drawn = [va for va in overlay if va["draw"] and not va["suspect"]]
        ov_listed = [va for va in overlay
                     if not va["draw"] and not va["suspect"]]
        ov_suppressed = sum(1 for va in overlay if va["suspect"])
        if vantage_snapshot is not None:
            # Snapshot-less builds (evidence renders) must not clobber the
            # /status counters with zeros (audit 2026-07-21 A3). The drawn
            # stash below ALWAYS updates — _render_asl must place exactly
            # what THIS dot contains.
            self._vantage_last_stats = {"drawn": len(ov_drawn),
                                        "listed": len(ov_listed),
                                        "suppressed": ov_suppressed}
        self._last_overlay_drawn = {va["name"]: va["attach"]
                                    for va in ov_drawn}
        vantage_row = None
        if vantage_snapshot is not None and (ov_listed or ov_suppressed):
            vantage_row = {"vantage": str(vantage_snapshot.vantage_node),
                           "listed": [va["list_label"] for va in ov_listed],
                           "suppressed": ov_suppressed}
        lines = [
            "graph asl {",
            # overlap=vpsc is the density linchpin (2026-07-04 evening,
            # after Bennett's "why so much sparser than ASL.org" pushback):
            # prism/scale-based removal INFLATES the whole drawing, while
            # vpsc moves nodes minimally — bubbles end up nearly touching,
            # like the official map, without actual overlaps. sep=+6pt is
            # the air gap. splines stay straight (ASL.org look; spline
            # routing falls back anyway at this packing density).
            # dpi=180: the vpsc-compacted layout is only ~6in across, so at
            # the default 96dpi the PNG came out ~600px and HA upscaled it,
            # clipping/blurring 9pt ascenders (Bennett 2026-07-04 evening).
            # Higher dpi scales the raster only — layout inches unchanged.
            # spread=True deliberately brings the prism inflation BACK as a
            # viewer-selectable airy variant (Bennett 2026-07-06).
            f'  graph [layout={self.engine}, {root_attr}'
            + ('overlap=false, sep="+8", ' if spread
               else 'overlap=vpsc, sep="+6", ')
            + (f'ratio={ratio}, ' if ratio else '')
            + f'splines=line, ranksep="1.0", dpi=180, '
            f'bgcolor="white", '
            f'label={self._legend_label(timestamp, vantage_row, any(i.get("role") == "monitored_by_guest" for i in topology.values()))}, '
            'labelloc="b"];',
            '  node [style=filled, fontname="Helvetica", fontsize=9, '
            'margin="0.06,0.045", height=0.3];',
            '  edge [dir=both, arrowsize=0.5];',
        ]
        known_nodes: set[str] = set()
        for nid, info in topology.items():
            role = info.get("role", "")
            known_nodes.add(str(nid))
            fill, shape, extra = _ROLE_STYLE.get(role, _DEFAULT_STYLE)
            if (role == "regular" and self.core_nodes
                    and str(nid) not in self.core_nodes):
                # A non-bridge hop-1 node that is NOT in the configured core
                # is a witting direct-to-hub guest, not a core member — the
                # role vocabulary cannot see the difference (Bennett caught
                # 60222 drawn green, 2026-07-18). Display-only; with no
                # core_nodes configured, legacy coloring stands.
                fill = _ROLE_STYLE["guest"][0]
            label = self._node_label(nid, info, label_style=label_style)
            attrs = f'label="{label}", fillcolor="{fill}", shape={shape}'
            if extra:
                attrs += ", " + extra
            if role == "focus":
                # Belt and suspenders: graphviz 15's twopi honors the node-
                # level root reliably; the graph-level attr alone did not.
                attrs += ", root=true"
            lines.append(f'  "{_esc(str(nid))}" [{attrs}];')
        # Edges from the walk (parent pointers). Undirected graph; dir=both
        # arrowheads give the official map's double-arrow look.
        #
        # Per-edge target lengths (honored by neato/fdp; twopi ignores len,
        # and neato ignores len in the edge-DEFAULTS line — both verified on
        # graphviz 15.1.0, 2026-07-04): focus spokes ALTERNATE short/long so
        # wide bubbles interleave at two radii instead of all sitting on one
        # worst-case ring — that single ring was the long-branch cause
        # (Bennett's density feedback). Alternation follows sorted child
        # order, so it is stable scan-to-scan.
        spokes = sorted(str(n) for n, i in topology.items()
                        if focus is not None
                        and str(i.get("parent")) == str(focus))
        spoke_idx = {n: i for i, n in enumerate(spokes)}
        for nid, info in topology.items():
            parent = info.get("parent")
            if parent is None:
                continue
            key = str(nid)
            attrs = _edge_attrs(info)
            if key in spoke_idx:
                attrs.append(f"len={0.8 if spoke_idx[key] % 2 == 0 else 1.4}")
            else:
                attrs.append("len=1.0")
            lines.append(f'  "{_esc(str(parent))}" -- "{_esc(key)}" '
                         f'[{", ".join(attrs)}];')

        # Vantage-only nodes: in the app_rpt mesh but invisible to the API
        # walk. Since 2026-07-21 only the drawn subset (unconfirmed EchoLink
        # at its gateway) becomes graph nodes; the rest ride the legend row
        # built above, and sustained ghosts are suppressed entirely.
        for va in ov_drawn:
            lines.append(
                f'  "{_esc(va["name"])}" [label="{va["label"]}", '
                f'fillcolor="#fafafa", shape=ellipse, '
                f'style="filled,dotted"];')
            # dir=none: arrows now carry link-mode meaning, and an overlay
            # edge (mesh-listed, not API-confirmed) has no mode evidence.
            lines.append(f'  "{_esc(va["attach"])}" -- "{_esc(va["name"])}" '
                         f'[style=dotted, color="#757575", dir=none, len=1.2];')
        lines.append("}")
        return "\n".join(lines)

    def _vantage_attachments(self, topology: dict, vantage_snapshot,
                             label_style: str = "full") -> list:
        """Synthesize the vantage-only overlay set: mesh nodes invisible to
        the API walk. Dedup/translation rules unchanged (2026-07-04/05).
        Returns [{"name", "attach", "label", "list_label", "draw",
        "suspect"}]:
          draw=True     — still drawn as a dotted graph node: ONLY the
                          unconfirmed-EchoLink-at-gateway case (Bennett
                          2026-07-05 00:03). Everything else is list-only
                          (Bennett 2026-07-21: a phantom edge to the
                          vantage node misstates attachment and mass
                          ghosts blew up the layout).
          suspect=True  — sustained ghost: older than the grace window AND
                          a full API scan has completed since first sight
                          without confirming it. Excluded from graph AND
                          list; surfaced only as a suppressed count.
        First-seen state purges when a node leaves the mesh (or becomes
        API-confirmed), so a genuine reconnect restarts its grace clock."""
        if vantage_snapshot is None:
            return []           # no mesh view: keep state, nothing to show
        known_nodes = {str(nid) for nid in topology}
        known_callsigns = {str(info.get("callsign", ""))
                           for info in topology.values()}
        vantage = str(vantage_snapshot.vantage_node)
        now = time.monotonic()
        out = []
        for mnode in vantage_snapshot.mesh_nodes:
            mstr = str(mnode)
            if mstr in known_nodes:
                continue
            # EchoLink endpoints ride the mesh in chan_echolink's wire
            # form "3%06u" (7 digits, leading 3 — source-verified
            # 2026-05). The API walk records the SAME connection as an
            # ext_* entry with callsign "EchoLink-<id>". Translate before
            # deduping, or a confirmed EchoLink guest renders twice
            # (Bennett caught the duplicate live, 2026-07-04 23:36).
            echolink_id = None
            if mstr.isdigit() and len(mstr) == 7 and mstr.startswith("3"):
                echolink_id = mstr[1:].lstrip("0") or "0"
                if f"EchoLink-{echolink_id}" in known_callsigns:
                    continue    # confirmed on its real host — no ghost
            # Externals appear in topology under ext_* keys with callsign
            # labels; skip mesh entries that match a known callsign too.
            if mstr in known_callsigns:
                continue
            t0, gen0 = self._vantage_first_seen.setdefault(
                mstr, (now, self._scan_generation))
            suspect = (now - t0 >= self.vantage_ghost_grace_s
                       and self._scan_generation > gen0)
            cached = self._cached(mnode)
            attach = vantage
            draw = False
            if echolink_id is not None:
                # Speculative classification until the next full scan
                # confirms the attachment point — drawn off the system's
                # designated EchoLink gateway when it is on the map,
                # listed (not drawn) when the gateway is absent.
                label = (f"EchoLink-{echolink_id}\\n{_esc(mstr)}\\n"
                         f"(unconfirmed, not in stats API)")
                list_label = f"EchoLink-{echolink_id} ({mstr})"
                if self.echolink_host and self.echolink_host in known_nodes:
                    attach = self.echolink_host
                    draw = True
            else:
                label = f"{_esc(mstr)}\\n(not in stats API)"
                cs = cached.get("callsign")
                if cs and cs not in _PLACEHOLDER_CALLSIGNS and str(cs) != mstr:
                    list_label = f"{mstr} {cs}"
                else:
                    list_label = mstr
            out.append({"name": mstr, "attach": attach, "label": label,
                        "list_label": list_label, "draw": draw,
                        "suspect": suspect})
        current = {e["name"] for e in out}
        for k in list(self._vantage_first_seen):
            if k not in current:
                del self._vantage_first_seen[k]
        return out

    # --- rendering -------------------------------------------------------------

    def render(self, topology: dict, vantage_snapshot=None,
               timestamp: str = "") -> Optional[Path]:
        """Per-scan render (main-loop thread). Build + render the map, update
        the node-info cache, and stash a deep-copied topology for the refresh
        path (the main loop keeps mutating/consuming the scan result after
        this returns). Returns the PNG path, or None on failure. Never
        raises."""
        with self._lock:
            # Per-scan entry point: this topology came from a fresh API
            # walk, so any vantage-only node it does NOT contain has now
            # missed a confirmation opportunity (ghost-filter clock).
            self._scan_generation += 1
            try:
                if self.node_cache is not None:
                    self.node_cache.update_from_topology(topology)
            except Exception as e:
                logger.warning("bubble_map: node cache update failed: %s", e)
            try:
                self._last_topology = copy.deepcopy(topology)
                self._last_ts = timestamp
            except Exception as e:
                logger.warning("bubble_map: topology stash failed "
                               "(refresh disabled until next scan): %s", e)
                self._last_topology = None
            return self._render_locked(topology, vantage_snapshot, timestamp,
                                       readonly_qrz=False)

    def _render_locked(self, topology: dict, vantage_snapshot, timestamp: str,
                       readonly_qrz: bool) -> Optional[Path]:
        """Portrait render + optional landscape/spread companions. Caller
        holds self._lock. Never raises. Returns the portrait path (companion
        results land in self.last_*_png)."""
        self._last_render_started = time.monotonic()
        main = self._render_one(topology, vantage_snapshot, timestamp,
                                readonly_qrz, self.out_path, ratio=None)
        if main is None:
            # Main render failed/timed out — don't spend up to 3 more
            # timeouts on companions while holding _lock (audit 07-06, S2).
            return None
        # QRZ misses were cached by the first build; readonly on companions
        # keeps them from double-spending the per-scan budget. Companion
        # timeouts are capped LOW: renders measure ~0.15s, and the total
        # _lock hold must stay bounded (audit 07-06, S2 — worst case is now
        # render_timeout + 3x10s instead of 4x render_timeout).
        cap = min(10, self.render_timeout_s)
        if self.landscape_out_path is not None:
            self.last_wide_png = self._render_one(
                topology, vantage_snapshot, timestamp, True,
                self.landscape_out_path, ratio=self.landscape_ratio,
                timeout_s=cap)
        if self.spread_enabled:
            self.last_spread_png = self._render_one(
                topology, vantage_snapshot, timestamp, True,
                self.spread_out_path, ratio=None, spread=True, timeout_s=cap)
            if self.spread_wide_out_path is not None:
                self.last_spread_wide_png = self._render_one(
                    topology, vantage_snapshot, timestamp, True,
                    self.spread_wide_out_path, ratio=self.landscape_ratio,
                    spread=True, timeout_s=cap)
        if self.asl_enabled:
            # Both asl subprocesses share ONE `cap`-bounded deadline (audit
            # S7): per-scan worst-case _lock hold is render_timeout + 4x10s
            # (was +3x10 before this companion), documented in the plan.
            self.last_asl_png = self._render_asl(
                topology, vantage_snapshot, timestamp, self.asl_out_path,
                deadline=time.monotonic() + cap)
        return main

    def _render_one(self, topology: dict, vantage_snapshot, timestamp: str,
                    readonly_qrz: bool, out_path: Path,
                    ratio: Optional[float], spread: bool = False,
                    timeout_s: Optional[float] = None) -> Optional[Path]:
        """Build + subprocess + atomic replace for ONE output. Never raises."""
        try:
            # Dir first: build_dot may save the QRZ name cache into it.
            out_path.parent.mkdir(parents=True, exist_ok=True)
            dot_src = self.build_dot(topology, vantage_snapshot, timestamp,
                                     readonly_qrz=readonly_qrz, ratio=ratio,
                                     spread=spread)
            tmp = out_path.with_suffix(".tmp.png")
            proc = subprocess.run(
                [self.engine_path, "-Tpng", "-o", str(tmp)],
                input=dot_src.encode(), capture_output=True,
                timeout=timeout_s or self.render_timeout_s)
            if proc.returncode != 0 or not tmp.exists():
                logger.error("bubble_map: %s render failed rc=%d stderr=%s",
                             self.engine, proc.returncode,
                             proc.stderr.decode(errors="replace")[:300])
                return None
            os.replace(tmp, out_path)           # atomic: never a torn PNG
            return out_path
        except FileNotFoundError:
            logger.error("bubble_map: Graphviz engine %r not found — "
                         "install graphviz (brew install graphviz)", self.engine)
            return None
        except Exception as e:
            logger.error("bubble_map: render failed (non-fatal): %s", e)
            return None

    # --- ASL-style custom layout (2026-07-18) --------------------------------

    # A node statement is `"name" [attrs];` — the quoted name (escape-aware)
    # followed directly by `[`. Edge statements have ` -- ` BETWEEN quoted
    # names, i.e. before the `[`, so they can never match this. Substring
    # tests are NOT safe here: labels/names are remote-controlled and a
    # location like "Austin -- TX" made the old `" -- " not in s` test skip
    # the node entirely — unpinned, silently collapsed to origin (7b audit
    # C1). Structural match + the two-way set assertion below close that.
    _NODE_STMT = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*\[')

    @staticmethod
    def _pin_dot(dot_src: str, pos: dict) -> str:
        """Pin computed positions (inches -> points) into the DOT and patch
        it for pin-honoring re-route: splines=true, overlap=true (CRITICAL —
        `neato -n1` with overlap=false/vpsc silently runs prism and
        re-compacts pinned positions; verified on graphviz 15.1.0).
        Raises PlacementError unless the DOT node set and the placement
        node set match EXACTLY — an unpinned node would default to the
        origin and collapse the map."""
        out_lines, seen = [], set()
        for line in dot_src.splitlines():
            m = BubbleMapGenerator._NODE_STMT.match(line)
            if m:
                name = re.sub(r"\\(.)", r"\1", m.group(1))
                seen.add(name)
                if name in pos:
                    x, y = pos[name]
                    line = (line[:m.end()]
                            + f'pos="{x * 72:.1f},{y * 72:.1f}", '
                            + line[m.end():])
            out_lines.append(line)
        if seen != set(pos):
            raise asl_placer.PlacementError(
                "DOT/placement node-set mismatch: "
                f"dot_only={sorted(seen - set(pos))[:5]} "
                f"pos_only={sorted(set(pos) - seen)[:5]}")
        routed = "\n".join(out_lines)
        routed = routed.replace("splines=line", "splines=true")
        routed = routed.replace("overlap=vpsc", "overlap=true")
        routed = routed.replace("overlap=false", "overlap=true")
        # Force the embedded layout attr to neato (7a audit S1): graphviz
        # honors `layout=` over the invoked binary, so with engine=twopi in
        # config the -n1 pass would silently re-layout and discard every
        # pin. The binary alone is not the guard — this line is.
        routed = re.sub(r"layout=\w+", "layout=neato", routed, count=1)
        return routed

    def _render_asl(self, topology: dict, vantage_snapshot, timestamp: str,
                    out_path: Path, deadline: float) -> Optional[Path]:
        """ASL-style render: compact-label DOT -> neato -Tplain sizing pass
        -> asl_placer.place_topology -> pinned neato -n1 -Tpng. `deadline`
        (time.monotonic value) is SHARED across both subprocesses — the
        caller budgets it against its lock-hold bound. Never raises; on any
        failure returns None with the fallback counter/last-error updated
        (the caller renders the production vpsc layout instead)."""
        if not self.asl_enabled:
            return None
        tmp = None
        try:
            # Defense-in-depth ceiling (7b A2): the pure-Python placement
            # has no internal preemption point, so bound its input. 400 is
            # far above the drag-in catalog cap (~30) yet still places in
            # well under a second at the measured O(n^2) constants.
            n_nodes = len(topology)
            if n_nodes > 400:
                raise asl_placer.PlacementError(
                    f"topology too large for asl layout ({n_nodes} nodes)")
            dot_src = self.build_dot(topology, vantage_snapshot, timestamp,
                                     readonly_qrz=True,
                                     label_style=self.asl_label_style)
            remaining = deadline - time.monotonic()
            if remaining <= 0.5:
                raise asl_placer.PlacementError("deadline before sizing pass")
            proc = subprocess.run([self.neato_path, "-Tplain"],
                                  input=dot_src.encode(),
                                  capture_output=True, timeout=remaining)
            if proc.returncode != 0:
                raise RuntimeError(
                    "sizing pass rc=%d: %s" % (
                        proc.returncode,
                        proc.stderr.decode(errors="replace")[:200]))
            _, sizes = asl_placer.parse_plain(proc.stdout.decode())
            # Placement set must EXACTLY match the DOT node set (_pin_dot
            # asserts two-way). build_dot above stashed the drawn overlay
            # subset it emitted — reuse it rather than recomputing, or a
            # node crossing the ghost-grace boundary between the two calls
            # would desync the sets and trip the assert.
            pos, health = asl_placer.place_topology(
                topology, sizes, extra_parents=dict(self._last_overlay_drawn))
            routed = self._pin_dot(dot_src, pos)
            remaining = deadline - time.monotonic()
            if remaining <= 0.5:
                raise asl_placer.PlacementError("deadline before routing pass")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = out_path.with_suffix(".tmp.png")
            proc = subprocess.run([self.neato_path, "-n1", "-Tpng",
                                   "-o", str(tmp)],
                                  input=routed.encode(),
                                  capture_output=True, timeout=remaining)
            if proc.returncode != 0 or not tmp.exists():
                raise RuntimeError(
                    "routing pass rc=%d: %s" % (
                        proc.returncode,
                        proc.stderr.decode(errors="replace")[:200]))
            os.replace(tmp, out_path)           # atomic: never a torn PNG
            if health.get("corridor_hits"):
                # Observational only (plan v1.3): an interleave with zero
                # node overlaps is still a valid map — warn, don't fail.
                logger.warning("asl_layout: %d cross-cluster corridor "
                               "hit(s): %s", health["corridor_hits"],
                               "; ".join(health.get("corridor_detail", [])))
            self.asl_last_health = health
            self.asl_last_ok = timestamp or time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.asl_consecutive_fallbacks = 0     # recovered (7b S1)
            self.asl_last_error = None
            self.asl_last_error_at = None
            return out_path
        except Exception as e:
            if tmp is not None:                    # stale-tmp hygiene (7b A3)
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
            self.asl_fallback_count += 1
            self.asl_consecutive_fallbacks += 1
            err = f"{type(e).__name__}: {e}"[:300]
            # First occurrence (or a changed cause) at ERROR; the same
            # persisting cause repeats at WARNING so a stable, correctly
            # falling-back condition cannot bury real errors (7b S2).
            log = (logger.error if err != self.asl_last_error
                   else logger.warning)
            self.asl_last_error = err
            self.asl_last_error_at = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                   time.gmtime())
            log("asl_layout: custom render failed (vpsc fallback engaged, "
                "count=%d, consecutive=%d): %s", self.asl_fallback_count,
                self.asl_consecutive_fallbacks, e)
            return None

    def asl_health(self) -> Optional[dict]:
        """Health block for /status (plan S6: a permanently-broken custom
        path must be observable, not log-buried). None when disabled."""
        if not self.asl_enabled:
            return None
        h = {"enabled": True,
             "fallback_count": self.asl_fallback_count,
             "consecutive_fallbacks": self.asl_consecutive_fallbacks,
             "last_error": self.asl_last_error,
             "last_error_at": self.asl_last_error_at,
             "last_ok": self.asl_last_ok,
             "label_style": self.asl_label_style}
        if self.asl_last_health:
            h["corridor_hits"] = self.asl_last_health.get("corridor_hits", 0)
            h["components"] = self.asl_last_health.get("components")
        return h

    def vantage_overlay_stats(self) -> dict:
        """Vantage-overlay block for /status: how many vantage-reported
        entries the last build drew (EchoLink-at-gateway), listed in the
        legend, and suppressed as sustained ghosts. A large suppressed
        count is the ghost-union signature (2026-07-20 incident)."""
        s = dict(self._vantage_last_stats)
        s["grace_s"] = self.vantage_ghost_grace_s
        s["tracked"] = len(self._vantage_first_seen)
        return s

    def render_evidence(self, topology: dict, out_path: Path,
                        timestamp: str = "") -> Optional[Path]:
        """One-off render of a violation topology to `out_path` for email
        evidence — the fallback when the official ASL.org map shot does not
        show a short-lived violation (Bennett, 2026-07-17: official map when
        it corroborates, our own render when it does not). Does NOT touch
        the live map outputs, the stashed refresh topology, or the caches
        (QRZ read-only; the scan's own render already fed them). Serialized
        with normal renders via self._lock — BOUNDED acquire so a refresh
        render in flight can never stall the violation-email path beyond
        ~30s total (audit 2026-07-17; same discipline as carry_last_from).
        Never raises; None on failure."""
        try:
            if not self._lock.acquire(timeout=15):
                logger.warning("bubble_map: evidence render skipped — "
                               "render lock busy >15s (email will go "
                               "without attachment)")
                return None
            try:
                # ONE deadline covers the ASL attempt AND the vpsc fallback
                # (audit C1): the documented ~30s worst-case total for the
                # violation-email path is preserved exactly.
                budget = min(15, self.render_timeout_s)
                deadline = time.monotonic() + budget
                png = self._render_asl(topology, None, timestamp, out_path,
                                       deadline)
                if png is not None:
                    return png
                remaining = deadline - time.monotonic()
                if remaining <= 0.5:
                    logger.warning("bubble_map: evidence deadline exhausted "
                                   "before vpsc fallback — email will go "
                                   "without attachment")
                    return None
                return self._render_one(topology, None, timestamp,
                                        readonly_qrz=True, out_path=out_path,
                                        ratio=None, timeout_s=remaining)
            finally:
                self._lock.release()
        except Exception as e:                    # belt-and-braces; _render_one
            logger.error("bubble_map: evidence render failed "
                         "(non-fatal): %s", e)     # already never raises
            return None

    # --- link-change refresh (called from the link-watch thread) --------------

    def request_refresh(self, vantage_snapshot=None) -> None:
        """Schedule a render-only refresh: last scan topology + this vantage
        overlay. Debounced, single-flight, runs on a short-lived daemon
        thread so the watcher's enforcement duties never wait on a render.
        Returns immediately. Never raises."""
        try:
            with self._sched_lock:
                if self._last_topology is None:
                    return              # nothing rendered yet this process
                now = time.monotonic()
                if now - self._last_render_started < self.refresh_min_interval_s:
                    return              # debounce (also spaces off scan renders)
                if self._refresh_thread is not None \
                        and self._refresh_thread.is_alive():
                    return              # one in flight max
                # Stamp at schedule time so a wake burst collapses to one
                # refresh even before the worker takes the render lock.
                self._last_render_started = now
                t = threading.Thread(target=self._refresh_worker,
                                     args=(vantage_snapshot,),
                                     name="bubble-refresh", daemon=True)
                self._refresh_thread = t
                t.start()
        except Exception as e:
            logger.error("bubble_map: refresh scheduling failed "
                         "(non-fatal): %s", e)

    def _refresh_worker(self, vantage_snapshot) -> None:
        try:
            with self._lock:
                topo = self._last_topology
                if topo is None:
                    return
                ts = (f"{self._last_ts} — link change "
                      f"{time.strftime('%H:%M:%S', time.gmtime())}Z "
                      f"(topology from last scan)")
                png = self._render_locked(topo, vantage_snapshot, ts,
                                          readonly_qrz=True)
            if png is not None:
                logger.info("bubble_map: link-change refresh rendered")
        except Exception as e:
            logger.error("bubble_map: refresh render failed (non-fatal): %s", e)

    def carry_last_from(self, other: "BubbleMapGenerator") -> None:
        """SIGHUP: inherit the outgoing generator's last topology so refresh
        capability survives a reload (otherwise refreshes no-op until the
        next scan). Never raises.

        Bounded acquire (audit 2026-07-04 v2, S1): this runs on the MAIN
        thread during reload; if the outgoing generator has a refresh render
        in flight (its _lock held across a subprocess for up to
        render_timeout_seconds), waiting would stall the scan loop on
        presentation work. On contention, degrade to "refresh disabled until
        the next scan" instead."""
        try:
            if not other._lock.acquire(timeout=2):
                logger.info("bubble_map: carry_last_from skipped (outgoing "
                            "generator busy rendering) — link-change refresh "
                            "resumes after the next scan")
                return
            try:
                topo, ts = other._last_topology, other._last_ts
            finally:
                other._lock.release()
            with self._lock:
                self._last_topology, self._last_ts = topo, ts
        except Exception as e:
            logger.warning("bubble_map: carry_last_from failed: %s", e)


def build_bubble_map_generator(config: dict, qrz_client=None):
    """Build a BubbleMapGenerator from config, or None if disabled.
    Never raises. qrz_client is optional (names skipped without it)."""
    try:
        bcfg = config.get("bubble_map") or {}
        if not isinstance(bcfg, dict) or not bcfg.get("enabled", False):
            return None
        out = Path(bcfg.get("output", "bubble_maps_local/current.png"))
        if not out.is_absolute():
            out = Path(__file__).parent / out
        engine = str(bcfg.get("engine", "neato"))
        if engine not in ("twopi", "dot", "neato", "fdp", "circo"):
            logger.error("bubble_map: unknown engine %r; using neato", engine)
            engine = "neato"
        # Resolve the binary NOW: under launchd the daemon's PATH lacks
        # /opt/homebrew/bin, so a bare engine name fails at render time.
        engine_path = shutil.which(engine) or next(
            (p for p in (f"/opt/homebrew/bin/{engine}",
                         f"/usr/local/bin/{engine}") if Path(p).exists()),
            None)
        if engine_path is None:
            logger.error("bubble_map: Graphviz engine %r not found on PATH or "
                         "in Homebrew locations — install graphviz; "
                         "generator disabled this run", engine)
            return None

        def _int_opt(key, default, floor=1):
            try:
                return max(floor, int(bcfg.get(key, default)))
            except (TypeError, ValueError):
                logger.warning("bubble_map: bad %s in config; using %s",
                               key, default)
                return default

        render_timeout_s = _int_opt("render_timeout_seconds",
                                    _DEFAULT_RENDER_TIMEOUT_S)
        refresh_min_s = _int_opt("refresh_min_interval_seconds",
                                 _DEFAULT_REFRESH_MIN_INTERVAL_S)
        ttl_s = _int_opt("node_info_ttl_days", 30) * 86400
        landscape_out = None
        landscape_ratio = 0.45
        if bcfg.get("landscape_enabled", True):
            landscape_out = Path(bcfg.get(
                "landscape_output", "bubble_maps_local/current_wide.png"))
            if not landscape_out.is_absolute():
                landscape_out = Path(__file__).parent / landscape_out
            try:
                landscape_ratio = float(bcfg.get("landscape_ratio", 0.45))
                if not (0.1 <= landscape_ratio <= 1.0):
                    raise ValueError
            except (TypeError, ValueError):
                logger.warning("bubble_map: bad landscape_ratio; using 0.45")
                landscape_ratio = 0.45
        # ASL-style layout (2026-07-18): dedicated neato resolution — the
        # pinned -n1 path is neato-ONLY (D9: every other engine, fdp
        # included, silently discards pins), so the configured engine must
        # not leak into it.
        # Default FALSE (7b A1): a config that drops the key must not
        # auto-enable a gated feature — enabling is an explicit config act.
        asl_enabled = bool(bcfg.get("asl_layout_enabled", False))
        neato_path = (engine_path if engine == "neato" else
                      shutil.which("neato") or next(
                          (p for p in ("/opt/homebrew/bin/neato",
                                       "/usr/local/bin/neato")
                           if Path(p).exists()), None))
        # 60222 fix (2026-07-18): the analytics core list is the ground
        # truth for which hop-1 "regular" nodes are actually core members;
        # everything else at hop 1 is a witting direct-to-hub guest.
        acfg = config.get("analytics")
        core_raw = acfg.get("core_nodes") if isinstance(acfg, dict) else None
        core_nodes = ({str(n) for n in core_raw}
                      if isinstance(core_raw, list) else set())
        name_cache = None
        if bcfg.get("qrz_names", False) and qrz_client is not None:
            name_cache = QrzNameCache(
                qrz_client,
                out.parent / "qrz_name_cache.json",
                per_scan_budget=int(bcfg.get("qrz_lookups_per_scan", 3)))
        node_cache = NodeInfoCache(out.parent / "node_info_cache.json",
                                   ttl_s=ttl_s)
        system_name = (config.get("analytics") or {}).get("system_name", "") \
            if isinstance(config.get("analytics"), dict) else ""
        gen = BubbleMapGenerator(engine=engine, out_path=out,
                                 system_name=system_name,
                                 name_cache=name_cache,
                                 node_cache=node_cache,
                                 engine_path=engine_path,
                                 render_timeout_s=render_timeout_s,
                                 refresh_min_interval_s=refresh_min_s,
                                 echolink_host=bcfg.get("echolink_host"),
                                 landscape_out_path=landscape_out,
                                 landscape_ratio=landscape_ratio,
                                 spread_enabled=bool(
                                     bcfg.get("spread_enabled", True)),
                                 asl_enabled=asl_enabled,
                                 neato_path=neato_path,
                                 core_nodes=core_nodes,
                                 asl_label_style=str(
                                     bcfg.get("asl_label_style", "full")),
                                 vantage_ghost_grace_s=_int_opt(
                                     "vantage_ghost_grace_seconds", 60,
                                     floor=0),
                                 vantage_list_max=_int_opt(
                                     "vantage_list_max", 10))
        logger.info("Bubble map generator: ENABLED (engine=%s at %s, out=%s, "
                    "qrz_names=%s, refresh_on_link_change=%s, "
                    "render_timeout=%ds, asl_layout=%s, core_nodes=%d, "
                    "vantage_ghost_grace=%ds)",
                    engine, engine_path, out,
                    "on" if name_cache else "off",
                    "on" if bcfg.get("refresh_on_link_change", True) else "off",
                    render_timeout_s,
                    "on" if gen.asl_enabled else "off", len(core_nodes),
                    gen.vantage_ghost_grace_s)
        return gen
    except Exception as e:
        logger.error("bubble_map init failed (disabled this run): %s", e)
        return None


# --- selftest ----------------------------------------------------------------

def _selftest() -> int:            # pragma: no cover - developer tool
    import tempfile

    failures = []

    def check(name, cond):
        if cond:
            print(f"  [OK] {name}")
        else:
            failures.append(name)
            print(f"  [FAIL] {name}")

    topology = {
        12345: {"depth": 0, "parent": None, "role": "focus",
                "client_type": "allstar", "callsign": "N0CALL",
                "location": "Anytown/Texas", "frequency": "145.250",
                "tone": "162.2", "lat": 30.123456, "lon": -97.654321},
        23456: {"depth": 1, "parent": 12345, "role": "bridge",
                "client_type": "allstar", "callsign": "N0CALL",
                "location": "Anytown, TX", "frequency": "", "tone": "",
                "lat": None, "lon": None},
        34567: {"depth": 2, "parent": 23456, "role": "guest",
                "client_type": "allstar", "callsign": "K0GST",
                "location": "Elsewhere, TX", "frequency": "446.000",
                "tone": "", "lat": 31.0, "lon": -98.0},
        45678: {"depth": 2, "parent": 23456, "role": "unauthorized",
                "client_type": "allstar", "callsign": "K0BAD",
                "location": "Unknown", "frequency": "", "tone": "",
                "lat": None, "lon": None},
        56789: {"depth": 3, "parent": 45678, "role": "dragged_in",
                "client_type": "allstar", "callsign": "K0DRG",
                "location": "Unknown", "frequency": "", "tone": "",
                "lat": None, "lon": None},
        "ext_23456_EchoLink-999999": {
            "depth": 2, "parent": 23456, "role": "permitted_external",
            "client_type": "echolink", "callsign": "EchoLink-999999",
            "location": "External Connection", "frequency": "", "tone": "",
            "lat": None, "lon": None},
    }

    class _Snap:
        vantage_node = 23456
        # 3999999 matches the fixture's CONFIRMED ext_* EchoLink (ghost must
        # be suppressed); 3888888 is unconfirmed (speculative label).
        mesh_nodes = [12345, 23456, 34567, 45678, 56789, 447709,
                      3999999, 3888888]

    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)

        # --- NodeInfoCache -------------------------------------------------
        cache = NodeInfoCache(tdir / "nic.json", ttl_s=3600)
        cache.update_from_topology(topology)
        check("cache stores numeric nodes",
              cache.get(12345).get("frequency") == "145.250")
        check("cache skips ext_* keys",
              cache.get("ext_23456_EchoLink-999999") == {})
        # Non-clobbering merge: empty scan fields must not erase cached values
        cache.update_from_topology({
            12345: {"role": "focus", "callsign": "Unknown", "location": "Hub",
                    "frequency": "", "tone": "", "lat": None, "lon": None}})
        check("empty fields do not clobber",
              cache.get(12345).get("frequency") == "145.250"
              and cache.get(12345).get("callsign") == "N0CALL")
        # TTL expiry
        cache._cache["12345"]["ts"] = time.time() - 7200
        check("expired entry returns {}", cache.get(12345) == {})
        # Corrupt JSON -> empty start
        (tdir / "bad.json").write_text("{not json")
        check("corrupt cache file starts empty",
              NodeInfoCache(tdir / "bad.json")._cache == {})

        # --- build_dot golden checks --------------------------------------
        gen = BubbleMapGenerator(
            engine="twopi", out_path=tdir / "map.png",
            system_name="Test & Sons <sys>",
            node_cache=NodeInfoCache(tdir / "nic2.json", ttl_s=3600))
        gen.node_cache.update_from_topology(topology)
        dot = gen.build_dot(topology, _Snap(), timestamp="2026-01-01T00:00:00Z")
        check("ellipse everywhere", "shape=ellipse" in dot
              and "shape=circle" not in dot and "doublecircle" not in dot)
        check("focus peripheries=2", "peripheries=2" in dot)
        check("edge dir=both", "edge [dir=both, arrowsize=0.5];" in dot)
        check("HTML legend present", "<TABLE" in dot and "UNAUTHORIZED" in dot)
        check("system_name HTML-escaped",
              "Test &amp; Sons &lt;sys&gt;" in dot and "<sys>" not in dot)
        check("superset label line",
              "Node 12345 145.250 162.2" in dot)
        check("lat/lon 4-decimal line", "30.1235 -97.6543" in dot)
        check("no lat/lon line when absent",
              "Node 45678\\nK0BAD\\nUNAUTHORIZED" in dot)
        # 2026-07-21: vantage-only entries are LIST-ONLY (legend row), never
        # graph nodes attached to the vantage node.
        check("vantage-only node NOT drawn as graph node",
              '"447709"' not in dot and "filled,dotted" not in dot)
        check("vantage-only node in legend list row",
              "Reported by vantage 23456" in dot and "447709" in dot)
        # EchoLink wire-form handling (2026-07-04 late: Bennett's live catch)
        check("unconfirmed 3NNNNNN listed as translated EchoLink",
              "EchoLink-888888 (3888888)" in dot)
        check("confirmed EchoLink suppresses ghost entirely",
              "3999999" not in dot)
        # Landscape companion (2026-07-05)
        rdot = gen.build_dot(topology, None, timestamp="t", ratio=0.45)
        check("ratio attr present when requested",
              "ratio=0.45," in rdot)
        check("no ratio attr by default", "ratio=" not in dot)
        # Spread variant (2026-07-06)
        sdot2 = gen.build_dot(topology, None, timestamp="t", spread=True)
        check("spread uses prism overlap removal",
              "overlap=false" in sdot2 and "overlap=vpsc" not in sdot2)
        check("dense default uses vpsc",
              "overlap=vpsc" in dot and "overlap=false" not in dot)
        # Activity caption (2026-07-06)
        gen.activity_provider = lambda: "ACTIVE since 12:34 CDT & <t>"
        adot = gen.build_dot(topology, None, timestamp="t")
        check("activity line on caption, HTML-escaped",
              "ACTIVE since 12:34 CDT &amp; &lt;t&gt;" in adot)
        gen.activity_provider = lambda: (_ for _ in ()).throw(RuntimeError())
        bdot = gen.build_dot(topology, None, timestamp="t")
        check("broken activity provider never breaks the render",
              "<TABLE" in bdot)
        gen.activity_provider = None
        import shutil as _sh
        gen_w = BubbleMapGenerator(
            engine="neato", out_path=tdir / "p.png",
            engine_path=_sh.which("neato"),
            landscape_out_path=tdir / "w.png", landscape_ratio=0.45,
            spread_enabled=True)
        if gen_w.engine_path:
            got = gen_w.render(topology, None, timestamp="t")
            check("quad render writes all four files",
                  got is not None and (tdir / "p.png").exists()
                  and (tdir / "w.png").exists()
                  and (tdir / "p_spread.png").exists()
                  and (tdir / "w_spread.png").exists()
                  and gen_w.last_spread_png == tdir / "p_spread.png")
            # Audit 2026-07-21 S1: a POPULATED vantage legend row (numeric
            # entities, <BR/>, escaped hostile metachars) must be proven
            # against the real graphviz binary — a rejected entity fails
            # EVERY render exactly when vantage-only nodes exist.
            class _SnapHostile:
                vantage_node = 23456
                mesh_nodes = [12345, 23456, 447709, 3888888,
                              'x&<>"\'y', "EV]; evil -- x ["] \
                    + [600000 + i for i in range(12)]
            hpng = gen_w.render(topology, _SnapHostile(),
                                timestamp="t & <hostile>")
            check("populated+hostile legend row renders via graphviz",
                  hpng is not None and (tdir / "p.png").exists())
            hldot = gen_w.build_dot(topology, _SnapHostile(), timestamp="t")
            check("hostile list entries escaped in legend",
                  "x&amp;&lt;&gt;&quot;&#x27;y" in hldot
                  and 'x&<>"\'y' not in hldot
                  and "(+" in hldot)
        else:
            print("  [SKIP] quad render (graphviz not installed here)")

        # Speculative attachment to the designated EchoLink gateway — the
        # ONLY vantage-only case still drawn as a graph node (2026-07-05
        # decision preserved through the 2026-07-21 list-only change).
        gen.echolink_host = "12345"
        gdot = gen.build_dot(topology, _Snap(), timestamp="t")
        check("unconfirmed EchoLink attaches to echolink_host",
              '"12345" -- "3888888"' in gdot
              and '"23456" -- "3888888"' not in gdot
              and "filled,dotted" in gdot)
        gen.echolink_host = "77777"      # gateway off-map -> list, not vantage
        fdot = gen.build_dot(topology, _Snap(), timestamp="t")
        check("gateway absent -> listed, never drawn at vantage",
              '-- "3888888"' not in fdot
              and "EchoLink-888888 (3888888)" in fdot)
        gen.echolink_host = None

        # Sustained-ghost filter (Bennett 2026-07-21): age >= grace AND a
        # full scan completed since first sight -> suppressed everywhere.
        gen._vantage_first_seen["447709"] = (time.monotonic() - 120, -1)
        supdot = gen.build_dot(topology, _Snap(), timestamp="t")
        check("sustained ghost suppressed from graph and list",
              "447709" not in supdot and "unconfirmed" in supdot
              and "suppressed" in supdot)
        check("mixed list uses 'plus N unconfirmed' wording",
              "plus 1 unconfirmed" in supdot and "none" not in supdot)
        gen._vantage_first_seen["3888888"] = (time.monotonic() - 120, -1)
        alldot = gen.build_dot(topology, _Snap(), timestamp="t")
        check("all-suppressed list drops the 'none' placeholder",
              "none" not in alldot
              and "2 unconfirmed &#8805;60s &#8212; suppressed" in alldot)
        gen._vantage_first_seen["447709"] = (time.monotonic() - 120,
                                             gen._scan_generation)
        agedot = gen.build_dot(topology, _Snap(), timestamp="t")
        check("aged node without a confirming scan stays listed",
              "447709" in agedot)
        gen._vantage_first_seen["447709"] = (time.monotonic(), -1)
        frdot = gen.build_dot(topology, _Snap(), timestamp="t")
        check("scan-passed node within grace stays listed",
              "447709" in frdot)

        class _SnapGone:
            vantage_node = 23456
            mesh_nodes = [12345, 23456]
        gen.build_dot(topology, _SnapGone(), timestamp="t")
        check("first-seen state purges on mesh departure",
              "447709" not in gen._vantage_first_seen)
        check("stats reflect last build",
              gen.vantage_overlay_stats()["listed"] == 0
              and gen.vantage_overlay_stats()["tracked"] == 0
              and gen.vantage_overlay_stats()["grace_s"] == 60)

        # List cap: vantage_list_max entries shown, remainder counted.
        class _SnapMany:
            vantage_node = 23456
            mesh_nodes = [12345, 23456] + [500000 + i for i in range(15)]
        mdot = gen.build_dot(topology, _SnapMany(), timestamp="t")
        check("legend list capped with +N more",
              "(+5 more)" in mdot and "500000" in mdot)
        check("splines=line + ranksep", "splines=line" in dot
              and 'ranksep="1.0"' in dot)

        # DOT injection: hostile remote-controlled strings (audit v2, S2).
        # A callsign/location may contain quotes/backslashes/HTML metachars
        # and control chars; none may escape the quoted-label context.
        hostile = {
            66666: {"depth": 1, "parent": 12345, "role": "guest",
                    "client_type": "allstar",
                    "callsign": 'EV"], color=red]; evil -- x ["',
                    "location": 'a\\b"<script>&amp;\r\nend',
                    "frequency": '14"5', "tone": 'T"1',
                    "lat": None, "lon": None},
        }
        hdot = gen.build_dot({**topology, **hostile}, None, timestamp="t")
        check("hostile quote cannot break label context",
              '\\"' in hdot and 'color=red]; evil' not in
              hdot.replace('EV\\"], color=red]; evil', ""))
        check("hostile control chars stripped", "\r" not in hdot
              and "\nend" not in hdot.replace("\\nend", ""))
        try:
            proc = subprocess.run(
                [shutil.which("twopi") or "/opt/homebrew/bin/twopi", "-Tpng",
                 "-o", str(tdir / "hostile.png")],
                input=hdot.encode(), capture_output=True, timeout=20)
            check("hostile DOT still renders (no syntax break)",
                  proc.returncode == 0 and (tdir / "hostile.png").exists())
        except FileNotFoundError:
            print("  [SKIP] hostile render (graphviz not installed here)")

        # Spoke stagger + label clamps (density feedback 2026-07-04)
        check("every edge carries a len target", all(
            " -- " not in ln or "len=" in ln for ln in dot.split("\n")))
        star = {**topology}
        for i in range(4):      # 5 focus spokes total (incl. 23456)
            star[70000 + i] = {"depth": 1, "parent": 12345, "role": "regular",
                               "client_type": "allstar",
                               "callsign": f"W{i}STR", "location": "Town, TX",
                               "frequency": "AllStar Gateway 1 Open Std ASL Port"
                               if i == 0 else "146.520",
                               "tone": "", "lat": None, "lon": None}
        sdot = gen.build_dot(star, None, timestamp="t")
        lens = [seg.split("len=")[1].split("]")[0].split(",")[0]
                for seg in sdot.split("\n") if " -- " in seg and "len=" in seg]
        check("focus spokes alternate short/long",
              "0.8" in lens and "1.4" in lens and "1.0" in lens)

        # --- Monitor (one-way) link rendering (2026-09-06) ------------------
        mono = copy.deepcopy(topology)
        mono[34567]["link_mode_to_parent"] = "R"      # guest monitors bridge
        mono[34567]["link_mode_from_parent"] = "T"    # bridge always says T
        mono[45678]["link_mode_to_parent"] = "T"
        mono[45678]["link_mode_from_parent"] = "R"    # bridge monitors offender
        mono[56789]["link_mode_to_parent"] = "L"      # both ends listen
        mono[56789]["link_mode_from_parent"] = "R"
        mono[23456]["link_mode_to_parent"] = "C"      # still connecting
        mono[23456]["link_mode_from_parent"] = "T"
        mono[67890] = {"depth": 3, "parent": 34567, "role": "monitored_by_guest",
                       "client_type": "allstar", "callsign": "QQ0QQM",
                       "location": "Far Away", "frequency": "", "tone": "",
                       "lat": None, "lon": None,
                       "link_mode_to_parent": "T",       # outside node says T
                       "link_mode_from_parent": "R"}     # the guest monitors it
        mdot = gen.build_dot(mono, _Snap(), timestamp="t")
        edge = {ln.split(" -- ")[1].split('"')[1]: ln
                for ln in mdot.split("\n") if " -- " in ln and "len=" in ln}
        check("child-listener: dashed purple open arrow at child",
              'style=dashed' in edge["34567"] and _EDGE_MONITOR in edge["34567"]
              and "dir=forward, arrowhead=onormal" in edge["34567"]
              and "arrowtail" not in edge["34567"])
        check("parent-listener on violation: red wins, dashed, arrow at parent",
              _EDGE_VIOLATION in edge["45678"] and _EDGE_MONITOR not in edge["45678"]
              and "style=dashed" in edge["45678"] and "penwidth=2" in edge["45678"]
              and "dir=back, arrowtail=onormal" in edge["45678"])
        check("both-listener: dir=both with two open heads",
              "dir=both, arrowhead=onormal, arrowtail=onormal" in edge["56789"])
        check("connecting: dotted, no arrows",
              "style=dotted" in edge["23456"] and "dir=none" in edge["23456"]
              and "dashed" not in edge["23456"])
        check("T/None edges unchanged (no dir override)",
              "dir=" not in edge["ext_23456_EchoLink-999999"]
              and _EDGE_EXTERNAL in edge["ext_23456_EchoLink-999999"])
        check("each edge key emitted once",
              all(ln.count("color=") <= 1 and ln.count("style=") <= 1
                  and ln.count("dir=") <= 1 for ln in edge.values()))
        check("len= still last on every edge",
              all(ln.rstrip("];").split(",")[-1].strip().startswith("len=")
                  for ln in edge.values()))
        check("overlay edges dir=none", all(
            "dir=none" in ln for ln in mdot.split("\n")
            if " -- " in ln and "style=dotted" in ln and "#757575" in ln))
        check("legend names monitor links", "monitor: dashed" in mdot)
        check("monitored-by-guest legend row only when such a node exists",
              "monitored by guest" in mdot and "monitored by guest" not in dot)
        check("monitored_by_guest: own fill, purple dashed, arrow at the guest",
              'fillcolor="#ede7f6"' in mdot and "monitored by guest" in mdot
              and _EDGE_MONITOR in edge["67890"] and "style=dashed" in edge["67890"]
              and "dir=back, arrowtail=onormal" in edge["67890"]
              and _EDGE_VIOLATION not in edge["67890"])
        try:
            proc = subprocess.run(
                [shutil.which("neato") or "/opt/homebrew/bin/neato", "-Tpng",
                 "-o", str(tdir / "monitor.png")],
                input=mdot.encode(), capture_output=True, timeout=20)
            check("monitor-link DOT renders", proc.returncode == 0
                  and (tdir / "monitor.png").exists())
            sample = os.environ.get("BUBBLE_SELFTEST_SAMPLE")
            if sample and proc.returncode == 0:
                shutil.copy(tdir / "monitor.png", sample)
                print(f"  [INFO] sample monitor-link render: {sample}")
        except FileNotFoundError:
            print("  [SKIP] monitor render (graphviz not installed here)")
        check("junk-wide frequency clamped",
              "…" in sdot and "ASL Port" not in sdot)
        jt = gen._node_label(88888, {"role": "regular", "callsign": "K1JNK",
                                     "location": "Town", "frequency": "446.000",
                                     "tone": "Open Std ASL Port",
                                     "lat": None, "lon": None})
        check("non-CTCSS tone dropped", "Open" not in jt and "446.000" in jt)
        jt2 = gen._node_label(88889, {"role": "regular", "callsign": "K2JNK",
                                      "location": "Town", "frequency": "146.52",
                                      "tone": "162.2", "lat": None, "lon": None})
        check("real CTCSS tone kept", "162.2" in jt2)

        # Vantage-only list entry enriched from cache (callsign appended)
        gen.node_cache.update_from_topology({
            447709: {"role": "guest", "callsign": "K0VAN",
                     "location": "Someplace, TX", "frequency": "446.500",
                     "tone": "", "lat": None, "lon": None}})
        dot2 = gen.build_dot(topology, _Snap(), timestamp="t")
        check("vantage-only list entry enriched from cache",
              "447709 K0VAN" in dot2)

        # --- compact labels + core coloring + ASL layout (2026-07-18) ------
        gen.name_cache = QrzNameCache(object(), tdir / "q2.json")
        gen.name_cache._cache["K0GST"] = {"name": "Cached Op",
                                          "ts": time.time()}
        info_g = {"role": "guest", "callsign": "K0GST",
                  "location": "Elsewhere, TX", "frequency": "446.000",
                  "tone": "", "lat": 31.0, "lon": -98.0}
        full = gen._node_label(34567, info_g)
        comp = gen._node_label(34567, info_g, label_style="compact")
        check("compact folds callsign+location",
              "K0GST · Elsewhere, TX" in comp)
        check("compact drops QRZ name line", "Cached Op" not in comp)
        check("compact keeps lat/lon", "31.0000 -98.0000" in comp)
        check("full label keeps QRZ name line",
              "K0GST\\nCached Op\\nElsewhere, TX" in full)
        gen.name_cache = None
        check("compact conditional: callsign only",
              gen._node_label(1, {"role": "guest", "callsign": "K1X",
                                  "location": "Unknown"},
                              label_style="compact").endswith("K1X"))
        check("compact conditional: location only", "· " not in
              gen._node_label(2, {"role": "guest", "callsign": "Unknown",
                                  "location": "Someplace, TX"}, label_style="compact"))
        longloc = gen._node_label(3, {"role": "guest", "callsign": "K2X",
                                      "location": "L" * 120}, label_style="compact")
        check("compact clamps hostile location",
              "…" in longloc and "L" * 29 not in longloc)
        comp_bad = gen._node_label(45678, topology[45678], label_style="compact")
        check("compact keeps UNAUTHORIZED line",
              comp_bad.endswith("UNAUTHORIZED"))
        cdot = gen.build_dot(topology, None, timestamp="t", label_style="compact")
        check("compact build_dot folds", "K0GST · Elsewhere, TX" in cdot)

        # Adaptive fold (Bennett 2026-07-19): narrow pairs fold, wide split
        ad_short = gen._node_label(5, {"role": "guest", "callsign": "K5X",
                                       "location": "Hutto/TX"},
                                   label_style="adaptive")
        ad_wide = gen._node_label(6, {"role": "guest", "callsign": "KD5LONG",
                                      "location": "Somewhere Far Away, TX"},
                                  label_style="adaptive")
        check("adaptive folds narrow pair", "K5X · Hutto/TX" in ad_short)
        check("adaptive splits wide pair", "·" not in ad_wide
              and "KD5LONG\\nSomewhere Far Away, TX" in ad_wide)
        gen.name_cache = QrzNameCache(object(), tdir / "q3.json")
        gen.name_cache._cache["KD5LONG"] = {"name": "Op Name",
                                            "ts": time.time()}
        ad_q = gen._node_label(6, {"role": "guest", "callsign": "KD5LONG",
                                   "location": "Somewhere Far Away, TX"},
                               label_style="adaptive")
        check("adaptive split still drops QRZ name", "Op Name" not in ad_q)
        gen.name_cache = None
        check("bad label style falls back to full",
              BubbleMapGenerator(engine="neato", out_path=tdir / "x.png",
                                 asl_label_style="bogus"
                                 ).asl_label_style == "full")

        # 60222-class miscolor fix: regular NOT in core_nodes -> guest white
        gen.core_nodes = {"70000"}
        core_dot = gen.build_dot(star, None, timestamp="t")
        l70000 = next(l for l in core_dot.splitlines() if '"70000"' in l
                      and " -- " not in l)
        l70001 = next(l for l in core_dot.splitlines() if '"70001"' in l
                      and " -- " not in l)
        check("core regular stays green", "#c8e6c9" in l70000)
        check("non-core regular renders guest-white", "#ffffff" in l70001)
        gen.core_nodes = set()
        legacy_dot = gen.build_dot(star, None, timestamp="t")
        l70001b = next(l for l in legacy_dot.splitlines() if '"70001"' in l
                       and " -- " not in l)
        check("empty core_nodes keeps legacy green", "#c8e6c9" in l70001b)

        # _pin_dot: patches + full-coverage assertion
        if asl_placer is not None:
            names = [ln.strip().split("[")[0].strip().strip('"').strip()
                     for ln in cdot.splitlines()
                     if ln.strip().startswith('"') and " -- " not in ln.strip()
                     and "[" in ln]
            allpos = {n_: (1.0 * i, 2.0) for i, n_ in enumerate(names)}
            routed = gen._pin_dot(cdot, allpos)
            check("_pin_dot pins every node",
                  routed.count("pos=") == len(names)
                  and "overlap=true" in routed and "splines=true" in routed
                  and "overlap=vpsc" not in routed)
            try:
                gen._pin_dot(cdot, {k: v for k, v in allpos.items()
                                    if k != names[0]})
                check("_pin_dot coverage assert trips", False)
            except asl_placer.PlacementError:
                check("_pin_dot coverage assert trips", True)
            # 7b C1 regression: remote-controlled label text containing
            # " -- " must not make a node line parse as an edge (it would
            # skip pinning and silently collapse the node to the origin).
            h2 = {**topology,
                  77777: {"depth": 2, "parent": 23456, "role": "guest",
                          "client_type": "allstar", "callsign": "K7X",
                          "location": "Austin -- TX", "frequency": "",
                          "tone": "", "lat": None, "lon": None}}
            h2dot = gen.build_dot(h2, None, timestamp="t")
            h2names = set()
            for ln in h2dot.splitlines():
                m2 = BubbleMapGenerator._NODE_STMT.match(ln)
                if m2:
                    h2names.add(re.sub(r"\\(.)", r"\1", m2.group(1)))
            check("C1: ' -- ' label node still parsed as node",
                  "77777" in h2names)
            h2routed = gen._pin_dot(h2dot, {n_: (1.0, 1.0)
                                            for n_ in h2names})
            l77 = next(ln for ln in h2routed.splitlines()
                       if ln.strip().startswith('"77777"'))
            check("C1: ' -- ' label node gets pinned", "pos=" in l77)
            try:
                gen._pin_dot(h2dot, {**{n_: (1.0, 1.0) for n_ in h2names},
                                     "ghost": (0.0, 0.0)})
                check("C1: surplus placement key trips mismatch", False)
            except asl_placer.PlacementError:
                check("C1: surplus placement key trips mismatch", True)
        else:
            print("  [SKIP] _pin_dot checks (asl_placer unavailable)")

        # ASL end-to-end + fallback counter (needs graphviz + asl_placer)
        neato_bin = shutil.which("neato")
        if neato_bin and asl_placer is not None:
            gen_a = BubbleMapGenerator(
                engine="neato", out_path=tdir / "asl_main.png",
                engine_path=neato_bin,
                node_cache=NodeInfoCache(tdir / "nic3.json", ttl_s=3600),
                asl_enabled=True, neato_path=neato_bin)
            got = gen_a._render_asl(topology, None, "t",
                                    tdir / "asl_map.png",
                                    deadline=time.monotonic() + 20)
            check("asl render writes PNG", got is not None
                  and (tdir / "asl_map.png").exists()
                  and gen_a.asl_fallback_count == 0)
            check("asl health: violation splits components",
                  (gen_a.asl_last_health or {}).get("components") == 2)
            # Forced failure -> counter + vpsc fallback in render_evidence
            gen_a.neato_path = str(tdir / "no_such_binary")
            ev = gen_a.render_evidence(topology, tdir / "ev.png",
                                       timestamp="t")
            check("asl failure falls back to vpsc evidence",
                  ev is not None and (tdir / "ev.png").exists()
                  and gen_a.asl_fallback_count == 1
                  and gen_a.asl_last_error is not None)
            h = gen_a.asl_health()
            check("asl health block populated",
                  h is not None and h["fallback_count"] == 1
                  and h["enabled"] is True)
        else:
            print("  [SKIP] asl end-to-end (graphviz/asl_placer missing)")

        # --- QRZ readonly mode ---------------------------------------------
        class _RaisingQrz:
            def lookup(self, cs):
                raise AssertionError("QRZ lookup called in readonly mode")
        qrz = QrzNameCache(_RaisingQrz(), tdir / "qrz.json", per_scan_budget=3)
        qrz._cache["K0GST"] = {"name": "Cached Op", "ts": time.time()}
        qrz.begin_scan(readonly=True)
        check("readonly QRZ serves cache", qrz.name_for("K0GST") == "Cached Op")
        try:
            got = qrz.name_for("W1ABC")     # uncached: must NOT lookup
            check("readonly QRZ never looks up", got == "")
        except AssertionError:
            check("readonly QRZ never looks up", False)

        # --- refresh scheduling ---------------------------------------------
        rendered = []
        gen2 = BubbleMapGenerator(engine="twopi", out_path=tdir / "m2.png")
        gen2._render_locked = lambda *a, **k: rendered.append(1) or None
        gen2.request_refresh(_Snap())
        check("refresh no-ops before first scan", rendered == [])
        gen2._last_topology = dict(topology)
        gen2._last_render_started = 0.0
        gen2.request_refresh(_Snap())
        if gen2._refresh_thread is not None:
            gen2._refresh_thread.join(5)    # isolate DEBOUNCE from single-
        gen2.request_refresh(_Snap())       # flight: thread done, still
        time.sleep(0.2)                     # within the 10s window
        check("debounce collapses burst to one render", len(rendered) == 1)

    print(f"\n{'PASS' if not failures else 'FAIL'}: "
          f"{len(failures)} failure(s) {failures or ''}")
    return 1 if failures else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print("Usage: python3 bubble_map_gen.py --selftest", file=sys.stderr)
    sys.exit(2)
