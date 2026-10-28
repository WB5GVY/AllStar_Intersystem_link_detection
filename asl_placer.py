"""ASL-style custom placer — pure geometry, no subprocesses, no daemon imports.

Ported 2026-07-18 from the diagnostically-validated prototype (scratchpad
diagB/proto_exits.py; bit-exact winner reproduction, five multi-exit
topologies, full pin coverage — see the productionization plan in
Claude-shared/2026-07-18_1850_asl_placer_productionization_plan.md).

Places a scan topology the way ASL.org's official map does: each system laid
out as per-hub equal-angle radial stars (full-360° rings ONLY at component
roots, outward wedges at non-root hubs), foreign systems as separate clusters
translated along their bridge-exit rays. Deterministic throughout — the only
"organic" irregularity is a fixed alternating jitter, so identical topology
always yields identical positions.

Component split is role-driven: every edge whose CHILD has role
"unauthorized" is cut; the child and its subtree (dragged_in nodes) form one
foreign cluster. Zero cuts -> single component (the everyday live map), K
cuts -> K foreign clusters, including multiple cuts per attach node and cuts
directly under the focus (each exit is a phantom child fed through the same
equal-angle slot machinery as real children, so exits can never collide with
child arcs by construction).

Failure policy: anything that cannot be placed cleanly raises PlacementError.
The caller (bubble_map_gen) treats ANY failure as "fall back to the
production vpsc layout" — evidence emails must never be blocked by layout
problems. The cross-cluster corridor scan is deliberately OBSERVATIONAL
(warn, don't fail): a chain interleave with zero node overlaps is still a
valid, readable map, and ASL.org's own maps show crossings at scale.

Geometry units are inches (graphviz -Tplain convention); the caller converts
to points (x72) when pinning positions into DOT.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict

# --- Winner recipe (2026-07-18 style convergence, DIST 0.86 vs ASL corpus) ---
CHORD_MULT = 1.0          # chord floor = CHORD_MULT * median node width
JITTER = 0.1              # +/- fraction of the slot angle, alternating
EXIT_PREF_DEG = -12.0     # primary exit tilt at the home root (landscape lean)
HULL_GAP_IN = 0.6         # clear space between cluster hulls along the exit ray
PAD_IN = 0.12             # inter-ellipse clearance pad inside rings
# Overlap margin, unified (plan v1.1 A2 resolution; D6 verified the winner is
# bit-identical at 0.95, so one constant replaces the harness's 0.92/0.95).
MARGIN = 0.95
GROW_FACTOR = 1.12        # assemble-and-grow ring inflation per iteration
GROW_MAX_ITER = 12        # loud failure beyond this (plan S2 fix)
PUSH_STEP_IN = 0.5        # cluster push-out step on merge overlap
PUSH_MAX = 12             # loud failure beyond this (plan S1 fix)
THRU_SHRINK = 0.9         # sightline test ellipse shrink (corridor scan)
ROTATE_STEP_DEG = 15      # single-component rotation pass granularity
ASPECT_TARGET = 1.7       # ASL.org landscape aspect (style corpus)


class PlacementError(RuntimeError):
    """Raised when a clean placement cannot be produced. The caller falls
    back to the production vpsc layout — never rendered around."""


def ell_radius(w: float, h: float, ang: float) -> float:
    """Radius of an axis-aligned ellipse (full w,h) along direction ang."""
    a, b = w / 2, h / 2
    return math.hypot(a * math.cos(ang), b * math.sin(ang))


def ellipses_overlap(pos: dict, sizes: dict, margin: float = MARGIN) -> bool:
    """True if any two node ellipses overlap (axis-aligned approximation —
    the same test the layout was validated with)."""
    ns = list(pos)
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            a, b = ns[i], ns[j]
            dx = pos[a][0] - pos[b][0]
            dy = pos[a][1] - pos[b][1]
            rx = (sizes[a][0] + sizes[b][0]) / 2 * margin
            ry = (sizes[a][1] + sizes[b][1]) / 2 * margin
            if (dx / rx) ** 2 + (dy / ry) ** 2 < 1:
                return True
    return False


def parse_plain(plain_text: str):
    """Parse graphviz -Tplain output -> ({name: (x, y)}, {name: (w, h)}),
    all in inches. Tolerates quoted names."""
    pos, sizes = {}, {}
    for line in plain_text.splitlines():
        f = line.split()
        if f and f[0] == "node" and len(f) >= 6:
            name = f[1].strip('"')
            pos[name] = (float(f[2]), float(f[3]))
            sizes[name] = (float(f[4]), float(f[5]))
    return pos, sizes


def _is_phantom(c) -> bool:
    return isinstance(c, str) and c.startswith("__exit_")


def _tree_edges(tree_parent: dict) -> list:
    """[(child, parent)] for every node with a parent."""
    return [(c, p) for c, p in tree_parent.items() if p is not None]


def find_cuts(tree_parent: dict, roles: dict) -> list:
    """Sorted [(parent, child)] for every edge whose child is unauthorized."""
    return sorted((p, c) for c, p in tree_parent.items()
                  if p is not None and roles.get(c) == "unauthorized")


def _subtree(kids: dict, root: str) -> set:
    out, stack = set(), [root]
    while stack:
        x = stack.pop()
        out.add(x)
        stack.extend(kids[x])
    return out


def place_tree(tree_parent: dict, comp: set, root: str, sizes: dict,
               med_w: float, exits: dict | None = None,
               exit_pref: float = 0.0, root_incoming: float | None = None,
               chord_mult: float = CHORD_MULT, pad: float = PAD_IN,
               jitter: float = JITTER):
    """Recursive equal-angle placer for one tree component (the validated
    generalized form). exits maps {node: [cluster_key, ...]}; each exit is a
    phantom child occupying a real slot. Returns (pos, {cluster_key: angle}).
    Raises PlacementError if assemble-and-grow cannot clear overlaps."""
    exits = exits or {}
    kids = defaultdict(list)
    for c, p in tree_parent.items():
        if p is not None and c in comp and p in comp:
            kids[p].append(c)
    for p in kids:
        kids[p].sort()          # determinism regardless of dict order
    chord_floor = chord_mult * med_w
    ph_key = {f"__exit_{k}__": k
              for keys in exits.values() for k in keys}

    def phantoms_at(node):
        return [f"__exit_{k}__" for k in exits.get(node, [])]

    def ell_max(nd):
        return sizes[nd][0] / 2

    def build(node, incoming, is_root=False):
        ch = kids[node]
        phs = phantoms_at(node)
        if not ch and not phs:
            return {node: (0.0, 0.0)}, ell_max(node), {}
        slots = {}
        if phs and incoming is not None and not is_root:
            # EXIT-CARRIER: first phantom exactly opposite the incoming edge
            # (straight bridge chain); remaining phantoms join the real
            # children in the side arcs through the same machinery.
            slots[phs[0]] = incoming + math.pi
            rest = ch + phs[1:]
            d1 = (len(rest) + 1) // 2
            d2 = len(rest) - d1
            for i in range(d1):
                slots[rest[i]] = incoming + math.pi * (i + 1) / (d1 + 1)
            for i in range(d2):
                slots[rest[d1 + i]] = incoming - math.pi * (i + 1) / (d2 + 1)
        elif incoming is not None and not is_root:
            # Non-root hub without exits: outward wedge (twopi-like; full
            # rings belong to component roots only — ASL phenomenology).
            d = len(ch)
            beta = math.radians(50) if d <= 4 else math.pi / (d + 1)
            out = incoming + math.pi
            zig_src = sorted(ch, key=lambda c: (-sizes[c][0], c))
            zig, lo, hi = [], 0, len(zig_src) - 1
            while lo <= hi:
                zig.append(zig_src[lo]); lo += 1
                if lo <= hi:
                    zig.append(zig_src[hi]); hi -= 1
            for k, c in enumerate(zig):
                ang = out + (k - (d - 1) / 2) * beta
                if jitter:
                    ang += (1 if k % 2 else -1) * jitter * beta
                slots[c] = ang
        else:
            # ROOT RING: full 360, one slot per child/phantom (+ incoming).
            n_slots = len(ch) + len(phs) + (1 if incoming is not None else 0)
            alpha = 2 * math.pi / n_slots
            base = incoming if incoming is not None else exit_pref

            def carries(c):
                stack = [c]
                while stack:
                    x = stack.pop()
                    if exits.get(x):
                        return True
                    stack.extend(kids[x])
                return False
            exit_children = [c for c in ch if carries(c)]
            subtrees = sorted((c for c in ch if kids[c]
                               and c not in exit_children),
                              key=lambda c: (-len(kids[c]), c))
            leaves = sorted((c for c in ch if not kids[c]
                             and c not in exit_children),
                            key=lambda c: (-sizes[c][0], c))
            zig, lo, hi = [], 0, len(leaves) - 1
            while lo <= hi:
                zig.append(leaves[lo]); lo += 1
                if lo <= hi:
                    zig.append(leaves[hi]); hi -= 1
            rest = zig
            for stree in subtrees:      # heavy subtrees mid-list
                rest.insert(len(rest) // 2, stree)
            for c in reversed(exit_children):   # exit-carriers lead
                rest.insert(0, c)
            order = list(rest)
            if phs:
                # First phantom takes the lead slot (== the original
                # single-exit placement); extras spaced so two exits are
                # never adjacent.
                step = max(1, (len(order) + len(phs)) // len(phs))
                for i, ph in enumerate(phs):
                    order.insert(min(i * step, len(order)), ph)
            k0 = 1 if incoming is not None else 0
            for k, c in enumerate(order):
                ang = base + (k + k0) * alpha
                if jitter and not _is_phantom(c):
                    ang += (1 if k % 2 else -1) * jitter * alpha
                slots[c] = ang
        # Recurse real children first (their extents size this ring).
        sub = {c: build(c, slots[c] + math.pi) for c in ch}
        corridor = med_w / 2

        def half_extent(c, direction):
            if _is_phantom(c):
                return corridor
            return ell_radius(*sizes[c], direction)
        items = sorted(slots.items(), key=lambda kv: (kv[1] % (2 * math.pi),
                                                      str(kv[0])))
        if incoming is not None:
            items.append(("__in__", incoming))
            items.sort(key=lambda kv: (kv[1] % (2 * math.pi), str(kv[0])))
        r = chord_floor / (2 * math.sin(math.pi / max(2, len(items))))
        for i, (c, ang) in enumerate(items):
            nxt, ang2 = items[(i + 1) % len(items)]
            gap_ang = (ang2 - ang) % (2 * math.pi)
            if gap_ang < 1e-6:
                continue
            cdir = (ang + gap_ang / 2) + math.pi / 2
            he1 = corridor if c == "__in__" else half_extent(c, cdir)
            he2 = corridor if nxt == "__in__" else half_extent(nxt, cdir)
            need = he1 + he2 + pad
            if gap_ang < math.pi:
                r = max(r, need / (2 * math.sin(gap_ang / 2)))
        for c, ang in slots.items():    # hub clearance along each spoke
            if _is_phantom(c):
                continue
            pos_c = sub[c][0]
            toward = max((-(x * math.cos(ang) + y * math.sin(ang))) +
                         ell_radius(*sizes[n_], ang)
                         for n_, (x, y) in pos_c.items())
            r = max(r, ell_radius(*sizes[node], ang) + toward + pad)
        # NN in a ring is min(spoke, chord): the spoke must meet the floor too.
        r = max(r, chord_floor)

        def assemble(rr):
            p = {node: (0.0, 0.0)}
            for c in ch:
                cx, cy = rr * math.cos(slots[c]), rr * math.sin(slots[c])
                for n_, (x, y) in sub[c][0].items():
                    p[n_] = (cx + x, cy + y)
            return p
        pos = assemble(r)
        grown = 0
        while ellipses_overlap(pos, sizes, margin=MARGIN):
            grown += 1
            if grown > GROW_MAX_ITER:
                raise PlacementError(
                    f"assemble-and-grow at hub {node}: overlaps persist "
                    f"after {GROW_MAX_ITER} iterations")
            r *= GROW_FACTOR
            pos = assemble(r)
        ea = {ph_key[p_]: slots[p_] for p_ in phs}
        for c in ch:
            ea.update(sub[c][2])
        big_r = max(math.dist((0, 0), p) + ell_max(n_)
                    for n_, p in pos.items())
        return pos, big_r, ea

    pos, _, ea = build(root, root_incoming, is_root=True)
    return pos, ea


def _segment_hits_ellipse(a, b, center, w, h, shrink=THRU_SHRINK,
                          samples=24) -> bool:
    (ax, ay), (bx, by), (x, y) = a, b, center
    rx, ry = w / 2 * shrink, h / 2 * shrink
    if rx <= 0 or ry <= 0:
        return False
    return any(((ax + (bx - ax) * s / samples - x) / rx) ** 2 +
               ((ay + (by - ay) * s / samples - y) / ry) ** 2 < 1
               for s in range(1, samples))


def _segments_cross(p1, q1, p2, q2) -> bool:
    def ccw(p, q, r):
        return (r[1] - p[1]) * (q[0] - p[0]) > (q[1] - p[1]) * (r[0] - p[0])
    return (ccw(p1, p2, q2) != ccw(q1, p2, q2)
            and ccw(p1, q1, p2) != ccw(p1, q1, q2))


def corridor_scan(pos: dict, sizes: dict, clusters: dict,
                  tree_parent: dict) -> list:
    """Observational cross-cluster defect scan (plan v1.3 delta 2).
    For every ordered cluster pair (X, Y): X-internal edges (both endpoints
    in X — join edges excluded by construction) vs Y-node ellipses (thru),
    plus X-internal vs Y-internal edge crossings. Returns a list of
    ("thru"|"xing", detail) tuples; empty on the validated winner."""
    edges_of = {key: [(c, p) for c, p in _tree_edges(tree_parent)
                      if c in comp and p in comp and c in pos and p in pos]
                for key, comp in clusters.items()}
    hits = []
    keys = sorted(clusters)
    for xk in keys:
        for yk in keys:
            if xk == yk:
                continue
            for a, b in edges_of[xk]:
                for node in clusters[yk]:
                    if node not in pos:
                        continue
                    if _segment_hits_ellipse(pos[a], pos[b], pos[node],
                                             *sizes[node]):
                        hits.append(("thru", f"{a}--{b} through {node}"))
            if xk < yk:         # unordered pair once for crossings
                for a, b in edges_of[xk]:
                    for c, d in edges_of[yk]:
                        if {a, b} & {c, d}:
                            continue
                        if _segments_cross(pos[a], pos[b], pos[c], pos[d]):
                            hits.append(("xing", f"{a}--{b} x {c}--{d}"))
    return hits


def _defect_count(pos, sizes, edges) -> int:
    """thru + crossings over the given edge set (rotation acceptance)."""
    thru = 0
    for a, b in edges:
        for k, c in pos.items():
            if k in (a, b):
                continue
            if _segment_hits_ellipse(pos[a], pos[b], c, *sizes[k]):
                thru += 1
                break
    x = 0
    for i in range(len(edges)):
        for j in range(i + 1, len(edges)):
            a1, b1 = edges[i]
            a2, b2 = edges[j]
            if {a1, b1} & {a2, b2}:
                continue
            if _segments_cross(pos[a1], pos[b1], pos[a2], pos[b2]):
                x += 1
    return thru + x


def rotate_landscape(pos: dict, sizes: dict, edges: list):
    """Single-component rotation pass (plan v1.3 delta 3): rotate node
    centers (labels stay axis-aligned) in ROTATE_STEP_DEG steps; among
    angles that are overlap-free at MARGIN and whose defect count does not
    exceed the unrotated baseline, pick the aspect (raw dx/dy) closest to
    ASPECT_TARGET. The unrotated layout always qualifies, so this never
    fails — worst case it returns the input. Returns (pos, degrees)."""
    if len(pos) < 3:
        return pos, 0
    cx = sum(p[0] for p in pos.values()) / len(pos)
    cy = sum(p[1] for p in pos.values()) / len(pos)
    baseline = _defect_count(pos, sizes, edges)

    def aspect_of(pp):
        xs = [p[0] for p in pp.values()]
        ys = [p[1] for p in pp.values()]
        dy = (max(ys) - min(ys)) or 1e-9
        return (max(xs) - min(xs)) / dy

    best = (abs(aspect_of(pos) - ASPECT_TARGET), 0, pos)
    for deg in range(-90 + ROTATE_STEP_DEG, 90, ROTATE_STEP_DEG):
        if deg == 0:
            continue
        t = math.radians(deg)
        c, s = math.cos(t), math.sin(t)
        rp = {n: (cx + (x - cx) * c - (y - cy) * s,
                  cy + (x - cx) * s + (y - cy) * c)
              for n, (x, y) in pos.items()}
        if ellipses_overlap(rp, sizes, margin=MARGIN):
            continue
        if _defect_count(rp, sizes, edges) > baseline:
            continue
        key = abs(aspect_of(rp) - ASPECT_TARGET)
        if key < best[0]:
            best = (key, deg, rp)
    return best[2], best[1]


def place_topology(topology: dict, sizes: dict,
                   extra_parents: dict | None = None):
    """Place a daemon scan topology (int + ext_* keys; each value carries
    "parent"/"role"). sizes: {DOT node name: (w, h) inches} from a -Tplain
    sizing pass — must cover every node. extra_parents: {name: parent_name}
    for vantage-overlay nodes present in the DOT but not in the topology.

    Returns (pos, health): pos = {name: (x, y) inches} covering every tree
    node; health = dict for the /status surface. Raises PlacementError on
    any condition that prevents a clean placement (caller falls back)."""
    tree_parent, roles = {}, {}
    for nid, info in topology.items():
        name = str(nid)
        par = info.get("parent")
        tree_parent[name] = str(par) if par is not None else None
        roles[name] = info.get("role", "")
    for name, par in (extra_parents or {}).items():
        name, par = str(name), str(par)
        if name not in tree_parent:
            tree_parent[name] = par
            roles[name] = "overlay"
    missing_sizes = [n for n in tree_parent if n not in sizes]
    if missing_sizes:
        raise PlacementError(f"no size for node(s) {missing_sizes[:5]} "
                             "(sizing pass out of sync with topology)")
    kids = defaultdict(list)
    for c, p in tree_parent.items():
        if p is not None:
            kids[p].append(c)
    for p in kids:
        kids[p].sort()

    focus = next((n for n in sorted(tree_parent)
                  if roles.get(n) == "focus"), None)
    if focus is None:
        focus = next((n for n in sorted(tree_parent)
                      if tree_parent[n] is None), None)
    if focus is None:
        raise PlacementError("no focus/root node in topology")

    cuts = find_cuts(tree_parent, roles)
    cluster_nodes = {c: _subtree(kids, c) for _, c in cuts}
    # Top-level clusters only (an unauthorized node nested under another
    # cut's subtree belongs to that cluster, not its own top-level one).
    top = sorted(c for c in cluster_nodes
                 if not any(c in v for k2, v in cluster_nodes.items()
                            if k2 != c))
    foreign = set().union(*(cluster_nodes[c] for c in top)) if top else set()
    home = set(tree_parent) - foreign
    if focus in foreign:
        raise PlacementError(f"focus {focus} inside a foreign cluster")
    # True median (7a audit A1: the validated prototype used
    # statistics.median; the upper-middle element diverges on even counts).
    med_w = statistics.median(sizes[n][0] for n in tree_parent)

    def exits_for(comp):
        e = defaultdict(list)
        for p, c in cuts:
            if c in comp:
                continue        # nested cut inside this cluster: no exit
            if p in comp:
                e[p].append(c)
            elif c in top and p not in tree_parent and focus in comp:
                # Orphan-parent cut (parent id absent from the topology):
                # adopted by the focus. A NESTED cut (parent inside another
                # foreign cluster) must NOT reach here — it would put a
                # spurious phantom exit on the home ring (7a audit A2).
                e[focus].append(c)
        return {k: sorted(v) for k, v in e.items()}

    pos, exit_angles = place_tree(
        tree_parent, home, focus, sizes, med_w, exits=exits_for(home),
        exit_pref=math.radians(EXIT_PREF_DEG))
    unplaced_home = home - set(pos)
    if unplaced_home:
        raise PlacementError(
            f"home nodes unreachable from focus {focus}: "
            f"{sorted(unplaced_home)[:5]}")

    merged = dict(pos)
    health = {"components": 1 + len(top), "clusters": {},
              "push_steps_total": 0, "corridor_hits": 0,
              "corridor_detail": [], "rotated_deg": None}
    attach_of = {c: (p if p in home else focus) for p, c in cuts}
    for key in top:
        comp = cluster_nodes[key]
        ang = exit_angles.get(key)
        if ang is None:
            raise PlacementError(f"no exit angle recorded for cluster {key}")
        u = (math.cos(ang), math.sin(ang))
        pos_b, sub_ea = place_tree(
            tree_parent, comp, key, sizes, med_w, exits=exits_for(comp),
            root_incoming=ang + math.pi)
        exit_angles.update(sub_ea)
        if comp - set(pos_b):
            raise PlacementError(
                f"cluster {key}: unplaced nodes {sorted(comp - set(pos_b))[:5]}")
        bx, by = pos_b[key]
        back = 0.0
        for n_, (x, y) in pos_b.items():
            rel = ((x - bx) * -u[0] + (y - by) * -u[1])
            a2 = math.atan2(y - by, x - bx) if n_ != key else 0.0
            back = max(back, rel + ell_radius(*sizes[n_], a2))
        attach = attach_of[key]
        ax, ay = merged[attach]
        d = ell_radius(*sizes[attach], ang) + HULL_GAP_IN + back
        steps = 0
        while True:
            dx, dy = ax + d * u[0] - bx, ay + d * u[1] - by
            trial = dict(merged)
            trial.update({k2: (x + dx, y + dy)
                          for k2, (x, y) in pos_b.items()})
            if not ellipses_overlap(trial, sizes, margin=MARGIN):
                break
            steps += 1
            if steps > PUSH_MAX:
                raise PlacementError(
                    f"cluster {key}: merge overlap persists after "
                    f"{PUSH_MAX} push-out steps")
            d += PUSH_STEP_IN
        merged = trial
        health["clusters"][key] = {
            "attach": attach,
            "exit_deg": round(math.degrees(ang) % 360.0, 1),
            "push_steps": steps,
        }
        health["push_steps_total"] += steps

    if not top:
        # Single component (everyday live map): landscape rotation pass.
        edges = [(c, p) for c, p in _tree_edges(tree_parent)
                 if c in merged and p in merged]
        merged, deg = rotate_landscape(merged, sizes, edges)
        health["rotated_deg"] = deg
    else:
        scan_clusters = {"home": home}
        scan_clusters.update({k: cluster_nodes[k] for k in top})
        hits = corridor_scan(merged, sizes, scan_clusters, tree_parent)
        health["corridor_hits"] = len(hits)
        health["corridor_detail"] = [f"{kind}: {d}" for kind, d in hits[:6]]

    uncovered = set(tree_parent) - set(merged)
    if uncovered:
        raise PlacementError(f"placement incomplete: {sorted(uncovered)[:5]}")
    return merged, health


# --- selftest ----------------------------------------------------------------

def _selftest() -> int:            # pragma: no cover - developer tool
    failures = []

    def check(name, cond):
        print(f"  [{'OK' if cond else 'FAIL'}] {name}")
        if not cond:
            failures.append(name)

    def mk(nodes):
        """topology fixture: {id: (parent, role)} -> daemon-shaped dict."""
        return {nid: {"parent": par, "role": role}
                for nid, (par, role) in nodes.items()}

    def uniform_sizes(topo, extra=(), w=2.4, h=0.7):
        s = {str(n): (w, h) for n in topo}
        s.update({str(n): (w, h) for n in extra})
        return s

    base = mk({
        10001: (None, "focus"),
        10002: (10001, "regular"), 10003: (10001, "regular"),
        10004: (10001, "regular"), 10005: (10001, "regular"),
        10006: (10001, "bridge"),
        10007: (10006, "guest"), 10008: (10006, "guest"),
        10009: (10006, "guest"),
        "ext_10006_EchoLink-123": (10006, "permitted_external"),
    })

    # --- zero cuts: single component + rotation --------------------------
    pos, health = place_topology(base, uniform_sizes(base))
    check("single component places all nodes", set(pos) ==
          {str(k) for k in base})
    check("single component health", health["components"] == 1
          and health["rotated_deg"] is not None
          and health["corridor_hits"] == 0)
    check("no overlaps @MARGIN",
          not ellipses_overlap(pos, uniform_sizes(base)))

    # --- determinism ------------------------------------------------------
    pos2, _ = place_topology(base, uniform_sizes(base))
    check("deterministic (identical positions)", pos == pos2)

    # --- str-key normalization -------------------------------------------
    check("int keys map to str names", "10001" in pos and 10001 not in pos)

    # --- one cut ----------------------------------------------------------
    v1 = dict(base)
    v1.update(mk({
        20001: (10009, "unauthorized"),
        51001: (20001, "dragged_in"), 51002: (20001, "dragged_in"),
    }))
    pos, health = place_topology(v1, uniform_sizes(v1))
    check("one cut -> 2 components", health["components"] == 2
          and "20001" in health["clusters"]
          and health["clusters"]["20001"]["attach"] == "10009")
    check("one cut all placed + clean",
          set(pos) == {str(k) for k in v1}
          and not ellipses_overlap(pos, uniform_sizes(v1)))

    # --- two cuts, distinct attach nodes ---------------------------------
    v2 = dict(v1)
    v2.update(mk({
        70001: (10002, "unauthorized"), 70002: (70001, "dragged_in"),
    }))
    pos, health = place_topology(v2, uniform_sizes(v2))
    check("two cuts distinct attach", health["components"] == 3
          and health["clusters"]["70001"]["attach"] == "10002"
          and not ellipses_overlap(pos, uniform_sizes(v2)))

    # --- two cuts, one attach node ---------------------------------------
    v3 = dict(v1)
    v3.update(mk({
        71001: (10009, "unauthorized"), 71002: (71001, "dragged_in"),
    }))
    pos, health = place_topology(v3, uniform_sizes(v3))
    a1 = health["clusters"]["20001"]["exit_deg"]
    a2 = health["clusters"]["71001"]["exit_deg"]
    check("two cuts one attach: distinct exit slots",
          health["components"] == 3 and abs(a1 - a2) > 5.0
          and not ellipses_overlap(pos, uniform_sizes(v3)))

    # --- cut directly under focus ----------------------------------------
    v4 = dict(base)
    v4.update(mk({72001: (10001, "unauthorized"),
                  72002: (72001, "dragged_in")}))
    pos, health = place_topology(v4, uniform_sizes(v4))
    check("cut under focus", health["clusters"]["72001"]["attach"] == "10001"
          and set(pos) == {str(k) for k in v4})

    # --- unauthorized leaf ------------------------------------------------
    v5 = dict(base)
    v5.update(mk({73001: (10009, "unauthorized")}))
    pos, health = place_topology(v5, uniform_sizes(v5))
    check("unauthorized leaf cluster", health["components"] == 2
          and "73001" in pos)

    # --- nested cut: no phantom exit on the home ring (7a A2) ------------
    v8 = dict(v1)
    v8.update(mk({75001: (51001, "unauthorized"),
                  75002: (75001, "dragged_in")}))
    pos, health = place_topology(v8, uniform_sizes(v8))
    check("nested cut renders inline, top-level only",
          health["components"] == 2
          and list(health["clusters"]) == ["20001"]
          and "75001" in pos and "75002" in pos
          and not ellipses_overlap(pos, uniform_sizes(v8)))

    # --- vantage overlay via extra_parents -------------------------------
    extra = {"90101": "10006", "3009876": "10001"}
    pos, health = place_topology(base, uniform_sizes(base, extra), extra)
    check("overlay nodes placed", "90101" in pos and "3009876" in pos)

    # --- missing size -> PlacementError ----------------------------------
    try:
        place_topology(v1, {k: (2.4, 0.7) for k in ("10001",)})
        check("missing sizes raise", False)
    except PlacementError:
        check("missing sizes raise", True)

    # --- orphan-parent unauthorized attaches at focus --------------------
    v6 = dict(base)
    v6.update(mk({74001: (99999, "unauthorized")}))   # parent not in topo
    sizes6 = uniform_sizes(v6, extra=(99999,))
    try:
        pos, health = place_topology(v6, sizes6)
        # 99999 is in the tree (as 74001's parent reference) but has no
        # entry -> it becomes an isolated name; reachable check governs.
        ok = "74001" in pos
    except PlacementError:
        ok = True                    # loud failure -> fallback also correct
    check("orphan-parent cut handled loudly or attached", ok)

    # --- exhausted push budget -> PlacementError -------------------------
    # The placer's translation math is self-protective (back-extent is part
    # of the initial offset), so a natural overlap needs contrived geometry.
    # Instead exercise the real failure path: force an initial overlap with
    # a negative hull gap and a zero push budget (constants restored after).
    import sys as _sys
    _self = _sys.modules[__name__]     # NOT `import asl_placer`: under
    _save = (_self.HULL_GAP_IN, _self.PUSH_MAX)   # __main__ that loads a
    try:                                          # second, unused copy
        _self.HULL_GAP_IN, _self.PUSH_MAX = -5.0, 0
        try:
            place_topology(v1, uniform_sizes(v1))
            check("exhausted push budget raises PlacementError", False)
        except PlacementError:
            check("exhausted push budget raises PlacementError", True)
    finally:
        _self.HULL_GAP_IN, _self.PUSH_MAX = _save

    # --- corridor scan unit tests ----------------------------------------
    tp = {"a": None, "b": "a", "x": None, "y": "x"}
    cl = {"A": {"a", "b"}, "B": {"x", "y"}}
    sz = {k: (1.0, 0.5) for k in tp}
    # B's node x sits mid-way on A's a--b edge -> thru hit
    p = {"a": (0, 0), "b": (4, 0), "x": (2, 0), "y": (2, 3)}
    hits = corridor_scan(p, sz, cl, tp)
    check("corridor thru detected", any(k == "thru" for k, _ in hits))
    # crossing: a--b horizontal, x--y vertical through it, nodes clear
    p = {"a": (0, 0), "b": (4, 0), "x": (2, 2), "y": (2, -2)}
    hits = corridor_scan(p, sz, cl, tp)
    check("corridor crossing detected", any(k == "xing" for k, _ in hits))
    # clean separation -> no hits
    p = {"a": (0, 0), "b": (4, 0), "x": (0, 5), "y": (4, 5)}
    check("clean clusters scan silent",
          corridor_scan(p, sz, cl, tp) == [])

    # --- rotation never degrades ------------------------------------------
    edges = [("b", "a"), ("y", "x")]
    p = {"a": (0, 0), "b": (0, 4), "x": (1.5, 0), "y": (1.5, 4)}
    rp, deg = rotate_landscape(p, sz, edges)
    check("rotation returns overlap-free layout",
          not ellipses_overlap(rp, sz))
    check("rotation deterministic",
          rotate_landscape(p, sz, edges) == (rp, deg))

    print(f"\n{'PASS' if not failures else 'FAIL'}: "
          f"{len(failures)} failure(s) {failures or ''}")
    return 1 if failures else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print("Usage: python3 asl_placer.py --selftest", file=sys.stderr)
    sys.exit(2)
