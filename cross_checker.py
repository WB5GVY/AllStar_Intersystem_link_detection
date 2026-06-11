"""Cross-check API-based topology analysis with bubble map image analysis.

The API gives exact node IDs and callsigns but has non-reporting gaps (non-reporting
nodes whose link lists are invisible). The bubble map image sees the complete
topology as rendered by AllStarLink, including all connections through
non-reporting nodes, but doesn't provide node IDs and may have false positive
connections from the contour/path detection.

Cross-check logic:
  1. Node count comparison: API node count validates image detection
     (filters contour artifacts). Significant overshoot in image = artifacts.
  2. Max distance comparison: Image max_distance > API max depth = possible
     hidden-path bridging that the API missed.
  3. Consistency check: If API found bridging, image should also show
     max_distance ≥ 3. If it doesn't, the API result may be a stale-link
     false positive.
"""

import logging
from collections import deque
from dataclasses import dataclass, field

from graph_analyzer import ScanResult
from bubble_analyzer import BubbleAnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class StructuredPathResult:
    """Exact topology distances computed from the structured edge union.

    Item B (2026-06-11): replaces the bubble-map computer-vision hidden-path
    heuristic with exact graph analysis over the bidirectional link union the
    scan already collects (ScanResult.edges). The CV's distance was traced from
    rendered pixels and produced off-by-one phantom distances in dense node
    clusters (the 2026-06-02/05 false-positive hidden-path alerts); this is
    computed from real reported edges, so those phantoms cannot occur.

    Runs in SHADOW MODE — logged alongside the CV verdict for soak validation,
    not yet an alerting source.
    """
    focus_node: int
    node_count: int                 # reachable nodes in the union (incl. focus)
    max_distance: int
    distances: dict                 # node_id -> hops from focus
    deep_nodes: list                # node_ids at distance >= 3 (real bridging)
    hidden_path: bool               # any genuine node at distance >= 3
    notes: list

    def summary(self) -> str:
        deep = ", ".join(str(n) for n in self.deep_nodes) or "none"
        return (
            f"Structured-Path (exact, from edge union): "
            f"{self.node_count} reachable nodes, max distance "
            f"{self.max_distance}, distance>=3 nodes: {deep}"
        )


def analyze_structured_paths(result: ScanResult) -> StructuredPathResult:
    """Compute exact BFS distances from the focus over result.edges.

    The edge union preserves cross-links that the directed scan tree discards,
    so a node bridged in through a non-reporting hop (whose neighbors report it)
    lands at its true distance — no image, no CV, no phantom edges.
    """
    focus = result.focus_node
    adj: dict = {}
    for e in result.edges:
        if len(e) != 2:        # defensive: skip any malformed/self edge
            continue
        a, b = tuple(e)
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)

    distances = {focus: 0}
    q = deque([focus])
    while q:
        cur = q.popleft()
        for nbr in adj.get(cur, ()):
            if nbr not in distances:
                distances[nbr] = distances[cur] + 1
                q.append(nbr)

    max_distance = max(distances.values()) if distances else 0
    # Exclude the bridge nodes' own permitted second hop is already encoded in
    # the topology rules; here we simply surface any node at distance >= 3,
    # which under the focus/bridge model is always a real Screen-1 violation.
    deep_nodes = sorted(n for n, d in distances.items() if d >= 3)

    notes = []
    api_max_depth = max(
        (info.get("depth", 0) for info in result.topology.values()), default=0
    )
    if max_distance != api_max_depth:
        notes.append(
            f"structured max distance {max_distance} vs API tree depth "
            f"{api_max_depth} (cross-links can legitimately differ)"
        )

    return StructuredPathResult(
        focus_node=focus,
        node_count=len(distances),
        max_distance=max_distance,
        distances=distances,
        deep_nodes=deep_nodes,
        hidden_path=bool(deep_nodes),
        notes=notes,
    )


@dataclass
class CrossCheckResult:
    """Result of cross-checking API and image analyses."""
    api_result: ScanResult
    image_result: BubbleAnalysisResult

    # Counts
    api_node_count: int = 0
    image_node_count: int = 0

    # Max distances
    api_max_depth: int = 0
    image_max_distance: int = 0

    # Flags
    image_shows_deeper_topology: bool = False
    possible_hidden_path_bridging: bool = False
    node_count_mismatch_significant: bool = False
    api_bridging_confirmed_by_image: bool = False

    # Messages for logging/notification
    findings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_concerns(self) -> bool:
        return self.possible_hidden_path_bridging or len(self.warnings) > 0

    def summary(self) -> str:
        lines = [
            f"Cross-Check: API={self.api_node_count} nodes (max depth {self.api_max_depth}), "
            f"Image={self.image_node_count} nodes (max distance {self.image_max_distance})",
        ]
        for f in self.findings:
            lines.append(f"  [OK] {f}")
        for w in self.warnings:
            lines.append(f"  [!!] {w}")
        return "\n".join(lines)


def cross_check(api_result: ScanResult,
                image_result: BubbleAnalysisResult) -> CrossCheckResult:
    """Compare API-based and image-based topology analysis results.

    Returns a CrossCheckResult with findings and warnings.
    """
    result = CrossCheckResult(
        api_result=api_result,
        image_result=image_result,
    )

    # === Node counts ===
    result.api_node_count = len(api_result.topology)
    result.image_node_count = image_result.node_count

    # The API count is authoritative for nodes it can see.
    # The image may detect more (non-reporting nodes visible on map)
    # or fewer (small nodes missed) or more (contour artifacts).
    count_diff = result.image_node_count - result.api_node_count
    if abs(count_diff) <= 2:
        result.findings.append(
            f"Node counts closely match (API={result.api_node_count}, "
            f"Image={result.image_node_count})"
        )
    elif count_diff > 2:
        # Image sees more nodes — could be artifacts or could be real
        # nodes not visible to API (non-reporting)
        if count_diff > result.api_node_count * 0.5:
            result.node_count_mismatch_significant = True
            result.warnings.append(
                f"Image detected significantly more nodes than API "
                f"({result.image_node_count} vs {result.api_node_count}). "
                f"Possible contour artifacts OR non-reporting nodes with "
                f"connections the API cannot see."
            )
        else:
            result.findings.append(
                f"Image detected {count_diff} more nodes than API "
                f"({result.image_node_count} vs {result.api_node_count}). "
                f"Likely non-reporting nodes visible on the map."
            )
    else:
        result.findings.append(
            f"Image detected fewer nodes than API "
            f"({result.image_node_count} vs {result.api_node_count}). "
            f"Some nodes may be too small to detect in the image."
        )

    # === Max distance/depth ===
    result.api_max_depth = max(
        (info["depth"] for info in api_result.topology.values()), default=0
    )
    result.image_max_distance = image_result.max_distance

    if result.image_max_distance > result.api_max_depth:
        result.image_shows_deeper_topology = True
        if result.image_max_distance >= 3 and result.api_max_depth < 3:
            # Image sees nodes at distance ≥ 3 but API didn't detect bridging.
            # This is the historically-named hidden-path detection scenario.
            #
            # SUPPRESSION GATES (in order):
            #
            # (a) Focus triangle: when the API topology contains a triangle
            #     through the focus (focus↔A, focus↔B, A↔B), the bubble-map's
            #     straight-line edge tracer occasionally drops one of the
            #     routed-around edges, producing a phantom +1 distance for
            #     nodes hanging off the affected corner. We trust the API.
            #
            # (b) Insufficient deep extras: a real hidden path through a non-
            #     reporting hop-1 typically pulls in multiple deep nodes (the
            #     non-reporting node's children, and often their links). A
            #     contour artifact in the image — phantom 12th ellipse from
            #     text or anti-aliasing — produces exactly one extra deep node.
            #     Require at least 2 image nodes at distance ≥ 2 beyond what
            #     the API has at depth ≥ 2. This is the more useful gate in
            #     practice; (a) is kept as a belt-and-suspenders.
            api_deep = sum(
                1 for info in api_result.topology.values()
                if info.get("depth", 0) >= 2
            )
            image_deep = sum(
                1 for d in image_result.distances.values()
                if d >= 2
            )
            deep_extra = image_deep - api_deep
            if api_result.has_focus_triangle:
                result.findings.append(
                    f"Image max distance ({result.image_max_distance}) exceeds "
                    f"API max depth ({result.api_max_depth}), but API topology "
                    f"contains a focus triangle — known to produce phantom "
                    f"distance jumps via image-processor edge dropouts. "
                    f"Hidden-path alert suppressed."
                )
            elif deep_extra < 2:
                result.findings.append(
                    f"Image max distance ({result.image_max_distance}) exceeds "
                    f"API max depth ({result.api_max_depth}), but image only "
                    f"shows {deep_extra} extra node(s) at distance ≥ 2 vs API "
                    f"({image_deep} image, {api_deep} API). A real hidden path "
                    f"would typically pull in ≥ 2 deep nodes; one extra is "
                    f"more consistent with a contour artifact. Hidden-path "
                    f"alert suppressed."
                )
            else:
                result.possible_hidden_path_bridging = True
                result.warnings.append(
                    f"IMAGE SHOWS DEEPER TOPOLOGY than API! "
                    f"Image max distance={result.image_max_distance}, "
                    f"API max depth={result.api_max_depth}. "
                    f"Image has {deep_extra} extra node(s) at distance ≥ 2. "
                    f"This may indicate bridging through a non-reporting node "
                    f"that the API cannot see (hidden path)."
                )
        else:
            result.findings.append(
                f"Image max distance ({result.image_max_distance}) slightly "
                f"exceeds API max depth ({result.api_max_depth}). "
                f"May be due to non-reporting intermediate nodes."
            )
    elif result.image_max_distance == result.api_max_depth:
        result.findings.append(
            f"Max distance matches: API={result.api_max_depth}, "
            f"Image={result.image_max_distance}"
        )
    else:
        # API sees deeper than image — image may have missed connections
        result.findings.append(
            f"API max depth ({result.api_max_depth}) exceeds image max "
            f"distance ({result.image_max_distance}). Image may have missed "
            f"some connections."
        )

    # === Bridging confirmation ===
    if api_result.has_problems:
        if result.image_max_distance >= 3:
            result.api_bridging_confirmed_by_image = True
            result.findings.append(
                f"API-detected bridging CONFIRMED by image analysis "
                f"(image max distance={result.image_max_distance})"
            )
        else:
            result.warnings.append(
                f"API detected bridging but image shows max distance="
                f"{result.image_max_distance} (< 3). Possible stale-link "
                f"false positive in API, or image connection detection missed "
                f"the bridging path."
            )

    # === Image-only: nodes beyond distance 2 ===
    if not api_result.has_problems and result.image_max_distance <= 2:
        result.findings.append("Both API and image agree: no bridging detected.")

    # Log summary
    logger.info(result.summary())
    if result.has_concerns:
        for w in result.warnings:
            logger.warning(w)

    return result
