"""Bubble map image analysis for AllStarLink network topology.

Fetches the AllStarLink bubble chart image for a given node and analyzes
its topology using computer vision — detecting nodes (ellipses), connections
(arrows), and computing graph distances from the focus node.

This approach complements the API-based detection by seeing the complete
topology as rendered by AllStarLink, including nodes that don't report stats.

The bubble map is generated server-side by Graphviz (DOT) and served as JPEG.
URL: https://stats.allstarlink.org/stats/{NODE}/networkMap
"""

import logging
import tempfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import cv2
import numpy as np
import requests

logger = logging.getLogger(__name__)

BUBBLE_MAP_URL = "https://stats.allstarlink.org/stats/{node}/networkMap"


@dataclass
class DetectedNode:
    """A node detected in the bubble map image."""
    index: int
    center: tuple[int, int]    # (x, y) pixel coordinates
    bbox: tuple[int, int, int, int]  # (x, y, w, h)
    color: str                 # "BLUE", "PINK", or "WHITE"
    area: int                  # Contour area in pixels


@dataclass
class BubbleAnalysisResult:
    """Result of analyzing a bubble map image."""
    image_path: str
    image_size: tuple[int, int]       # (width, height)
    nodes: list[DetectedNode]
    connections: set[tuple[int, int]] # Set of (i, j) index pairs
    blue_node_index: Optional[int]    # Index of the focus (blue) node
    distances: dict[int, int]         # node_index -> hops from blue node
    max_distance: int
    unreachable_count: int

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def blue_count(self) -> int:
        return sum(1 for n in self.nodes if n.color == "BLUE")

    @property
    def pink_count(self) -> int:
        return sum(1 for n in self.nodes if n.color == "PINK")

    @property
    def white_count(self) -> int:
        return sum(1 for n in self.nodes if n.color == "WHITE")

    @property
    def nodes_beyond_distance(self) -> dict[int, int]:
        """Count of nodes at each distance threshold."""
        counts = {}
        for d in range(1, self.max_distance + 1):
            counts[d] = sum(1 for dist in self.distances.values() if dist > d)
        return counts

    def summary(self) -> str:
        lines = [
            f"Bubble Map Analysis: {self.node_count} nodes detected "
            f"(BLUE={self.blue_count}, PINK={self.pink_count}, WHITE={self.white_count})",
            f"Connections: {len(self.connections)}",
            f"Max distance from focus node: {self.max_distance}",
        ]
        if self.unreachable_count > 0:
            lines.append(f"Unreachable nodes: {self.unreachable_count}")
        beyond = self.nodes_beyond_distance
        for d, count in beyond.items():
            if count > 0:
                lines.append(f"Nodes at distance > {d}: {count}")
        return "\n".join(lines)


def fetch_bubble_map(node_id: int, save_path: Optional[str] = None,
                     timeout: int = 30) -> Optional[str]:
    """Fetch the bubble map image from AllStarLink.

    Returns the path to the saved image file, or None on error.
    """
    url = BUBBLE_MAP_URL.format(node=node_id)
    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "ASL-LinkDetector/1.0",
            "Accept": "image/jpeg",
        })
        resp.raise_for_status()

        if "image" not in resp.headers.get("Content-Type", ""):
            logger.error(f"Unexpected content type: {resp.headers.get('Content-Type')}")
            return None

        if save_path is None:
            fd, save_path = tempfile.mkstemp(suffix=".jpg", prefix="asl_bubble_")
            import os
            os.close(fd)

        Path(save_path).write_bytes(resp.content)
        logger.info(f"Bubble map saved to {save_path} ({len(resp.content)} bytes)")
        return save_path

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch bubble map for node {node_id}: {e}")
        return None


def analyze_bubble_map(image_path: str) -> Optional[BubbleAnalysisResult]:
    """Analyze a bubble map image for topology information.

    Detects nodes (ellipses), classifies them by color (blue=focus, pink=not
    in database, white=normal), finds connections (arrows), and computes
    BFS distances from the focus node.
    """
    img = cv2.imread(image_path)
    if img is None:
        logger.error(f"Could not read image: {image_path}")
        return None

    h_img, w_img = img.shape[:2]
    logger.info(f"Analyzing bubble map: {w_img}x{h_img}")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

    # === STEP 1: Detect node blobs ===
    # Graphviz renders ellipses with thin dark outlines and text inside.
    # Thresholding captures both outlines and text as dark regions.
    _, dark = cv2.threshold(gray, 160, 255, cv2.THRESH_BINARY_INV)
    contours_all, _ = cv2.findContours(dark, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

    # Filter for node-sized, solid, roughly elliptical contours
    node_blobs = []
    node_contour_list = []
    for c in contours_all:
        area = cv2.contourArea(c)
        if area < 3000:
            continue
        x, y, w, h = cv2.boundingRect(c)
        hull = cv2.convexHull(c)
        hull_area = cv2.contourArea(hull)
        solidity = area / hull_area if hull_area > 0 else 0
        extent = area / (w * h) if w * h > 0 else 0
        if solidity < 0.5 or extent < 0.35:
            continue
        # Filter out very elongated shapes (likely merged arrow+text)
        aspect = min(w, h) / max(w, h) if max(w, h) > 0 else 0
        if aspect < 0.15:
            continue

        cx, cy = x + w // 2, y + h // 2
        node_blobs.append({
            "center": (cx, cy), "bbox": (x, y, w, h),
            "area": area, "contour": c, "color": "WHITE"
        })
        node_contour_list.append(c)

    # === STEP 2: Detect colored fills and match to blobs ===
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (15, 15))

    # Blue fills (the focus node)
    blue_mask = cv2.inRange(hsv, (85, 30, 100), (135, 255, 200))
    blue_filled = cv2.erode(cv2.dilate(blue_mask, kernel, iterations=2),
                            kernel, iterations=2)
    blue_centers = _find_fill_centers(blue_filled, min_area=800)

    # Pink fills ("Not in Database" nodes)
    pink_mask = cv2.inRange(hsv, (140, 15, 150), (180, 255, 255))
    pink_filled = cv2.erode(cv2.dilate(pink_mask, kernel, iterations=2),
                            kernel, iterations=2)
    pink_centers = _find_fill_centers(pink_filled, min_area=400)

    # Match fills to nearest blob, or add as new node if no match
    _assign_color(node_blobs, blue_centers, "BLUE", max_dist=150)
    _assign_color(node_blobs, pink_centers, "PINK", max_dist=150)

    # === STEP 2b: Merge coincident (split) detections ===
    # A single Graphviz ellipse occasionally fragments into 2+ contours (outline
    # split by interior text/anti-aliasing), producing duplicate node blobs that
    # inflate BFS distance and manufacture phantom distance>=3 "hidden path"
    # false positives (root cause of the 2026-06-02/05 alerts). Merge on
    # bounding-box OVERLAP (fragments of one ellipse overlap heavily; distinct
    # Graphviz-placed nodes never overlap) — scale-free, and safe against hiding
    # a real deep link (a center-distance threshold could transitively chain a
    # fragment into a nearby distinct node; bbox overlap cannot).
    pre_merge = len(node_blobs)
    node_blobs = _merge_coincident_blobs(node_blobs)
    if len(node_blobs) != pre_merge:
        logger.info(f"Merged {pre_merge - len(node_blobs)} coincident "
                    f"(split) node detection(s)")

    logger.info(f"Detected {len(node_blobs)} nodes "
                f"(BLUE={sum(1 for n in node_blobs if n['color']=='BLUE')}, "
                f"PINK={sum(1 for n in node_blobs if n['color']=='PINK')}, "
                f"WHITE={sum(1 for n in node_blobs if n['color']=='WHITE')})")

    # === STEP 3: Detect connections (arrows) ===
    connections = _find_connections(node_blobs, dark, gray.shape, w_img, h_img)
    logger.info(f"Detected {len(connections)} connections")

    # === STEP 4: BFS from blue node ===
    blue_indices = [i for i, n in enumerate(node_blobs) if n["color"] == "BLUE"]
    blue_idx = blue_indices[0] if blue_indices else None

    N = len(node_blobs)
    adj = {i: [] for i in range(N)}
    for i, j in connections:
        adj[i].append(j)
        adj[j].append(i)

    distances = {}
    max_dist = 0
    unreachable = 0

    if blue_idx is not None:
        distances = {blue_idx: 0}
        queue = deque([blue_idx])
        while queue:
            curr = queue.popleft()
            for neighbor in adj[curr]:
                if neighbor not in distances:
                    distances[neighbor] = distances[curr] + 1
                    queue.append(neighbor)
        max_dist = max(distances.values()) if distances else 0
        unreachable = N - len(distances)
    else:
        logger.warning("No blue (focus) node detected in bubble map!")
        unreachable = N

    # Build result
    detected_nodes = []
    for i, n in enumerate(node_blobs):
        detected_nodes.append(DetectedNode(
            index=i,
            center=n["center"],
            bbox=n["bbox"],
            color=n["color"],
            area=n["area"],
        ))

    result = BubbleAnalysisResult(
        image_path=image_path,
        image_size=(w_img, h_img),
        nodes=detected_nodes,
        connections=connections,
        blue_node_index=blue_idx,
        distances=distances,
        max_distance=max_dist,
        unreachable_count=unreachable,
    )

    logger.info(result.summary())
    return result


def _find_fill_centers(fill_mask: np.ndarray, min_area: int) -> list[tuple[int, int]]:
    """Find centers of colored fill regions."""
    contours, _ = cv2.findContours(fill_mask, cv2.RETR_EXTERNAL,
                                   cv2.CHAIN_APPROX_SIMPLE)
    centers = []
    for c in contours:
        if cv2.contourArea(c) >= min_area:
            x, y, w, h = cv2.boundingRect(c)
            centers.append((x + w // 2, y + h // 2))
    return centers


def _assign_color(node_blobs: list[dict], fill_centers: list[tuple[int, int]],
                  color: str, max_dist: int = 150):
    """Assign color to the nearest blob for each fill center.

    If no blob is close enough, create a new synthetic blob.
    """
    for fc in fill_centers:
        best_idx = None
        best_dist = float("inf")
        for i, b in enumerate(node_blobs):
            d = np.sqrt((fc[0] - b["center"][0])**2 + (fc[1] - b["center"][1])**2)
            if d < best_dist:
                best_dist = d
                best_idx = i

        if best_idx is not None and best_dist < max_dist:
            node_blobs[best_idx]["color"] = color
        else:
            # No matching blob — add as a new node
            node_blobs.append({
                "center": fc,
                "bbox": (fc[0] - 90, fc[1] - 40, 180, 80),
                "area": 8000,
                "contour": None,
                "color": color,
            })


def _bbox_overlap_frac(a: tuple, b: tuple) -> float:
    """Intersection area of two (x,y,w,h) boxes as a fraction of the SMALLER box.

    ~1.0 when one box sits inside the other (text-contour inside an outline, or
    two arcs of the same split ellipse); 0.0 for disjoint boxes (distinct nodes).
    """
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    ix = max(0, min(ax + aw, bx + bw) - max(ax, bx))
    iy = max(0, min(ay + ah, by + bh) - max(ay, by))
    inter = ix * iy
    if inter == 0:
        return 0.0
    smaller = min(aw * ah, bw * bh)
    return inter / smaller if smaller > 0 else 0.0


def _merge_coincident_blobs(node_blobs: list[dict],
                            min_overlap: float = 0.30) -> list[dict]:
    """Collapse node detections that are fragments of ONE Graphviz ellipse.

    A single ellipse occasionally fragments into 2+ contours (outline split by
    interior text/anti-aliasing). Left separate, the duplicate + spurious
    intra-bubble edge inflate BFS distance into phantom distance>=3 hidden-path
    false positives.

    Merge criterion is BOUNDING-BOX OVERLAP, not center distance: fragments of
    the same ellipse have heavily overlapping bboxes, while DISTINCT nodes never
    overlap (Graphviz lays them out with clear separation). This is scale-free
    and — unlike a fixed center-distance threshold — cannot transitively chain a
    split fragment into a nearby-but-distinct node (a false-negative vector that
    would hide a real deep link). All member contours are retained on the
    representative so connection detection still masks the whole ellipse.
    """
    n = len(node_blobs)
    if n < 2:
        return node_blobs

    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(n):
        for j in range(i + 1, n):
            if _bbox_overlap_frac(node_blobs[i]["bbox"],
                                  node_blobs[j]["bbox"]) >= min_overlap:
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[rj] = ri

    clusters: dict = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(i)

    color_rank = {"BLUE": 3, "PINK": 2, "WHITE": 1}
    merged = []
    for members in clusters.values():
        if len(members) == 1:
            b = dict(node_blobs[members[0]])
            c = b.get("contour")
            b["contours"] = [c] if c is not None else []
            merged.append(b)
            continue
        # Representative = largest-area member (most complete contour), but the
        # color is the highest-priority across the whole cluster so a small BLUE
        # focus fragment is never demoted to WHITE.
        best = max(members, key=lambda k: node_blobs[k]["area"])
        rep = dict(node_blobs[best])
        boxes = [node_blobs[k]["bbox"] for k in members]
        x0 = min(b[0] for b in boxes)
        y0 = min(b[1] for b in boxes)
        x1 = max(b[0] + b[2] for b in boxes)
        y1 = max(b[1] + b[3] for b in boxes)
        rep["bbox"] = (x0, y0, x1 - x0, y1 - y0)
        rep["center"] = (x0 + (x1 - x0) // 2, y0 + (y1 - y0) // 2)
        rep["area"] = max(node_blobs[k]["area"] for k in members)
        rep["color"] = max((node_blobs[k]["color"] for k in members),
                           key=lambda c: color_rank.get(c, 0))
        # Retain EVERY member's contour so _find_connections masks the whole
        # ellipse (otherwise dropped fragments' outline pixels leak into the
        # arrow mask and can re-create spurious edges).
        rep["contours"] = [node_blobs[k].get("contour") for k in members
                           if node_blobs[k].get("contour") is not None]
        rep["contour"] = rep["contours"][0] if rep["contours"] else None
        merged.append(rep)
    return merged


def _find_connections(node_blobs: list[dict], dark_mask: np.ndarray,
                      img_shape: tuple, w_img: int, h_img: int) -> set[tuple[int, int]]:
    """Find connections between nodes by tracing arrow paths.

    Strategy: Remove node regions from the dark mask to isolate arrows,
    then for each pair of nearby nodes, check if arrow pixels form a
    continuous path between them.
    """
    N = len(node_blobs)

    # Remove node regions from dark mask to isolate arrows
    node_mask = np.zeros(img_shape, dtype=np.uint8)
    for n in node_blobs:
        # Mask EVERY contour the blob carries. Merged (formerly-split) blobs
        # keep all member contours in "contours" so the whole ellipse is masked
        # out of the arrow layer; otherwise dropped fragment outlines leak in as
        # spurious edge pixels. Fall back to the single "contour", then to a
        # synthetic ellipse for contour-less (color-fill-only) blobs.
        conts = n.get("contours")
        if conts is None:
            conts = [n["contour"]] if n.get("contour") is not None else []
        if conts:
            for c in conts:
                cv2.drawContours(node_mask, [c], -1, 255, 25)
        else:
            cx, cy = n["center"]
            cv2.ellipse(node_mask, (cx, cy), (100, 50), 0, 0, 360, 255, -1)

    arrows = cv2.bitwise_and(dark_mask, cv2.bitwise_not(node_mask))

    # Dilate arrows to bridge small gaps (arrowhead vs shaft)
    arrows = cv2.dilate(arrows, np.ones((3, 3), np.uint8), iterations=1)

    # Scale the max connection distance based on image size
    # Larger images (more nodes) have longer arrows
    max_connection_dist = max(w_img, h_img) * 0.4

    connections = set()
    for i in range(N):
        for j in range(i + 1, N):
            x1, y1 = node_blobs[i]["center"]
            x2, y2 = node_blobs[j]["center"]
            dist = np.sqrt((x2 - x1)**2 + (y2 - y1)**2)

            if dist > max_connection_dist:
                continue

            # Trace along the line between the two nodes.
            # Sample multiple points along the path and check for arrow pixels.
            # A true connection should have arrow pixels along most of the middle
            # portion of the path (excluding the endpoints which are inside nodes).
            connected = _check_path_connected(
                arrows, (x1, y1), (x2, y2), dist, img_shape
            )
            if connected:
                connections.add((i, j))

    return connections


def _check_path_connected(arrows: np.ndarray, p1: tuple, p2: tuple,
                          dist: float, img_shape: tuple) -> bool:
    """Check if two points are connected by arrow pixels along the path.

    Samples the middle 60% of the path (avoiding node interiors at endpoints)
    and checks if a sufficient fraction of sample points have arrow pixels nearby.
    """
    x1, y1 = p1
    x2, y2 = p2

    # Sample the middle portion of the path (skip 20% at each end)
    num_samples = max(10, int(dist / 15))
    hit_count = 0
    sample_count = 0
    search_radius = 15  # Pixels to search around the path

    for k in range(num_samples):
        t = 0.2 + 0.6 * k / (num_samples - 1) if num_samples > 1 else 0.5
        sx = int(x1 + t * (x2 - x1))
        sy = int(y1 + t * (y2 - y1))

        # Check a small region around this sample point
        sy1 = max(0, sy - search_radius)
        sy2 = min(img_shape[0], sy + search_radius)
        sx1 = max(0, sx - search_radius)
        sx2 = min(img_shape[1], sx + search_radius)

        roi = arrows[sy1:sy2, sx1:sx2]
        if np.count_nonzero(roi) > 0:
            hit_count += 1
        sample_count += 1

    if sample_count == 0:
        return False

    hit_ratio = hit_count / sample_count

    # Require at least 30% of sample points to have nearby arrow pixels.
    # Direct connections typically score 60-90%. False positives (paths that
    # happen to cross arrow pixels from other connections) tend to score lower.
    return hit_ratio >= 0.30


def fetch_and_analyze(node_id: int, save_dir: Optional[str] = None) -> Optional[BubbleAnalysisResult]:
    """Fetch the bubble map for a node and analyze it.

    Convenience function combining fetch + analyze.
    """
    if save_dir:
        save_path = str(Path(save_dir) / f"bubble_{node_id}.jpg")
    else:
        save_path = None

    image_path = fetch_bubble_map(node_id, save_path=save_path)
    if image_path is None:
        return None

    return analyze_bubble_map(image_path)
