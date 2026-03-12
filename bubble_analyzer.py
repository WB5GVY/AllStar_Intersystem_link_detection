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
        if n["contour"] is not None:
            cv2.drawContours(node_mask, [n["contour"]], -1, 255, 25)
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
