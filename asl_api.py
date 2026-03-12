"""AllStarLink Stats API client with rate limiting."""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

API_BASE = "https://stats.allstarlink.org/api/stats"

# Rate limit: 30 requests/minute aggregate across all per-node queries.
# We enforce a minimum delay between requests to stay well under the limit.
MIN_REQUEST_INTERVAL = 2.5  # seconds between requests (~24/min max)


class ASLApiClient:
    """Client for the AllStarLink Stats API with built-in rate limiting."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self._last_request_time = 0.0
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ASL-LinkDetector/1.0",
            "Accept": "application/json",
        })

    def _rate_limit_wait(self):
        """Enforce minimum interval between API requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < MIN_REQUEST_INTERVAL:
            sleep_time = MIN_REQUEST_INTERVAL - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)
        self._last_request_time = time.time()

    def get_node_stats(self, node_id: int) -> Optional[dict]:
        """Fetch stats for a single node. Returns the full JSON response or None on error."""
        self._rate_limit_wait()
        url = f"{API_BASE}/{node_id}"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            stats = data.get("stats")
            if stats and isinstance(stats, dict) and stats.get("data"):
                link_count = len(stats["data"].get("links", []))
                logger.debug(f"Node {node_id}: got {link_count} links")
            else:
                logger.debug(f"Node {node_id}: no stats data (node may not report stats)")
            return data
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 429:
                logger.warning(f"Rate limited by API (429). Backing off 60s.")
                time.sleep(60)
                return self.get_node_stats(node_id)  # Retry once
            logger.error(f"HTTP error fetching node {node_id}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error fetching node {node_id}: {e}")
            return None
        except ValueError as e:
            logger.error(f"JSON decode error for node {node_id}: {e}")
            return None

    def get_linked_nodes(self, node_id: int) -> Optional[list[int]]:
        """Get list of node IDs linked to the given node.

        Returns None on API error, empty list if node exists but has no stats/links.
        """
        data = self.get_node_stats(node_id)
        if data is None:
            return None
        try:
            stats = data.get("stats")
            if not stats or not isinstance(stats, dict):
                return []  # Node exists but doesn't report stats
            stats_data = stats.get("data")
            if not stats_data or not isinstance(stats_data, dict):
                return []
            links = stats_data.get("links", [])
            return [int(n) for n in links]
        except (KeyError, TypeError, ValueError) as e:
            logger.error(f"Error parsing links for node {node_id}: {e}")
            return None

    def get_node_info(self, node_id: int) -> Optional[dict]:
        """Get detailed info (callsign, location, etc.) for a node.

        Returns a dict with keys: callsign, location, frequency, affiliation, name.
        """
        data = self.get_node_stats(node_id)
        if data is None:
            return None
        try:
            # Try multiple locations where node info might be
            candidates = []
            stats = data.get("stats")
            if stats and isinstance(stats, dict):
                if stats.get("user_node"):
                    candidates.append(stats["user_node"])
            if data.get("node"):
                candidates.append(data["node"])

            for node_data in candidates:
                if node_data and node_data.get("callsign"):
                    server = node_data.get("server", {}) or {}
                    regsec = node_data.get("regseconds", 0)
                    return {
                        "node_id": node_id,
                        "callsign": node_data.get("callsign", "Unknown"),
                        "location": server.get("Location", "Unknown"),
                        "frequency": node_data.get("node_frequency", ""),
                        "affiliation": server.get("Affiliation", ""),
                        "site_name": server.get("SiteName", ""),
                        "regseconds": regsec,
                        "last_seen_utc": self._regseconds_to_datetime(regsec),
                    }

            logger.warning(f"No detailed info available for node {node_id}")
            return {"node_id": node_id, "callsign": "Unknown", "location": "Unknown",
                    "frequency": "", "affiliation": "", "site_name": "",
                    "regseconds": 0, "last_seen_utc": None}
        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing node info for {node_id}: {e}")
            return None

    def get_linked_node_details(self, node_id: int) -> Optional[list[dict]]:
        """Get detailed info for all nodes linked to the given node.

        This is more efficient than calling get_node_info for each linked node,
        because the linkedNodes array in the parent's stats already contains
        callsign, location, etc. for each connected node.

        Returns None on API error, empty list if node has no stats/links.
        """
        data = self.get_node_stats(node_id)
        if data is None:
            return None
        try:
            stats = data.get("stats")
            if not stats or not isinstance(stats, dict):
                return []  # Node exists but doesn't report stats
            stats_data = stats.get("data")
            if not stats_data or not isinstance(stats_data, dict):
                return []
            linked = stats_data.get("linkedNodes", [])
            results = []
            for n in linked:
                # The "name" field is normally a numeric node ID, but some
                # connections (e.g., RepeaterPhone/EchoLink) use callsigns.
                name_raw = str(n.get("name", "0"))
                if not name_raw.isdigit():
                    # Non-numeric = external connection (RepeaterPhone, EchoLink, etc.)
                    results.append({
                        "node_id": 0,
                        "external_name": name_raw,
                        "is_external": True,
                        "callsign": name_raw,
                        "location": "External Connection",
                        "frequency": "",
                        "affiliation": "",
                        "site_name": "",
                        "regseconds": 0,
                        "last_seen_utc": None,
                    })
                    logger.info(
                        f"  Node {node_id} has external connection: "
                        f"'{name_raw}' (RepeaterPhone/EchoLink/etc.)"
                    )
                    continue
                server = n.get("server", {}) or {}
                regsec = n.get("regseconds", 0)
                results.append({
                    "node_id": int(name_raw),
                    "is_external": False,
                    "callsign": n.get("callsign", "Unknown"),
                    "location": server.get("Location", "Unknown"),
                    "frequency": n.get("node_frequency", ""),
                    "affiliation": server.get("Affiliation", ""),
                    "site_name": server.get("SiteName", ""),
                    "regseconds": regsec,
                    "last_seen_utc": self._regseconds_to_datetime(regsec),
                })
            return results
        except (KeyError, TypeError, ValueError) as e:
            logger.error(f"Error parsing linked node details for {node_id}: {e}")
            return None

    @staticmethod
    def _regseconds_to_datetime(regsec) -> Optional[datetime]:
        """Convert regseconds (unix timestamp) to a UTC datetime, or None if invalid."""
        try:
            if regsec and int(regsec) > 0:
                return datetime.fromtimestamp(int(regsec), tz=timezone.utc)
        except (ValueError, TypeError, OSError):
            pass
        return None

    @staticmethod
    def node_age_minutes(regsec) -> Optional[float]:
        """Return how many minutes ago the node was last seen, based on regseconds.

        Returns None if regseconds is missing/invalid.
        Note: the stats API's regseconds can lag behind the live registration
        server by up to ~60 minutes, so use a generous threshold.
        """
        try:
            if regsec and int(regsec) > 0:
                dt = datetime.fromtimestamp(int(regsec), tz=timezone.utc)
                delta = datetime.now(timezone.utc) - dt
                return delta.total_seconds() / 60.0
        except (ValueError, TypeError, OSError):
            pass
        return None

    def close(self):
        self.session.close()
