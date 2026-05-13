"""AllStarLink Stats API client with rate limiting."""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

API_BASE = "https://stats.allstarlink.org/api/stats"

# Rate limit: 30 requests/minute/IP aggregate across all per-node queries.
# Documented in ASL3-Manual (AllStarLink GitHub): docs/developers/api.md
# Confirmed via X-RateLimit-Limit: 30 response header from stats.allstarlink.org.
# Exceeding the limit returns HTTP 429 with Retry-After header (~40s observed).
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
        # Health tracking (read by StatusCollector — no functional side effects)
        self._api_healthy: bool = True
        self.last_rate_limit_remaining: Optional[int] = None
        self.last_429_timestamp: Optional[str] = None

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
            self._api_healthy = True
            rl = resp.headers.get("X-RateLimit-Remaining")
            if rl is not None:
                try:
                    self.last_rate_limit_remaining = int(rl)
                except ValueError:
                    pass
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
                self.last_429_timestamp = datetime.now(timezone.utc).isoformat()
                logger.warning(f"Rate limited by API (429). Backing off 60s.")
                time.sleep(60)
                return self.get_node_stats(node_id)  # Retry once
            self._api_healthy = False
            logger.error(f"HTTP error fetching node {node_id}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            self._api_healthy = False
            logger.error(f"Request error fetching node {node_id}: {e}")
            return None
        except ValueError as e:
            self._api_healthy = False
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
                # Endpoint classification — schema-first, then name-pattern.
                #
                # The AllStarLink stats API returns linkedNodes entries in two
                # distinct shapes:
                #   (a) Real AllStar node: full registry record with Node_ID,
                #       User_ID, callsign, server.*, ipaddr, regseconds, etc.
                #   (b) Non-AllStar leaf: name-only object, e.g. {"name": "WB5GVY"}
                #       or {"name": "3461188"} — no registry presence.
                # Presence of Node_ID (or server / ipaddr) is therefore the strong
                # AllStar-vs-not signal. We use that as the primary gate.
                #
                # Within the non-AllStar branch, distinguish EchoLink from
                # WebTransceiver-type IAX2 softclients by the "name" pattern.
                # chan_echolink encodes EchoLink endpoints with the format
                # snprintf("3%06u", echolink_node_id) — source-verified in both
                # legacy AllStarLink/ASL-Asterisk (chan_echolink.c:1269) and
                # current ASL3 AllStarLink/app_rpt (chan_echolink.c:1796, 2516).
                # That is: a 7-digit numeric name beginning with "3" is
                # unambiguously an EchoLink endpoint. Any other name (typically
                # a bare callsign, sometimes a custom iax.conf peer label) is a
                # WebTransceiver-type softclient — the stats API does not
                # distinguish WebTransceiver / AllScan / RepeaterPhone / generic
                # IAX2 softphone, and the access_webtransceiver / access_telephoneportal
                # flags on the host node are advertised intent, not operational
                # truth (empirically verified 2026-05-12), so we do not use them
                # for sub-classification.
                #
                # External (non-AllStar) entries cannot be probed via this API,
                # so they are flagged here to skip recursion in graph_analyzer.
                #
                # EchoLink user vs. conference (deferred, 2026-05-13):
                # An EchoLink-NNNNNN endpoint may be a single-user EchoLink node
                # OR an EchoLink conference room (e.g., *WX-TALK*, *JOTA*).
                # EchoLink conferences CAN multi-bridge AllStar systems via
                # multiple chan_echolink peers joined to the same conference.
                # EchoLink itself assigns conference and user IDs from one
                # sequential namespace — there is no numeric-range rule that
                # distinguishes them (researched 2026-05-13, transcript at
                # perplexity-research/2026-05-13_echolink_node_numbering_and_directory.json).
                # If a future need arises, the path is to scrape
                # https://www.echolink.org/validation/node_lookup.jsp for the
                # callsign of a given EchoLink ID — conference callsigns are
                # asterisk-bracketed. That work is currently deferred; we
                # accept rare EchoLink-conference multi-bridge as residual
                # risk per the 2026-05-13 policy discussion.
                is_allstar = (
                    "Node_ID" in n
                    or "server" in n
                    or "ipaddr" in n
                )
                name_raw = str(n.get("name", "0"))
                if not is_allstar:
                    is_echolink_numeric = (
                        name_raw.isdigit()
                        and len(name_raw) == 7
                        and name_raw.startswith("3")
                    )
                    if is_echolink_numeric:
                        echolink_id = name_raw[1:].lstrip('0') or '0'
                        ext_name = f"EchoLink-{echolink_id}"
                        client_type = "echolink"
                        kind = "EchoLink"
                    else:
                        ext_name = name_raw
                        client_type = "webtransceiver_type"
                        kind = "WebTransceiver-type IAX2 softclient"
                    results.append({
                        "node_id": 0,
                        "external_name": ext_name,
                        "is_external": True,
                        "client_type": client_type,
                        "callsign": ext_name,
                        "location": "External Connection",
                        "frequency": "",
                        "affiliation": "",
                        "site_name": "",
                        "regseconds": 0,
                        "last_seen_utc": None,
                    })
                    logger.info(
                        f"  Node {node_id} has external connection: "
                        f"'{ext_name}' ({kind})"
                    )
                    continue
                # AllStar node — use the full registry record. The "name" field
                # holds the numeric AllStar node number for these entries
                # (Node_ID is a separate AllStarLink-internal database key — do
                # not confuse the two).
                server = n.get("server", {}) or {}
                regsec = n.get("regseconds", 0)
                try:
                    node_id_int = int(name_raw)
                except (TypeError, ValueError):
                    node_id_int = 0
                results.append({
                    "node_id": node_id_int,
                    "is_external": False,
                    "client_type": "allstar",
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
