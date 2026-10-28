"""AllStarLink Stats API client with rate limiting."""

import logging
import threading
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

# Link-mode letters app_rpt prefixes onto each adjacent link in the stats
# post (ASL3 rpt_link.c __mklinklist, LINKPOST format): T transceive,
# R monitor (receive-only), L local monitor, C still connecting. The letter is
# the REPORTING node's own view of its link; an incoming link is always
# created as transceive on the receiving end (app_rpt.c rpt_exec), so only the
# node that initiated a monitor connection ever reports R.
LINK_MODE_LETTERS = frozenset("TRLC")


def parse_link_modes(nodes_field) -> dict[str, str]:
    """Map raw link name -> mode letter from the stats "nodes" string.

    "TQQ0QQQ,T11111,R22222" -> {"QQ0QQQ": "T", "11111": "T", "22222": "R"}.
    Anything that is not a string, or a token without a known letter, is
    skipped — a schema surprise must never abort a scan."""
    if not isinstance(nodes_field, str):
        return {}
    modes: dict[str, str] = {}
    conflicted: set[str] = set()
    for tok in nodes_field.split(","):
        tok = tok.strip()
        if len(tok) < 2 or tok[0] not in LINK_MODE_LETTERS:
            continue
        name, letter = tok[1:], tok[0]
        # A name listed twice with different letters is ambiguous. Never
        # let the last one win: once the letters drive a permit decision
        # (phase 2 listeners), an R must not paper over a T.
        if name in modes and modes[name] != letter:
            conflicted.add(name)
        modes.setdefault(name, letter)
    for name in conflicted:
        modes.pop(name, None)
    return modes


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
        # Nodes already warned about for a missing/unparseable "nodes" field.
        self._no_modes_warned: set = set()
        # Last failure of an OPTIONAL fetch (retry_429=False): (kind, iso ts),
        # kind in {"429", "http", "request", "json"}. Optional fetches never
        # mark the client unhealthy; the caller reads this to tell an
        # API-wide problem (429 / request) from one node's own (http / json).
        self.last_optional_failure: Optional[tuple] = None

    # One token bucket for EVERY instance in this process (audit 2026-09-08
    # S4): the scan client, the watcher's client and the dark-guest client
    # share the API's per-IP budget, so the interval is enforced globally.
    _shared_lock = threading.Lock()
    _shared_last_request = 0.0

    def _rate_limit_wait(self):
        """Enforce minimum interval between API requests (process-wide)."""
        with ASLApiClient._shared_lock:
            elapsed = time.time() - ASLApiClient._shared_last_request
            if elapsed < MIN_REQUEST_INTERVAL:
                sleep_time = MIN_REQUEST_INTERVAL - elapsed
                logger.debug(f"Rate limiting: sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)
            ASLApiClient._shared_last_request = time.time()
            self._last_request_time = ASLApiClient._shared_last_request

    def get_node_stats(self, node_id: int, _attempt: int = 0,
                       retry_429: bool = True) -> Optional[dict]:
        """Fetch stats for a single node. Returns the full JSON response or None on error.

        `retry_429=False` marks an OPTIONAL fetch (node_health's extra fetches,
        2026-10-18): a 429 returns None at once — no 60 s sleep in the scan
        thread — and NO failure of an optional fetch marks the client
        unhealthy (the fetch was expendable); the 429 timestamp is still
        recorded and `last_optional_failure` says what kind of failure it was
        so the caller can back off or move on."""
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
                if not retry_429:
                    self.last_optional_failure = ("429", self.last_429_timestamp)
                    logger.warning(f"Rate limited by API (429) on an optional fetch of node "
                                   f"{node_id} — dropped, no retry")
                    return None
                if _attempt >= 1:                   # audit 2026-09-08: bounded
                    self._api_healthy = False
                    logger.error(f"Rate limited by API (429) twice for node "
                                 f"{node_id} — giving up this fetch")
                    return None
                logger.warning(f"Rate limited by API (429). Backing off 60s.")
                time.sleep(60)
                return self.get_node_stats(node_id, _attempt=_attempt + 1)  # Retry once
            if not retry_429:
                self.last_optional_failure = ("http", datetime.now(timezone.utc).isoformat())
                logger.warning(f"HTTP error on an optional fetch of node {node_id}: {e}")
                return None
            self._api_healthy = False
            logger.error(f"HTTP error fetching node {node_id}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            if not retry_429:
                self.last_optional_failure = ("request", datetime.now(timezone.utc).isoformat())
                logger.warning(f"Request error on an optional fetch of node {node_id}: {e}")
                return None
            self._api_healthy = False
            logger.error(f"Request error fetching node {node_id}: {e}")
            return None
        except ValueError as e:
            if not retry_429:
                self.last_optional_failure = ("json", datetime.now(timezone.utc).isoformat())
                logger.warning(f"JSON decode error on an optional fetch of node {node_id}: {e}")
                return None
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
                        # User_ID = the registered OWNING account, which can
                        # differ from the broadcast callsign (e.g. a node
                        # keyed under a club call but owned by an individual
                        # — Bennett, 2026-07-18).
                        "owner": node_data.get("User_ID", ""),
                        "location": server.get("Location", "Unknown"),
                        "frequency": node_data.get("node_frequency", ""),
                        "affiliation": server.get("Affiliation", ""),
                        "site_name": server.get("SiteName", ""),
                        "regseconds": regsec,
                        "last_seen_utc": self._regseconds_to_datetime(regsec),
                    }

            logger.warning(f"No detailed info available for node {node_id}")
            return {"node_id": node_id, "callsign": "Unknown", "owner": "",
                    "location": "Unknown",
                    "frequency": "", "affiliation": "", "site_name": "",
                    "regseconds": 0, "last_seen_utc": None}
        except (KeyError, TypeError) as e:
            logger.error(f"Error parsing node info for {node_id}: {e}")
            return None

    # A post time this far in OUR future is not clock skew, it is an unusable
    # record (audit 2026-09-08 C2: a clamped-to-0 age would read as
    # maximally fresh forever — e.g. a Pi with no RTC that booted in 2030).
    POST_TIME_FUTURE_TOLERANCE_SECONDS = 300

    @staticmethod
    def post_age_seconds(data: Optional[dict], now: Optional[float] = None) -> Optional[float]:
        """Age of a node's stats POST (`stats.data.time`, epoch seconds set
        by the posting node) — the freshness of the record itself, as
        distinct from `regseconds` (the registration time of a node). None
        when the record has no usable time, including a time more than
        POST_TIME_FUTURE_TOLERANCE_SECONDS in the future (small skew is
        clamped to 0). None reads as "not fresh" at every consumer."""
        try:
            t = ((data or {}).get("stats") or {}).get("data", {}).get("time")
            t = int(t)
            if t <= 0:
                return None
            age = (now if now is not None else time.time()) - t
            if age < -ASLApiClient.POST_TIME_FUTURE_TOLERANCE_SECONDS:
                return None
            return max(0.0, age)
        except (TypeError, ValueError, AttributeError):
            return None

    def get_linked_node_details(self, node_id: int,
                                data: Optional[dict] = None) -> Optional[list[dict]]:
        """Get detailed info for all nodes linked to the given node.

        This is more efficient than calling get_node_info for each linked node,
        because the linkedNodes array in the parent's stats already contains
        callsign, location, etc. for each connected node.

        `data`: an already-fetched get_node_stats() payload (saves a call).
        Returns None on API error, empty list if node has no stats/links.
        """
        if data is None:
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
            # Per-link mode letters ride in the separate "nodes" string
            # ("TQQ0QQQ,T11111"); linkedNodes carries no mode. Keyed by the raw
            # name because linkedNodes ordering differs from links/nodes.
            link_modes = parse_link_modes(stats_data.get("nodes"))
            matched_modes = 0
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
                link_mode = link_modes.get(name_raw)
                if link_mode is not None:
                    matched_modes += 1
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
                        "tone": "",
                        "lat": None,
                        "lon": None,
                        "affiliation": "",
                        "site_name": "",
                        "regseconds": 0,
                        "last_seen_utc": None,
                        "link_mode": link_mode,
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
                    "owner": n.get("User_ID", ""),
                    "location": server.get("Location", "Unknown"),
                    "frequency": n.get("node_frequency", ""),
                    "tone": n.get("node_tone", ""),
                    # The registry misspells it "Logitude"; check the correct
                    # spelling too in case the API ever fixes it.
                    "lat": self._parse_coord(server.get("Latitude"), bound=90.0),
                    "lon": self._parse_coord(server.get("Logitude",
                                                        server.get("Longitude"))),
                    "affiliation": server.get("Affiliation", ""),
                    "site_name": server.get("SiteName", ""),
                    "regseconds": regsec,
                    "last_seen_utc": self._regseconds_to_datetime(regsec),
                    "link_mode": link_mode,
                })
            if linked and not link_modes:
                # A reporting node with links but no parseable mode letters
                # means the schema or letter set changed — say so once per
                # node rather than silently rendering everything as transceive.
                if node_id not in self._no_modes_warned:
                    self._no_modes_warned.add(node_id)
                    logger.warning(
                        f"  Node {node_id}: {len(linked)} linkedNodes but no "
                        f"link-mode letters parsed from 'nodes' "
                        f"({stats_data.get('nodes')!r}) — modes unknown")
            elif link_modes and matched_modes != len(link_modes):
                logger.debug(
                    f"  Node {node_id}: {len(link_modes)} mode tokens, "
                    f"{matched_modes} matched linkedNodes entries")
            return results
        except (KeyError, TypeError, ValueError) as e:
            logger.error(f"Error parsing linked node details for {node_id}: {e}")
            return None

    @staticmethod
    def _parse_coord(v, bound: float = 180.0) -> Optional[float]:
        """Parse a latitude/longitude registry string. These are
        remote-controlled (node owners type them into the registry), so
        anything unparsable or out of range is None — never an exception.
        bound: 90.0 for latitude, 180.0 (default) for longitude. Rounding is
        a display concern, not done here."""
        if v is None:
            return None
        try:
            f = float(v)
        except (TypeError, ValueError):
            return None
        return f if -bound <= f <= bound else None

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


def _selftest() -> int:
    """Offline checks for the link-mode parse and its join onto linkedNodes.
    Synthetic payload; no network."""
    payload = {"stats": {"data": {
        "links": ["23456", "12345", "WB5GVY", "3461188", "34567"],
        # Order deliberately differs from linkedNodes; X9 is an unknown letter.
        "nodes": "R23456,T12345,TWB5GVY,C3461188,L34567,X9,",
        "linkedNodes": [
            {"Node_ID": 1, "name": 12345, "callsign": "AA1AA", "server": {}},
            {"Node_ID": 2, "name": 23456, "callsign": "BB1BB", "server": {}},
            {"name": "WB5GVY"},
            {"name": "3461188"},
            {"Node_ID": 3, "name": 34567, "callsign": "CC1CC", "server": {}},
            {"Node_ID": 4, "name": 45678, "callsign": "DD1DD", "server": {}},
        ]}}}
    client = ASLApiClient()
    client.get_node_stats = lambda node_id: payload  # type: ignore[assignment]
    details = client.get_linked_node_details(1)
    by_name = {(d["external_name"] if d["is_external"] else str(d["node_id"])): d
               for d in details}
    checks = [
        ("parse basic", parse_link_modes("TQQ0QQQ,T11111") == {"QQ0QQQ": "T", "11111": "T"}),
        ("parse non-string", parse_link_modes(None) == {} and parse_link_modes(["T1"]) == {}),
        ("parse drops unknown letter", "9" not in parse_link_modes("X9,T1")),
        ("conflicting duplicate -> dropped, not last-wins",
         parse_link_modes("T5,R5,T6") == {"6": "T"}
         and parse_link_modes("R5,T5") == {}),
        ("agreeing duplicate kept", parse_link_modes("R5,R5") == {"5": "R"}),
        ("int name joined by string", by_name["12345"]["link_mode"] == "T"),
        ("R survives ordering", by_name["23456"]["link_mode"] == "R"),
        ("L kept", by_name["34567"]["link_mode"] == "L"),
        ("external softclient joined", by_name["WB5GVY"]["link_mode"] == "T"),
        ("echolink joined by raw name", by_name["EchoLink-461188"]["link_mode"] == "C"),
        ("unlisted link is None", by_name["45678"]["link_mode"] is None),
        ("all entries carry key", all("link_mode" in d for d in details)),
    ]
    # Absent / malformed "nodes" must not abort the parse.
    for bad in (None, {"a": 1}, 42):
        payload["stats"]["data"]["nodes"] = bad
        d2 = client.get_linked_node_details(1)
        checks.append((f"nodes={type(bad).__name__} tolerated",
                       d2 is not None and all(x["link_mode"] is None for x in d2)))
    # post_age_seconds (audit 2026-09-08 C2): future-dated posts
    pa = ASLApiClient.post_age_seconds
    rec = lambda t: {"stats": {"data": {"time": t}}}  # noqa: E731
    checks += [
        ("post_age: 4 s old -> 4.0", pa(rec(1000), now=1004) == 4.0),
        ("post_age: small future skew (60 s) clamps to 0", pa(rec(1060), now=1000) == 0.0),
        ("post_age: far-future time (1 h) -> None, not fresh", pa(rec(4600), now=1000) is None),
        ("post_age: no time / zero / junk -> None",
         pa({"stats": {"data": {}}}) is None and pa(rec(0)) is None
         and pa(rec("x")) is None and pa(None) is None),
    ]
    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
    print(f"asl_api selftest: {len(checks) - len(failed)}/{len(checks)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print("usage: python3 asl_api.py --selftest")
