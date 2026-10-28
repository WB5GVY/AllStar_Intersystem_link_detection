"""Three-state node health — what the AllStarLink stats registry says about
each monitored node, as three INDEPENDENT facts (2026-10-18, PLAN v2 §4):

  registered  the node checked in with the AllStar registry recently
              (`node.regseconds` age < registered_max_age_seconds, 90 min)
  posting     the node is sending its own stats post
              (`stats.data.time` age < posting_max_age_seconds, 10 min)
  letter      what the node's EXPECTED PARENT reports about its link to the
              node, one letter from the parent's `stats.data.nodes` string:
              T live · R rx-only · L local monitor (ASL3 only) · C parent is
              dialing / re-dialing, not connected, no audio · '-' parent does
              not list it · '?' parent data unavailable (parent record not
              obtained this scan, or the parent's own post is older than
              posting_max_age_seconds) · 'self' for the hub
  linked      letter in T/R/L; for the hub: posting ("hub up")

Why: on 2026-10-18 the HA card said two member nodes were "offline" for
days (registration age) while the digest said 100 % (presence in the hub's
link list); the hub's own record said T<member A> (live link, audio passing)
and C<member B> (dialing, no audio). Nothing showed the three facts
together, and a C link counted as "present".

Pure observation — never touches detection, never alerts. One
NodeHealthTracker per daemon; `observe(result)` runs in the scan thread after
the per-scan enforcement work, on the ScanResult the walk already produced
(zero extra API requests for every node the walk fetched). Nodes the walk did
NOT reach (not listed by their parent — offline, or the parent itself was not
reached) are fetched at most once per extra_fetch_interval_seconds, at most
extra_fetch_max_per_scan per scan, inside a 10 s wall-clock budget with a
short socket timeout, never during the top-of-hour burst window, never when
any fetch failed earlier in the same scan, never within 10 min of a 429 and
never while the API client reports itself unhealthy (audit C1 — the scan
thread must not be held up by the health add-on). A cached extra record is
served for up to EXTRA_CACHE_MAX_S so the burst window never starves it.

Recording (analytics.db via the Recorder, fail-safe): a change in any of the
three fields is written as ONE transition row after confirm_scans consecutive
scans show it (hysteresis — `regseconds` can lag the registry by ~60 min, and
one stale read must not flip a state). The first observation of a node after
a (re)start writes a BASELINE row per field (old NULL) so a report window can
reconstruct the state at any instant from the rows alone. `current_node_health`
holds the live debounced state and seeds the tracker on restart, so a restart
never produces spurious transitions. A node that disappears from the config
is RETIRED at start-up (closing '?' rows, current row deleted) so it does not
haunt every later digest (audit S4). Rows that could not be written are kept
and retried on the next scan (audit A1).

"No observation" is not a state (audit S1): when a node's OWN record was not
obtained this scan (fetch failed, nothing cached) its registered / posting
facts are unknown ('?') and are NOT debounced or recorded — the recorded
value stands and /status shows the observed value as null. The LETTER '?'
("parent data unavailable") IS a recorded state: it is a fact about the
parent's record, and the digest keeps it out of the linked denominator.

Validity gate (N1): when the record of a node's parent could NOT be fetched
this scan (API error / 429 / timeout — ScanResult.fetch_failed) or the walk
never ran (the hub is not in the topology), nothing is recorded for the nodes
under that parent and /status shows them `gated`. A parent that IS fetched
but is not posting is NOT a gate: that is a real state (the hub silent → its
children's letter is '?', the hub's own posting flag is false). The same gate
makes asl_link_detector skip presence recording when the hub fetch failed
(the old mass-"disappeared" defect).
"""

from __future__ import annotations

import logging
import re
import time
import types
from datetime import datetime, timezone
from typing import Optional

from asl_api import parse_link_modes
from dns_checker import check_node_dns, check_node_dns_full, DNSRecordSet, _valid_ip
from graph_analyzer import record_addr, record_version, record_public

logger = logging.getLogger(__name__)

FIELDS = ("registered", "posting", "letter")
LINKED_LETTERS = frozenset("TRL")
LETTER_TEXT = {
    "T": "live",
    "R": "rx-only",
    "L": "local monitor",
    "C": "dialing, no audio",
    "-": "not listed",
    "?": "parent data unavailable",
    "self": "hub",
}
# A cached extra-fetch record is served for at most this long after the
# fetch. 25 min: the last fetch before the burst blackout (:55) still covers
# the whole blackout (to :10) plus a scan (audit S1).
EXTRA_CACHE_MAX_S = 1500
# Wall-clock budget for all extra fetches in one scan, and the socket
# timeout used for them (the client's default 15 s is for the walk).
EXTRA_FETCH_BUDGET_S = 10.0
EXTRA_FETCH_TIMEOUT_S = 4
# No extra fetches within this long after the client saw a 429.
RECENT_429_S = 600
# After one DNS lookup failure (resolver down / timeout) skip DNS for this
# long so a dead resolver cannot add ten timeouts to every scan; a cached
# DNS value is shown for at most DNS_CACHE_MAX_S while paused.
DNS_BACKOFF_S = 300
DNS_CACHE_MAX_S = 900
DNS_TIMEOUT_S = 2.0
# Wall-clock budget for all DNS lookups in one scan (two zones × TXT + A per
# node; a slow-but-answering resolver must not stretch the scan — audit 9).
# Nodes past the budget are served from the cache or shown as not looked up;
# lookups run oldest-cache-first so a tight budget rotates, never starves.
DNS_BUDGET_S = 12.0
# DNS cross-check findings are debounced on DISTINCT DNS SAMPLES (a cached
# value re-read during the :55–:10 burst or while paused does not count —
# audit pass 3, S-A/S-C): an issue is reported after `confirm_scans`
# consecutive samples that show it, and a DNS-vs-stats address mismatch must
# ALSO have been first seen at least DNS_STATS_MISMATCH_MIN_S ago, because
# the stats registry can lag DNS by up to ~60 min after a node's address
# changes (audit pass 2, S3). A finding's counter is reset only by a sample
# whose comparison RAN and was clean; a skipped comparison (cached stats
# record, HamVoIP zone paused) leaves it frozen (S-B / S-D).
DNS_STATS_MISMATCH_MIN_S = 3600
DNS_STATS_ISSUES = ("ASL DNS IP ≠ stats",)   # port dropped 2026-10-19: stats `node.port` is the NAT-observed port
# Keys whose comparison depends on the HamVoIP record set.
DNS_HV_KEYS = ("HamVoIP TXT records disagree", "HamVoIP record missing",
               "HamVoIP IP ≠ ASL", "HamVoIP port ≠ ASL")   # findings only for nodes listed in hamvoip_nodes
# A node whose own lookup keeps failing is retried with its own back-off
# (300 s × 2^failures, capped) so it cannot re-trigger the global pause every
# scan and starve the others (audit pass 3, S-E).
DNS_NODE_BACKOFF_MAX_S = 3600
# A post / registration time this far in our future is an unusable record
# (mirrors ASLApiClient.POST_TIME_FUTURE_TOLERANCE_SECONDS).
FUTURE_TOLERANCE_S = 300
# Unwritten rows kept for retry (audit A1); beyond this the oldest are dropped.
MAX_UNSAVED_ROWS = 1000
# A node whose extra fetch keeps failing is retried with exponential back-off
# (interval × 2^failures, capped) so it cannot spend the per-scan budget every
# scan and starve the nodes behind it (audit pass 3).
EXTRA_BACKOFF_MAX_S = 3600
# A fact unobserved for longer than this (cache expired, fetches blocked or
# failing) is RECORDED as '?' instead of holding the last state forever
# (audit pass 3): the cache lifetime plus two normal scan intervals.
STALE_UNOBSERVED_S = EXTRA_CACHE_MAX_S + 2 * 300


def _supports_kw(fn, name: str, _cache: dict = {}) -> bool:  # noqa: B006 (module cache)
    """Does callable `fn` accept keyword `name`? Decided once per callable
    type by signature, never by try/except around a network call (audit
    pass 3)."""
    # Keyed on the function OBJECT (a bound method's __func__), not its name:
    # every lambda shares the qualname "<lambda>" (audit pass 2, A1).
    key = (getattr(fn, "__func__", fn), name)
    if key not in _cache:
        try:
            import inspect
            params = inspect.signature(fn).parameters
            _cache[key] = (name in params or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()))
        except (TypeError, ValueError):
            _cache[key] = False
    return _cache[key]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bool(v, default: bool) -> bool:
    """YAML booleans, plus quoted 'false'/'no'/'0' (audit A6)."""
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v).strip().lower()
    if s in ("false", "no", "off", "0", ""):
        return False
    if s in ("true", "yes", "on", "1"):
        return True
    return default


def node_health_cfg(config: dict) -> Optional[dict]:
    """Parse the `node_health:` config block. None when absent, disabled or
    unusable (logged) — the daemon then runs without node health, exactly as
    before. Shape:

        node_health:
          enabled: true
          nodes:                 # node: expected parent ('self' for the hub)
            HUB: self
            MEMBER: HUB
            GUEST: BRIDGE
          registered_max_age_seconds: 5400
          posting_max_age_seconds: 600
          confirm_scans: 2
          extra_fetch_interval_seconds: 300
          extra_fetch_max_per_scan: 8
          dns_lookups: true

    Without `nodes`, the hub is 'self' and the analytics core + bridge nodes
    hang off the hub (a node reached through a bridge must be listed
    explicitly). The extra-fetch blackout follows `top_of_hour_polling`
    (before_minutes / after_minutes; audit A2)."""
    raw = (config or {}).get("node_health")
    if not isinstance(raw, dict) or not _bool(raw.get("enabled"), False):
        return None
    focus = config.get("focus_node")
    nodes: dict[int, object] = {}
    nodes_raw = raw.get("nodes")
    if isinstance(nodes_raw, dict) and nodes_raw:
        for k, v in nodes_raw.items():
            try:
                n = int(k)
            except (TypeError, ValueError):
                logger.warning("node_health.nodes: ignoring non-numeric node %r", k)
                continue
            if isinstance(v, str) and v.strip().lower() == "self":
                nodes[n] = "self"
                continue
            try:
                nodes[n] = int(v)
            except (TypeError, ValueError):
                logger.warning("node_health.nodes: ignoring node %s with parent %r "
                               "(want a node number or 'self')", n, v)
    else:
        if focus is None:
            logger.warning("node_health: no nodes and no focus_node — disabled")
            return None
        acfg = config.get("analytics") if isinstance(config.get("analytics"), dict) else {}
        members = set(acfg.get("core_nodes") or []) | set(
            acfg.get("bridge_nodes") or config.get("bridge_nodes") or [])
        nodes = {int(focus): "self"}
        for n in members:
            try:
                n = int(n)
            except (TypeError, ValueError):
                continue
            if n != int(focus):
                nodes[n] = int(focus)
    if not nodes:
        logger.warning("node_health: no usable nodes — disabled")
        return None
    for n, p in nodes.items():
        if isinstance(p, int) and p not in nodes:
            logger.info("node_health: node %s hangs off %s, which is not itself monitored", n, p)

    def _int(src, key, default, lo):
        try:
            v = int((src or {}).get(key, default))
        except (TypeError, ValueError):
            v = default
        return max(lo, v)

    toh = config.get("top_of_hour_polling") if isinstance(
        config.get("top_of_hour_polling"), dict) else {}
    before = min(59, _int(toh, "before_minutes", 5, 0))
    after = min(59, _int(toh, "after_minutes", 10, 0))
    blackout_enabled = _bool(toh.get("enabled"), True)
    return {
        "nodes": nodes,
        "registered_max_age_seconds": _int(raw, "registered_max_age_seconds", 5400, 60),
        "posting_max_age_seconds": _int(raw, "posting_max_age_seconds", 600, 30),
        "confirm_scans": _int(raw, "confirm_scans", 2, 1),
        "extra_fetch_interval_seconds": _int(raw, "extra_fetch_interval_seconds", 300, 60),
        "extra_fetch_max_per_scan": _int(raw, "extra_fetch_max_per_scan", 8, 0),
        "dns_lookups": _bool(raw.get("dns_lookups"), True),
        "dns_cache_seconds": min(DNS_CACHE_MAX_S, _int(raw, "dns_cache_seconds", 60, 10)),
        # Nodes that register with HamVoIP: their <n>.asl.hamvoip.org record
        # must exist and agree with the ASL one. Every other node's HamVoIP
        # record is informational (registering with HamVoIP is optional).
        # None = no list. (2026-10-19)
        "hamvoip_nodes": _int_list(raw.get("hamvoip_nodes")),
        # the daemon's own aggressive-poll window: [60 - before, after)
        "blackout_enabled": blackout_enabled,
        "blackout_from_minute": 60 - before,
        "blackout_to_minute": after,
    }


def _int_list(v) -> Optional[set]:
    """A YAML list of node numbers -> set[int]; None when absent/not a list;
    non-numeric entries are dropped with a warning."""
    if v is None:
        return None
    if isinstance(v, int) and not isinstance(v, bool):
        v = [v]                                  # a single node number is a one-item list
    if not isinstance(v, (list, tuple, set)):
        logger.warning("node_health.hamvoip_nodes: expected a list, got %r — ignored", v)
        return None
    out = set()
    for x in v:
        if isinstance(x, bool):                 # YAML `yes`/`true` is not a node
            logger.warning("node_health.hamvoip_nodes: ignoring boolean %r", x)
            continue
        try:
            out.add(int(x))
        except (TypeError, ValueError):
            logger.warning("node_health.hamvoip_nodes: ignoring non-numeric %r", x)
    if v and not out:
        logger.warning("node_health.hamvoip_nodes: no usable node numbers in %r — "
                       "ignored (no node's HamVoIP record is required)", v)
        return None
    return out


def _finding_base(k: str) -> str:
    """The comparison a finding key belongs to (the two '… names node N'
    keys carry the node number; strip it)."""
    for base in ("HamVoIP TXT names node", "ASL TXT names node"):
        if k.startswith(base):
            return base
    return k


def _wrap_legacy_dns(info):
    """A check_node_dns-style result (ASL TXT only) in the full shape."""
    failed = bool(getattr(info, "lookup_failed", False))
    asl = DNSRecordSet(present=bool(getattr(info, "is_registered", False)) and not failed,
                       txt_ip=getattr(info, "ip_address", None),
                       txt_port=getattr(info, "port", None), lookup_failed=failed)
    # HamVoIP was never looked up by a legacy function: hamvoip=None.
    return types.SimpleNamespace(asl=asl, hamvoip=None, lookup_failed=failed)


def _recent_429(api, now_epoch: float) -> bool:
    ts = getattr(api, "last_429_timestamp", None)
    if not ts:
        return False
    try:
        t = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return (now_epoch - t.timestamp()) < RECENT_429_S
    except Exception:
        return True          # unparseable but present: be conservative


class NodeHealthTracker:
    """Per-scan assembly + debounce + recording of the three facts.

    Injection points (selftest): `now_fn` (epoch), `mono_fn`, `dns_fn`
    (check_node_dns signature), `minute_fn` (wall-clock minute for the
    extra-fetch blackout)."""

    def __init__(self, cfg: dict, recorder=None, now_fn=time.time,
                 mono_fn=time.monotonic, dns_fn=None, minute_fn=None,
                 dns_full_fn=None):
        self.cfg = cfg
        self.nodes: dict[int, object] = dict(cfg["nodes"])
        self.recorder = recorder
        self._now = now_fn
        self._mono = mono_fn
        # Two-system lookup (2026-10-19). A legacy `dns_fn` (check_node_dns
        # signature, ASL TXT only) is wrapped into the full shape.
        if dns_full_fn is not None:
            self._dns_full = dns_full_fn
        elif dns_fn is not None:
            self._dns_full = lambda n, timeout=None: _wrap_legacy_dns(dns_fn(n, timeout=timeout))
        else:
            self._dns_full = check_node_dns_full
        self._minute = minute_fn or (lambda: datetime.now().minute)
        self._version: dict[int, str] = {}            # node -> last known apprptvers (monitored nodes)
        self._dns_issues_seen: dict[int, tuple] = {}  # node -> last logged (confirmed) issue tuple
        self._dns_confirmed: dict[int, tuple] = {}    # node -> confirmed issue tuple (debounced)
        self._dns_streak: dict[int, dict] = {}        # node -> {issue: [samples, first_seen_epoch]}
        self._dns_last_sample: dict[int, float] = {}  # node -> mono of the sample last fed to the debounce
        self._dns_last_attempt: dict[int, float] = {} # node -> mono of the last real lookup attempt
        self._dns_node_fail: dict[int, list] = {}     # node -> [failures, retry_not_before_mono]
        self._dns_hv_backoff_until = 0.0              # HamVoIP zone trouble: its own pause
        self._dns_deadline = None                     # per-scan wall-clock budget (mono)
        self._dns_budget_nodes: set = set()           # nodes that hit the budget this scan
        self._dns_error_logged: dict[int, float] = {} # node -> mono of the last code-error warning
        self._dns_verdict: dict[int, object] = {}     # node -> `consistent` computed on its latest sample
        self._dns_last_success_mono = float("-inf")   # any node's last successful lookup
        self._dns_pause_set_mono = float("-inf")      # when the global pause was last set
        # node -> {"registered","posting","letter","parent","since":{field: ts}}
        self._current: dict[int, dict] = {}
        self._pending: dict[tuple, list] = {}      # (node, field) -> [value, count]
        self._baselined: set[int] = set()
        self._extra: dict[int, dict] = {}          # node -> cached own record
        self._dns_cache: dict[int, tuple] = {}     # node -> (mono, value)
        self._dns_backoff_until = 0.0
        self._unsaved: list = []                   # rows awaiting a successful write
        self._unsaved_current: dict[int, dict] = {}
        self._last_obs: dict[tuple, float] = {}    # (node, field) -> epoch of the last real observation
        self._started = float(now_fn())
        self.last_block: Optional[dict] = None
        self.extra_fetches_total = 0
        if recorder is not None:
            try:
                stale_nodes = []
                for row in recorder.load_current_node_health():
                    n = int(row["node_id"])
                    if n not in self.nodes:
                        stale_nodes.append(n)
                        continue
                    self._current[n] = {
                        "registered": row.get("registered"),
                        "posting": row.get("posting"),
                        "letter": row.get("letter"),
                        "parent": self.nodes[n],
                        "since": {"registered": row.get("since_registered"),
                                  "posting": row.get("since_posting"),
                                  "letter": row.get("since_letter")},
                    }
                if self._current:
                    logger.info("node health: seeded %d node state(s) from analytics.db",
                                len(self._current))
                if stale_nodes:
                    # Audit S4: a node dropped from the config must not carry
                    # its last state into every later digest.
                    n_rows = recorder.retire_node_health(stale_nodes, _now_iso())
                    logger.info("node health: retired %d node(s) no longer configured "
                                "(%s; %d closing rows)", len(stale_nodes),
                                ", ".join(str(n) for n in sorted(stale_nodes)), n_rows)
            except Exception as e:
                logger.warning("node health: could not load/retire current state (%s) — "
                               "starting fresh", e)

    # ------------------------------------------------------------------ #
    def _in_blackout(self) -> bool:
        if not self.cfg.get("blackout_enabled", True):
            return False
        try:
            m = int(self._minute())
        except Exception:
            return False
        return m >= self.cfg["blackout_from_minute"] or m < self.cfg["blackout_to_minute"]

    def _ordered_nodes(self) -> list[int]:
        """Parents before children so a parent's extra-fetched record can
        serve its children's letters in the same scan."""
        parents = {p for p in self.nodes.values() if isinstance(p, int)}
        return (sorted(n for n in self.nodes if n in parents or self.nodes[n] == "self")
                + sorted(n for n in self.nodes
                         if n not in parents and self.nodes[n] != "self"))

    def _extra_fetch(self, api, node: int) -> tuple:
        """One own-record fetch for a node the walk did not reach; cached.
        Returns (entry to serve or None, attempt_ok, api_wide): the fresh
        entry on success, else an older good one (still served) with
        attempt_ok False; api_wide True when the failure says the API itself
        is the problem (429 / connection / timeout — or a client without the
        optional-fetch contract that marked itself unhealthy) rather than
        this node's own record (HTTP 4xx/5xx for it, bad JSON)."""
        healthy_before = getattr(api, "_api_healthy", True)
        fail_before = getattr(api, "last_optional_failure", None)
        try:
            # `retry_429=False`: a 429 returns None at once instead of the
            # client's 60 s sleep-and-retry (audit C1); the keyword is chosen
            # by signature, so a test double without it gets the plain call.
            if _supports_kw(api.get_node_stats, "retry_429"):
                data = api.get_node_stats(node, retry_429=False)
            else:
                data = api.get_node_stats(node)
        except Exception as e:
            logger.warning("node health: extra fetch of %s raised %s", node, e)
            data = None
        self.extra_fetches_total += 1
        prev = self._extra.get(node) or {}
        ent = {"mono": self._mono(), "fetched_epoch": float(self._now()),
               "ok": isinstance(data, dict), "fail_count": 0,
               "reg_time": None, "post_time": None, "raw": None,
               "addr": (None, None), "version": None, "public": None}
        if ent["ok"]:
            try:
                rs = (data.get("node") or {}).get("regseconds")
                ent["reg_time"] = int(rs) if rs is not None else None
            except (TypeError, ValueError, AttributeError, OverflowError):
                pass
            ent["addr"] = record_addr(data)
            ent["version"] = record_version(data)
            ent["public"] = record_public(data)
            try:
                sd = ((data.get("stats") or {}).get("data") or {})
                pt = sd.get("time")
                ent["post_time"] = int(pt) if pt is not None and int(pt) > 0 else None
                raw = sd.get("nodes")
                ent["raw"] = raw[:2000] if isinstance(raw, str) else None
            except (TypeError, ValueError, AttributeError):
                pass
        if ent["ok"]:
            self._extra[node] = ent
            return ent, True, False
        # Classify the failure.
        fail_now = getattr(api, "last_optional_failure", None)
        if fail_now is not None and fail_now is not fail_before:
            api_wide = (fail_now[0] in ("429", "request"))
        elif getattr(api, "_api_healthy", True) is False and healthy_before is not False:
            api_wide = True                        # a client without the contract
        else:
            api_wide = _recent_429(api, float(self._now()))
        fails = int(prev.get("fail_count") or 0) + 1
        if prev.get("ok"):
            prev["retry_mono"] = ent["mono"]       # spent the budget; keep serving
            prev["fail_count"] = fails
            return prev, False, api_wide
        ent["fail_count"] = fails
        self._extra[node] = ent
        return None, False, api_wide

    def _due_interval(self, ent: Optional[dict]) -> float:
        """Seconds between extra-fetch attempts for a node: the configured
        interval, doubled per consecutive failure, capped."""
        base = float(self.cfg["extra_fetch_interval_seconds"])
        fails = int((ent or {}).get("fail_count") or 0)
        return min(EXTRA_BACKOFF_MAX_S, base * (2 ** min(fails, 12)))

    def _dns_lookup(self, node: int) -> dict:
        """{"asl": DNSRecordSet|None, "hv": DNSRecordSet|None, "failed": bool
        (the AllStarLink TXT query failed), "hv_failed": bool, "hv_paused":
        bool, "budget": bool, "disabled": bool}. A None record set = not
        looked up. Short cache; a resolver failure on the AllStarLink zone
        pauses ALL lookups (DNS_BACKOFF_S) while a HamVoIP-zone failure
        pauses only the HamVoIP lookup (its own timer); cached values are
        shown for at most DNS_CACHE_MAX_S while paused (audit A4). A
        per-scan wall-clock budget (DNS_BUDGET_S, set by observe()) stops
        a slow-but-answering resolver from stretching the scan."""
        empty = {"asl": None, "hv": None, "failed": False, "hv_failed": False,
                 "hv_paused": False, "budget": False, "disabled": False,
                 "error": None, "sample": None}
        if not self.cfg.get("dns_lookups", True):
            return dict(empty, disabled=True)
        mono = self._mono()
        ent = self._dns_cache.get(node)
        if ent is not None and mono - ent[0] < self.cfg["dns_cache_seconds"]:
            return ent[1]
        if mono < self._dns_backoff_until:
            if ent is not None and mono - ent[0] < DNS_CACHE_MAX_S:
                return ent[1]
            return dict(empty, failed=True)
        nf = self._dns_node_fail.get(node)
        if nf is not None and mono < nf[1]:          # this node's own retry back-off
            if ent is not None and mono - ent[0] < DNS_CACHE_MAX_S:
                return ent[1]
            return dict(empty, failed=True)
        if self._dns_deadline is not None and mono > self._dns_deadline:
            self._dns_budget_nodes.add(node)
            if ent is not None and mono - ent[0] < DNS_CACHE_MAX_S:
                return dict(ent[1], budget=True)
            return dict(empty, budget=True)
        want_hv = not (mono < self._dns_hv_backoff_until)
        self._dns_last_attempt[node] = mono
        try:
            if _supports_kw(self._dns_full, "want_hamvoip"):
                info = self._dns_full(node, timeout=DNS_TIMEOUT_S, want_hamvoip=want_hv)
            else:
                info = self._dns_full(node, timeout=DNS_TIMEOUT_S)
            asl = getattr(info, "asl", None)
            hv = getattr(info, "hamvoip", None)
            failed = bool(getattr(info, "lookup_failed", False)) or asl is None or bool(asl.lookup_failed)
            hv_failed = hv is not None and bool(getattr(hv, "lookup_failed", False))
            val = dict(empty, asl=None if failed else asl,
                       hv=None if (hv is None or hv_failed) else hv,
                       failed=failed, hv_failed=hv_failed,
                       hv_paused=(not want_hv) or hv_failed, sample=mono)
        except Exception as e:
            # A CODE fault (parser etc.), not resolver trouble: no pause,
            # shown as `error`, warned once per back-off period (audit pass 3, S-E).
            if mono - self._dns_error_logged.get(node, -1e9) >= DNS_BACKOFF_S:
                logger.warning("node health: DNS lookup code error for %s (%s: %s)",
                               node, type(e).__name__, e)
                self._dns_error_logged[node] = mono
            val = dict(empty, error="%s: %s" % (type(e).__name__, e))
            if ent is not None and mono - ent[0] < DNS_CACHE_MAX_S:
                return dict(ent[1], error=val["error"])
            return val
        if val["failed"]:
            # The failure counts toward THIS node's own back-off only when the
            # resolver has answered some other node since the last pause —
            # otherwise it is the resolver's outage, not the node's (audit
            # pass 4, S2: no hour-long back-offs piled up during an outage).
            node_specific = self._dns_last_success_mono >= self._dns_pause_set_mono
            fails = int((nf or [0, 0])[0]) + (1 if node_specific else 0)
            fails = max(fails, 1)
            self._dns_node_fail[node] = [fails, mono + min(DNS_NODE_BACKOFF_MAX_S, DNS_BACKOFF_S * (2 ** min(fails - 1, 12)))]
            self._dns_backoff_until = mono + DNS_BACKOFF_S
            self._dns_pause_set_mono = mono
            logger.info("node health: DNS lookup failed for %s — DNS paused %d s (node retry in %d s)",
                        node, DNS_BACKOFF_S, int(self._dns_node_fail[node][1] - mono))
            if ent is not None and mono - ent[0] < DNS_CACHE_MAX_S:
                served = dict(ent[1], failed=True)   # serve the cached good value, flagged
                self._dns_cache[node] = (ent[0], served)   # so the per-node pass sees the flag too
                return served
            return val          # do not cache a failure over a good value
        self._dns_node_fail.pop(node, None)
        self._dns_last_success_mono = mono
        if val["hv_failed"]:
            self._dns_hv_backoff_until = mono + DNS_BACKOFF_S
            logger.info("node health: HamVoIP DNS lookup failed for %s — HamVoIP DNS paused %d s",
                        node, DNS_BACKOFF_S)
        self._dns_cache[node] = (mono, val)
        return val

    def _dns_cache_age(self, node: int) -> Optional[int]:
        ent = self._dns_cache.get(node)
        return None if ent is None else int(max(0.0, self._mono() - ent[0]))

    def _dns_prefetch(self, gated_nodes: set) -> None:
        """Run this scan's lookups oldest-cache-first (a node without a
        cache entry first of all) so the per-scan budget rotates across
        nodes instead of starving the same tail every scan (audit pass 2,
        S2). The per-node pass then reads the 60 s cache."""
        if not self.cfg.get("dns_lookups", True):
            return
        # Oldest ATTEMPT first (not oldest success): a node that keeps failing
        # does not stay at the head of the queue (audit pass 3, S-E).
        order = sorted((n for n in self.nodes if n not in gated_nodes),
                       key=lambda n: (self._dns_last_attempt.get(n, float("-inf")), n))
        for n in order:
            try:
                self._dns_lookup(n)
            except Exception as e:
                logger.debug("node health: DNS prefetch for %s raised %s", n, e)

    def _hamvoip_expected(self, n: int) -> Optional[bool]:
        """True for a node listed in `hamvoip_nodes` (it registers with
        HamVoIP, so its record must exist); None for every other node.
        Registering with HamVoIP is optional — many HamVoIP nodes register
        with allstarlink.org only (Bennett, 2026-10-19) — so a node's
        software version implies nothing, and no node is ever "not expected"
        (False): an unlisted node's HamVoIP record is informational either way."""
        listed = self.cfg.get("hamvoip_nodes")
        if listed is not None and n in listed:
            return True
        return None

    def _dns_block(self, n: int, dns: dict, stats_ip, stats_port, fresh: bool,
                   gated: bool = False) -> dict:
        """The per-node /status `dns` entry (always a dict, same keys): both
        record sets, the stats record's address, and the cross-checks.
        `issues` = disagreements that mean something is wrong; `notes` =
        informational oddities (the A record lagging the TXT). `consistent`
        is True/False only when at least one real comparison ran AND the
        HamVoIP side was checked whenever a record is expected; else None.
        `fresh` = the stats address comes from a record obtained this scan
        (walk / extra), not from the cache (audit S13)."""
        asl: Optional[DNSRecordSet] = dns.get("asl")
        hv: Optional[DNSRecordSet] = dns.get("hv")
        expected = self._hamvoip_expected(n)
        stats_ip = _valid_ip(stats_ip) or stats_ip     # canonical form, like txt_ip
        observed: list[str] = []
        notes: list[str] = []
        ran: set = set()          # finding keys whose comparison actually RAN this time
        compared = False
        if asl is not None:
            ran.update(("ASL TXT records disagree", "ASL TXT names node"))
            if asl.txt_conflict:
                observed.append("ASL TXT records disagree")
            if asl.txt_node is not None and asl.txt_node != n:
                observed.append("ASL TXT names node %s" % asl.txt_node)
            if asl.txt_ip and asl.a_ips and asl.txt_ip not in asl.a_ips:
                notes.append("A record %s differs from TXT" % ",".join(asl.a_ips))
            if fresh and stats_ip and asl.txt_ip:
                compared = True
                ran.add(DNS_STATS_ISSUES[0])
                if stats_ip != asl.txt_ip:
                    observed.append(DNS_STATS_ISSUES[0])
            # No port comparison: stats.allstarlink.org `node.port` is the port the
            # server OBSERVED, which behind NAT / for co-located nodes is not the
            # node's IAX port (2026-10-19: 6 of 10 monitored nodes differed while
            # working normally). The IP comparison stands.
        hv_checked = hv is not None
        if hv is not None:
            # HamVoIP findings exist only for a node that registers with HamVoIP
            # (listed in hamvoip_nodes). For any other node the same observations
            # are NOTES: registering with HamVoIP is optional, so an absent, stale
            # or diverging HamVoIP record is information, not a fault (2026-10-19).
            hv_sink = observed if expected is True else notes
            if expected is True:
                ran.update(DNS_HV_KEYS)
                ran.add("HamVoIP TXT names node")
            if hv.txt_conflict:
                hv_sink.append("HamVoIP TXT records disagree")
            if hv.txt_node is not None and hv.txt_node != n:
                hv_sink.append("HamVoIP TXT names node %s" % hv.txt_node)
            if expected is True and not hv.present:
                if asl is not None and asl.present:
                    compared = True
                    observed.append("HamVoIP record missing")     # registered in ASL only
                else:
                    notes.append("no registration in either zone")  # plain offline (audit S1): no verdict
            if hv.present and asl is not None and asl.present:
                if hv.txt_ip and asl.txt_ip:
                    if expected is True:
                        compared = True
                    if hv.txt_ip != asl.txt_ip:
                        hv_sink.append("HamVoIP IP ≠ ASL")
                if hv.txt_port and asl.txt_port:
                    if expected is True:
                        compared = True
                    if int(hv.txt_port) != int(asl.txt_port):
                        hv_sink.append("HamVoIP port ≠ ASL")
        # The HamVoIP side could not be checked while something about it is
        # expected (True or False): no verdict about it, and its findings are
        # frozen — the AllStarLink-only findings keep going (pass-3 S-D).
        hv_unknown = (hv is None) and (expected is not None) and not dns.get("disabled")
        # Debounce on distinct DNS samples (see the constants above).
        confirmed = self._dns_confirmed.get(n, ())
        sample = dns.get("sample")
        new_sample = (asl is not None and sample is not None
                      and sample != self._dns_last_sample.get(n))
        streak = self._dns_streak.setdefault(n, {})
        if new_sample:
            self._dns_last_sample[n] = sample
            now_ep = float(self._now())
            for k in list(streak):
                if _finding_base(k) in ran and k not in observed:
                    del streak[k]             # the comparison ran and was clean: reset
            for k in observed:
                if k in streak:
                    streak[k][0] += 1
                else:
                    streak[k] = [1, now_ep]
            def _ok(k):
                s = streak.get(k)
                if not s or s[0] < self.cfg["confirm_scans"]:
                    return False
                if k in DNS_STATS_ISSUES and now_ep - s[1] < DNS_STATS_MISMATCH_MIN_S:
                    return False
                return True
            # keep a confirmed finding while its comparison is frozen (not run)
            keep = [k for k in confirmed if k not in observed and k in streak and _finding_base(k) not in ran]
            confirmed = tuple(sorted(set(k for k in observed if _ok(k)) | set(keep)))
            self._dns_confirmed[n] = confirmed
            if self._dns_issues_seen.get(n) != confirmed:
                if n in self._dns_issues_seen or confirmed:
                    logger.info("node health: %s DNS issues now %s", n, list(confirmed) or "none")
                self._dns_issues_seen[n] = confirmed
        looked_up = asl is not None
        issues = list(confirmed) if looked_up else []
        # Pending = seen now but unconfirmed, PLUS frozen unconfirmed findings
        # whose comparison did not run this time (audit pass 4, S1).
        pending = sorted(set(k for k in observed if k not in confirmed)
                         | set(k for k in streak if k not in confirmed and k not in observed
                               and _finding_base(k) not in ran))
        # The verdict is decided once per DNS sample and then held, so a
        # cached re-read (burst, blackout) cannot flip it (pass-4 S1).
        if new_sample or n not in self._dns_verdict:
            self._dns_verdict[n] = (None if (hv_unknown or not compared or pending or not looked_up)
                                    else (not issues))
        consistent = self._dns_verdict[n] if looked_up else None
        mono = self._mono()
        return {
            "gated": bool(gated),
            "asl": None if asl is None else {
                "present": asl.present, "a_ip": asl.a_ip, "a_ips": list(asl.a_ips),
                "a_failed": bool(asl.a_failed), "txt_ip": asl.txt_ip,
                "txt_port": asl.txt_port},
            "hamvoip": {
                "expected": expected, "checked": hv_checked,
                "present": None if hv is None else hv.present,
                "txt_ip": None if hv is None else hv.txt_ip,
                "txt_port": None if hv is None else hv.txt_port},
            "stats_ip": stats_ip, "stats_port": stats_port, "stats_fresh": bool(fresh),
            "consistent": consistent, "issues": issues, "issues_pending": pending,
            "issues_last_confirmed": [] if looked_up else list(confirmed),
            "notes": notes, "error": dns.get("error"),
            "lookup_failed": bool(dns.get("failed")),
            "hv_lookup_failed": bool(dns.get("hv_failed")),
            "paused": bool(mono < self._dns_backoff_until),
            "hv_paused": bool(mono < self._dns_hv_backoff_until) or bool(dns.get("hv_failed")),
            "budget": bool(dns.get("budget")),
            "cache_age_s": self._dns_cache_age(n),
            "disabled": bool(dns.get("disabled")),
        }

    # ------------------------------------------------------------------ #
    def observe(self, result, api=None) -> dict:
        """Assemble the three facts for every monitored node from this scan,
        debounce, record transitions, and return the /status block."""
        ts = getattr(result, "timestamp", None) or _now_iso()
        now = float(self._now())
        fetched = set(getattr(result, "fetched", None) or ())
        failed = set(getattr(result, "fetch_failed", None) or ())
        raw_nodes = getattr(result, "raw_nodes", None) or {}
        post_time = getattr(result, "post_time", None) or {}
        node_addr = getattr(result, "node_addr", None) or {}
        node_version = getattr(result, "node_version", None) or {}
        node_public = getattr(result, "node_public", None) or {}     # team page facts (2026-10-20)
        regs = getattr(result, "regseconds", None) or {}
        peer_regs = getattr(result, "peer_regseconds", None) or {}
        focus = getattr(result, "focus_node", None)
        topo = getattr(result, "topology", None)
        # The walk never ran: hub fetch failed, OR the hub payload arrived but
        # did not parse (hub in `fetched`, yet absent from the topology —
        # audit S2).
        scan_aborted = (focus in failed) or (isinstance(topo, dict) and focus not in topo)
        pmax = self.cfg["posting_max_age_seconds"]
        rmax = self.cfg["registered_max_age_seconds"]

        # 1. Records: the walk's first, then extra fetches / cache for the rest.
        # Every record carries `asof`, the instant it was obtained: ages are
        # judged AS OF that instant, so a record served from the cache states
        # "as of its fetch the node was posting / registered" and does not
        # drift into "not posting" merely because the cache is 20 min old
        # (audit S1 pass 2). The cache lifetime bounds the staleness.
        records: dict[int, dict] = {}
        for n in fetched:
            records[n] = {"reg_time": regs.get(n), "post_time": post_time.get(n),
                          "raw": raw_nodes.get(n), "source": "walk", "asof": now,
                          "addr": tuple(node_addr.get(n) or (None, None)),
                          "version": node_version.get(n),
                          "public": node_public.get(n)}
        blackout = self._in_blackout()
        has_problems = bool(getattr(result, "has_problems", False))
        # Audit C1: extra fetches only when the API is behaving right now and
        # no alert delivery is waiting on this scan.
        api_ok = (api is not None and not scan_aborted and not failed
                  and not has_problems
                  and getattr(api, "_api_healthy", True) is not False
                  and not _recent_429(api, now))
        budget = self.cfg["extra_fetch_max_per_scan"] if (api_ok and not blackout) else 0
        extra_skipped_reason = (None if budget or not self.cfg["extra_fetch_max_per_scan"]
                                else ("blackout" if blackout else
                                      "scan aborted" if scan_aborted else
                                      "fetch failure this scan" if failed else
                                      "violation this scan" if has_problems else
                                      "api unhealthy / recent 429" if api is not None
                                      else "no api"))
        extra_failed_nodes: set[int] = set()
        n_extra = 0
        t_budget0 = self._mono()
        saved_timeout = getattr(api, "timeout", None) if budget else None
        if budget and saved_timeout is not None:
            try:
                api.timeout = min(saved_timeout, EXTRA_FETCH_TIMEOUT_S)
            except Exception:
                saved_timeout = None
        try:
            for n in self._ordered_nodes():
                if n in records or n in failed:
                    continue
                ent = self._extra.get(n)
                mono = self._mono()
                last_try = (ent or {}).get("retry_mono", (ent or {}).get("mono"))
                fresh = ent is not None and last_try is not None and \
                    (mono - last_try) < self._due_interval(ent)
                if (not fresh and budget > 0
                        and (mono - t_budget0) < EXTRA_FETCH_BUDGET_S):
                    budget -= 1
                    n_extra += 1
                    ent, attempt_ok, api_wide = self._extra_fetch(api, n)
                    if not attempt_ok:
                        extra_failed_nodes.add(n)
                        # Stop spending only when the failure looks API-wide
                        # (429 / connection / timeout); one node's own failure
                        # must not starve the nodes behind it — it backs off
                        # on its own (audit C1 / pass 3 / pass 4).
                        if api_wide:
                            budget = 0
                            extra_skipped_reason = "extra fetch failed (api)"
                        else:
                            extra_skipped_reason = "extra fetch failed (node; others continued)"
                if ent is not None and ent.get("ok"):
                    age = mono - ent["mono"]
                    if age < EXTRA_CACHE_MAX_S:
                        records[n] = {"reg_time": ent["reg_time"], "post_time": ent["post_time"],
                                      "raw": ent["raw"],
                                      "source": "extra" if age < 1.0 else "cache",
                                      "asof": ent.get("fetched_epoch", now - age),
                                      "addr": tuple(ent.get("addr") or (None, None)),
                                      "version": ent.get("version"),
                                      "public": ent.get("public")}
        finally:
            if saved_timeout is not None:
                try:
                    api.timeout = saved_timeout
                except Exception:
                    pass

        # 2. Per node: the three facts.
        nodes_block: dict[str, dict] = {}
        counts = {"registered": 0, "registered_known": 0, "linked": 0,
                  "linked_known": 0, "posting": 0, "posting_known": 0,
                  "dns_asl": 0, "dns_asl_known": 0, "dns_hv": 0, "dns_hv_known": 0,
                  "dns_issues": 0}
        # Remember each monitored node's software version (a non-posting node
        # keeps its last known one) — it decides whether a HamVoIP record is
        # expected. Per-scan DNS wall-clock budget starts here.
        for n, rec in records.items():
            if n in self.nodes and rec.get("version"):
                self._version[n] = rec["version"]
        self._dns_deadline = self._mono() + DNS_BUDGET_S
        self._dns_budget_nodes = set()
        gated_nodes = {n for n, p in self.nodes.items()
                       if scan_aborted or (p in failed) or (p == "self" and n in failed)}
        self._dns_prefetch(gated_nodes)
        all_rows: list[tuple] = []
        changed_nodes: set[int] = set()
        for n, parent in self.nodes.items():
            try:
                self._observe_node(n, parent, records, failed, peer_regs, scan_aborted,
                                   extra_failed_nodes, now, ts, pmax, rmax,
                                   nodes_block, counts, all_rows, changed_nodes)
            except Exception as e:
                # One node's surprise must not cost the others their rows.
                logger.error("node health: node %s skipped this scan (%s: %s)",
                             n, type(e).__name__, e)

        # 3. Persist (fail-safe; unwritten rows are retried next scan — audit A1).
        for n in changed_nodes:
            self._unsaved_current[n] = self._current_row(n, ts)
        if all_rows:
            self._unsaved.extend(all_rows)
            if len(self._unsaved) > MAX_UNSAVED_ROWS:
                dropped = len(self._unsaved) - MAX_UNSAVED_ROWS
                del self._unsaved[:dropped]
                logger.warning("node health: dropped %d oldest unwritten rows", dropped)
        if (self._unsaved or self._unsaved_current) and self.recorder is not None:
            try:
                self.recorder.record_node_health(
                    list(self._unsaved),
                    [self._unsaved_current[n] for n in sorted(self._unsaved_current)])
                self._unsaved.clear()
                self._unsaved_current.clear()
            except Exception as e:
                logger.error("node health: DB write failed (non-fatal; %d row(s) kept "
                             "for retry): %s", len(self._unsaved), e)
        elif self.recorder is None:
            self._unsaved.clear()
            self._unsaved_current.clear()
        for (rts, n, f, old, new, base, _d) in all_rows:
            if not base:
                logger.info("node health: %s %s %s -> %s", n, f, old, new)

        block = {"updated": ts, "scan_gated": bool(scan_aborted),
                 "extra_fetches": n_extra, "extra_fetch_blackout": blackout,
                 "extra_fetches_skipped": extra_skipped_reason,
                 "unwritten_rows": len(self._unsaved),
                 "dns_paused": bool(self._mono() < self._dns_backoff_until),
                 "dns_hv_paused": bool(self._mono() < self._dns_hv_backoff_until),
                 "dns_budget_hits": len(self._dns_budget_nodes),
                 "nodes": nodes_block, "counts": counts}
        self._dns_deadline = None
        self.last_block = block
        return block

    # ------------------------------------------------------------------ #
    def _observe_node(self, n: int, parent, records: dict, failed: set, peer_regs: dict,
                      scan_aborted: bool, extra_failed_nodes: set, now: float, ts: str,
                      pmax: int, rmax: int, nodes_block: dict, counts: dict,
                      all_rows: list, changed_nodes: set) -> None:
        """The three facts for one node (ages as of the record's `asof`),
        debounce, counts, and its /status entry."""
        rec = records.get(n)
        asof = float((rec or {}).get("asof", now))
        gated = scan_aborted or (parent in failed) or (parent == "self" and n in failed)
        # registered (own record first, then the parent's linkedNodes copy)
        reg_time = (rec or {}).get("reg_time")
        if not reg_time:
            reg_time = peer_regs.get(n) or None
            if reg_time:
                asof_reg = now           # the parent's copy was read this scan
            else:
                asof_reg = asof
        else:
            asof_reg = asof
        reg_age = None
        if reg_time:
            reg_age = int(asof_reg - reg_time)
            if reg_age < -FUTURE_TOLERANCE_S:
                registered, reg_age = "?", None       # unusable record (audit A5)
            else:
                registered = "1" if reg_age < rmax else "0"
        elif rec is not None or n in peer_regs:
            registered = "0"          # record exists, never registered
        else:
            registered = "?"          # no observation this scan
        # posting
        pt = (rec or {}).get("post_time")
        post_age = None
        future = False
        if pt:
            post_age = asof - pt
            if post_age < -FUTURE_TOLERANCE_S:
                post_age, future = None, True
            else:
                post_age = int(max(0.0, post_age))
        if rec is None or future:
            posting = "?"
        else:
            posting = "1" if (post_age is not None and post_age < pmax) else "0"
        # letter: '?' = the parent's record was OBTAINED but is silent/stale
        # (a fact about the parent); None = the parent's record was not
        # obtained at all (no observation — never recorded; audit S1 pass 2).
        parent_post_age = None
        if parent == "self":
            letter = "self"
        else:
            prec = records.get(parent)
            if prec is None:
                letter = None
            else:
                ppt = prec.get("post_time")
                pasof = float(prec.get("asof", now))
                if ppt:
                    parent_post_age = pasof - ppt
                    parent_post_age = (None if parent_post_age < -FUTURE_TOLERANCE_S
                                       else int(max(0.0, parent_post_age)))
                if parent_post_age is None or parent_post_age >= pmax:
                    letter = "?"
                else:
                    raw = prec.get("raw") or ""
                    modes = parse_link_modes(raw)
                    if str(n) in modes:
                        letter = modes[str(n)]
                    elif re.search(r"(?<!\d)%d(?!\d)" % n, raw):
                        letter = "?"      # listed with an unparseable letter
                    else:
                        letter = "-"
        # DNS (both systems). Any surprise here must not cost the node its
        # three health facts (audit 16): fall back to an "error" entry.
        dns = {"asl": None, "hv": None, "failed": False, "hv_failed": False,
               "hv_paused": False, "budget": False, "disabled": False}
        try:
            if not gated:
                dns = self._dns_lookup(n)
            stats_ip, stats_port = tuple((rec or {}).get("addr") or (None, None))
            dns_block = self._dns_block(n, dns, stats_ip, stats_port,
                                        fresh=(rec or {}).get("source") in ("walk", "extra"),
                                        gated=gated)
        except Exception as e:
            logger.warning("node health: %s DNS block failed (%s: %s)", n, type(e).__name__, e)
            dns = {"asl": None, "hv": None, "failed": False, "hv_failed": False,
                   "hv_paused": False, "budget": False, "disabled": False}
            dns_block = {"gated": bool(gated), "error": "%s: %s" % (type(e).__name__, e),
                         "asl": None, "hamvoip": {"expected": None, "checked": False,
                                                  "present": None, "txt_ip": None, "txt_port": None},
                         "stats_ip": None, "stats_port": None, "stats_fresh": False,
                         "consistent": None, "issues": [], "issues_pending": [],
                         "issues_last_confirmed": [], "notes": [],
                         "lookup_failed": False, "hv_lookup_failed": False, "paused": False,
                         "hv_paused": False, "budget": False, "cache_age_s": None,
                         "disabled": False}
        asl_rs = dns.get("asl")
        dns_reg = None if asl_rs is None else bool(asl_rs.present)     # TXT record exists
        dns_failed = bool(dns.get("failed"))
        ip = None if asl_rs is None else asl_rs.txt_ip
        port = None if asl_rs is None else asl_rs.txt_port
        if parent == "self":
            linked = None if posting == "?" else (posting == "1")
        else:
            linked = None if letter in (None, "?") else (letter in LINKED_LETTERS)

        detail = {"parent": parent, "reg_age_s": reg_age, "post_age_s": post_age,
                  "parent_post_age_s": parent_post_age,
                  "dns_registered": dns_reg, "dns_lookup_failed": dns_failed,
                  "source": (rec or {}).get("source")}
        if not gated:
            rows = self._advance(n, parent, ts, {"registered": registered,
                                                 "posting": posting, "letter": letter},
                                 detail, now)
            if rows:
                all_rows.extend(rows)
                changed_nodes.add(n)
            if registered != "?":
                counts["registered_known"] += 1
                counts["registered"] += registered == "1"
            if posting != "?":
                counts["posting_known"] += 1
                counts["posting"] += posting == "1"
            if parent != "self" and letter not in (None, "?"):
                counts["linked_known"] += 1
                counts["linked"] += letter in LINKED_LETTERS
            if dns_block.get("asl") is not None:
                counts["dns_asl_known"] += 1
                counts["dns_asl"] += bool(dns_block["asl"]["present"])
            hvb = dns_block["hamvoip"]
            if hvb.get("expected") is True and hvb.get("present") is not None:
                counts["dns_hv_known"] += 1
                counts["dns_hv"] += bool(hvb["present"])
            counts["dns_issues"] += bool(dns_block["issues"])
        cur = self._current.get(n) or {}
        nodes_block[str(n)] = {
            "parent": parent,
            "gated": gated,
            "observed": not gated and rec is not None,
            "registered": None if gated or registered == "?" else registered == "1",
            "reg_time": reg_time if not gated else None,
            "reg_age_s": reg_age if not gated else None,
            "dns_registered": dns_reg,
            "dns_lookup_failed": dns_failed,
            "dns_paused": bool(self._mono() < self._dns_backoff_until),
            "ip": ip, "port": port,
            "dns": dns_block,
            "version": self._version.get(n),
            # display-only record facts for the team status page (2026-10-20);
            # None when nothing was observed this scan (gated / no record)
            "public": None if gated or rec is None else (rec.get("public") or None),
            "posting": None if gated or posting == "?" else posting == "1",
            "post_time": pt if not gated else None,
            "post_age_s": post_age if not gated else None,
            "letter": None if gated else letter,
            "letter_text": None if gated or letter is None else LETTER_TEXT.get(letter, letter),
            "parent_post_age_s": parent_post_age if not gated else None,
            "linked": None if gated else linked,
            "source": (rec or {}).get("source"),
            # ages above are AS OF the record's fetch; this is how old that fetch is
            "asof": None if gated or rec is None else int(asof),
            "asof_age_s": None if gated or rec is None else int(max(0.0, now - asof)),
            "parent_fetch_failed": bool(parent in extra_failed_nodes) if parent != "self" else False,
            "unobserved_s": {f: int(now - self._last_obs[(n, f)]) for f in FIELDS
                             if (n, f) in self._last_obs},
            "recorded": {f: cur.get(f) for f in FIELDS},
            "since": dict(cur.get("since") or {}),
            "pending": {f: self._pending[(n, f)][0] for f in FIELDS
                        if (n, f) in self._pending},
        }

    def _advance(self, n: int, parent, ts: str, obs: dict, detail: dict,
                 now: Optional[float] = None) -> list[tuple]:
        """Debounce one node's three observed values against the recorded
        state; return the rows to write: (ts, node, field, old, new,
        baseline, detail). A '?' for registered/posting, or None for the
        letter, is NO observation (audit S1): the field is left exactly as it
        was, pending included — until it has been unobserved for
        STALE_UNOBSERVED_S, after which '?' is recorded like any value (pass
        3: a state must not be held forever on no evidence)."""
        rows: list[tuple] = []
        now = float(now if now is not None else self._now())
        cur = self._current.get(n)
        if cur is None:
            cur = {"registered": None, "posting": None, "letter": None,
                   "parent": parent, "since": {}}
            self._current[n] = cur
        cur["parent"] = parent
        first = n not in self._baselined
        self._baselined.add(n)
        for f in FIELDS:
            v = obs[f]
            c = cur.get(f)
            unobserved = (v is None) or (f != "letter" and v == "?")
            if unobserved:
                last = self._last_obs.setdefault((n, f), self._started)
                if (c not in (None, "?")) and (now - last) > STALE_UNOBSERVED_S:
                    v, unobserved = "?", False       # stale: record the unknown
            else:
                self._last_obs[(n, f)] = now
            if c is None:
                if unobserved:
                    continue          # nothing known yet; wait for a real observation
                # Never recorded: adopt the observation now (baseline row).
                cur[f] = v
                cur["since"][f] = cur["since"].get(f) or ts
                rows.append((ts, n, f, None, v, 1, detail))
                self._pending.pop((n, f), None)
                continue
            if first:
                # Restart anchor: the carried state re-stamped at this instant.
                rows.append((ts, n, f, None, c, 1, detail))
            if unobserved:
                continue
            if v == c:
                self._pending.pop((n, f), None)
                continue
            p = self._pending.get((n, f))
            if p is None or p[0] != v:
                p = [v, 0]
                self._pending[(n, f)] = p
            p[1] += 1
            if p[1] >= self.cfg["confirm_scans"]:
                rows.append((ts, n, f, c, v, 0, detail))
                cur[f] = v
                cur["since"][f] = ts
                self._pending.pop((n, f), None)
        return rows

    def _current_row(self, n: int, ts: str) -> dict:
        cur = self._current[n]
        since = cur.get("since") or {}
        return {"node_id": n, "parent": str(cur.get("parent")),
                "registered": cur.get("registered"), "posting": cur.get("posting"),
                "letter": cur.get("letter"),
                "since_registered": since.get("registered"),
                "since_posting": since.get("posting"),
                "since_letter": since.get("letter"), "updated": ts}


# ---------------------------------------------------------------------- #
def _selftest() -> int:
    """Offline: fake ScanResults + fake API/DNS, scratch analytics.db."""
    import os
    import tempfile
    import types
    from analytics_db import init_db, Recorder, purge_node_health

    td = tempfile.mkdtemp()
    conn = init_db(os.path.join(td, "a.db"))
    rec = Recorder(conn)
    clock = {"now": 1_800_000_000.0, "mono": 1000.0, "minute": 30}

    def mk(fetched: dict, failed=(), focus=1000, ts="2026-10-18T20:00:00Z",
           peer_regs=None, topology=None):
        """fetched: node -> (reg_time, post_time, raw_nodes)"""
        if topology is None:
            topology = {focus: {}} if focus in fetched else {}
        r = types.SimpleNamespace(timestamp=ts, focus_node=focus, fetched=set(),
                                  fetch_failed=set(failed), raw_nodes={}, post_time={},
                                  regseconds={}, peer_regseconds=dict(peer_regs or {}),
                                  topology=topology)
        for n, (rt, pt, raw) in fetched.items():
            r.fetched.add(n)
            r.regseconds[n] = rt
            r.post_time[n] = pt
            if raw is not None:
                r.raw_nodes[n] = raw
        return r

    api_calls = []

    class FakeApi:
        payloads = {}
        timeout = 15
        _api_healthy = True
        last_429_timestamp = None
        seen_timeouts: list = []
        seen_retry_kw: list = []
        last_optional_failure = None
        fail_kind = "http"                 # how a missing payload "fails" (per the real client)

        def get_node_stats(self, n, _attempt=0, retry_429=True):
            api_calls.append(n)
            self.seen_retry_kw.append(retry_429)
            if self.timeout not in self.seen_timeouts:
                self.seen_timeouts.append(self.timeout)
            data = self.payloads.get(n)
            if data is None:
                # mirror ASLApiClient: an optional fetch records the kind and
                # leaves the health flag alone; a normal one marks unhealthy
                if retry_429:
                    self._api_healthy = False
                else:
                    self.last_optional_failure = (self.fail_kind, "ts")
            return data

    class PlainApi:                       # a client without the keyword / contract
        timeout = 15
        last_429_timestamp = None

        def __init__(self):
            self.calls = []
            self._api_healthy = True

        def get_node_stats(self, n):
            self.calls.append(n)
            self._api_healthy = False     # like the real client on any failure
            return None

    dns_calls = []

    def fake_dns(n, timeout=None):
        dns_calls.append(n)
        return types.SimpleNamespace(is_registered=(n != 3000), lookup_failed=False,
                                     ip_address="192.0.2.1", port=4569)

    cfg = node_health_cfg({"focus_node": 1000, "node_health": {
        "enabled": True, "confirm_scans": 2,
        "nodes": {1000: "self", 2000: 1000, 3000: 1000, 4000: 1000, 5000: 2000}}})
    tr = NodeHealthTracker(cfg, recorder=rec, now_fn=lambda: clock["now"],
                           mono_fn=lambda: clock["mono"], dns_fn=fake_dns,
                           minute_fn=lambda: clock["minute"])
    now = clock["now"]
    api = FakeApi()
    # Scan 1: hub posts "T2000,C3000"; 2000 (a bridge) posts "T1000,T5000";
    # 3000 fetched (its record exists: old registration, not posting);
    # 4000 not listed by anyone -> extra fetch (API has a record: registered, not posting).
    api.payloads[4000] = {"node": {"regseconds": int(now - 100)},
                          "stats": {"data": {"time": int(now - 7200), "nodes": ""}}}
    s1 = mk({1000: (int(now - 60), int(now - 30), "T2000,C3000"),
             2000: (int(now - 120), int(now - 40), "T1000,T5000"),
             3000: (int(now - 200000), None, None),
             5000: (int(now - 10), int(now - 20), "T2000")})
    b1 = tr.observe(s1, api=api)
    nb = b1["nodes"]
    checks = [
        ("hub: letter self, linked = posting, registered",
         nb["1000"]["letter"] == "self" and nb["1000"]["linked"] is True
         and nb["1000"]["registered"] is True),
        ("2000: T live via hub, registered, posting",
         nb["2000"]["letter"] == "T" and nb["2000"]["linked"] is True
         and nb["2000"]["posting"] is True),
        ("3000: C dialing, not registered (2.3 d), not posting",
         nb["3000"]["letter"] == "C" and nb["3000"]["linked"] is False
         and nb["3000"]["registered"] is False and nb["3000"]["posting"] is False),
        ("5000: T live via bridge 2000 (parent != hub)",
         nb["5000"]["letter"] == "T" and nb["5000"]["parent"] == 2000),
        ("4000: not listed -> extra fetch, '-' letter, registered via own record, not posting",
         api_calls == [4000] and nb["4000"]["letter"] == "-" and nb["4000"]["source"] == "extra"
         and nb["4000"]["registered"] is True and nb["4000"]["posting"] is False),
        ("extra fetch used the short socket timeout (4 s seen by the fake), restored 15, "
         "and asked for no 429 retry",
         api.timeout == 15 and api.seen_timeouts == [4] and api.seen_retry_kw == [False]),
        ("counts: linked 2/4 known (hub excluded), registered 4/5, posting 3/5",
         {k: b1["counts"][k] for k in ("registered", "registered_known", "linked",
                                        "linked_known", "posting", "posting_known")}
         == {"registered": 4, "registered_known": 5, "linked": 2,
             "linked_known": 4, "posting": 3, "posting_known": 5}),
        ("DNS looked up once per node", sorted(dns_calls) == [1000, 2000, 3000, 4000, 5000]
         and nb["3000"]["dns_registered"] is False),
    ]
    n_base = conn.execute("SELECT COUNT(*) FROM node_health_events WHERE baseline=1").fetchone()[0]
    n_cur = conn.execute("SELECT COUNT(*) FROM current_node_health").fetchone()[0]
    checks.append(("scan 1 writes one baseline row per node per field (15) and 5 current rows",
                   n_base == 15 and n_cur == 5))

    # Scan 2 (30 s later): hub now says T3000 (3000 answered). One scan is
    # not enough (confirm_scans 2): recorded letter stays C, pending shows T.
    clock["now"] += 30
    clock["mono"] += 30
    s2 = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,T3000"),
             2000: (int(now - 120), int(clock["now"] - 6), "T1000,T5000"),
             3000: (int(now - 200000), None, None),
             5000: (int(now - 10), int(clock["now"] - 7), "T2000")},
            ts="2026-10-18T20:00:30Z")
    b2 = tr.observe(s2, api=api)
    checks += [
        ("debounce: first differing scan is pending, not recorded",
         b2["nodes"]["3000"]["letter"] == "T" and b2["nodes"]["3000"]["recorded"]["letter"] == "C"
         and b2["nodes"]["3000"]["pending"] == {"letter": "T"}),
        ("extra-fetch cache: 4000 served from cache, no second API call",
         api_calls == [4000] and b2["nodes"]["4000"]["source"] == "cache"),
        ("DNS cache: no second lookup inside 60 s", len(dns_calls) == 5),
    ]
    # Scan 3: still T -> transition recorded.
    clock["now"] += 30
    clock["mono"] += 30
    s3 = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,T3000"),
             2000: (int(now - 120), int(clock["now"] - 6), "T1000,T5000"),
             3000: (int(now - 200000), None, None),
             5000: (int(now - 10), int(clock["now"] - 7), "T2000")},
            ts="2026-10-18T20:01:00Z")
    b3 = tr.observe(s3, api=api)
    tr_rows = conn.execute("SELECT node_id, field, old, new, ts FROM node_health_events "
                           "WHERE baseline=0 ORDER BY id").fetchall()
    cur3000 = conn.execute("SELECT letter, since_letter FROM current_node_health "
                           "WHERE node_id=3000").fetchone()
    checks += [
        ("debounce: second consecutive scan records C -> T, since = that scan",
         tr_rows == [(3000, "letter", "C", "T", "2026-10-18T20:01:00Z")]
         and b3["nodes"]["3000"]["recorded"]["letter"] == "T"
         and cur3000 == ("T", "2026-10-18T20:01:00Z")),
    ]
    # Scan 4 (400 s later, so 4000's cached record is older than the 5 min
    # refetch interval): a hub fetch FAILURE -> everything gated, nothing
    # written, and NO extra fetches even though 4000 is due.
    before = conn.execute("SELECT COUNT(*) FROM node_health_events").fetchone()[0]
    clock["now"] += 400
    clock["mono"] += 400
    s4 = mk({}, failed=[1000], ts="2026-10-18T20:03:30Z")
    b4 = tr.observe(s4, api=api)
    after = conn.execute("SELECT COUNT(*) FROM node_health_events").fetchone()[0]
    checks += [
        ("gate: hub fetch failed -> scan_gated, every node gated, no rows, no extra fetches",
         b4["scan_gated"] and all(v["gated"] for v in b4["nodes"].values())
         and after == before and api_calls == [4000]
         and b4["nodes"]["3000"]["recorded"]["letter"] == "T"),
    ]
    # Scan 5: hub fetched but NOT posting (empty record, old post) -> not a
    # gate: hub posting 0, children '?' letter (needs 2 scans); extra fetches
    # for the unlisted children happen (budget), parent-first ordering.
    clock["now"] += 150
    clock["mono"] += 150
    api.payloads[2000] = {"node": {"regseconds": int(clock["now"] - 50)},
                          "stats": {"data": {"time": int(clock["now"] - 9), "nodes": "T1000,T5000"}}}
    api.payloads[3000] = {"node": {"regseconds": int(now - 200000)}, "stats": {}}
    api.payloads[5000] = {"node": {"regseconds": int(clock["now"] - 50)},
                          "stats": {"data": {"time": int(clock["now"] - 9), "nodes": "T2000"}}}
    s5 = mk({1000: (int(now - 60), int(clock["now"] - 1200), None)}, ts="2026-10-18T20:06:00Z")
    b5 = tr.observe(s5, api=api)
    checks += [
        ("hub not posting is a state, not a gate: hub posting False, not gated",
         b5["nodes"]["1000"]["posting"] is False and not b5["nodes"]["1000"]["gated"]
         and not b5["scan_gated"]),
        ("children of a silent hub: letter '?' (parent post stale), linked None",
         b5["nodes"]["2000"]["letter"] == "?" and b5["nodes"]["2000"]["linked"] is None),
        ("extra fetches: unlisted nodes fetched parent-first; 4000 re-fetched (cache > 5 min)",
         api_calls[1:] == [2000, 3000, 4000, 5000]),
        ("5000 via extra-fetched bridge record: letter T (parent record from the cache)",
         b5["nodes"]["5000"]["letter"] == "T" and b5["nodes"]["5000"]["source"] == "extra"),
    ]
    # Blackout: at :57 no extra fetches are made (cache may still serve).
    clock["minute"] = 57
    clock["now"] += 400
    clock["mono"] += 400
    s6 = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,T3000")}, ts="2026-10-18T20:12:40Z")
    n_before = len(api_calls)
    b6 = tr.observe(s6, api=api)
    checks.append(("blackout :55-:10: no extra fetches, cached records still served",
                   len(api_calls) == n_before and b6["extra_fetch_blackout"]
                   and b6["nodes"]["2000"]["source"] == "cache"
                   and b6["extra_fetches_skipped"] == "blackout"))
    # S1 (pass 2): 300 s further into the blackout the cached records are
    # 700 s old — older than the 600 s posting limit — yet judged AS OF their
    # fetch: 2000 still posting, 5000 still T via the cached bridge record,
    # no transition, nothing pending.
    clock["minute"] = 59
    clock["now"] += 300
    clock["mono"] += 300
    rows_b = conn.execute("SELECT COUNT(*) FROM node_health_events").fetchone()[0]
    s6b = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,T3000")}, ts="2026-10-18T20:17:40Z")
    b6b = tr.observe(s6b, api=api)
    checks.append(("S1 pass 2: a 700 s old cached record is judged as of its fetch — posting stays "
                   "True, child letter stays T, no rows, nothing pending",
                   b6b["nodes"]["2000"]["posting"] is True and b6b["nodes"]["2000"]["source"] == "cache"
                   and b6b["nodes"]["5000"]["letter"] == "T" and b6b["nodes"]["2000"]["pending"] == {}
                   and b6b["nodes"]["5000"]["pending"] == {}
                   and conn.execute("SELECT COUNT(*) FROM node_health_events").fetchone()[0] == rows_b))
    # A parent whose record was NOT obtained at all (fresh tracker, no cache,
    # blackout): the child's letter is None = no observation, never '?', and
    # NOTHING is recorded for that field (own scratch recorder).
    conn_cold = init_db(os.path.join(td, "cold.db"))
    tr_cold = NodeHealthTracker(cfg, recorder=Recorder(conn_cold), now_fn=lambda: clock["now"],
                                mono_fn=lambda: clock["mono"], dns_fn=fake_dns,
                                minute_fn=lambda: clock["minute"])
    b_cold = tr_cold.observe(s6b, api=api)
    cold_letter_rows = conn_cold.execute("SELECT COUNT(*) FROM node_health_events WHERE node_id=5000 "
                                         "AND field='letter'").fetchone()[0]
    cold_other_rows = conn_cold.execute("SELECT COUNT(*) FROM node_health_events WHERE node_id=2000 "
                                        "AND field='letter'").fetchone()[0]
    conn_cold.close()
    checks.append(("S1 pass 2: parent record not obtained -> child letter None (unobserved), "
                   "no letter row written; hub children from the hub's own record still judged",
                   b_cold["nodes"]["5000"]["letter"] is None and b_cold["nodes"]["5000"]["linked"] is None
                   and cold_letter_rows == 0 and cold_other_rows == 1
                   and b_cold["nodes"]["2000"]["letter"] == "T"
                   and b_cold["counts"]["linked_known"] == 3))
    clock["minute"] = 30
    # Audit S1: a node whose OWN fetch failed this scan -> registered/posting
    # are "no observation": observed None, recorded unchanged, nothing pending,
    # no transition even after two such scans; its LETTER (from the hub) stays.
    base_rows = conn.execute("SELECT COUNT(*) FROM node_health_events").fetchone()[0]
    for k in range(2):
        clock["now"] += 30
        clock["mono"] += 30
        s_f = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,T3000"),
                  2000: (int(now - 120), int(clock["now"] - 6), "T1000,T5000"),
                  5000: (int(now - 10), int(clock["now"] - 7), "T2000")},
                 failed=[3000], ts=f"2026-10-18T20:13:{10 + 30 * k:02d}Z")
        b_f = tr.observe(s_f, api=api)
    checks += [
        ("S1: own fetch failed -> registered/posting observed None, recorded kept, no pending",
         b_f["nodes"]["3000"]["registered"] is None and b_f["nodes"]["3000"]["posting"] is None
         and b_f["nodes"]["3000"]["recorded"]["registered"] == "0"
         and b_f["nodes"]["3000"]["recorded"]["posting"] == "0"
         and b_f["nodes"]["3000"]["pending"] == {} and b_f["nodes"]["3000"]["letter"] == "T"
         and conn.execute("SELECT COUNT(*) FROM node_health_events").fetchone()[0] == base_rows),
        ("C1: any fetch failure this scan -> no extra fetches (4000 due, not fetched)",
         len(api_calls) == n_before and b_f["extra_fetches_skipped"] == "fetch failure this scan"),
    ]
    # Audit C1: a recent 429 on the client -> no extra fetches; an unhealthy client -> none.
    clock["now"] += 30
    clock["mono"] += 30
    api.last_429_timestamp = datetime.fromtimestamp(clock["now"] - 60, timezone.utc).isoformat()
    s_429 = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,T3000"),
                2000: (int(now - 120), int(clock["now"] - 6), "T1000,T5000"),
                3000: (int(now - 200000), None, None),
                5000: (int(now - 10), int(clock["now"] - 7), "T2000")},
               ts="2026-10-18T20:14:40Z")
    b_429 = tr.observe(s_429, api=api)
    api.last_429_timestamp = None
    api._api_healthy = False
    b_unh = tr.observe(s_429, api=api)
    api._api_healthy = True
    checks.append(("C1: recent 429 / unhealthy client -> extra fetches skipped",
                   len(api_calls) == n_before
                   and b_429["extra_fetches_skipped"] == "api unhealthy / recent 429"
                   and b_unh["extra_fetches_skipped"] == "api unhealthy / recent 429"))
    # Audit S2: hub fetched but absent from the topology (payload did not parse) -> aborted.
    s_parse = mk({1000: (int(now - 60), int(clock["now"] - 5), None)}, topology={},
                 ts="2026-10-18T20:15:00Z")
    b_parse = tr.observe(s_parse, api=api)
    checks.append(("S2: hub in fetched but not in topology -> scan_gated, all gated",
                   b_parse["scan_gated"] and all(v["gated"] for v in b_parse["nodes"].values())))
    # Audit A1: a failing DB write keeps the rows and retries on the next success.
    clock["now"] += 30
    clock["mono"] += 30
    real_write = rec.record_node_health
    rec.record_node_health = lambda rows, current: (_ for _ in ()).throw(RuntimeError("disk"))
    s_w1 = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,C3000"),
               2000: (int(now - 120), int(clock["now"] - 6), "T1000,T5000"),
               3000: (int(now - 200000), None, None),
               5000: (int(now - 10), int(clock["now"] - 7), "T2000")},
              ts="2026-10-18T20:15:30Z")
    tr.observe(s_w1, api=api)
    clock["now"] += 30
    clock["mono"] += 30
    s_w2 = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,C3000"),
               2000: (int(now - 120), int(clock["now"] - 6), "T1000,T5000"),
               3000: (int(now - 200000), None, None),
               5000: (int(now - 10), int(clock["now"] - 7), "T2000")},
              ts="2026-10-18T20:16:00Z")
    b_w2 = tr.observe(s_w2, api=api)        # the T -> C transition is confirmed here, write fails
    unwritten = b_w2["unwritten_rows"]
    rec.record_node_health = real_write
    clock["now"] += 30
    clock["mono"] += 30
    s_w3 = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,C3000"),
               2000: (int(now - 120), int(clock["now"] - 6), "T1000,T5000"),
               3000: (int(now - 200000), None, None),
               5000: (int(now - 10), int(clock["now"] - 7), "T2000")},
              ts="2026-10-18T20:16:30Z")
    b_w3 = tr.observe(s_w3, api=api)
    tc_row = conn.execute("SELECT ts FROM node_health_events WHERE node_id=3000 AND field='letter' "
                          "AND old='T' AND new='C'").fetchone()
    checks.append(("A1: rows from a failed write are kept and written on the next scan",
                   unwritten == 1 and b_w3["unwritten_rows"] == 0
                   and tc_row == ("2026-10-18T20:16:00Z",)
                   and conn.execute("SELECT letter FROM current_node_health WHERE node_id=3000"
                                    ).fetchone() == ("C",)))
    # Restart: a new tracker seeds from current_node_health, writes baseline
    # rows (carried state) and no spurious transition.
    tr2 = NodeHealthTracker(cfg, recorder=rec, now_fn=lambda: clock["now"],
                            mono_fn=lambda: clock["mono"], dns_fn=fake_dns,
                            minute_fn=lambda: clock["minute"])
    seeded = tr2._current.get(3000, {}).get("letter")
    n_tr_before = conn.execute("SELECT COUNT(*) FROM node_health_events WHERE baseline=0").fetchone()[0]
    clock["now"] += 60
    clock["mono"] += 60
    s7 = mk({1000: (int(now - 60), int(clock["now"] - 5), "T2000,C3000"),
             2000: (int(now - 120), int(clock["now"] - 6), "T1000,T5000"),
             3000: (int(now - 200000), None, None),
             5000: (int(now - 10), int(clock["now"] - 7), "T2000")},
            ts="2026-10-18T20:17:40Z")
    api_calls.clear()
    tr2.observe(s7, api=api)
    n_tr_after = conn.execute("SELECT COUNT(*) FROM node_health_events WHERE baseline=0").fetchone()[0]
    n_base2 = conn.execute("SELECT COUNT(*) FROM node_health_events WHERE baseline=1 "
                           "AND ts='2026-10-18T20:17:40Z'").fetchone()[0]
    checks += [
        ("restart: seeded from current_node_health (3000 letter C)", seeded == "C"),
        ("restart: baseline rows re-stamped (15), no spurious transition",
         n_base2 == 15 and n_tr_after == n_tr_before),
    ]
    # Audit S4: a node dropped from the config is retired at start-up.
    cfg_small = node_health_cfg({"focus_node": 1000, "node_health": {
        "enabled": True, "nodes": {1000: "self", 2000: 1000, 3000: 1000, 5000: 2000}}})
    tr3 = NodeHealthTracker(cfg_small, recorder=rec, now_fn=lambda: clock["now"],
                            mono_fn=lambda: clock["mono"], dns_fn=fake_dns,
                            minute_fn=lambda: clock["minute"])
    closing = conn.execute("SELECT field, old, new FROM node_health_events WHERE node_id=4000 "
                           "AND new='?' ORDER BY field").fetchall()
    checks.append(("S4: node 4000 dropped from config -> closing '?' rows, current row deleted",
                   [c[0] for c in closing] == ["letter", "posting", "registered"]
                   and closing[0][1] == "-"
                   and conn.execute("SELECT COUNT(*) FROM current_node_health WHERE node_id=4000"
                                    ).fetchone()[0] == 0 and 4000 not in tr3._current))
    # Purge (audit S3): age every 3000 row EXCEPT its newest 'letter' row, so
    # newer rows exist for that field; the newest OLD row per (node, field)
    # must survive as the anchor, all other old rows go, new rows untouched.
    newest_letter = conn.execute("SELECT MAX(id) FROM node_health_events WHERE node_id=3000 "
                                 "AND field='letter'").fetchone()[0]
    conn.execute("UPDATE node_health_events SET ts='2020-01-01T00:00:00Z' WHERE node_id=3000 "
                 "AND id != ?", (newest_letter,))
    conn.commit()
    n3000 = conn.execute("SELECT COUNT(*) FROM node_health_events WHERE node_id=3000").fetchone()[0]
    anchor_letter = conn.execute("SELECT MAX(id) FROM node_health_events WHERE node_id=3000 "
                                 "AND field='letter' AND ts < '2026'").fetchone()[0]
    purged = purge_node_health(conn, now=datetime(2026, 10, 18, tzinfo=timezone.utc))
    left_ids = {r[0] for r in conn.execute("SELECT id FROM node_health_events WHERE node_id=3000")}
    left3000 = len(left_ids)
    checks.append(("purge: old rows deleted but the newest OLD row per (node, field) kept (4 left: "
                   "3 anchors + the newer letter row)",
                   n3000 > 4 and left3000 == 4 and purged == n3000 - 4
                   and anchor_letter in left_ids and newest_letter in left_ids))
    # Config parsing: defaults from analytics roles; malformed entries skipped;
    # quoted booleans; blackout from top_of_hour_polling.
    c_def = node_health_cfg({"focus_node": 10, "bridge_nodes": [20],
                             "analytics": {"core_nodes": [10, 11]},
                             "top_of_hour_polling": {"before_minutes": 3, "after_minutes": 7},
                             "node_health": {"enabled": True}})
    c_bad = node_health_cfg({"focus_node": 10, "node_health": {
        "enabled": True, "nodes": {"x": 10, 12: "hub", 13: 10}}})
    checks += [
        ("config: default nodes = hub self + core/bridges under the hub; blackout 57..7",
         c_def["nodes"] == {10: "self", 11: 10, 20: 10}
         and (c_def["blackout_from_minute"], c_def["blackout_to_minute"]) == (57, 7)),
        ("config: bad node ids / parents skipped, good one kept",
         c_bad["nodes"] == {13: 10}),
        ("config: disabled/absent/quoted-false -> None",
         node_health_cfg({"focus_node": 1}) is None
         and node_health_cfg({"focus_node": 1, "node_health": {"enabled": False}}) is None
         and node_health_cfg({"focus_node": 1, "node_health": {"enabled": "false"}}) is None),
    ]
    # A tracker without a recorder still produces the block.
    tr4 = NodeHealthTracker(cfg, recorder=None, now_fn=lambda: clock["now"],
                            mono_fn=lambda: clock["mono"], dns_fn=fake_dns,
                            minute_fn=lambda: clock["minute"])
    b = tr4.observe(s7, api=None)
    checks.append(("no recorder / no api: block still built, unlisted node '-' and posting None",
                   b["nodes"]["4000"]["letter"] == "-" and b["nodes"]["4000"]["posting"] is None
                   and b["extra_fetches_skipped"] == "no api"))
    conn.close()
    # ---- Pass 3 cases (last: they advance the shared clock by ~1.5 h) -------
    # A node whose extra fetch always fails must not starve the nodes behind
    # it, and must back off (interval x 2^failures); a client without the
    # retry keyword gets the plain call (signature dispatch, no retry).
    ts_of = lambda: datetime.fromtimestamp(clock["now"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    cfg_two = node_health_cfg({"focus_node": 1000, "node_health": {
        "enabled": True, "dns_lookups": False,
        "nodes": {1000: "self", 7000: 1000, 8000: 1000}}})
    api2 = FakeApi()
    api2.payloads = {8000: {"node": {"regseconds": int(clock["now"] - 10)},
                            "stats": {"data": {"time": int(clock["now"] - 5), "nodes": ""}}}}
    calls_before = len(api_calls)
    tr_two = NodeHealthTracker(cfg_two, recorder=None, now_fn=lambda: clock["now"],
                               mono_fn=lambda: clock["mono"], dns_fn=fake_dns,
                               minute_fn=lambda: clock["minute"])
    s_two = mk({1000: (int(now - 60), int(clock["now"] - 5), "")}, ts=ts_of())
    b_two = tr_two.observe(s_two, api=api2)
    first_calls = api_calls[calls_before:]
    # 350 s later: 7000 (1 failure) is due only after 600 s -> not retried; 8000 is refetched.
    clock["now"] += 350
    clock["mono"] += 350
    s_two2 = mk({1000: (int(now - 60), int(clock["now"] - 5), "")}, ts=ts_of())
    tr_two.observe(s_two2, api=api2)
    second_calls = api_calls[calls_before + len(first_calls):]
    plain = PlainApi()
    tr_plain = NodeHealthTracker(cfg_two, recorder=None, now_fn=lambda: clock["now"],
                                 mono_fn=lambda: clock["mono"], dns_fn=fake_dns,
                                 minute_fn=lambda: clock["minute"])
    b_plain = tr_plain.observe(s_two, api=plain)
    # An API-wide failure kind (connection/timeout) on the first node stops the budget.
    api3 = FakeApi()
    api3.fail_kind = "request"
    api3.payloads = dict(api2.payloads)
    tr_three = NodeHealthTracker(cfg_two, recorder=None, now_fn=lambda: clock["now"],
                                 mono_fn=lambda: clock["mono"], dns_fn=fake_dns,
                                 minute_fn=lambda: clock["minute"])
    calls3 = len(api_calls)
    b_three = tr_three.observe(s_two, api=api3)
    checks += [
        ("pass 3/4: one node's own failure (HTTP) does not starve 8000 — both attempted, 8000 served",
         first_calls == [7000, 8000] and b_two["nodes"]["8000"]["posting"] is True
         and b_two["nodes"]["7000"]["posting"] is None
         and b_two["extra_fetches_skipped"] == "extra fetch failed (node; others continued)"
         and api2._api_healthy is True),
        ("pass 3: the failing node backs off (not retried at 350 s), the good one is refreshed",
         second_calls == [8000]),
        ("pass 4: an API-wide failure kind (request/timeout) stops the budget for this scan",
         api_calls[calls3:] == [7000] and b_three["extra_fetches_skipped"] == "extra fetch failed (api)"),
        ("pass 3: a client without retry_429 gets the plain call, no exception, no second request; "
         "its own unhealthy flag counts as API-wide",
         plain.calls == [7000] and b_plain["nodes"]["8000"]["posting"] is None
         and b_plain["extra_fetches_skipped"] == "extra fetch failed (api)"),
    ]
    # A fact unobserved for longer than STALE_UNOBSERVED_S (counted from the
    # last real observation — a served cache entry counts) is recorded as '?'
    # (debounced) instead of being held forever. Timeline for 8000: fetched at
    # T0, served from cache through T0+1200 s (the last observation), expired
    # at T0+1500 s; the API has no record (fetches fail, back off); '?' goes
    # pending at T0+3600 s (> 2100 s since the last observation) and is
    # recorded at T0+3900 s — index 12 of the 16 scans.
    conn_st = init_db(os.path.join(td, "stale.db"))
    tr_st = NodeHealthTracker(cfg_two, recorder=Recorder(conn_st), now_fn=lambda: clock["now"],
                              mono_fn=lambda: clock["mono"], dns_fn=fake_dns,
                              minute_fn=lambda: clock["minute"])
    tr_st.observe(s_two2, api=api2)                      # 8000 observed: posting 1 recorded
    api2.payloads = {}                                   # 8000 vanishes from the API
    stale_states = []
    for k in range(1, 17):                               # 16 scans x 300 s = 80 min
        clock["now"] += 300
        clock["mono"] += 300
        s_k = mk({1000: (int(now - 60), int(clock["now"] - 5), "")}, ts=ts_of())
        b_k = tr_st.observe(s_k, api=api2)
        stale_states.append(b_k["nodes"]["8000"]["recorded"]["posting"])
    st_rows = conn_st.execute("SELECT old, new FROM node_health_events WHERE node_id=8000 "
                              "AND field='posting' AND baseline=0").fetchall()
    conn_st.close()
    checks.append(("pass 3: unobserved > ceiling -> '?' recorded once (debounced) 45 min after "
                   "the last observation (scan index 12); held as '1' before that",
                   stale_states[:12] == ["1"] * 12 and stale_states[12] == "?"
                   and stale_states[-1] == "?" and st_rows == [("1", "?")]))
    # ---- two-system DNS (2026-10-19): record sets, expectation, cross-checks ----
    import json
    from dns_checker import DNSRecordSet as RS

    def rs(a=None, txt=None, port=None, present=None, **kw):
        r = RS(a_ips=[a] if a else [], txt_ip=txt, txt_port=port, **kw)
        r.present = bool(txt) if present is None else present
        return r

    dns_full_calls = []
    dns_full_kw = []
    dns_table = {
        1000: (rs("198.51.100.1", "198.51.100.1", 4567), rs(None, "198.51.100.1", 4567)),
        2000: (rs("198.51.100.2", "198.51.100.2", 4569), rs()),
        3000: (rs(), rs()),
        4000: (rs("198.51.100.4", "198.51.100.4", 4569), rs()),
        5000: (rs("198.51.100.5", "198.51.100.6", 4569), rs(None, "198.51.100.6", 4569)),
    }

    def fake_full(n, timeout=None, want_hamvoip=True):
        dns_full_calls.append(n)
        dns_full_kw.append(want_hamvoip)
        a, h = dns_table[n]
        return types.SimpleNamespace(asl=a, hamvoip=h if want_hamvoip else None,
                                     lookup_failed=bool(a.lookup_failed))

    def mk_dns(ts):
        r = mk({1000: (int(clock["now"] - 60), int(clock["now"] - 30), "T2000,T3000,T4000,T5000"),
                2000: (int(clock["now"] - 60), int(clock["now"] - 30), "T1000"),
                3000: (int(clock["now"] - 200000), None, None),
                4000: (int(clock["now"] - 60), int(clock["now"] - 30), "T1000"),
                5000: (int(clock["now"] - 60), int(clock["now"] - 30), "T1000")}, ts=ts)
        r.node_addr = {1000: ("198.51.100.1", 4567), 2000: ("198.51.100.2", 4569),
                       3000: (None, None), 4000: ("198.51.100.4", 4569),
                       5000: ("198.51.100.7", 4570)}
        r.node_version = {1000: "hamvoip-1.7.1-01/22/2022", 2000: "3.9.3",
                          4000: "hamvoip-1.7.1-01/22/2022", 5000: "hamvoip-1.7.1-01/22/2022"}
        r.node_public = {1000: {"callsign": "N0CALL", "frequency": "145.250", "links": ["T2000", "T3000"]},
                         2000: {"callsign": "N0CALL", "frequency": None, "links": ["T1000"]}}
        return r

    conn_d = init_db(os.path.join(td, "dns.db"))
    # confirm_scans 1 here so single-scan assertions read the findings directly;
    # the debounce itself is tested below with confirm_scans 2.
    cfg_d = node_health_cfg({"focus_node": 1000, "node_health": {
        "enabled": True, "confirm_scans": 1, "hamvoip_nodes": [1000, 4000, 5000],
        "nodes": {1000: "self", 2000: 1000, 3000: 1000, 4000: 1000, 5000: 1000}}})
    tr_d = NodeHealthTracker(cfg_d, recorder=Recorder(conn_d), now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    bd = tr_d.observe(mk_dns(ts_of()), api=FakeApi())
    nd = bd["nodes"]
    d1, d2, d3, d4, d5 = (nd[str(k)]["dns"] for k in (1000, 2000, 3000, 4000, 5000))
    checks += [
        ("dns: hub (listed in hamvoip_nodes) has both records, consistent, no issues",
         d1["asl"]["present"] is True and d1["hamvoip"]["expected"] is True
         and d1["hamvoip"]["present"] is True and d1["consistent"] is True and d1["issues"] == []
         and d1["stats_ip"] == "198.51.100.1" and d1["stats_port"] == 4567),
        ("dns: unlisted node (ASL3, 3.9.3) -> HamVoIP expected None (don't care), absent, consistent",
         d2["hamvoip"]["expected"] is None and d2["hamvoip"]["present"] is False
         and d2["consistent"] is True and d2["issues"] == []),
        ("dns: unknown version, no records anywhere -> expected None, nothing compared (consistent None), "
         "legacy dns_registered False",
         d3["hamvoip"]["expected"] is None and d3["asl"]["present"] is False
         and d3["consistent"] is None and d3["issues"] == [] and nd["3000"]["dns_registered"] is False),
        ("dns: listed hamvoip node without its HamVoIP record -> 'HamVoIP record missing'",
         d4["issues"] == ["HamVoIP record missing"] and d4["consistent"] is False),
        ("dns: stats ip != DNS -> PENDING on the first scan (registry lag rule), no verdict; "
         "the port difference (4570 vs 4569) is NOT a finding; "
         "A != TXT is a NOTE only; HamVoIP == ASL TXT -> no HV finding",
         d5["issues"] == [] and d5["issues_pending"] == ["ASL DNS IP ≠ stats"]
         and d5["notes"] == ["A record 198.51.100.5 differs from TXT"]
         and d5["consistent"] is None and d5["stats_fresh"] is True),
        ("dns counts: asl 4/5, hamvoip 2/3 (expected nodes only), issues 1 (4000; 5000 still pending)",
         {k: bd["counts"][k] for k in ("dns_asl", "dns_asl_known", "dns_hv", "dns_hv_known", "dns_issues")}
         == {"dns_asl": 4, "dns_asl_known": 5, "dns_hv": 2, "dns_hv_known": 3, "dns_issues": 1}),
        ("dns: one full lookup per node; legacy ip/port keys still the ASL TXT values",
         sorted(dns_full_calls) == [1000, 2000, 3000, 4000, 5000]
         and nd["5000"]["ip"] == "198.51.100.6" and nd["5000"]["port"] == 4569),
        ("dns: version remembered per node", tr_d._version.get(1000, "").startswith("hamvoip")),
        ("public: record facts carried per node from the walk; None where the walk had none",
         nd["1000"]["public"] == {"callsign": "N0CALL", "frequency": "145.250", "links": ["T2000", "T3000"]}
         and nd["2000"]["public"]["links"] == ["T1000"] and nd["3000"]["public"] is None),
        ("dns: /status entry is JSON-serialisable", json.dumps(bd) is not None),
    ]
    # Registry-lag rule: the stats mismatch confirms only once it has been seen
    # for DNS_STATS_MISMATCH_MIN_S (distinct samples: the cache expires between scans).
    bd_k = bd
    t_first = float(clock["now"])
    while float(clock["now"]) + 400 - t_first < DNS_STATS_MISMATCH_MIN_S:   # stop one step short
        clock["mono"] += 400
        clock["now"] += 400
        bd_k = tr_d.observe(mk_dns(ts_of()), api=FakeApi())
    d5_before = bd_k["nodes"]["5000"]["dns"]
    clock["mono"] += 400
    clock["now"] += 400
    bd_k = tr_d.observe(mk_dns(ts_of()), api=FakeApi())
    d5k = bd_k["nodes"]["5000"]["dns"]
    checks.append(("dns: stats mismatch pending until %d s have elapsed, then confirmed -> issues, consistent False, counted"
                   % DNS_STATS_MISMATCH_MIN_S,
                   d5_before["issues"] == [] and d5_before["issues_pending"] != []
                   and d5k["issues"] == ["ASL DNS IP ≠ stats"]
                   and d5k["issues_pending"] == [] and d5k["consistent"] is False
                   and bd_k["counts"]["dns_issues"] == 2))
    # A skipped comparison (stats record from the cache) FREEZES the streak; the next fresh
    # sample continues it (pass-3 S-B). Direct _dns_block calls with synthetic samples.
    import copy as _copy
    base_dns = dict(tr_d._dns_cache[5000][1])
    s_before = _copy.deepcopy(tr_d._dns_streak[5000])
    tr_d._dns_block(5000, dict(base_dns, sample=99001.0), "198.51.100.7", 4570, fresh=False)
    s_after_skip = _copy.deepcopy(tr_d._dns_streak[5000])
    tr_d._dns_block(5000, dict(base_dns, sample=99002.0), "198.51.100.7", 4570, fresh=True)
    s_after_fresh = _copy.deepcopy(tr_d._dns_streak[5000])
    checks.append(("dns: a sample whose stats comparison did not run leaves the streak untouched; a fresh one advances it",
                   s_after_skip == s_before
                   and all(s_after_fresh[k][0] == s_before[k][0] + 1 for k in DNS_STATS_ISSUES)))
    checks.append(("dns: same comparison with a CACHED stats record (not fresh) -> nothing observed",
                   tr_d._dns_block(5000, tr_d._dns_cache[5000][1], "198.51.100.7", 4570,
                                   fresh=False)["issues_pending"] == []))
    # Debounce with confirm_scans 2: first scan pending, second confirms; a one-scan blip never confirms.
    cfg_d2 = node_health_cfg({"focus_node": 1000, "node_health": {
        "enabled": True, "confirm_scans": 2, "hamvoip_nodes": [1000, 4000, 5000],
        "nodes": {1000: "self", 2000: 1000, 3000: 1000, 4000: 1000, 5000: 1000}}})
    tr_2 = NodeHealthTracker(cfg_d2, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    x1 = tr_2.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["4000"]["dns"]
    clock["mono"] += 61
    x2 = tr_2.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["4000"]["dns"]
    clock["mono"] += 61
    dns_table[4000] = (rs("198.51.100.4", "198.51.100.4", 4569), rs(None, "198.51.100.4", 4569))  # record appears
    x3 = tr_2.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["4000"]["dns"]
    clock["mono"] += 61
    dns_table[4000] = (rs("198.51.100.4", "198.51.100.4", 4569), rs())                              # one-scan blip
    x4 = tr_2.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["4000"]["dns"]
    clock["mono"] += 61
    dns_table[4000] = (rs("198.51.100.4", "198.51.100.4", 4569), rs(None, "198.51.100.4", 4569))
    x5 = tr_2.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["4000"]["dns"]
    dns_table[4000] = (rs("198.51.100.4", "198.51.100.4", 4569), rs())
    checks.append(("dns debounce (confirm_scans 2): pending -> confirmed on the 2nd scan -> clears when the record "
                   "returns -> a one-scan blip stays pending and never confirms",
                   x1["issues"] == [] and x1["issues_pending"] == ["HamVoIP record missing"] and x1["consistent"] is None
                   and x2["issues"] == ["HamVoIP record missing"] and x2["consistent"] is False
                   and x3["issues"] == [] and x3["consistent"] is True
                   and x4["issues"] == [] and x4["issues_pending"] == ["HamVoIP record missing"]
                   and x5["issues"] == [] and x5["issues_pending"] == [] and x5["consistent"] is True))
    # S1: an offline HamVoIP node (no record in either zone) is NOT a DNS issue — a note.
    dns_table[1000] = (rs(), rs())
    tr_s1 = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                              mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                              minute_fn=lambda: clock["minute"])
    s1b = tr_s1.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["1000"]["dns"]
    dns_table[1000] = (rs("198.51.100.1", "198.51.100.1", 4567), rs(None, "198.51.100.1", 4567))
    checks.append(("dns: HamVoIP node offline in BOTH zones -> no issue, no verdict, note 'no registration in either zone'",
                   s1b["issues"] == [] and s1b["issues_pending"] == [] and s1b["consistent"] is None
                   and s1b["notes"] == ["no registration in either zone"] and s1b["asl"]["present"] is False))
    # Burst cadence (pass-3 S-A): scans 15 s apart re-read the 60 s cache = ONE sample; the
    # streak does not advance until a new lookup happens.
    tr_bc = NodeHealthTracker(cfg_d2, recorder=None, now_fn=lambda: clock["now"],
                              mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                              minute_fn=lambda: clock["minute"])
    dns_table[4000] = (rs("198.51.100.4", "198.51.100.4", 4569), rs())   # HamVoIP missing (4000 is listed)
    burst = []
    for _ in range(4):                       # 4 scans inside one 60 s cache window = one sample
        clock["mono"] += 14
        clock["now"] += 14
        burst.append(tr_bc.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["4000"]["dns"])
    clock["mono"] += 61
    clock["now"] += 61
    after = tr_bc.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["4000"]["dns"]
    checks.append(("dns: four burst scans on one cached sample stay PENDING (confirm_scans 2); the next real sample confirms",
                   all(b["issues"] == [] and b["issues_pending"] == ["HamVoIP record missing"] for b in burst)
                   and after["issues"] == ["HamVoIP record missing"]))
    # HamVoIP-zone outage (pass-3 S-D): the AllStarLink-only findings keep debouncing and the
    # confirmed HamVoIP finding is kept (frozen), not dropped.
    dns_table[4000] = (rs("198.51.100.4", "198.51.100.4", 4569, txt_conflict=True), rs(lookup_failed=True))
    tr_bc._dns_hv_backoff_until = 0.0
    clock["mono"] += 61
    clock["now"] += 61
    o1 = tr_bc.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["4000"]["dns"]
    clock["mono"] += 61
    clock["now"] += 61
    o2 = tr_bc.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["4000"]["dns"]
    checks.append(("dns: HamVoIP zone down -> ASL finding (TXT conflict) still confirms on the 2nd sample; "
                   "the earlier HamVoIP finding is kept frozen; no verdict",
                   o1["issues"] == ["HamVoIP record missing"] and o1["issues_pending"] == ["ASL TXT records disagree"]
                   and o2["issues"] == ["ASL TXT records disagree", "HamVoIP record missing"]
                   and o2["consistent"] is None and o2["hamvoip"]["checked"] is False))
    dns_table[4000] = (rs("198.51.100.4", "198.51.100.4", 4569), rs())
    # Deterministic per-node failure (pass-3 S-E): the failing node backs off on its own, the
    # others keep getting fresh samples; a CODE error (exception) never pauses anything.
    dns_table[3000] = (rs(lookup_failed=True), None)
    tr_e = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    samples = {k: set() for k in (1000, 2000, 4000, 5000)}
    calls_3000 = 0
    for _ in range(4):
        clock["mono"] += 301
        clock["now"] += 301
        n0 = dns_full_calls.count(3000)
        be = tr_e.observe(mk_dns(ts_of()), api=FakeApi())
        calls_3000 += dns_full_calls.count(3000) - n0
        for k in samples:
            samples[k].add(be["nodes"][str(k)]["dns"]["cache_age_s"] == 0)
    dns_table[3000] = (rs(), rs())

    def raising(n, timeout=None, want_hamvoip=True):
        if n == 2000:
            raise ValueError("parser boom")
        return fake_full(n, timeout=timeout, want_hamvoip=want_hamvoip)
    tr_x = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=raising,
                             minute_fn=lambda: clock["minute"])
    clock["mono"] += 61
    bx = tr_x.observe(mk_dns(ts_of()), api=FakeApi())
    # Resolver-wide outage (pass-4 S2): every lookup fails for a while; no node may pile up
    # an hour-long back-off, so recovery is immediate once the resolver answers again.
    saved_table = dict(dns_table)
    for k in dns_table:
        dns_table[k] = (rs(lookup_failed=True), None)
    tr_o = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    for _ in range(8):                                   # 8 × 301 s ≈ 40 min outage
        clock["mono"] += 301
        clock["now"] += 301
        tr_o.observe(mk_dns(ts_of()), api=FakeApi())
    worst_backoff = max((v[1] - clock["mono"] for v in tr_o._dns_node_fail.values()), default=0)
    dns_table.update(saved_table)                        # resolver back
    clock["mono"] += 301
    clock["now"] += 301
    br1 = tr_o.observe(mk_dns(ts_of()), api=FakeApi())
    fresh_after = sum(1 for k in ("1000", "2000", "3000", "4000", "5000")
                      if br1["nodes"][k]["dns"]["asl"] is not None and br1["nodes"][k]["dns"]["cache_age_s"] == 0)
    checks += [
        ("dns: a node that always fails is retried with its own back-off (3 attempts in 4 scans at 300 s: "
         "300 s, then 600 s), the other nodes still get fresh samples",
         calls_3000 == 3 and all(True in s for s in samples.values())),
        ("dns: a 40 min resolver-wide outage leaves no node with a back-off beyond one pause (<= 300 s); "
         "the first scan after recovery refreshes every node",
         worst_backoff <= 300 and fresh_after == 5),
        ("dns: a code exception in one node's lookup -> error entry for it, NO global pause, others fine",
         bx["nodes"]["2000"]["dns"]["error"] is not None and bx["dns_paused"] is False
         and bx["nodes"]["1000"]["dns"]["asl"]["present"] is True),
    ]
    # Configured list is authoritative: 2000 expected (missing -> issue); 1000 unlisted
    # (record present -> informational, no finding); 4000 unlisted -> expected None.
    cfg_l = node_health_cfg({"focus_node": 1000, "node_health": {
        "enabled": True, "hamvoip_nodes": [2000], "confirm_scans": 1,
        "nodes": {1000: "self", 2000: 1000, 3000: 1000, 4000: 1000, 5000: 1000}}})
    tr_l = NodeHealthTracker(cfg_l, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    bl = tr_l.observe(mk_dns(ts_of()), api=FakeApi())
    checks += [
        ("dns: hamvoip_nodes list is the only source (2000 missing; 1000 present-but-unlisted no finding; "
         "4000 hamvoip-by-version but unlisted -> expected None, no finding)",
         bl["nodes"]["2000"]["dns"]["issues"] == ["HamVoIP record missing"]
         and bl["nodes"]["1000"]["dns"]["issues"] == []
         and bl["nodes"]["1000"]["dns"]["hamvoip"]["expected"] is None
         and bl["nodes"]["1000"]["dns"]["hamvoip"]["present"] is True
         and bl["nodes"]["4000"]["dns"]["hamvoip"]["expected"] is None
         and bl["nodes"]["4000"]["dns"]["issues"] == []),
        ("dns: config list parsed as ints; a non-list is ignored (None)",
         cfg_l["hamvoip_nodes"] == {2000} and _int_list("x") is None and _int_list(None) is None),
        ("dns: legacy dns_fn wrap reports HamVoIP as not checked (present None), ASL from the fake",
         b1["nodes"]["2000"]["dns"]["hamvoip"]["present"] is None
         and b1["nodes"]["2000"]["dns"]["hamvoip"]["checked"] is False
         and b1["nodes"]["2000"]["dns"]["asl"]["present"] is True),
    ]
    # Gated node: no lookup, dns entry is a dict with gated True.
    tr_g = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    n_calls_before = len(dns_full_calls)
    bg = tr_g.observe(mk({}, failed=[1000]), api=FakeApi())
    checks.append(("dns: gated scan -> dns entry dict with gated True, asl None, no lookups",
                   bg["nodes"]["2000"]["dns"]["gated"] is True and bg["nodes"]["2000"]["dns"]["asl"] is None
                   and bg["nodes"]["2000"]["gated"] is True and len(dns_full_calls) == n_calls_before))
    # HamVoIP IP differs from ASL -> issue.
    dns_table[1000] = (rs("198.51.100.1", "198.51.100.1", 4567), rs(None, "198.51.100.9", 4567))
    tr_h = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    bh = tr_h.observe(mk_dns(ts_of()), api=FakeApi())
    checks.append(("dns: HamVoIP IP != ASL TXT on a LISTED node -> 'HamVoIP IP ≠ ASL', consistent False",
                   bh["nodes"]["1000"]["dns"]["issues"] == ["HamVoIP IP ≠ ASL"]
                   and bh["nodes"]["1000"]["dns"]["consistent"] is False))
    dns_table[1000] = (rs("198.51.100.1", "198.51.100.1", 4567), rs(None, "198.51.100.1", 4567))
    # The same divergence on an UNLISTED node (2000, not in hamvoip_nodes) is a NOTE, not a finding:
    # registering with HamVoIP is optional, so its record is informational.
    dns_table[2000] = (rs("198.51.100.2", "198.51.100.2", 4569), rs(None, "198.51.100.9", 4570, txt_conflict=True))
    tr_u = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    bu = tr_u.observe(mk_dns(ts_of()), api=FakeApi())["nodes"]["2000"]["dns"]
    checks.append(("dns: unlisted node with a diverging HamVoIP record (IP, port, TXT conflict) -> notes only, "
                   "no issues, no pending, verdict from the ASL side (consistent True), record still shown",
                   bu["issues"] == [] and bu["issues_pending"] == []
                   and set(bu["notes"]) == {"HamVoIP TXT records disagree", "HamVoIP IP ≠ ASL", "HamVoIP port ≠ ASL"}
                   and bu["consistent"] is True and bu["hamvoip"]["expected"] is None
                   and bu["hamvoip"]["present"] is True and bu["hamvoip"]["txt_ip"] == "198.51.100.9"))
    dns_table[2000] = (rs("198.51.100.2", "198.51.100.2", 4569), rs())
    # HamVoIP-zone failure: isolated (its own pause), ASL facts intact, consistent None
    # for a node that expects a record (never "missing"), no issue flapping in the log.
    dns_table[1000] = (rs("198.51.100.1", "198.51.100.1", 4567), rs(lookup_failed=True))
    tr_f = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    bf = tr_f.observe(mk_dns(ts_of()), api=FakeApi())
    f1 = bf["nodes"]["1000"]["dns"]
    clock["mono"] += 61                                   # cache expired, HV pause (300 s) still on
    dns_full_kw.clear()
    bf2 = tr_f.observe(mk_dns(ts_of()), api=FakeApi())
    checks += [
        ("dns: HamVoIP lookup failed -> ASL facts kept, hv checked False, consistent None, no 'missing' issue, "
         "hv_paused; ASL back-off NOT triggered",
         f1["asl"]["present"] is True and f1["hamvoip"]["checked"] is False and f1["consistent"] is None
         and f1["issues"] == [] and f1["hv_paused"] is True and bf["dns_paused"] is False
         and bf["dns_hv_paused"] is True and bf["nodes"]["2000"]["dns"]["asl"]["present"] is True),
        ("dns: while HamVoIP is paused the next lookups ask for ASL only (want_hamvoip False)",
         dns_full_kw and all(k is False for k in dns_full_kw)
         and bf2["nodes"]["2000"]["dns"]["hamvoip"]["checked"] is False),
    ]
    dns_table[1000] = (rs("198.51.100.1", "198.51.100.1", 4567), rs(None, "198.51.100.1", 4567))
    # AllStarLink-zone failure: global pause; a cached good value is served while paused.
    tr_a = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    ba0 = tr_a.observe(mk_dns(ts_of()), api=FakeApi())         # good lookups, cached
    clock["mono"] += 61
    dns_table[3000] = (rs(lookup_failed=True), None)           # 3000's ASL query now fails
    n_before = len(dns_full_calls)
    ba1 = tr_a.observe(mk_dns(ts_of()), api=FakeApi())
    clock["mono"] += 61
    n_mid = len(dns_full_calls)
    ba2 = tr_a.observe(mk_dns(ts_of()), api=FakeApi())         # paused: no new lookups at all
    checks += [
        ("dns: ASL lookup failure -> tracker paused, that node served its cached value (paused flag), no None",
         ba1["nodes"]["3000"]["dns"]["paused"] is True
         and ba1["nodes"]["3000"]["dns"]["asl"]["present"] is False
         and ba1["dns_paused"] is True and ba0["nodes"]["3000"]["dns"]["asl"]["present"] is False),
        ("dns: while paused, nodes are served from the cache (< 900 s) with no new lookups",
         len(dns_full_calls) == n_mid and ba2["nodes"]["1000"]["dns"]["asl"]["present"] is True
         and ba2["nodes"]["1000"]["dns"]["paused"] is True and n_mid > n_before),
    ]
    dns_table[3000] = (rs(), rs())
    # Per-scan budget: a slow resolver (the fake burns 13 s on the first node) -> the rest
    # are served from the cache or marked budget, and the scan does not wait.
    tr_b = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], minute_fn=lambda: clock["minute"],
                             dns_full_fn=lambda n, timeout=None, want_hamvoip=True: (
                                 clock.__setitem__("mono", clock["mono"] + 13.0) or fake_full(n)))
    n_before = len(dns_full_calls)
    bb = tr_b.observe(mk_dns(ts_of()), api=FakeApi())
    checks.append(("dns: per-scan budget -> one lookup, the other nodes marked budget (no cache yet), hits counted",
                   len(dns_full_calls) - n_before == 1 and bb["dns_budget_hits"] >= 4
                   and sum(1 for k in ("1000", "2000", "3000", "4000", "5000") if bb["nodes"][k]["dns"]["budget"]) == 4))
    # Budget rotation: with a cache from an earlier scan, the next scan looks up the OLDEST entries
    # first, so the tail is not starved; a cached value served past the budget carries budget=True.
    clock["mono"] += 61
    seen = []
    tr_r = NodeHealthTracker(cfg_d, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], minute_fn=lambda: clock["minute"],
                             dns_full_fn=lambda n, timeout=None, want_hamvoip=True: (
                                 seen.append(n) or clock.__setitem__("mono", clock["mono"] + 7.0) or fake_full(n)))
    tr_r.observe(mk_dns(ts_of()), api=FakeApi())          # scan A: ~2 lookups fit (7 s each, 12 s budget)
    first = list(seen)
    clock["mono"] += 61
    tr_r.observe(mk_dns(ts_of()), api=FakeApi())          # scan B: the nodes skipped in A come first
    second = seen[len(first):]
    clock["mono"] += 61
    tr_r.observe(mk_dns(ts_of()), api=FakeApi())
    third = seen[len(first) + len(second):]
    checks.append(("dns: budget rotation — the nodes skipped in one scan are looked up first in the next; "
                   "every node is refreshed within three scans",
                   len(first) == 2 and second[0] not in first and len(set(first + second + third)) == 5))
    # Disabled.
    cfg_off = node_health_cfg({"focus_node": 1000, "node_health": {
        "enabled": True, "dns_lookups": False,
        "nodes": {1000: "self", 2000: 1000, 3000: 1000, 4000: 1000, 5000: 1000}}})
    tr_o = NodeHealthTracker(cfg_off, recorder=None, now_fn=lambda: clock["now"],
                             mono_fn=lambda: clock["mono"], dns_full_fn=fake_full,
                             minute_fn=lambda: clock["minute"])
    n_before = len(dns_full_calls)
    bo = tr_o.observe(mk_dns(ts_of()), api=FakeApi())
    checks.append(("dns: dns_lookups false -> disabled entry, no lookups, counts zero",
                   bo["nodes"]["1000"]["dns"]["disabled"] is True and bo["nodes"]["1000"]["dns"]["asl"] is None
                   and len(dns_full_calls) == n_before and bo["counts"]["dns_asl_known"] == 0))
    # record_addr / record_version on odd payloads.
    checks += [
        ("record_addr: normal / string port / out-of-range / list ipaddr / missing",
         record_addr({"node": {"ipaddr": "192.0.2.1", "port": 4569}}) == ("192.0.2.1", 4569)
         and record_addr({"node": {"ipaddr": " 192.0.2.1 ", "port": "4569"}}) == ("192.0.2.1", 4569)
         and record_addr({"node": {"ipaddr": "192.0.2.1", "port": 70000}}) == ("192.0.2.1", None)
         and record_addr({"node": {"ipaddr": ["x"], "port": 1}}) == (None, 1)
         and record_addr({}) == (None, None) and record_addr(None) == (None, None)),
        ("record_version: normal / numeric / missing",
         record_version({"stats": {"data": {"apprptvers": "hamvoip-1.7.1-01/22/2022"}}}) == "hamvoip-1.7.1-01/22/2022"
         and record_version({"stats": {"data": {"apprptvers": 3}}}) == "3"
         and record_version({"stats": {}}) is None and record_version(None) is None),
        ("hamvoip_nodes: a list with no usable numbers is ignored (None), not an empty set",
         _int_list(["HUB", "BRIDGE1"]) is None and _int_list([]) == set() and _int_list(["12345", 1]) == {12345, 1}),
    ]
    conn_d.close()

    failed_names = [nm for nm, ok in checks if not ok]
    for nm, ok in checks:
        print(f"  [{'OK' if ok else 'FAIL'}] {nm}")
    print(f"node_health selftest: {len(checks) - len(failed_names)}/{len(checks)} passed")
    import shutil
    shutil.rmtree(td, ignore_errors=True)
    return 1 if failed_names else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        logging.basicConfig(level=logging.WARNING)
        raise SystemExit(_selftest())
    print(__doc__)
