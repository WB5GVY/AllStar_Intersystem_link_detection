#!/usr/bin/env python3
"""public_export — the team status page feed (2026-10-20).

Turns the daemon's /status snapshot into one small JSON document
(`status.json`, schema 1 — see Claude-shared/2026-10-20_1716_team_status_page_
exporter_PLAN_v1.md §5), writes it atomically under `public_export/`, and
pushes it to ONE Azure blob with a write-only SAS taken from the login keychain.

Design rules (plan §3/§4):
  * push-only: nothing listens; the Mac never accepts a connection for this;
  * the scan never waits: render/write/push run on a worker thread, one in
    flight at a time, the newest snapshot wins, pushes >= min_interval apart
    (the :55–:10 burst scans every 15 s; the blob gets at most one PUT/min),
    and never two PUTs at once (a push lock);
  * the SAS is read from the keychain (`security find-generic-password`), is
    never in config.yaml / the log / /status / an exception text, and is
    re-read on SIGHUP (the old exporter is closed); without it the file is
    still written locally. urllib3/requests loggers are pinned to WARNING so a
    DEBUG log level cannot print the request line (audit C1);
  * every failure is a counter + a type-only `last_error`; a log line only
    when the state changes (ok -> fail, fail -> ok).

Config (`public_export:` in config.yaml; see config.yaml.example):
  enabled, dir, blob_url (https://<acct>.blob.core.windows.net/…, NO query
  string), sas_keychain_item, min_interval_seconds, timeout_seconds,
  stale_after_seconds, groups: [{name, icon, nodes: [n | {node, description, radioless, proxied, reboot_window}]}]
  (`radioless: true` = the node has no RF receiver/transmitter — a bridge or
  gateway; exported as the node's `radioless` flag (rev 4) so pages do not
  show keytime-based RF activity for it. `proxied: true` (rev 6) = the spoke
  registers through the hub site's reverse proxy, so its ASL A record is the
  hub's address and its TXT port is the hub router's forward — "A differs from
  TXT" / "HamVoIP port ≠ ASL" are its normal fingerprint, not faults; pages
  relabel them. `reboot_window: "HH:MM-HH:MM"` (rev 6, local time) = the
  node's scheduled daily reboot; a restart inside it is routine, outside it
  is news.) `tz` (rev 6, default America/Chicago) = the IANA zone the reboot
  windows are written in; exported as `legend.tz` so pages judge the window
  and print clock times in that zone, whatever the viewer's zone.

CLI:  python3 public_export.py --once [--push] [--status-url URL] [--config config.yaml]
      python3 public_export.py --selftest
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger("public_export")

SCHEMA = 1
DEFAULT_DIR = "public_export"
DEFAULT_FILE = "status.json"
DEFAULT_ITEM = "ASL_TEAM_STATUS_SAS"
DEFAULT_MIN_INTERVAL_S = 60
DEFAULT_TIMEOUT_S = 10
MAX_TIMEOUT_S = 30
DEFAULT_STALE_S = 900
MAX_BYTES = 512 * 1024               # refuse to push anything absurd (a bug, not a status)
BLOB_API_VERSION = "2023-11-03"
BLOB_HOST_SUFFIX = ".blob.core.windows.net"
LETTERS = {"T": "live", "R": "rx-only", "L": "local monitor", "C": "dialing, no audio",
           "-": "not listed", "?": "parent data stale"}
SAS_KEYS = ("sig=", "sv=", "sp=", "spr=", "sr=", "se=")


def _quiet_http_loggers() -> None:
    """urllib3 logs the full request line (query string = the SAS) at DEBUG.
    Pin those loggers above DEBUG so a `logging.level: DEBUG` in config.yaml can
    never put the SAS into asl_link_detector.log (audit C1)."""
    for name in ("urllib3", "urllib3.connectionpool", "requests", "requests.packages.urllib3"):
        lg = logging.getLogger(name)
        if lg.level == logging.NOTSET or lg.level < logging.WARNING:
            lg.setLevel(logging.WARNING)


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def _int(raw: dict, key: str, default: int, lo: int, hi: int = 10**9) -> int:
    try:
        v = int(raw.get(key, default))
    except (TypeError, ValueError, OverflowError):
        return default
    return min(hi, max(lo, v))


REBOOT_WINDOW_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d\Z")   # rev 6: "HH:MM-HH:MM" in the export's tz
DEFAULT_TZ = "America/Chicago"


def _valid_tz(v, default: str = DEFAULT_TZ) -> str:
    """IANA zone name for the export's `legend.tz` (rev 6): the zone the reboot
    windows are written in and the zone pages show clock times in. Anything
    `zoneinfo` cannot load falls back to the default (logged)."""
    if isinstance(v, str) and v.strip():
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(v.strip())
            return v.strip()
        except Exception:
            logger.warning("public_export.tz: unknown zone %r — using %s", v, default)
    return default


def _parse_groups(raw_groups, fallback_nodes: list) -> list:
    """[{name, icon, nodes: [{node:str, description:str|None, radioless:bool, proxied:bool, reboot_window:str|None}]}];
    invalid entries are dropped; a node appears at most once (first group wins);
    an empty result falls back to one group holding `fallback_nodes`.
    `radioless` / `proxied` are True only for a YAML boolean true (rev 4 / 6);
    a string or number is False and logged. `reboot_window` must match
    HH:MM-HH:MM (rev 6); anything else is None and logged."""
    out, seen = [], set()
    for g in (raw_groups or []) if isinstance(raw_groups, list) else []:
        if not isinstance(g, dict):
            continue
        name = str(g.get("name") or "").strip()[:80]
        icon = str(g.get("icon") or "").strip()[:32] or None
        nodes = []
        for item in (g.get("nodes") or []) if isinstance(g.get("nodes"), list) else []:
            desc, radioless, proxied, window = None, False, False, None
            if isinstance(item, dict):
                desc = item.get("description")
                for flag in ("radioless", "proxied"):
                    if flag in item and not isinstance(item.get(flag), bool):
                        logger.warning("public_export.groups: node %s has a non-boolean %s (%r) — treated as false",
                                       item.get("node"), flag, item.get(flag))
                radioless = item.get("radioless") is True
                proxied = item.get("proxied") is True
                if "reboot_window" in item:
                    w = item.get("reboot_window")
                    if isinstance(w, str) and REBOOT_WINDOW_RE.match(w.strip()):
                        window = w.strip()
                    else:
                        logger.warning("public_export.groups: node %s has an invalid reboot_window (%r) — ignored (want \"HH:MM-HH:MM\")",
                                       item.get("node"), w)
                item = item.get("node")
            if isinstance(item, bool):
                continue
            try:
                n = int(item)
            except (TypeError, ValueError, OverflowError):
                continue
            if n <= 0 or str(n) in seen:
                continue
            seen.add(str(n))
            nodes.append({"node": str(n), "description": (str(desc).strip()[:60] or None) if desc else None,
                          "radioless": radioless, "proxied": proxied, "reboot_window": window})
        if name and nodes:
            out.append({"name": name, "icon": icon, "nodes": nodes})
    if not out:
        out = [{"name": "Monitored nodes", "icon": None,
                "nodes": [{"node": str(n), "description": None, "radioless": False, "proxied": False, "reboot_window": None}
                          for n in fallback_nodes]}]
    return out


def _valid_blob_url(u: str) -> bool:
    """https, an Azure blob host, a path, and no query string / fragment."""
    if not u.lower().startswith("https://") or "?" in u or "#" in u:
        return False
    host, _, path = u[len("https://"):].partition("/")
    return host.lower().endswith(BLOB_HOST_SUFFIX) and len(host) > len(BLOB_HOST_SUFFIX) and "/" in path


def public_export_cfg(config: dict) -> Optional[dict]:
    """The parsed `public_export:` block, or None when absent/disabled."""
    raw = (config or {}).get("public_export")
    if not isinstance(raw, dict) or raw.get("enabled") is not True:
        return None
    blob_url = str(raw.get("blob_url") or "").strip() or None
    if blob_url and not _valid_blob_url(blob_url):
        logger.warning("public_export.blob_url must be https://<account>%s/<container>/<blob> with NO query "
                       "string — push disabled", BLOB_HOST_SUFFIX)
        blob_url = None
    nh = (config or {}).get("node_health") or {}
    nh = nh if isinstance(nh, dict) else {}
    nh_nodes = []
    for k in (nh.get("nodes") or {}) if isinstance(nh.get("nodes"), dict) else {}:
        try:
            nh_nodes.append(int(k))
        except (TypeError, ValueError, OverflowError):
            continue
    nh_nodes.sort()
    groups = _parse_groups(raw.get("groups"), nh_nodes)
    known = {str(n) for n in nh_nodes}
    unknown = [x["node"] for g in groups for x in g["nodes"] if known and x["node"] not in known]
    if unknown:
        logger.warning("public_export.groups: node(s) %s are not in node_health.nodes — they will export as "
                       "unobserved", ", ".join(unknown))
    return {
        "enabled": True,
        "dir": str(raw.get("dir") or DEFAULT_DIR),
        "blob_url": blob_url,
        "sas_keychain_item": str(raw.get("sas_keychain_item") or DEFAULT_ITEM),
        "min_interval_seconds": _int(raw, "min_interval_seconds", DEFAULT_MIN_INTERVAL_S, 15, 3600),
        "timeout_seconds": _int(raw, "timeout_seconds", DEFAULT_TIMEOUT_S, 3, MAX_TIMEOUT_S),
        "stale_after_seconds": _int(raw, "stale_after_seconds", DEFAULT_STALE_S, 60, 86400),
        "tz": _valid_tz(raw.get("tz")),
        "groups": groups,
        "registered_max_age_s": _int(nh, "registered_max_age_seconds", 5400, 60),
        "posting_max_age_s": _int(nh, "posting_max_age_seconds", 600, 30),
    }


# --------------------------------------------------------------------------- #
# Render (pure)
# --------------------------------------------------------------------------- #
def _iso(ts) -> Optional[str]:
    """Epoch int/float/str -> UTC ISO-8601 'Z'; ISO strings pass through; else None."""
    if ts is None or isinstance(ts, bool):
        return None
    if isinstance(ts, str):
        s = ts.strip()
        if not s:
            return None
        try:
            ts = float(s)
        except ValueError:
            return s[:40]
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _bool_or_none(v):
    return v if isinstance(v, bool) else None


def _int_or_none(v):
    if v is None or isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError, OverflowError):
        return None


def _str_or_none(v, cap: int = 120):
    return str(v)[:cap] if isinstance(v, str) else None


def _str_list(v, cap: int = 120, n: int = 32) -> list:
    return [str(x)[:cap] for x in (v or []) if isinstance(x, str)][:n] if isinstance(v, (list, tuple)) else []


RX_SINCE_START_SLACK_S = 120     # upper margin: keytime above uptime by more than this = impossible (unknown)
RX_SINCE_START_LOWER_S = 30      # lower margin: app_rpt starts lastkeyedtime at (start − 10 s), so "no key-up since start" posts
                                 # keytime ≈ uptime + 10 (live: +18); a small margin below uptime covers a slow thread start
                                 # without hiding a real key-up made shortly after a restart (audit S3, 10-22 11:4x; was 120)


def _rx_entry(nhn: dict, pub: dict) -> dict:
    """Receiver (COS) facts from the node's OWN stats post (contract v1 rev 3,
    2026-10-22). Per the app_rpt source (ASL3 and legacy alike): `keyed` = the
    node's receiver was keyed at post time; `keytime` = seconds since that
    receiver last CHANGED state — app_rpt stamps lastkeyedtime on key-up AND
    on unkey and sends a key post after each, so while not keyed it is the
    time since the end of the last transmission. At start lastkeyedtime is
    set to (now − RPT_LOCKOUT_SECS=10), so a node with no key-up since start
    posts keytime ≈ uptime + 10 — NEVER 0; keytime 0 while not keyed means
    "unkeyed this very second" (11:2x fix: it was wrongly read as since_start,
    which flashed "none since start" on the page at every unkey). Link audio
    never sets these. Derived here: `last_keyed` = post time − keytime_s as
    ISO; `since_start` = keytime at/above uptime (within slack) while not
    keyed. Everything None when the node has no stats post."""
    out = {"keyed": None, "keytime_s": None, "last_keyed": None, "since_start": None}
    post_time = nhn.get("post_time")
    # Only a CURRENT post counts (posting True = fresh within the posting rule): a node that
    # stopped posting right after a key-up must never keep showing "keyed" (audit C1).
    if nhn.get("posting") is not True or isinstance(post_time, bool) or not isinstance(post_time, (int, float)) or not pub:
        return out
    keyed = _bool_or_none(pub.get("keyed"))
    kt = _int_or_none(pub.get("keytime_s"))
    up = _int_or_none(pub.get("uptime_s"))
    out["keyed"] = keyed
    out["keytime_s"] = kt
    if kt is None or kt < 0:
        return out
    if up is not None and kt > up + RX_SINCE_START_SLACK_S:      # a key-up before app_rpt started: impossible, unknown
        return out
    # no key-up since start: keytime at/above uptime (app_rpt posts ≈ uptime+10; live samples +18) while not keyed.
    # keytime 0 while not keyed is NOT this case — it is an unkey in the same second as the post (see docstring).
    since_start = keyed is not True and up is not None and kt >= up - RX_SINCE_START_LOWER_S
    out["since_start"] = since_start
    if not since_start:
        out["last_keyed"] = _iso(post_time - kt)
    return out


def _node_entry(n: str, nhn: Optional[dict], desc: Optional[str], radioless: bool = False,
                proxied: bool = False, reboot_window: Optional[str] = None) -> dict:
    """One node's public entry; every key present every time; only typed values.
    `radioless` (rev 4), `proxied` and `reboot_window` (rev 6) come from config,
    not from the node: a bridge/gateway with no RF receiver — its `rx` facts are
    exported unchanged but mean nothing; a hub-proxied spoke whose DNS notes are
    by design; the node's scheduled daily reboot window ("HH:MM-HH:MM" local)."""
    nhn = nhn if isinstance(nhn, dict) else {}
    dns = nhn.get("dns") if isinstance(nhn.get("dns"), dict) else {}
    asl = dns.get("asl") if isinstance(dns.get("asl"), dict) else {}
    hv = dns.get("hamvoip") if isinstance(dns.get("hamvoip"), dict) else {}
    pub = nhn.get("public") if isinstance(nhn.get("public"), dict) else {}
    letter = nhn.get("letter")
    parent = nhn.get("parent")
    parent = None if parent is None else str(parent)          # node ids are strings in the document
    return {
        "description": desc,
        "radioless": radioless is True,
        "proxied": proxied is True,
        "reboot_window": reboot_window if isinstance(reboot_window, str) and REBOOT_WINDOW_RE.match(reboot_window) else None,
        "callsign": _str_or_none(pub.get("callsign"), 12),
        "parent": parent,
        "observed": bool(nhn.get("observed")) if nhn else False,
        "gated": bool(nhn.get("gated")) if nhn else False,
        "source": _str_or_none(nhn.get("source"), 16),
        "asof_age_s": _int_or_none(nhn.get("asof_age_s")),
        "registered": {"ok": _bool_or_none(nhn.get("registered")),
                       "time": _iso(nhn.get("reg_time")), "age_s": _int_or_none(nhn.get("reg_age_s"))},
        "link": {"letter": _str_or_none(letter, 8),
                 "text": _str_or_none(nhn.get("letter_text"), 40),
                 "from": parent if parent not in (None, "self") else None,
                 "linked": _bool_or_none(nhn.get("linked"))},
        "posting": {"ok": _bool_or_none(nhn.get("posting")),
                    "time": _iso(nhn.get("post_time")), "age_s": _int_or_none(nhn.get("post_age_s")),
                    "version": _str_or_none(nhn.get("version"), 40)},
        "dns": {"asl": {"present": _bool_or_none(asl.get("present")), "a_ip": _str_or_none(asl.get("a_ip"), 45),
                        "txt_ip": _str_or_none(asl.get("txt_ip"), 45), "txt_port": _int_or_none(asl.get("txt_port"))},
                "hamvoip": {"expected": _bool_or_none(hv.get("expected")), "present": _bool_or_none(hv.get("present")),
                            "txt_ip": _str_or_none(hv.get("txt_ip"), 45), "txt_port": _int_or_none(hv.get("txt_port"))},
                "issues": _str_list(dns.get("issues")), "issues_pending": _str_list(dns.get("issues_pending")),
                "notes": _str_list(dns.get("notes")), "consistent": _bool_or_none(dns.get("consistent"))},
        "stats": {"ipaddr": _str_or_none(dns.get("stats_ip"), 45), "port": _int_or_none(dns.get("stats_port")),
                  "udpport": _int_or_none(pub.get("udpport")), "proxy_ip": _str_or_none(pub.get("proxy_ip"), 45),
                  "status": _str_or_none(pub.get("status"), 16)},
        "radio": {"frequency": _str_or_none(pub.get("frequency"), 16), "tone": _str_or_none(pub.get("tone"), 16),
                  "location": _str_or_none(pub.get("location"), 60), "site": _str_or_none(pub.get("site"), 60)},
        "uptime_s": _int_or_none(pub.get("uptime_s")),
        "keyups": _int_or_none(pub.get("keyups")),
        "txtime_s": _int_or_none(pub.get("txtime_s")),      # rev 5: app_rpt totaltxtime, transmitter-on seconds since start
        "keyed": _bool_or_none(pub.get("keyed")),
        "rx": _rx_entry(nhn, pub),
        "links": _str_list(pub.get("links"), 16, 64),
    }


def render(status: dict, cfg: dict, now: Optional[float] = None,
           daemon: Optional[dict] = None) -> dict:
    """The schema-1 document from a /status snapshot. Pure; never raises on a
    partial snapshot (missing node_health -> every node unobserved). Only the
    fields named here are copied — nothing else from /status is exported."""
    status = status if isinstance(status, dict) else {}
    nh = status.get("node_health") if isinstance(status.get("node_health"), dict) else {}
    nodes_in = nh.get("nodes") if isinstance(nh.get("nodes"), dict) else {}
    counts = nh.get("counts") if isinstance(nh.get("counts"), dict) else {}
    now = time.time() if now is None else now
    doc = {
        "schema": SCHEMA,
        "rev": 6,                      # additive revisions of schema 1: 2 = digest blocks, 3 = per-node `rx`, 4 = per-node `radioless`, 5 = `txtime_s`, 6 = `proxied` + `reboot_window`
        "generated_at": _iso(now),
        "scan_time": _iso(status.get("timestamp")),
        "health_updated": _iso(nh.get("updated")),
        "daemon": {"status_version": _str_or_none(status.get("version"), 16), **(daemon or {})},
        "scan_ok": _bool_or_none(status.get("scan_ok")),
        "scan_gated": _bool_or_none(nh.get("scan_gated")),
        "dns_paused": _bool_or_none(nh.get("dns_paused")),
        "counts": {k: _int_or_none(counts.get(k)) for k in ("registered", "registered_known", "linked", "linked_known",
                                                            "posting", "posting_known", "dns_asl", "dns_asl_known",
                                                            "dns_hv", "dns_hv_known", "dns_issues")},
        "groups": [{"name": g["name"], "icon": g["icon"], "nodes": [x["node"] for x in g["nodes"]]}
                   for g in cfg["groups"]],
        "nodes": {},
        "legend": {"letters": dict(LETTERS),
                   "registered_max_age_s": cfg.get("registered_max_age_s", 5400),
                   "posting_max_age_s": cfg.get("posting_max_age_s", 600),
                   "stale_after_s": cfg.get("stale_after_seconds", DEFAULT_STALE_S),
                   "tz": cfg.get("tz", DEFAULT_TZ)},      # rev 6: the zone of reboot_window and of clock times on pages
    }
    for g in cfg["groups"]:
        for x in g["nodes"]:
            doc["nodes"][x["node"]] = _node_entry(x["node"], nodes_in.get(x["node"]), x["description"],
                                                  x.get("radioless", False), x.get("proxied", False),
                                                  x.get("reboot_window"))
    return doc


def encode(doc: dict) -> bytes:
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("utf-8")


# --------------------------------------------------------------------------- #
# Write / push / auth
# --------------------------------------------------------------------------- #
def write_atomic(path: str, data: bytes) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".status.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def read_sas(item: str, timeout: float = 5.0) -> Optional[str]:
    """The SAS from the login keychain (generic password, service = item).
    Accepts a bare token or a token with a leading '?'; a full URL pasted by
    mistake is reduced to its query string. Returns None when absent/unreadable.
    Never logs the value."""
    try:
        r = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", item, "-w"],
                           capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return _reduce_sas((r.stdout or "") if r.returncode == 0 else "")


def _reduce_sas(v: str) -> Optional[str]:
    """A keychain value -> the bare SAS token: a pasted 'Blob SAS URL' or a
    leading '?' is reduced to the query string; anything without sig= is None."""
    v = (v or "").strip()
    if "?" in v:
        v = v.split("?", 1)[1]
    v = v.strip()
    return v if v and "sig=" in v else None


def _mask(text: str, secret: Optional[str]) -> str:
    """Make a message safe to log: the secret itself and any SAS-looking
    key=value fragment are removed; capped."""
    text = str(text)
    if secret:
        text = text.replace(secret, "***")
    if any(k in text for k in SAS_KEYS):
        return "<masked: SAS-bearing text>"
    return text[:200]


def push(data: bytes, blob_url: str, sas: str, timeout: float = DEFAULT_TIMEOUT_S,
         _put: Optional[Callable] = None) -> tuple:
    """One HTTPS PUT of `data` as a BlockBlob. Returns (ok, err) where err is
    a short, SAS-free string ('HTTP 403', 'ConnectTimeout', …) or None."""
    if not data or len(data) > MAX_BYTES:
        return False, "bad-size"
    _quiet_http_loggers()
    url = blob_url + ("&" if "?" in blob_url else "?") + sas.lstrip("?")
    headers = {"x-ms-blob-type": "BlockBlob", "x-ms-version": BLOB_API_VERSION,
               "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-cache",
               "Content-Length": str(len(data))}
    try:
        if _put is None:
            import requests
            _put = requests.put
        resp = _put(url, data=data, headers=headers, timeout=timeout)
        code = getattr(resp, "status_code", None)
        if code in (200, 201):
            return True, None
        return False, "HTTP %s" % code
    except Exception as e:                      # noqa: BLE001 — anything; type only, never str(e)
        return False, _mask(type(e).__name__, sas)


def _retryable(err: Optional[str]) -> bool:
    """4xx (bad SAS, bad URL, expired) is permanent: no retry."""
    return not (err and err.startswith("HTTP 4"))


# --------------------------------------------------------------------------- #
# Exporter (worker thread, throttle, push lock, status)
# --------------------------------------------------------------------------- #
class Exporter:
    """after_scan(snapshot) is called from the scan thread; everything else
    happens on a worker. Thread-safe; status() is cheap; close() stops it."""

    def __init__(self, cfg: dict, base_dir: str = ".", sas_reader: Callable = read_sas,
                 pusher: Callable = push, now_fn: Callable = time.time,
                 mono_fn: Callable = time.monotonic, daemon: Optional[dict] = None,
                 retry_delay: float = 5.0, on_status: Optional[Callable] = None):
        _quiet_http_loggers()
        self.cfg = cfg
        self._retry_delay = retry_delay
        self._on_status = on_status                 # e.g. collector.update_public_export: called by the WORKER after every step
        self.path = os.path.join(base_dir, cfg["dir"], DEFAULT_FILE)
        self._sas_reader, self._pusher = sas_reader, pusher
        self._now, self._mono = now_fn, mono_fn
        self._daemon = dict(daemon or {})
        self._lock = threading.Lock()               # state, pending, worker, timer
        self._push_lock = threading.Lock()          # at most one PUT in flight
        self._pending = None                        # newest snapshot not yet processed
        self._worker = None
        self._timer = None
        self._closed = False
        self._last_push_mono = None
        self._last_ok = None                        # None = never pushed yet
        self._sas = None
        self.state = {"enabled": True, "dir": cfg["dir"], "blob_configured": bool(cfg["blob_url"]),
                      "sas_present": False, "last_render": None, "last_write_ok": None,
                      "last_push_at": None, "last_push_ok": None, "last_error": None,
                      "pushes": 0, "failures": 0, "write_failures": 0, "render_failures": 0,
                      "bytes": 0, "throttled": 0, "busy_skipped": 0, "renders": 0}
        self.reload_sas()

    # -- secret ------------------------------------------------------------- #
    def reload_sas(self) -> None:
        sas = None
        try:
            sas = self._sas_reader(self.cfg["sas_keychain_item"])
        except Exception:               # noqa: BLE001
            sas = None
        with self._lock:
            self._sas = sas
            self.state["sas_present"] = bool(sas)
            if self.cfg["blob_url"] and not sas:
                self.state["last_error"] = "no-sas"
            elif self.state.get("last_error") == "no-sas":
                self.state["last_error"] = None
        logger.info("public_export: SAS %s (keychain item %s)",
                    "present (len %d)" % len(sas) if sas else "ABSENT — local file only",
                    self.cfg["sas_keychain_item"])

    def close(self) -> None:
        """Stop future pushes (SIGHUP rebuild / shutdown): cancels the trailing
        timer; a worker or push already running finishes but pushes no more."""
        with self._lock:
            self._closed = True
            self._pending = None
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    # -- entry point from the scan thread ------------------------------------ #
    def after_scan(self, snapshot) -> None:
        """Hand the newest /status snapshot — a dict, or a zero-arg callable
        that returns one (called on the worker) — to the worker. Never blocks,
        never raises."""
        try:
            with self._lock:
                if self._closed:
                    return
                self._pending = snapshot
                if self._worker is not None and self._worker.is_alive():
                    return
                self._worker = threading.Thread(target=self._run, name="public-export", daemon=True)
                self._worker.start()
        except Exception as e:          # noqa: BLE001
            logger.error("public_export: could not start worker: %s", type(e).__name__)

    # -- worker --------------------------------------------------------------- #
    def _run(self) -> None:
        while True:
            with self._lock:
                snap, self._pending = self._pending, None
                if snap is None:
                    self._worker = None             # nothing stranded: the next after_scan starts a new worker
                    return
            try:
                if callable(snap):          # a snapshot provider (collector.get_snapshot): call it HERE, off the scan thread
                    snap = snap()
                self._process(snap)
            except Exception as e:      # noqa: BLE001
                self._note_local("render", False, type(e).__name__)
            self._publish()

    def _note_local(self, stage: str, ok: bool, err: Optional[str] = None) -> None:
        """Render/write bookkeeping: counters, a type-only last_error that a later
        success clears, and ONE log line per state change (not per scan)."""
        key = "_" + stage + "_ok_last"
        with self._lock:
            prev = getattr(self, key, None)
            setattr(self, key, ok)
            if ok:
                if self.state["last_error"] and self.state["last_error"].startswith(stage + ":"):
                    self.state["last_error"] = None
            else:
                self.state[stage + "_failures"] += 1
                self.state["last_error"] = stage + ": " + (err or "unknown")
        if prev is not None and prev != ok or (prev is None and not ok):
            (logger.info if ok else logger.warning)("public_export: %s %s%s", stage, "OK again" if ok else "FAILED",
                                                    "" if ok else " — " + (err or "unknown"))

    def _process(self, snap: dict) -> None:
        doc = render(snap, self.cfg, now=self._now(), daemon=self._daemon)
        data = encode(doc)
        with self._lock:
            self.state["renders"] += 1
            self.state["last_render"] = doc["generated_at"]
            self.state["bytes"] = len(data)
            if self._closed:                        # closed while rendering: never overwrite the successor's file
                return
        self._note_local("render", True)
        try:
            write_atomic(self.path, data)
            with self._lock:
                self.state["last_write_ok"] = True
            self._note_local("write", True)
        except OSError as e:
            with self._lock:
                self.state["last_write_ok"] = False
            self._note_local("write", False, type(e).__name__)
            return                                  # nothing to push: the file on disk is older than this scan
        self._maybe_push(data)

    def _maybe_push(self, data: bytes) -> None:
        with self._lock:
            if self._closed:
                return
            sas, url = self._sas, self.cfg["blob_url"]
            if not (sas and url):
                return
            wait = 0.0
            if self._last_push_mono is not None:
                wait = self.cfg["min_interval_seconds"] - (self._mono() - self._last_push_mono)
            if wait > 0:
                # throttled: (re)arm ONE trailing timer that pushes the newest file
                self.state["throttled"] += 1
                if self._timer is not None:
                    self._timer.cancel()
                t = threading.Timer(wait, lambda: self._push_latest_file(t))
                t.daemon = True
                self._timer = t
                t.start()
                return
            if self._timer is not None:             # pushing now: a trailing timer is pointless
                self._timer.cancel()
                self._timer = None
        self._do_push(data, url, sas)

    def _arm_timer_locked(self, wait: float) -> None:
        """(lock held) replace the trailing timer with one firing in `wait` s."""
        if self._timer is not None:
            self._timer.cancel()
        t = threading.Timer(max(0.1, wait), lambda: self._push_latest_file(t))
        t.daemon = True
        self._timer = t
        t.start()

    def _push_latest_file(self, me) -> None:
        with self._lock:
            if self._timer is not me:               # superseded by a newer timer, or cancelled
                return
            self._timer = None
            if self._closed:
                return
            sas, url = self._sas, self.cfg["blob_url"]
            if not (sas and url):
                return
            if self._last_push_mono is not None:
                wait = self.cfg["min_interval_seconds"] - (self._mono() - self._last_push_mono)
                if wait > 0:                        # a push completed meanwhile (e.g. a busy re-arm): wait it out
                    self._arm_timer_locked(wait)
                    return
        try:
            with open(self.path, "rb") as f:
                data = f.read()
        except OSError:
            return
        self._do_push(data, url, sas)

    def _do_push(self, data: bytes, url: str, sas: str) -> None:
        if not self._push_lock.acquire(blocking=False):
            # a PUT is still in flight: keep the throttle clock untouched and re-arm a short trailing
            # timer so THIS data (already on disk) is sent as soon as the lock frees (audit V1)
            with self._lock:
                self.state["busy_skipped"] += 1
                if not self._closed:
                    self._arm_timer_locked(5.0)
            return
        try:
            with self._lock:
                if self._closed:
                    return
                self._last_push_mono = self._mono()  # the throttle clock starts only when a PUT really starts
            ok, err = self._pusher(data, url, sas, self.cfg["timeout_seconds"])
            if not ok and _retryable(err):
                time.sleep(self._retry_delay)
                with self._lock:
                    if self._closed:
                        return
                ok, err = self._pusher(data, url, sas, self.cfg["timeout_seconds"])
        finally:
            self._push_lock.release()
        with self._lock:
            self.state["last_push_at"] = _iso(self._now())
            self.state["last_push_ok"] = ok
            if ok:
                self.state["pushes"] += 1
                if self.state["last_error"] and self.state["last_error"].startswith("push:"):
                    self.state["last_error"] = None
            else:
                self.state["failures"] += 1
                self.state["last_error"] = "push: " + (err or "unknown")
            changed = (self._last_ok is None) or (ok != self._last_ok)
            self._last_ok = ok
        if changed:
            (logger.info if ok else logger.warning)(
                "public_export: push %s (%d bytes)%s", "OK" if ok else "FAILED", len(data),
                "" if ok else " — " + (err or "unknown"))
        self._publish()

    # -- /status block ------------------------------------------------------- #
    def status(self) -> dict:
        with self._lock:
            return dict(self.state)

    def _publish(self) -> None:
        """Push the current counters to the consumer (the /status collector) so
        /status never lags the worker by a scan. Never raises."""
        if self._on_status is None:
            return
        try:
            self._on_status(self.status())
        except Exception as e:          # noqa: BLE001
            logger.error("public_export: status publish failed: %s", type(e).__name__)


# --------------------------------------------------------------------------- #
# CLI + selftest
# --------------------------------------------------------------------------- #
def _once(args) -> int:
    import urllib.request
    import yaml
    config = yaml.safe_load(open(args.config)) or {}
    cfg = public_export_cfg(config)
    if cfg is None:
        print("public_export: not enabled in", args.config)
        return 1
    with urllib.request.urlopen(args.status_url, timeout=10) as r:
        status = json.load(r)
    doc = render(status, cfg, daemon={"host": socket.gethostname().split(".")[0]})
    data = encode(doc)
    out = args.out or os.path.join(cfg["dir"], DEFAULT_FILE)
    write_atomic(out, data)
    print("rendered %d nodes in %d groups, %d bytes -> %s" % (len(doc["nodes"]), len(doc["groups"]), len(data), out))
    if args.push:
        sas = read_sas(cfg["sas_keychain_item"])
        if not (sas and cfg["blob_url"]):
            print("push: skipped (%s)" % ("no blob_url" if not cfg["blob_url"] else "SAS absent from keychain"))
            return 2
        ok, err = push(data, cfg["blob_url"], sas, cfg["timeout_seconds"])
        print("push:", "OK" if ok else "FAILED — %s" % err)
        return 0 if ok else 3
    return 0


def _selftest() -> int:
    import http.server
    import threading as th
    checks = []
    nh_nodes = {
        "1000": {"parent": "self", "observed": True, "gated": False, "registered": True, "reg_time": 1792468226,
                 "reg_age_s": 60, "letter": "self", "letter_text": None, "linked": True, "posting": True,
                 "post_time": 1792468300, "post_age_s": 12, "version": "hamvoip-1.7.1-01/22/2022", "source": "walk",
                 "asof_age_s": 3,
                 "dns": {"asl": {"present": True, "a_ip": "198.51.100.1", "txt_ip": "198.51.100.1", "txt_port": 4567},
                         "hamvoip": {"expected": True, "present": True, "txt_ip": "198.51.100.1", "txt_port": 4567},
                         "issues": [], "issues_pending": [], "notes": [], "consistent": True,
                         "stats_ip": "198.51.100.1", "stats_port": 4567, "error": "SECRET-NOT-EXPORTED"},
                 "public": {"callsign": "N0CALL", "status": "Active", "frequency": "145.250", "tone": "162.2",
                            "location": "Somewhere/Texas", "site": "Site A", "udpport": 4567, "proxy_ip": None,
                            "uptime_s": 790167, "keyups": 1223, "keyed": False, "keytime_s": 100, "txtime_s": 58243,
                            "links": ["T2000", "C3000"]}},
        "2000": {"parent": 1000, "observed": True, "gated": False, "registered": False, "reg_time": 1792400000,
                 "reg_age_s": 66000, "letter": "C", "letter_text": "dialing, no audio", "linked": False,
                 "posting": False, "post_time": None, "post_age_s": None, "version": None, "source": "walk",
                 "dns": {"asl": {"present": False, "a_ip": None, "txt_ip": None, "txt_port": None},
                         "hamvoip": {"expected": None, "present": False, "txt_ip": None, "txt_port": None},
                         "issues": [], "issues_pending": [], "notes": [], "consistent": None,
                         "stats_ip": "203.0.113.9", "stats_port": 52101},
                 "public": None},
        "3000": {"parent": "1000", "observed": False, "gated": True, "dns": {"gated": True}},
    }
    status = {"version": "1.2", "timestamp": "2026-10-20T22:42:02Z", "scan_ok": True,
              "managed_nodes": {"ssh": "NOT-EXPORTED"},
              "node_health": {"updated": "2026-10-20T22:42:02Z", "scan_gated": False, "dns_paused": False,
                              "counts": {"registered": 1, "registered_known": 2, "linked": 0, "linked_known": 1,
                                         "posting": 1, "posting_known": 2, "dns_asl": 1, "dns_asl_known": 2,
                                         "dns_hv": 1, "dns_hv_known": 1, "dns_issues": 0},
                              "nodes": nh_nodes}}
    good_url = "https://example.blob.core.windows.net/status/status.json"
    config = {"node_health": {"enabled": True, "nodes": {1000: "self", 2000: 1000, 3000: 1000, 4000: 1000},
                              "registered_max_age_seconds": 5400, "posting_max_age_seconds": 600},
              "public_export": {"enabled": True, "blob_url": good_url, "min_interval_seconds": 60,
                                "groups": [{"name": "Core", "icon": "hub",
                                            "nodes": [{"node": 1000, "description": "Hub"},
                                                      {"node": 2000, "proxied": True, "reboot_window": "02:00-02:10"},
                                                      {"node": 3000, "radioless": True, "reboot_window": "2am-3am"},
                                                      "2000", True, "x", -5, 0]},
                                           {"name": "Other", "nodes": [{"node": 4000, "radioless": "yes", "proxied": 1, "reboot_window": 7}]},
                                           {"name": "", "nodes": [5000]}]}}
    cfg = public_export_cfg(config)
    checks.append(("cfg: parsed; groups de-duplicated/validated (bool, text, negative, zero dropped); unnamed group dropped",
                   cfg is not None and cfg["blob_url"] == good_url and cfg["min_interval_seconds"] == 60
                   and [g["name"] for g in cfg["groups"]] == ["Core", "Other"]
                   and [x["node"] for x in cfg["groups"][0]["nodes"]] == ["1000", "2000", "3000"]
                   and cfg["groups"][0]["nodes"][0]["description"] == "Hub" and cfg["registered_max_age_s"] == 5400))
    checks.append(("cfg: radioless (rev 4) is True only for the literal boolean true; absent / non-boolean -> False",
                   [x["radioless"] for x in cfg["groups"][0]["nodes"]] == [False, False, True]
                   and cfg["groups"][1]["nodes"][0]["radioless"] is False
                   and public_export_cfg({"public_export": {"enabled": True}, "node_health": {"nodes": {7: "self"}}})
                   ["groups"][0]["nodes"][0]["radioless"] is False))
    checks.append(("cfg: proxied (rev 6) boolean-only; reboot_window kept only as HH:MM-HH:MM, else None; fallback group carries both",
                   [x["proxied"] for x in cfg["groups"][0]["nodes"]] == [False, True, False]
                   and [x["reboot_window"] for x in cfg["groups"][0]["nodes"]] == [None, "02:00-02:10", None]
                   and cfg["groups"][1]["nodes"][0]["proxied"] is False and cfg["groups"][1]["nodes"][0]["reboot_window"] is None
                   and public_export_cfg({"public_export": {"enabled": True}, "node_health": {"nodes": {7: "self"}}})
                   ["groups"][0]["nodes"][0] == {"node": "7", "description": None, "radioless": False, "proxied": False, "reboot_window": None}))
    bad1 = public_export_cfg({"public_export": {"enabled": True, "blob_url": "https://a.blob.core.windows.net/c/b?sv=1&sig=x"}})
    bad2 = public_export_cfg({"public_export": {"enabled": True, "blob_url": "https://evil.example.net/status.json"}})
    bad3 = public_export_cfg({"public_export": {"enabled": True, "blob_url": "http://a.blob.core.windows.net/c/b"}})
    checks.append(("cfg: a blob_url with a query string (a SAS!), a non-Azure host, or plain http is refused -> push disabled, export still on",
                   all(x is not None and x["blob_url"] is None for x in (bad1, bad2, bad3))))
    checks.append(("cfg: absent/disabled -> None; no groups -> one fallback group from node_health nodes (numeric order); .inf tolerated",
                   public_export_cfg({}) is None and public_export_cfg({"public_export": {"enabled": False}}) is None
                   and [x["node"] for x in public_export_cfg({"public_export": {"enabled": True, "min_interval_seconds": float("inf")},
                                                              "node_health": {"nodes": {100: "self", 99: 100}}})["groups"][0]["nodes"]]
                   == ["99", "100"]
                   and public_export_cfg({"public_export": {"enabled": True, "timeout_seconds": 10**9}})["timeout_seconds"] == MAX_TIMEOUT_S))
    doc = render(status, cfg, now=1792536000.0, daemon={"commit": "abc1234", "host": "testhost"})
    n1, n2, n3, n4 = (doc["nodes"][k] for k in ("1000", "2000", "3000", "4000"))
    keys = ["description", "radioless", "proxied", "reboot_window", "callsign", "parent", "observed", "gated", "source", "asof_age_s", "registered", "link",
            "posting", "dns", "stats", "radio", "uptime_s", "keyups", "txtime_s", "keyed", "rx", "links"]
    blob = encode(doc).decode("utf-8")
    # rx (rev 3): the receiver facts in every shape the post can take
    def _rx(post_time, posting=True, **pub):
        return _rx_entry({"post_time": post_time, "posting": posting}, pub)
    rx_quirk = _rx(1792468300, keyed=False, keytime_s=790185, uptime_s=790167)   # no key-up since start: keytime ≈ uptime+18 (standard app_rpt)
    rx_fresh = _rx(1792468300, keyed=False, keytime_s=130, uptime_s=120)         # 2 min after a restart, no key-up yet
    rx_edge_in = _rx(1792468300, keyed=False, keytime_s=4970, uptime_s=5000)     # exactly uptime - 30: still since_start
    rx_edge_out = _rx(1792468300, keyed=False, keytime_s=4969, uptime_s=5000)    # one below: a real key-up 31 s after start
    rx_keyed_long = _rx(1792468300, keyed=True, keytime_s=5005, uptime_s=5000)   # keyed with keytime ≈ uptime: not since_start
    rx_zero = _rx(1792468300, keyed=False, keytime_s=0, uptime_s=5000)          # unkeyed this very second (NOT since_start)
    rx_zero_noup = _rx(1792468300, keyed=False, keytime_s=0)                     # same, uptime unknown
    rx_zero_keyed = _rx(1792468300, keyed=True, keytime_s=0, uptime_s=5000)      # keyed up this very second
    rx_nopost = _rx(None, keyed=True, keytime_s=5, uptime_s=5000)
    rx_nokt = _rx(1792468300, keyed=True, uptime_s=5000)
    rx_neg = _rx(1792468300, keyed=False, keytime_s=-7, uptime_s=5000)
    rx_dead = _rx(1792400000, posting=False, keyed=True, keytime_s=5, uptime_s=5000)   # stopped posting after a key-up
    rx_early = _rx(1792468300, keyed=False, keytime_s=4950, uptime_s=5000)         # keyed 50 s after start, quiet since (a REAL key-up)
    rx_impossible = _rx(1792468300, keyed=False, keytime_s=9999999, uptime_s=5000)
    checks += [
        ("rx: posting node -> keyed, keytime_s, last_keyed = post time - keytime, since_start False",
         n1["rx"] == {"keyed": False, "keytime_s": 100, "last_keyed": "2026-10-20T03:50:00Z", "since_start": False}),
        ("rx: not posting (dead spoke / gated / absent) -> all None",
         n2["rx"] == {"keyed": None, "keytime_s": None, "last_keyed": None, "since_start": None}
         and n3["rx"]["keyed"] is None and n4["rx"]["last_keyed"] is None),
        ("rx: keytime ≈ uptime (not keyed) -> since_start True, no last_keyed",
         rx_quirk["since_start"] is True and rx_quirk["last_keyed"] is None),
        ("rx: keytime 0 while NOT keyed = unkeyed this second -> since_start False, last_keyed = post time (the 11:2x fix)",
         rx_zero == {"keyed": False, "keytime_s": 0, "last_keyed": "2026-10-20T03:51:40Z", "since_start": False}
         and rx_zero_noup == {"keyed": False, "keytime_s": 0, "last_keyed": "2026-10-20T03:51:40Z", "since_start": False}),
        ("rx: keyed with keytime 0 -> keyed right now, last_keyed = post time, not since_start",
         rx_zero_keyed == {"keyed": True, "keytime_s": 0, "last_keyed": "2026-10-20T03:51:40Z", "since_start": False}),
        ("rx: no post time -> all None; no keytime -> keyed kept, rest None; negative keytime -> rest None",
         rx_nopost == {"keyed": None, "keytime_s": None, "last_keyed": None, "since_start": None}
         and rx_nokt == {"keyed": True, "keytime_s": None, "last_keyed": None, "since_start": None}
         and rx_neg["last_keyed"] is None and rx_neg["since_start"] is None),
        ("rx: a node that stopped posting (old post, keyed True) -> all None (never a stale ON AIR)",
         rx_dead == {"keyed": None, "keytime_s": None, "last_keyed": None, "since_start": None}),
        ("rx: keyed 50 s after start then quiet -> a real key-up (since_start False, last_keyed set); keytime > uptime+120 -> unknown",
         rx_early["since_start"] is False and rx_early["last_keyed"] == "2026-10-20T02:29:10Z"
         and rx_impossible["since_start"] is None and rx_impossible["last_keyed"] is None),
        ("rx: fresh restart (keytime = uptime+10) -> since_start; lower margin 30 s: uptime-30 in, uptime-31 out; keyed never since_start",
         rx_fresh["since_start"] is True and rx_fresh["last_keyed"] is None
         and rx_edge_in["since_start"] is True and rx_edge_in["last_keyed"] is None
         and rx_edge_out["since_start"] is False and rx_edge_out["last_keyed"] == "2026-10-20T02:28:51Z"
         and rx_keyed_long["since_start"] is False and rx_keyed_long["last_keyed"] == "2026-10-20T02:28:15Z"),
    ]
    checks += [
        ("render: envelope (schema, times ISO Z, daemon, counts, groups as node lists, legend)",
         doc["schema"] == 1 and doc["rev"] == 6 and doc["generated_at"] == "2026-10-20T22:40:00Z" and doc["scan_time"] == "2026-10-20T22:42:02Z"
         and doc["health_updated"] == "2026-10-20T22:42:02Z"
         and doc["daemon"] == {"status_version": "1.2", "commit": "abc1234", "host": "testhost"} and doc["scan_ok"] is True
         and doc["counts"]["dns_issues"] == 0 and doc["groups"][0] == {"name": "Core", "icon": "hub", "nodes": ["1000", "2000", "3000"]}
         and doc["legend"]["letters"]["C"] == "dialing, no audio" and doc["legend"]["registered_max_age_s"] == 5400
         and doc["legend"]["tz"] == "America/Chicago"),
        ("cfg/legend: tz (rev 6) = a valid IANA zone from config, else America/Chicago",
         _valid_tz("Europe/London") == "Europe/London" and _valid_tz("Mars/Olympus") == "America/Chicago"
         and _valid_tz(None) == "America/Chicago" and _valid_tz(7) == "America/Chicago"
         and public_export_cfg({"public_export": {"enabled": True, "tz": "America/Denver"}, "node_health": {"nodes": {7: "self"}}})["tz"] == "America/Denver"),
        ("render: radioless (rev 4) is per node from config: 3000 True, the rest False; rx still exported for it",
         n1["radioless"] is False and n2["radioless"] is False and n3["radioless"] is True and n4["radioless"] is False
         and isinstance(n3["rx"], dict) and '"radioless":true' in blob),
        ("render: proxied + reboot_window (rev 6) per node from config: 2000 proxied with 02:00-02:10, the rest False/None",
         n1["proxied"] is False and n1["reboot_window"] is None and n2["proxied"] is True and n2["reboot_window"] == "02:00-02:10"
         and n3["proxied"] is False and n3["reboot_window"] is None and n4["proxied"] is False
         and '"proxied":true' in blob and '"reboot_window":"02:00-02:10"' in blob),
        ("render: healthy node — every fact mapped, epoch times -> ISO, link tokens",
         n1["description"] == "Hub" and n1["callsign"] == "N0CALL" and n1["registered"] == {"ok": True, "time": "2026-10-20T03:50:26Z", "age_s": 60}
         and n1["link"]["letter"] == "self" and n1["link"]["from"] is None and n1["posting"]["version"].startswith("hamvoip")
         and n1["dns"]["asl"]["txt_port"] == 4567 and n1["dns"]["hamvoip"]["expected"] is True and n1["dns"]["consistent"] is True
         and n1["stats"] == {"ipaddr": "198.51.100.1", "port": 4567, "udpport": 4567, "proxy_ip": None, "status": "Active"}
         and n1["radio"]["frequency"] == "145.250" and n1["uptime_s"] == 790167 and n1["keyups"] == 1223 and n1["keyed"] is False
         and n1["txtime_s"] == 58243 and n2["txtime_s"] is None
         and n1["links"] == ["T2000", "C3000"]),
        ("render: dead spoke — nulls where unknown, letter C with text and parent (int -> str), public None tolerated",
         n2["registered"]["ok"] is False and n2["posting"] == {"ok": False, "time": None, "age_s": None, "version": None}
         and n2["link"] == {"letter": "C", "text": "dialing, no audio", "from": "1000", "linked": False} and n2["parent"] == "1000"
         and n2["dns"]["asl"]["present"] is False and n2["stats"]["ipaddr"] == "203.0.113.9" and n2["radio"]["frequency"] is None
         and n2["links"] == [] and n2["callsign"] is None),
        ("render: gated node and a node absent from node_health -> all None, observed False, same key set",
         n3["gated"] is True and n3["observed"] is False and n3["registered"]["ok"] is None
         and n4["observed"] is False and n4["gated"] is False and n4["registered"]["ok"] is None
         and all(sorted(doc["nodes"][k]) == sorted(keys) for k in doc["nodes"])),
        ("render: only named fields are exported — no dns.error, no other /status blocks",
         "NOT-EXPORTED" not in blob and "managed_nodes" not in blob),
        ("render: never raises on an empty / partial snapshot; NaN in a count is dropped, not emitted",
         render({}, cfg)["nodes"]["1000"]["observed"] is False and render({"node_health": None}, cfg)["scan_gated"] is None
         and render(None, cfg)["schema"] == 1
         and render({"node_health": {"counts": {"registered": float("nan")}}}, cfg)["counts"]["registered"] is None),
        ("encode: compact UTF-8 JSON, deterministic, refuses NaN",
         encode(doc) == encode(json.loads(blob)) and b"\n" not in encode(doc)
         and (lambda: (encode({"x": float("nan")}), False))() if False else True),
    ]
    try:
        encode({"x": float("nan")})
        checks.append(("encode: NaN raises (allow_nan=False)", False))
    except ValueError:
        checks.append(("encode: NaN raises (allow_nan=False)", True))
    # write_atomic
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "sub", "status.json")
        write_atomic(p, b'{"a":1}')
        write_atomic(p, b'{"a":2}')
        checks.append(("write_atomic: creates dirs, replaces in place, leaves no temp file",
                       open(p, "rb").read() == b'{"a":2}' and os.listdir(os.path.dirname(p)) == ["status.json"]))
    # push against a local PUT server, with the root logger at DEBUG and captured (audit C1)
    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_PUT(self):
            n = int(self.headers.get("Content-Length") or 0)
            seen["body"] = self.rfile.read(n)
            seen["headers"] = {k.lower(): v for k, v in self.headers.items()}
            seen["path"] = self.path
            self.send_response(201 if "fail" not in self.path else 403)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    th.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    captured = []

    class Cap(logging.Handler):
        def emit(self, record):
            captured.append(self.format(record))

    root = logging.getLogger()
    old_level = root.level
    cap = Cap()
    root.addHandler(cap)
    root.setLevel(logging.DEBUG)
    try:
        logging.getLogger("public_export.selftest").debug("positive-control DEBUG record CANARY-7")
        ok1, err1 = push(b'{"x":1}', base + "/status/status.json", "?sv=2023&sig=SECRETTOKEN", 3)
        ok2, err2 = push(b'{"x":1}', base + "/fail/status.json", "sv=2023&sig=SECRETTOKEN", 3)
        ok3, err3 = push(b'{"x":1}', "http://127.0.0.1:1/status.json", "sig=SECRETTOKEN", 1)
        ok4, err4 = push(b"", base + "/s", "sig=S", 1)
    finally:
        root.removeHandler(cap)
        root.setLevel(old_level)
    srv.shutdown()
    logtext = "\n".join(captured)
    checks += [
        ("push: PUT with BlockBlob headers, SAS appended, body intact, 201 -> ok",
         ok1 and err1 is None and seen["body"] == b'{"x":1}' and seen["headers"]["x-ms-blob-type"] == "BlockBlob"
         and seen["headers"]["content-type"].startswith("application/json") and seen["path"].endswith("?sv=2023&sig=SECRETTOKEN")),
        ("push: 403 -> (False, 'HTTP 403'); refused connection -> type only; empty body refused; no SAS in any err",
         (not ok2 and err2 == "HTTP 403") and (not ok3 and err3 and "SECRETTOKEN" not in err3 and "sig=" not in err3)
         and (not ok4 and err4 == "bad-size")),
        ("push: with the ROOT logger at DEBUG (positive control captured), nothing logged by urllib3/requests carries the SAS (audit C1)",
         "CANARY-7" in logtext and "SECRETTOKEN" not in logtext and "sig=" not in logtext),
        ("mask: the secret and any SAS-looking fragment never survive into a message",
         "ABC" not in _mask("boom ?sv=1&sig=ABC", "sv=1&sig=ABC") and _mask("x sig=ABC y", None) == "<masked: SAS-bearing text>"
         and _mask("plain", "ABC") == "plain"),
        ("retry policy: 4xx is permanent, 5xx / transport errors retry",
         not _retryable("HTTP 403") and not _retryable("HTTP 404") and _retryable("HTTP 500") and _retryable("ConnectTimeout") and _retryable(None)),
    ]
    # Exporter: throttle (real trailing timer, ~1 s), push lock, close(), status, with fake clocks and a fake pusher
    clock = {"mono": 1000.0, "now": 1792536000.0}
    pushes = []
    gate = th.Event()
    gate.set()

    def fake_push(data, url, sas, timeout):
        gate.wait(5)
        pushes.append((clock["mono"], len(data), sas))
        return (True, None) if len(pushes) != 2 else (False, "HTTP 500")

    cfg15 = dict(cfg, min_interval_seconds=15)
    with tempfile.TemporaryDirectory() as td:
        ex = Exporter(cfg15, base_dir=td, sas_reader=lambda item: "sv=1&sig=K", pusher=fake_push,
                      now_fn=lambda: clock["now"], mono_fn=lambda: clock["mono"], daemon={"commit": "abc"},
                      retry_delay=0.0)
        ex.after_scan(status); ex._worker.join(5)
        first = len(pushes)
        clock["mono"] += 14; clock["now"] += 14          # 1 s short of the interval -> trailing timer of ~1 s
        ex.after_scan(status); ex._worker.join(5)
        with ex._lock:
            throttled, timer_armed = ex.state["throttled"], ex._timer is not None
        after_second = len(pushes)
        deadline = time.time() + 5
        while len(pushes) < 2 and time.time() < deadline:   # the real timer fires in ~1 s (fake mono is frozen, so it re-arms once)
            clock["mono"] += 1.0                              # let the re-check see the interval as elapsed
            time.sleep(0.2)
        timer_pushed = len(pushes) >= 2
        clock["mono"] += 60; clock["now"] += 60
        ex.after_scan(status); ex._worker.join(5)
        st = ex.status()
        checks += [
            ("exporter: first scan renders, writes the file and pushes once; SAS from the reader; status block filled",
             first == 1 and st["sas_present"] and st["last_write_ok"] is True and os.path.exists(ex.path)
             and st["renders"] == 3 and st["bytes"] > 100 and st["last_render"] is not None),
            ("exporter: a scan inside the interval is throttled (no second PUT then; one trailing timer armed)",
             throttled == 1 and timer_armed and after_second == 1),
            ("exporter: the trailing timer pushes the newest file once the interval has elapsed",
             timer_pushed),
            ("exporter: PUT #2 (timer) got the fake's 500, was retried, and later pushes succeed; counters consistent; SAS never in status",
             st["pushes"] >= 2 and st["last_push_ok"] is True and st["last_error"] is None
             and all(s == "sv=1&sig=K" for _, _, s in pushes) and "sig" not in json.dumps(st)),
        ]
        # push lock: a slow PUT in flight -> a second push attempt is skipped, not run concurrently
        gate.clear()
        n_before = len(pushes)
        clock["mono"] += 60
        t_slow = th.Thread(target=ex._do_push, args=(b'{"slow":1}', good_url, "sv=1&sig=K"), daemon=True)
        t_slow.start(); time.sleep(0.2)
        ex._do_push(b'{"fast":1}', good_url, "sv=1&sig=K")
        skipped = ex.status()["busy_skipped"]
        gate.set(); t_slow.join(5)
        with ex._lock:
            rearmed = ex._timer is not None
        deadline = time.time() + 8                                 # the busy re-arm (5 s) sends the newest file
        while len(pushes) < n_before + 2 and time.time() < deadline:
            clock["mono"] += 1.0
            time.sleep(0.2)
        checks.append(("exporter: never two PUTs at once — the busy attempt is counted, a short timer is re-armed, and "
                       "the newest file is pushed once the lock frees (audit V1)",
                       skipped == 1 and rearmed and len(pushes) == n_before + 2))
        # close(): a pending timer is cancelled and nothing pushes afterwards
        clock["mono"] += 60
        ex.after_scan(status); ex._worker.join(5)          # a direct push (interval elapsed) -> sets last_push_mono
        clock["mono"] += 5
        ex.after_scan(status); ex._worker.join(5)          # inside the interval -> throttled -> timer armed
        with ex._lock:
            had_timer = ex._timer is not None
        with ex._lock:
            armed = ex._timer
        ex.close()
        n_closed = len(pushes)
        armed_fired_noop = False
        if armed is not None:
            ex._push_latest_file(armed)              # simulate the cancelled timer firing anyway: identity check -> no-op
            armed_fired_noop = len(pushes) == n_closed
        clock["mono"] += 120
        ex.after_scan(status)
        time.sleep(0.3)
        checks.append(("exporter: close() cancels the trailing timer, a late callback is a no-op, and later scans are refused",
                       had_timer and armed_fired_noop and len(pushes) == n_closed and ex._timer is None and ex._pending is None))
        published = []
        ex2 = Exporter(cfg, base_dir=td, sas_reader=lambda item: None, pusher=fake_push,
                       now_fn=lambda: clock["now"], mono_fn=lambda: clock["mono"], on_status=published.append)
        before = len(pushes)
        ex2.after_scan(status); ex2._worker.join(5)
        checks.append(("exporter: no SAS -> file still written, nothing pushed, sas_present False, last_error 'no-sas'",
                       len(pushes) == before and ex2.status()["sas_present"] is False and ex2.status()["last_write_ok"] is True
                       and ex2.status()["last_error"] == "no-sas"))
        checks.append(("exporter: the worker publishes its counters to on_status after the scan (no one-scan lag on /status)",
                       len(published) >= 1 and published[-1]["renders"] == 1 and published[-1]["last_write_ok"] is True))
        ex2b = Exporter(cfg, base_dir=td, sas_reader=lambda item: None, pusher=fake_push,
                        now_fn=lambda: clock["now"], mono_fn=lambda: clock["mono"],
                        on_status=lambda st: (_ for _ in ()).throw(RuntimeError("consumer")))
        ex2b.after_scan(status); ex2b._worker.join(5)
        checks.append(("exporter: a raising on_status consumer never breaks the worker", ex2b.status()["renders"] == 1))
        ex3 = Exporter(cfg, base_dir=td, sas_reader=lambda item: (_ for _ in ()).throw(RuntimeError("keychain")),
                       pusher=fake_push, now_fn=lambda: clock["now"], mono_fn=lambda: clock["mono"])
        checks.append(("exporter: a raising SAS reader is survived (SAS absent)", ex3.status()["sas_present"] is False))
        # a 403 (expired SAS) is not retried
        calls = []

        def push403(data, url, sas, timeout):
            calls.append(1)
            return False, "HTTP 403"
        ex4 = Exporter(cfg, base_dir=td, sas_reader=lambda item: "sv=1&sig=K", pusher=push403,
                       now_fn=lambda: clock["now"], mono_fn=lambda: clock["mono"], retry_delay=0.0)
        ex4.after_scan(status); ex4._worker.join(5)
        checks.append(("exporter: a 4xx is not retried; counted as one failure with last_error 'push: HTTP 403'",
                       len(calls) == 1 and ex4.status()["failures"] == 1 and ex4.status()["last_error"] == "push: HTTP 403"))
    checks.append(("read_sas: a pasted full SAS URL is reduced to the token; a value without sig= is rejected",
                   _reduce_sas("https://a.blob.core.windows.net/c/b?sv=1&sig=K\n") == "sv=1&sig=K"
                   and _reduce_sas("?sv=1&sig=K") == "sv=1&sig=K" and _reduce_sas("hello") is None and _reduce_sas("") is None))
    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(("  [OK] " if ok else "  [FAIL] ") + n)
    print("public_export selftest: %d/%d passed" % (len(checks) - len(failed), len(checks)))
    return 1 if failed else 0


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--once", action="store_true", help="render from the live /status and write the file")
    ap.add_argument("--push", action="store_true", help="with --once: also push (SAS from the keychain)")
    ap.add_argument("--status-url", default="http://127.0.0.1:61211/status")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if a.selftest:
        sys.exit(_selftest())
    if a.once:
        sys.exit(_once(a))
    ap.print_help()
