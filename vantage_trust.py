"""Vantage-trust gating from an external vantage-health monitor (2026-08-22).

Motivation: a 2026-08 incident left the vantage node's bridge to the hub
wedged (link-state ESTABLISHED with no real transport) for ~15 hours. During
that window the fast detection layer (tripwire + link-state watchdog, both
fed from the vantage) was blind to the hub-side mesh while every ILDS health
indicator stayed green — ssh_healthy proves the SSH path, not that the
vantage's view is alive.

Rather than duplicating the separately-owned vantage health monitor (a
15-minute job with ghost/transport/hysteresis checks), this module consumes
its machine-readable output — an atomically-rewritten local JSON file — and
derives a single trust verdict for the vantage-derived signals:

    ok        source fresh, watched checks acceptable
    degraded  overall alarm level, or a watched check at alarm level
    unknown   source missing/stale/unparseable, or a watched check
              missing/unknown (absence is never treated as health)
    silenced  the producer is deliberately muted (maintenance) — surfaced,
              never emailed
    disabled  feature off in config (or no source file configured)

Verdict semantics honor the PRODUCER's vocabulary: its per-check values are
pass|warn|alert|fatal|ghost|unknown, where "warn" means hysteresis-pending
(a transient it deliberately does not alert on). ILDS therefore degrades
only on alert/fatal/ghost — re-alerting on "warn" would defeat the
producer's hysteresis one layer up (audit S1, 2026-08-22).

The verdict is presentation + notification only: it annotates /status and
emails the internal recipient on transitions. It NEVER gates enforcement —
the stats-API detection layer is independent of the vantage and keeps
working regardless.

Notification state machine (audit C1/C3, 2026-08-22): a transition queues a
PENDING notice that is retried every scan until the notifier reports a
successful send — a notice born during quiet hours is delivered when they
end, not swallowed. If trust returns to the pre-notice state before
delivery, the pending notice is collapsed (nothing happened worth telling).
Degradation notices honor a cooldown stamped only on SUCCESSFUL delivery;
a recovery notice is sent only when a degradation for the same episode was
actually delivered. Worst-case email volume is therefore bounded at one
degradation per cooldown window plus one recovery per delivered
degradation, regardless of source flapping.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Producer per-check values that mean the vantage's view is compromised.
DEFAULT_DEGRADED_CHECK_VALUES = ("alert", "fatal", "ghost")
# Producer overall values that mean the same regardless of watched checks.
DEFAULT_DEGRADED_OVERALL = ("alert", "fatal")
# Clock-sanity guard: a source stamped further in the future than this is a
# clock fault and must not read as eternally fresh (audit A2).
FUTURE_SKEW_LIMIT_S = 60


def _as_str_list(value, name: str, default: list) -> list:
    """Config lists must be lists of strings; scalars/garbage fall back
    loudly instead of failing open (audit S4)."""
    if value is None:
        return list(default)
    if isinstance(value, str):
        logger.warning("vantage_trust.%s is a scalar (%r); wrapping as a "
                       "one-element list", name, value)
        return [value]
    if isinstance(value, (list, tuple)):
        out = []
        for v in value:
            if isinstance(v, str):
                out.append(v)
            else:
                logger.warning("vantage_trust.%s entry %r is not a string; "
                               "coercing", name, v)
                out.append(str(v))
        return out
    logger.warning("vantage_trust.%s has unusable type %s; using default %r",
                   name, type(value).__name__, default)
    return list(default)


def _as_int(value, name: str, default: int) -> int:
    if value is None:            # key absent — default silently
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.warning("vantage_trust.%s value %r is not an integer; "
                       "using default %d", name, value, default)
        return default


class VantageTrustMonitor:
    """Reads the vantage-health status file and tracks trust transitions."""

    def __init__(self, config: dict):
        try:
            cfg = (config or {}).get("vantage_trust") or {}
            if not isinstance(cfg, dict):
                logger.warning("vantage_trust config is not a mapping; "
                               "feature disabled")
                cfg = {}
            raw_path = cfg.get("status_file")
            self.status_file: Optional[Path] = (
                Path(str(raw_path)).expanduser() if raw_path else None)
            # No source file configured -> disabled: the real path carries a
            # deployment-specific name and lives in the (gitignored) config,
            # never in code (audit S7).
            self.enabled: bool = bool(cfg.get("enabled", True)) \
                and self.status_file is not None
            self.stale_after_s = _as_int(
                cfg.get("stale_after_s"), "stale_after_s", 2400)
            self.degraded_overall = set(
                s.lower() for s in _as_str_list(
                    cfg.get("degraded_overall"), "degraded_overall",
                    list(DEFAULT_DEGRADED_OVERALL)))
            self.degraded_check_values = set(
                s.lower() for s in _as_str_list(
                    cfg.get("degraded_check_values"), "degraded_check_values",
                    list(DEFAULT_DEGRADED_CHECK_VALUES)))
            self.watch_checks = _as_str_list(
                cfg.get("watch_checks"), "watch_checks", [])
            if self.enabled and not self.watch_checks:
                logger.warning("vantage_trust: no watch_checks configured — "
                               "only the source's overall level is watched")
            self.email_cooldown_s = _as_int(
                cfg.get("email_cooldown_s"), "email_cooldown_s", 21600)
        except Exception as e:  # last-ditch: never take the daemon down (C2)
            logger.error("vantage_trust config unusable (%s); feature "
                         "disabled", e)
            self.enabled = False
            self.status_file = None
            self.stale_after_s = 2400
            self.degraded_overall = set(DEFAULT_DEGRADED_OVERALL)
            self.degraded_check_values = set(DEFAULT_DEGRADED_CHECK_VALUES)
            self.watch_checks = []
            self.email_cooldown_s = 21600
        # --- notification state ---
        self._last_trust: Optional[str] = None   # None until first evaluate
        self._pending: Optional[dict] = None     # undelivered notice
        self._episode_notified: bool = False     # degradation delivered?
        self._last_degradation_email_ts: float = 0.0

    # -- evaluation -------------------------------------------------------

    def evaluate(self) -> dict:
        """Return the current trust block. Never raises (audit S3)."""
        block = {
            "trust": "unknown",
            "reason": None,
            "source": str(self.status_file) if self.status_file else None,
            "source_age_s": None,
            "overall": None,
            "failing_watched": [],
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        if not self.enabled:
            block["trust"] = "disabled"
            block["reason"] = "disabled in config or no status_file set"
            return block
        try:
            try:
                raw = self.status_file.read_text()
            except FileNotFoundError:
                block["reason"] = "status file missing"
                return block
            except OSError as e:
                block["reason"] = f"status file unreadable: {e}"
                return block
            try:
                data = json.loads(raw)
            except (ValueError, TypeError) as e:
                block["reason"] = f"status file not valid JSON: {e}"
                return block
            if not isinstance(data, dict):
                block["reason"] = ("status file is valid JSON but not an "
                                   "object")
                return block

            age = self._source_age_s(data.get("timestamp"))
            block["source_age_s"] = age
            overall = data.get("overall")
            block["overall"] = overall
            if age is None:
                block["reason"] = "source timestamp missing/unparseable"
                return block
            if age < -FUTURE_SKEW_LIMIT_S:
                block["reason"] = (f"source timestamp {-age}s in the future "
                                   "— clock fault")
                return block
            if age > self.stale_after_s:
                block["reason"] = (
                    f"source stale ({age}s old > {self.stale_after_s}s)")
                return block

            # Producer deliberately muted (maintenance): surface, never
            # alarm (audit S8).
            if data.get("silenced"):
                block["trust"] = "silenced"
                block["reason"] = "source silenced (maintenance)"
                return block

            checks = data.get("checks")
            if not isinstance(checks, dict):
                checks = {}
            degraded, missing_or_unknown = [], []
            for c in self.watch_checks:
                v = checks.get(c)
                if v is None or str(v).lower() == "unknown":
                    missing_or_unknown.append(c)
                elif str(v).lower() in self.degraded_check_values:
                    degraded.append(c)
                # producer "warn" = hysteresis pending -> acceptable (S1)
            block["failing_watched"] = degraded + missing_or_unknown
            # Every source check at alarm level, watched or not — so the
            # operator reads WHY the source went to alarm (2026-09-08: an
            # "overall=alert" caused by the source's unwatched link_<node>
            # check read as a bare "source overall=alert").
            failing_pairs = sorted(
                (str(name), str(val).lower()) for name, val in checks.items()
                if str(val).lower() in self.degraded_check_values)
            failing_source = [f"{name} ({val})" for name, val in failing_pairs]
            block["failing_source"] = failing_source

            if str(overall or "").lower() in self.degraded_overall:
                block["trust"] = "degraded"
                if failing_source:
                    unwatched = [name for name, _ in failing_pairs
                                 if name not in self.watch_checks]
                    shown = ", ".join(failing_source[:10])
                    if len(failing_source) > 10:
                        shown += f" (+{len(failing_source) - 10} more)"
                    block["reason"] = (
                        f"source overall={overall} — failing check(s): " + shown
                        + ("; none of the watched checks is failing — the "
                           "source's overall level is what degrades trust"
                           if unwatched and not degraded and not missing_or_unknown
                           else ""))
                else:
                    block["reason"] = (f"source overall={overall} (no individual "
                                       f"check at alarm level in the file)")
            elif degraded:
                block["trust"] = "degraded"
                block["reason"] = ("watched checks at alarm level: "
                                   + ", ".join(degraded))
            elif missing_or_unknown:
                # Absence of a watched check is never health (audit S2).
                block["trust"] = "unknown"
                block["reason"] = ("watched checks missing/unknown at "
                                   "source: " + ", ".join(missing_or_unknown))
            else:
                block["trust"] = "ok"
                block["reason"] = "source fresh, watched checks acceptable"
            return block
        except Exception as e:
            block["trust"] = "unknown"
            block["reason"] = f"evaluation error: {e}"
            return block

    @staticmethod
    def _source_age_s(ts) -> Optional[int]:
        """Signed age in seconds (negative = stamped in the future)."""
        if not ts or not isinstance(ts, str):
            return None
        try:
            t = ts.strip()
            if len(t) >= 5 and (t[-5] in "+-") and t[-3] != ":":
                t = t[:-2] + ":" + t[-2:]
            parsed = datetime.fromisoformat(t)
            if parsed.tzinfo is None:
                parsed = parsed.astimezone()
            return int((datetime.now(timezone.utc) - parsed).total_seconds())
        except (ValueError, TypeError):
            return None

    # -- notification state machine ---------------------------------------

    # Trust values that never generate or sustain a notice.
    _QUIET_STATES = ("disabled", "silenced")

    def note(self, block: dict) -> None:
        """Record the verdict and manage the pending notice.

        First evaluation: a non-ok start QUEUES a degradation notice — a
        restart during blindness must announce it, not silently re-baseline
        (audit S5). Later transitions queue/collapse per the module
        docstring. Logs every transition.
        """
        new = block.get("trust")
        old = self._last_trust
        self._last_trust = new
        if new == old:
            return
        if old is not None:
            level = logger.warning if new not in ("ok",) else logger.info
            level("VANTAGE TRUST: %s -> %s (%s)",
                  old, new, block.get("reason"))
        if new in self._QUIET_STATES:
            self._pending = None
            return
        if new == "ok":
            if old in self._QUIET_STATES or old is None:
                self._pending = None
            elif self._episode_notified:
                self._pending = {"kind": "recovery", "old": old, "new": new,
                                 "block": dict(block)}
            else:
                # Degradation never delivered; net-nothing — collapse.
                self._pending = None
        else:  # degraded or unknown
            self._pending = {"kind": "degradation",
                             "old": old if old is not None else "startup",
                             "new": new, "block": dict(block)}

    def pending(self) -> Optional[dict]:
        """The notice to send this scan, or None (cooldown-gated)."""
        p = self._pending
        if p is None:
            return None
        if p["kind"] == "degradation":
            since = time.time() - self._last_degradation_email_ts
            if since < self.email_cooldown_s:
                return None
        return p

    def mark_sent(self, notice: dict) -> None:
        """Called ONLY on a successful dispatch — a refused send (quiet
        hours, caps, SMTP failure) keeps the notice pending for retry next
        scan (audit C1)."""
        if notice is self._pending or notice == self._pending:
            self._pending = None
        if notice["kind"] == "degradation":
            self._episode_notified = True
            self._last_degradation_email_ts = time.time()
        else:
            self._episode_notified = False

    def carry_state_from(self, other: "VantageTrustMonitor") -> None:
        """Preserve transition/notification state across a SIGHUP reload."""
        self._last_trust = other._last_trust
        self._pending = other._pending
        self._episode_notified = other._episode_notified
        self._last_degradation_email_ts = other._last_degradation_email_ts

    def describe(self) -> str:
        if not self.enabled:
            return "vantage_trust: DISABLED"
        return (f"vantage_trust: ENABLED (source={self.status_file}, "
                f"stale_after={self.stale_after_s}s, "
                f"watch=[{','.join(self.watch_checks)}], "
                f"degrade_on=[{','.join(sorted(self.degraded_check_values))}],"
                f" email_cooldown={self.email_cooldown_s}s)")


# ---------------------------------------------------------------------------
# Self-test: python3 vantage_trust.py
# ---------------------------------------------------------------------------

def _selftest() -> int:
    import tempfile

    failures = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    def fresh_ts(offset_s=0):
        from datetime import timedelta
        return (datetime.now().astimezone()
                + timedelta(seconds=offset_s)).strftime(
                    "%Y-%m-%dT%H:%M:%S%z")

    with tempfile.TemporaryDirectory() as tmp:
        sf = Path(tmp) / "status.json"

        def write(payload):
            sf.write_text(json.dumps(payload) if isinstance(payload, (dict, list))
                          else payload)

        def monitor(**over):
            cfg = {"vantage_trust": {
                "status_file": str(sf),
                "watch_checks": ["link_hub", "ghost_hub", "chan_hub"],
                **over}}
            return VantageTrustMonitor(cfg)

        allpass = {"link_hub": "pass", "ghost_hub": "pass",
                   "chan_hub": "pass"}

        # --- verdict semantics (producer vocabulary) ---
        m = monitor()
        write({"timestamp": fresh_ts(), "overall": "ok", "silenced": 0,
               "checks": allpass})
        check("healthy -> ok", m.evaluate()["trust"] == "ok")

        write({"timestamp": fresh_ts(), "overall": "warn", "silenced": 0,
               "checks": dict(allpass, link_hub="warn")})
        check("producer warn (hysteresis pending) -> ok, not degraded",
              m.evaluate()["trust"] == "ok")

        for v in ("alert", "fatal", "ghost"):
            write({"timestamp": fresh_ts(), "overall": "warn", "silenced": 0,
                   "checks": dict(allpass, ghost_hub=v)})
            check(f"watched check {v} -> degraded",
                  m.evaluate()["trust"] == "degraded")

        write({"timestamp": fresh_ts(), "overall": "fatal", "silenced": 0,
               "checks": allpass})
        b = m.evaluate()
        check("overall fatal -> degraded", b["trust"] == "degraded")
        check("overall alarm with no failing check: reason says so",
              "no individual check at alarm level" in b["reason"] and b["failing_source"] == [])
        # 2026-09-08: the live case — overall=alert caused by an UNWATCHED
        # check (the source's link to the operator's own node). The reason
        # must name it and say the watched checks are fine.
        write({"timestamp": fresh_ts(), "overall": "alert", "silenced": 0,
               "checks": dict(allpass, link_77777="alert")})
        b = m.evaluate()
        check("overall alert via an unwatched check -> degraded, reason names the check",
              b["trust"] == "degraded" and "link_77777 (alert)" in b["reason"]
              and "none of the watched checks is failing" in b["reason"]
              and b["failing_source"] == ["link_77777 (alert)"] and b["failing_watched"] == [])
        write({"timestamp": fresh_ts(), "overall": "alert", "silenced": 0,
               "checks": dict(allpass, link_hub="alert", link_77777="alert")})
        b = m.evaluate()
        check("overall alert with a watched check failing too -> both named, no 'none failing' clause",
              "link_hub (alert)" in b["reason"] and "link_77777 (alert)" in b["reason"]
              and "none of the watched" not in b["reason"] and b["failing_watched"] == ["link_hub"])

        write({"timestamp": fresh_ts(), "overall": "ok", "silenced": 0,
               "checks": dict(allpass, chan_hub="unknown")})
        check("watched check unknown -> unknown",
              m.evaluate()["trust"] == "unknown")

        write({"timestamp": fresh_ts(), "overall": "ok", "silenced": 0,
               "checks": {"link_hub": "pass"}})
        check("watched check MISSING -> unknown (never fail-open)",
              m.evaluate()["trust"] == "unknown")

        write({"timestamp": fresh_ts(), "overall": "warn", "silenced": 1,
               "checks": dict(allpass, link_hub="fatal")})
        check("silenced source -> silenced (no alarm)",
              m.evaluate()["trust"] == "silenced")

        # --- source integrity ---
        write({"timestamp": "2026-01-01T00:00:00-0600", "overall": "ok",
               "checks": allpass})
        check("stale -> unknown", m.evaluate()["trust"] == "unknown")
        write({"timestamp": fresh_ts(3600), "overall": "ok",
               "checks": allpass})
        check("future timestamp -> unknown (clock fault)",
              m.evaluate()["trust"] == "unknown")
        sf.unlink()
        check("missing file -> unknown", m.evaluate()["trust"] == "unknown")
        write("{not json")
        check("malformed JSON -> unknown", m.evaluate()["trust"] == "unknown")
        write([1, 2, 3])
        check("JSON array (schema drift) -> unknown, no exception",
              m.evaluate()["trust"] == "unknown")
        write({"timestamp": fresh_ts(), "overall": "ok",
               "checks": ["not", "a", "dict"]})
        check("checks list (schema drift) -> unknown",
              m.evaluate()["trust"] == "unknown")

        # --- notification state machine ---
        m2 = monitor()
        write({"timestamp": fresh_ts(), "overall": "ok", "silenced": 0,
               "checks": allpass})
        m2.note(m2.evaluate())
        check("startup ok -> no pending notice", m2.pending() is None)

        write({"timestamp": fresh_ts(), "overall": "alert", "silenced": 0,
               "checks": allpass})
        m2.note(m2.evaluate())
        p = m2.pending()
        check("ok->degraded queues degradation notice",
              p is not None and p["kind"] == "degradation")
        # refused send (quiet hours): pending survives
        check("refused send keeps notice pending", m2.pending() is not None)
        # net-nothing flap before delivery collapses
        write({"timestamp": fresh_ts(), "overall": "ok", "silenced": 0,
               "checks": allpass})
        m2.note(m2.evaluate())
        check("undelivered degradation + recovery collapses (no email)",
              m2.pending() is None)

        # degradation delivered -> recovery notice; cooldown on repeats
        m3 = monitor(email_cooldown_s=3600)
        write({"timestamp": fresh_ts(), "overall": "ok", "silenced": 0,
               "checks": allpass})
        m3.note(m3.evaluate())
        write({"timestamp": fresh_ts(), "overall": "alert", "silenced": 0,
               "checks": allpass})
        m3.note(m3.evaluate())
        p = m3.pending()
        check("degradation notice available", p is not None)
        m3.mark_sent(p)
        check("after delivery nothing pending", m3.pending() is None)
        write({"timestamp": fresh_ts(), "overall": "ok", "silenced": 0,
               "checks": allpass})
        m3.note(m3.evaluate())
        p = m3.pending()
        check("recovery notice after delivered degradation",
              p is not None and p["kind"] == "recovery")
        m3.mark_sent(p)
        write({"timestamp": fresh_ts(), "overall": "alert", "silenced": 0,
               "checks": allpass})
        m3.note(m3.evaluate())
        check("re-degradation inside cooldown is queued but gated",
              m3._pending is not None and m3.pending() is None)

        # startup during blindness announces (S5)
        m4 = monitor()
        write({"timestamp": fresh_ts(), "overall": "fatal", "silenced": 0,
               "checks": allpass})
        m4.note(m4.evaluate())
        p = m4.pending()
        check("startup during degradation queues notice",
              p is not None and p["old"] == "startup")

        # disabled / silenced states never notify
        m5 = monitor(enabled=False)
        b = m5.evaluate()
        m5.note(b)
        check("disabled -> trust=disabled, no notice",
              b["trust"] == "disabled" and m5.pending() is None)

        # --- constructor robustness (C2/S4) ---
        for bad in (
            {"vantage_trust": {"status_file": str(sf),
                               "watch_checks": None}},
            {"vantage_trust": {"status_file": str(sf),
                               "watch_checks": "link_hub"}},
            {"vantage_trust": {"status_file": str(sf),
                               "watch_checks": [12345],
                               "degraded_overall": "alert",
                               "stale_after_s": "40m",
                               "email_cooldown_s": ""}},
            {"vantage_trust": "garbage"},
            {"vantage_trust": None},
            None,
        ):
            try:
                mm = VantageTrustMonitor(bad)
                mm.describe()
                mm.evaluate()
                ok = True
            except Exception:
                ok = False
            check(f"constructor survives {str(bad)[:60]!r}", ok)
        m6 = VantageTrustMonitor(
            {"vantage_trust": {"status_file": str(sf),
                               "degraded_overall": "alert",
                               "watch_checks": ["link_hub", "ghost_hub",
                                                "chan_hub"]}})
        write({"timestamp": fresh_ts(), "overall": "alert", "silenced": 0,
               "checks": allpass})
        check("scalar degraded_overall still degrades (no fail-open)",
              m6.evaluate()["trust"] == "degraded")

        # no status_file configured -> disabled
        m7 = VantageTrustMonitor({"vantage_trust": {"enabled": True}})
        check("no status_file -> disabled",
              m7.evaluate()["trust"] == "disabled")

        # carry_state_from preserves the full notification state
        m8 = monitor()
        m8.carry_state_from(m3)
        check("carry_state_from preserves pending + episode",
              m8._pending == m3._pending
              and m8._episode_notified == m3._episode_notified
              and m8._last_trust == m3._last_trust)

    print(f"\nSelf-test: {'PASS' if not failures else 'FAIL'} "
          f"(failures: {failures or 'none'})")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
