"""DNS-based node registration checker for AllStarLink.

AllStarLink nodes register via IAX2 and their registration is published
as DNS TXT records at <node>.nodes.allstarlink.org. The DNS record is
updated within ~60 seconds of registration and has a TTL of 60 seconds.

A node with an active TXT record is confirmed to be online and actively
registering with AllStarLink — a much stronger freshness signal than
the stats API's regseconds field, which can lag by up to ~60 minutes.

A node with NO TXT record is either offline, unregistered, or nonexistent.
"""

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

ASL_DNS_DOMAIN = "nodes.allstarlink.org"

# Try to use dnspython for proper TXT record lookups.
# Fall back to subprocess + dig if dnspython is not installed.
try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False
    logger.info("dnspython not installed; falling back to dig for DNS lookups")


@dataclass
class NodeDNSInfo:
    """Result of a DNS lookup for an AllStar node."""
    node_id: int
    is_registered: bool   # True if TXT record exists (node is online)
    ip_address: Optional[str] = None
    port: Optional[int] = None
    # True when the LOOKUP itself failed (no nameservers, timeout, resolver
    # error) as opposed to a definite "no such record" (NXDOMAIN / no TXT).
    # is_registered is False in both cases; callers that must tell "not
    # registered" from "could not check" read this (node_health, 2026-10-18).
    lookup_failed: bool = False

    def __str__(self):
        if self.is_registered:
            return f"Node {self.node_id}: registered at {self.ip_address}:{self.port}"
        return f"Node {self.node_id}: NOT registered (offline or nonexistent)"


def _port(port_str) -> Optional[int]:
    """A malformed PT= field is a record oddity, not a lookup failure."""
    try:
        return int(port_str) if port_str else None
    except (TypeError, ValueError):
        logger.debug(f"DNS: unparseable PT field {port_str!r}")
        return None


def check_node_dns(node_id: int, timeout: float = 5.0) -> NodeDNSInfo:
    """Check if a node has an active DNS registration.

    This is the most reliable real-time check for whether a node is online,
    since AllStarLink DNS records propagate within ~60 seconds and have a
    60-second TTL.

    Returns a NodeDNSInfo with is_registered=True if the node has a TXT record.
    """
    hostname = f"{node_id}.{ASL_DNS_DOMAIN}"

    if _HAS_DNSPYTHON:
        return _check_with_dnspython(node_id, hostname, timeout)
    else:
        return _check_with_dig(node_id, hostname, timeout)


def _check_with_dnspython(node_id: int, hostname: str, timeout: float) -> NodeDNSInfo:
    """DNS lookup using dnspython library."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(hostname, "TXT")

        # Parse TXT record fields: "NN=12345" "IP=198.51.100.1" "PT=4569"
        fields = {}
        for rdata in answers:
            for s in rdata.strings:
                text = s.decode("utf-8", errors="replace")
                if "=" in text:
                    key, _, value = text.partition("=")
                    fields[key.strip()] = value.strip()

        ip = fields.get("IP")
        port = _port(fields.get("PT"))

        logger.debug(f"DNS: {hostname} -> IP={ip}, PT={port}")
        return NodeDNSInfo(node_id=node_id, is_registered=True,
                           ip_address=ip, port=port)

    except dns.resolver.NXDOMAIN:
        logger.debug(f"DNS: {hostname} -> NXDOMAIN (not registered)")
        return NodeDNSInfo(node_id=node_id, is_registered=False)
    except dns.resolver.NoAnswer:
        logger.debug(f"DNS: {hostname} -> no TXT record")
        return NodeDNSInfo(node_id=node_id, is_registered=False)
    except dns.resolver.NoNameservers:
        logger.warning(f"DNS: {hostname} -> no nameservers available")
        return NodeDNSInfo(node_id=node_id, is_registered=False, lookup_failed=True)
    except Exception as e:
        logger.warning(f"DNS lookup error for {hostname}: {e}")
        return NodeDNSInfo(node_id=node_id, is_registered=False, lookup_failed=True)


def _check_with_dig(node_id: int, hostname: str, timeout: float) -> NodeDNSInfo:
    """DNS lookup using dig subprocess as fallback."""
    import subprocess
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", hostname],
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout.strip()

        if not output:
            logger.debug(f"DNS (dig): {hostname} -> no record")
            return NodeDNSInfo(node_id=node_id, is_registered=False)

        # Parse: "NN=12345" "IP=198.51.100.1" "PT=4569"
        fields = {}
        for part in output.replace('"', '').split():
            if "=" in part:
                key, _, value = part.partition("=")
                fields[key.strip()] = value.strip()

        ip = fields.get("IP")
        port = _port(fields.get("PT"))

        logger.debug(f"DNS (dig): {hostname} -> IP={ip}, PT={port}")
        return NodeDNSInfo(node_id=node_id, is_registered=True,
                           ip_address=ip, port=port)

    except subprocess.TimeoutExpired:
        logger.warning(f"DNS (dig): {hostname} -> timeout")
        return NodeDNSInfo(node_id=node_id, is_registered=False, lookup_failed=True)
    except FileNotFoundError:
        logger.error("dig command not found — install dnsutils/bind-tools or pip install dnspython")
        return NodeDNSInfo(node_id=node_id, is_registered=False, lookup_failed=True)
    except Exception as e:
        logger.warning(f"DNS (dig) error for {hostname}: {e}")
        return NodeDNSInfo(node_id=node_id, is_registered=False, lookup_failed=True)


# --------------------------------------------------------------------------- #
# Two-system lookup (2026-10-19): AllStarLink AND HamVoIP registration DNS.
#
#   <n>.nodes.allstarlink.org   A   = <ip>                (one or more; may lag the TXT)
#                               TXT = "NN=<n>" "IP=<ip>" "PT=<port>"
#   <n>.asl.hamvoip.org         TXT = "radio@<ip>:<port>/<n>,<ip>"   (no A record seen)
#
# Only HamVoIP nodes ever have the second set; ASL3 nodes have the first only.
# The TXT record is the registration fact ("present"); the A record is
# carried for display and a soft cross-check only. `check_node_dns` above
# (ASL TXT only) is unchanged for its other callers (asl_link_detector,
# auto_disconnect).
# --------------------------------------------------------------------------- #
HAMVOIP_DNS_DOMAIN = "asl.hamvoip.org"


def _valid_ip(s) -> Optional[str]:
    """The canonical text of a real IPv4/IPv6 address, else None (brackets
    and surrounding whitespace tolerated)."""
    if s is None:
        return None
    t = str(s).strip().strip("[]")
    if not t:
        return None
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


def _node_num(s) -> Optional[int]:
    """A node number: ASCII digits only (no '12_345', no non-ASCII digits)."""
    t = str(s).strip() if s is not None else ""
    return int(t) if (t.isascii() and t.isdigit()) else None


def _valid_port(p) -> Optional[int]:
    """1..65535 as int, else None."""
    s = str(p).strip() if p is not None else ""
    if not (s.isascii() and s.isdigit()):  # int() accepts "4_569"; isdigit() accepts "²"
        return None
    v = int(s)
    return v if 0 < v < 65536 else None


@dataclass
class DNSRecordSet:
    """What one registration domain publishes for a node."""
    present: bool = False             # a TXT record exists (the registration fact)
    txt_ip: Optional[str] = None
    txt_port: Optional[int] = None
    txt_node: Optional[int] = None    # the node number the TXT names (ASL NN= / HamVoIP /<n>)
    txt_conflict: bool = False        # several TXT records with different ip/port
    a_ips: list = field(default_factory=list)   # every A record (sorted)
    a_failed: bool = False            # the A query itself failed (TXT result still valid)
    lookup_failed: bool = False       # the TXT query itself failed (resolver trouble)

    @property
    def a_ip(self) -> Optional[str]:
        return self.a_ips[0] if self.a_ips else None


@dataclass
class NodeDNSFull:
    node_id: int
    asl: DNSRecordSet
    hamvoip: Optional[DNSRecordSet]   # None = not looked up (skipped / not wanted)

    @property
    def lookup_failed(self) -> bool:
        """The AllStarLink TXT query failed — the signal the caller's resolver
        back-off keys on. A HamVoIP-only failure is reported in `hamvoip`."""
        return self.asl.lookup_failed


def _parse_asl_txt_one(text: str) -> tuple:
    """(node, ip, port) from one 'NN=… IP=… PT=…' string (missing → None)."""
    fields = {}
    for part in text.replace('"', "").split():
        if "=" in part:
            key, _, value = part.partition("=")
            fields[key.strip().upper()] = value.strip()
    return (_node_num(fields.get("NN")), _valid_ip(fields.get("IP")), _valid_port(fields.get("PT")))


def _parse_hamvoip_txt_one(text: str) -> tuple:
    """(node, ip, port) from one 'radio@<ip>:<port>/<node>,<ip>' string."""
    t = text.replace('"', "").strip()
    if "@" not in t:
        return (None, None, None)
    rest = t.split("@", 1)[1]                 # <ip>:<port>/<node>,<ip>
    hostport, _, tail = rest.partition("/")   # <ip>:<port> | <node>,<ip>
    if hostport.startswith("["):              # [v6]:port
        ip_s, _, port_s = hostport[1:].partition("]")
        port_s = port_s.lstrip(":")
    elif ":" in hostport:
        ip_s, _, port_s = hostport.rpartition(":")
    else:                                     # no ':' → whole thing is the ip
        ip_s, port_s = hostport, ""
    return (_node_num(tail.split(",", 1)[0] if tail else None), _valid_ip(ip_s), _valid_port(port_s))


def _parse_records(texts: list, one) -> tuple:
    """Parse every TXT record separately; use the first complete one, flag a
    conflict when another record disagrees on ip or port."""
    parsed = [one(t) for t in texts if t and t.strip()]
    parsed = sorted((p for p in parsed if p[1] or p[2] or p[0]),
                    key=lambda p: (str(p[1] or ""), p[2] or 0, p[0] or 0))   # answer order must not matter
    if not parsed:
        return (None, None, None, False)
    best = next((p for p in parsed if p[1] and p[2]), parsed[0])
    conflict = any((p[1] and best[1] and p[1] != best[1]) or (p[2] and best[2] and p[2] != best[2])
                   for p in parsed)
    return (best[0], best[1], best[2], conflict)


def _txt_records(answers) -> list:
    """One text per TXT RECORD: a record's character-strings are joined with
    a space ("NN=1" "IP=…" "PT=…" is ONE record with three strings — the
    AllStarLink shape). Returns [] when there are none."""
    out = []
    for rdata in answers:
        parts = [s.decode("utf-8", errors="replace") if isinstance(s, (bytes, bytearray)) else str(s)
                 for s in getattr(rdata, "strings", ())]
        text = " ".join(p for p in parts if p is not None).strip()
        if text:
            out.append(text)
    return out


def _resolve(hostname: str, rtype: str, timeout: float) -> tuple:
    """(records or None, failed). None = definitely absent (NXDOMAIN /
    NoAnswer). failed = resolver trouble (timeout, SERVFAIL, no
    nameservers). records: TXT → list[str]; A → list[str] (valid IPs only).
    Also tells the caller whether the NAME exists via the second return
    shape: returns ("nxdomain", False) when the whole name is absent."""
    if _HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        try:
            answers = resolver.resolve(hostname, rtype)
        except dns.resolver.NXDOMAIN:
            return ("nxdomain", False)
        except dns.resolver.NoAnswer:
            return (None, False)
        except Exception as e:                # NoNameservers, LifetimeTimeout, Timeout, YXDOMAIN…
            logger.debug("DNS: %s %s lookup error: %s", hostname, rtype, e)
            return (None, True)
        if rtype == "TXT":
            return (_txt_records(answers), False)
        ips = sorted({ip for ip in (_valid_ip(str(r)) for r in answers) if ip})
        return (ips or None, False)
    # dig fallback (exit status honoured; ';' lines and non-IP answers dropped)
    import subprocess
    try:
        r = subprocess.run(["dig", "+short", rtype, hostname],
                           capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        logger.debug("DNS (dig): %s %s error: %s", hostname, rtype, e)
        return (None, True)
    if r.returncode != 0:
        return (None, True)
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip() and not ln.startswith(";")]
    if rtype == "TXT":
        return (lines or None, False)
    ips = sorted({ip for ip in (_valid_ip(ln) for ln in lines) if ip})
    return (ips or None, False)


def _record_set(hostname: str, timeout: float, one_parser, want_a: bool = True) -> DNSRecordSet:
    txt, failed = _resolve(hostname, "TXT", timeout)
    rs = DNSRecordSet(lookup_failed=failed)
    if failed:
        return rs
    if txt == "nxdomain":                     # the name does not exist: no A either
        return rs
    if txt:
        rs.present = True
        rs.txt_node, rs.txt_ip, rs.txt_port, rs.txt_conflict = _parse_records(txt, one_parser)
    if not want_a:
        return rs
    a, a_failed = _resolve(hostname, "A", timeout)
    rs.a_failed = a_failed
    if a and a != "nxdomain":
        rs.a_ips = list(a)
    return rs


def check_node_dns_full(node_id: int, timeout: float = 2.0, want_hamvoip: bool = True) -> NodeDNSFull:
    """Both registration domains for one node. On an AllStarLink TXT lookup
    failure the HamVoIP lookup is skipped (resolver trouble; the caller's
    back-off takes over). `want_hamvoip=False` skips it too (caller's
    HamVoIP back-off); `hamvoip` is then None."""
    asl = _record_set(f"{node_id}.{ASL_DNS_DOMAIN}", timeout, _parse_asl_txt_one)
    if asl.lookup_failed or not want_hamvoip:
        return NodeDNSFull(node_id, asl, None)
    # HamVoIP publishes TXT only (no A record seen): one query, not two.
    hv = _record_set(f"{node_id}.{HAMVOIP_DNS_DOMAIN}", timeout, _parse_hamvoip_txt_one, want_a=False)
    return NodeDNSFull(node_id, asl, hv)


def _selftest() -> int:
    import types
    checks = [
        ("asl txt", _parse_asl_txt_one('NN=12345 IP=203.0.113.7 PT=4567') == (12345, "203.0.113.7", 4567)),
        ("asl txt quoted", _parse_asl_txt_one('"NN=1" "IP=192.0.2.9" "PT=4569"') == (1, "192.0.2.9", 4569)),
        ("asl txt bad port / bad ip", _parse_asl_txt_one('NN=1 IP=999.1.1.1 PT=abc') == (1, None, None)),
        ("asl txt port out of range", _parse_asl_txt_one('NN=1 IP=192.0.2.9 PT=70000') == (1, "192.0.2.9", None)),
        ("hamvoip txt", _parse_hamvoip_txt_one('radio@203.0.113.7:4567/12345,203.0.113.7') == (12345, "203.0.113.7", 4567)),
        ("hamvoip txt quoted", _parse_hamvoip_txt_one('"radio@198.51.100.22:4569/23456,198.51.100.22"') == (23456, "198.51.100.22", 4569)),
        ("hamvoip txt no port", _parse_hamvoip_txt_one('radio@192.0.2.1/1,192.0.2.1') == (1, "192.0.2.1", None)),
        ("hamvoip txt empty ip", _parse_hamvoip_txt_one('radio@:4569/1,x') == (1, None, 4569)),
        ("hamvoip txt bracketed v6", _parse_hamvoip_txt_one('radio@[2001:db8::1]:4569/1,2001:db8::1') == (1, "2001:db8::1", 4569)),
        ("hamvoip txt junk", _parse_hamvoip_txt_one('hello') == (None, None, None)),
        ("records: first complete wins, no conflict",
         _parse_records(['NN=1 IP=192.0.2.9 PT=4569', 'NN=1 IP=192.0.2.9 PT=4569'], _parse_asl_txt_one)
         == (1, "192.0.2.9", 4569, False)),
        ("records: conflicting ip flagged",
         _parse_records(['NN=1 IP=192.0.2.9 PT=4569', 'NN=1 IP=192.0.2.10 PT=4569'], _parse_asl_txt_one)[3] is True),
        ("records: incomplete then complete -> complete chosen",
         _parse_records(['NN=1 IP=192.0.2.9', 'NN=1 IP=192.0.2.9 PT=4569'], _parse_asl_txt_one)[:3] == (1, "192.0.2.9", 4569)),
        ("records: all junk -> empty", _parse_records(['x', ''], _parse_asl_txt_one) == (None, None, None, False)),
        ("txt records: three character-strings of ONE record are joined (ASL shape); two records stay two",
         _txt_records([types.SimpleNamespace(strings=[b"NN=1", b"IP=192.0.2.9", b"PT=4569"])])
         == ["NN=1 IP=192.0.2.9 PT=4569"]
         and len(_txt_records([types.SimpleNamespace(strings=[b"a"]), types.SimpleNamespace(strings=[b"b"])])) == 2
         and _parse_records(_txt_records([types.SimpleNamespace(strings=[b"NN=1", b"IP=192.0.2.9", b"PT=4569"])]),
                            _parse_asl_txt_one) == (1, "192.0.2.9", 4569, False)),
        ("valid_ip canonical / brackets / junk",
         _valid_ip(" 192.0.2.9 ") == "192.0.2.9" and _valid_ip("[2001:DB8::1]") == "2001:db8::1" and _valid_ip("a.b") is None),
        ("valid_port range", _valid_port("4569") == 4569 and _valid_port(0) is None and _valid_port("4_569") is None),
        ("record set: a_ip property", DNSRecordSet(a_ips=["192.0.2.2", "192.0.2.1"]).a_ip == "192.0.2.2"),
        ("full: lookup_failed keys on ASL TXT only",
         NodeDNSFull(1, DNSRecordSet(), DNSRecordSet(lookup_failed=True)).lookup_failed is False
         and NodeDNSFull(1, DNSRecordSet(lookup_failed=True), None).lookup_failed is True),
    ]
    # _record_set / check_node_dns_full with a fake resolver (exception mapping, short-circuits)
    global _resolve
    real = _resolve
    calls = []

    def fake_resolve(hostname, rtype, timeout):
        calls.append((hostname, rtype))
        table = {
            ("1.nodes.allstarlink.org", "TXT"): (['NN=1 IP=192.0.2.9 PT=4569'], False),
            ("1.nodes.allstarlink.org", "A"): (None, True),            # A query fails
            ("1.asl.hamvoip.org", "TXT"): (['radio@192.0.2.9:4569/1,192.0.2.9'], False),
            ("1.asl.hamvoip.org", "A"): (None, False),
            ("2.nodes.allstarlink.org", "TXT"): ("nxdomain", False),   # name absent: no A query
            ("2.asl.hamvoip.org", "TXT"): ("nxdomain", False),
            ("3.nodes.allstarlink.org", "TXT"): (None, True),          # TXT query fails
            ("4.nodes.allstarlink.org", "TXT"): (None, False),         # NoAnswer: name exists, try A
            ("4.nodes.allstarlink.org", "A"): (["192.0.2.4"], False),
            ("4.asl.hamvoip.org", "TXT"): (None, True),                # HamVoIP resolver fails
        }
        return table.get((hostname, rtype), (None, False))
    try:
        _resolve = fake_resolve
        r1 = check_node_dns_full(1)
        r2 = check_node_dns_full(2)
        r3 = check_node_dns_full(3)
        r4 = check_node_dns_full(4)
        r5 = check_node_dns_full(1, want_hamvoip=False)
    finally:
        _resolve = real
    checks += [
        ("full: TXT ok + A failed -> present, a_failed, NOT lookup_failed, HamVoIP looked up",
         r1.asl.present and r1.asl.a_failed and not r1.asl.lookup_failed and r1.asl.txt_port == 4569
         and r1.hamvoip is not None and r1.hamvoip.present and r1.hamvoip.txt_ip == "192.0.2.9"),
        ("full: NXDOMAIN -> absent, no A query sent",
         r2.asl.present is False and r2.hamvoip.present is False
         and ("2.nodes.allstarlink.org", "A") not in calls and ("2.asl.hamvoip.org", "A") not in calls),
        ("full: ASL TXT query failed -> lookup_failed, HamVoIP skipped (None)",
         r3.asl.lookup_failed and r3.hamvoip is None and r3.lookup_failed is True),
        ("full: NoAnswer TXT + A present -> NOT present (TXT is the fact), a_ips kept; HamVoIP failure isolated",
         r4.asl.present is False and r4.asl.a_ips == ["192.0.2.4"] and r4.hamvoip.lookup_failed is True
         and r4.lookup_failed is False),
        ("full: want_hamvoip=False -> hamvoip None, no HamVoIP query",
         r5.hamvoip is None and calls.count(("1.asl.hamvoip.org", "TXT")) == 1),
    ]
    bad = [name for name, ok in checks if not ok]
    print(f"dns_checker selftest: {len(checks) - len(bad)}/{len(checks)} passed"
          + (f" — FAILED: {bad}" if bad else ""))
    return 1 if bad else 0


def batch_check_nodes(node_ids: list[int], timeout: float = 5.0) -> dict[int, NodeDNSInfo]:
    """Check DNS registration for multiple nodes.

    Returns a dict mapping node_id -> NodeDNSInfo.
    """
    results = {}
    for node_id in node_ids:
        results[node_id] = check_node_dns(node_id, timeout=timeout)
    return results


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv or len(sys.argv) == 1:
        raise SystemExit(_selftest())
    for arg in sys.argv[1:]:            # ad-hoc: python3 dns_checker.py <node> [<node> ...]
        print(check_node_dns_full(int(arg)))
