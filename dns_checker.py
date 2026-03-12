"""DNS-based node registration checker for AllStarLink.

AllStarLink nodes register via IAX2 and their registration is published
as DNS TXT records at <node>.nodes.allstarlink.org. The DNS record is
updated within ~60 seconds of registration and has a TTL of 60 seconds.

A node with an active TXT record is confirmed to be online and actively
registering with AllStarLink — a much stronger freshness signal than
the stats API's regseconds field, which can lag by up to ~60 minutes.

A node with NO TXT record is either offline, unregistered, or nonexistent.
"""

import logging
from dataclasses import dataclass
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

    def __str__(self):
        if self.is_registered:
            return f"Node {self.node_id}: registered at {self.ip_address}:{self.port}"
        return f"Node {self.node_id}: NOT registered (offline or nonexistent)"


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

        # Parse TXT record fields: "NN=68822" "IP=172.56.91.138" "PT=4569"
        fields = {}
        for rdata in answers:
            for s in rdata.strings:
                text = s.decode("utf-8", errors="replace")
                if "=" in text:
                    key, _, value = text.partition("=")
                    fields[key.strip()] = value.strip()

        ip = fields.get("IP")
        port_str = fields.get("PT")
        port = int(port_str) if port_str else None

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
        return NodeDNSInfo(node_id=node_id, is_registered=False)
    except Exception as e:
        logger.warning(f"DNS lookup error for {hostname}: {e}")
        return NodeDNSInfo(node_id=node_id, is_registered=False)


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

        # Parse: "NN=68822" "IP=172.56.91.138" "PT=4569"
        fields = {}
        for part in output.replace('"', '').split():
            if "=" in part:
                key, _, value = part.partition("=")
                fields[key.strip()] = value.strip()

        ip = fields.get("IP")
        port_str = fields.get("PT")
        port = int(port_str) if port_str else None

        logger.debug(f"DNS (dig): {hostname} -> IP={ip}, PT={port}")
        return NodeDNSInfo(node_id=node_id, is_registered=True,
                           ip_address=ip, port=port)

    except subprocess.TimeoutExpired:
        logger.warning(f"DNS (dig): {hostname} -> timeout")
        return NodeDNSInfo(node_id=node_id, is_registered=False)
    except FileNotFoundError:
        logger.error("dig command not found — install dnsutils/bind-tools or pip install dnspython")
        return NodeDNSInfo(node_id=node_id, is_registered=False)
    except Exception as e:
        logger.warning(f"DNS (dig) error for {hostname}: {e}")
        return NodeDNSInfo(node_id=node_id, is_registered=False)


def batch_check_nodes(node_ids: list[int], timeout: float = 5.0) -> dict[int, NodeDNSInfo]:
    """Check DNS registration for multiple nodes.

    Returns a dict mapping node_id -> NodeDNSInfo.
    """
    results = {}
    for node_id in node_ids:
        results[node_id] = check_node_dns(node_id, timeout=timeout)
    return results
