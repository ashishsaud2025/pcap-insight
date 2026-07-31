"""Analysis layer.

Pure functions over :class:`~pcap_insight.parser.PacketRecord` lists: summary
stats, protocol breakdown, top talkers/ports, and the four suspicious-pattern
heuristics. No Scapy or I/O here; everything is unit-testable with plain
synthetic records.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

import socket

from .parser import PacketRecord

# Constants / thresholds

#: Shannon-entropy threshold for DNS subdomains (start value, tuned loosely).
DNS_ENTROPY_THRESHOLD = 3.5

#: Minimum number of SYNs before a syn-scan candidate is reported.
SYN_SCAN_MIN_SYNS = 10

#: A "suspiciously long" subdomain is one that is this many chars longer than
#: the registered domain it hangs off. Normal random-looking-but-benign labels
#: (CDN hostnames, `crypto`, `sjc1-xxxx` style names, tracking params) can
#: exceed this, which is exactly why this is a *flag*, not a block.
SUBNAME_PADDING = 20

#: Common-service fallback when :func:`socket.getservbyport` fails.
COMMON_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    123: "ntp",
    135: "epmap",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "ms-sql-s",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongod",
}


# Data structures
@dataclass
class ProtocolStat:
    """One row of the protocol breakdown table."""

    protocol: str
    count: int
    percent: float


@dataclass
class TalkerStat:
    """One row of the top-talkers tables."""

    src: str
    dst: str
    value: int  # packet count, or bytes


@dataclass
class PortStat:
    """One row of the top-ports table."""

    port: int
    count: int
    service: str  # best-effort service name


@dataclass
class Finding:
    """A single suspicious-pattern finding."""

    type: str  # stable machine id, e.g. "plaintext-credentials"
    severity: str  # "info" | "medium" | "high"
    summary: str  # one-line human summary
    details: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Everything produced by a full analysis run."""

    total_packets: int = 0
    duration_seconds: float = 0.0
    total_bytes: int = 0
    avg_packet_size: float = 0.0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    protocols: list[ProtocolStat] = field(default_factory=list)
    top_talkers_by_count: list[TalkerStat] = field(default_factory=list)
    top_talkers_by_bytes: list[TalkerStat] = field(default_factory=list)
    top_ports: list[PortStat] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


# Summary
def summarize(records: Iterable[PacketRecord]) -> AnalysisResult:
    """Compute the summary + all sections from a list of packet records."""
    recs = list(records)
    result = AnalysisResult()
    result.total_packets = len(recs)
    result.total_bytes = sum(r.length for r in recs)
    result.avg_packet_size = (
        result.total_bytes / result.total_packets if result.total_packets else 0.0
    )

    timestamps = [r.timestamp for r in recs if r.timestamp > 0]
    if timestamps:
        result.start_time = min(timestamps)
        result.end_time = max(timestamps)
        result.duration_seconds = result.end_time - result.start_time

    result.protocols = protocol_breakdown(recs)
    result.top_talkers_by_count = top_talkers(recs, by_bytes=False)
    result.top_talkers_by_bytes = top_talkers(recs, by_bytes=True)
    result.top_ports = top_ports(recs)
    result.findings = detect_suspicious(recs)
    return result


# Section builders
def protocol_breakdown(records: Iterable[PacketRecord]) -> list[ProtocolStat]:
    """Count packets per protocol label, sorted descending by count.

    Percentages are relative to the total number of records passed in.
    """
    recs = list(records)
    total = len(recs)
    counts = Counter(r.proto for r in recs)
    stats = [
        ProtocolStat(protocol=proto, count=count, percent=(count / total * 100) if total else 0.0)
        for proto, count in counts.most_common()
    ]
    return stats


def top_talkers(records: Iterable[PacketRecord], by_bytes: bool = False, limit: int = 10) -> list[TalkerStat]:
    """Top ``limit`` source/destination IP pairs by packet count or byte volume."""
    totals: Counter[tuple[str, str]] = Counter()
    for rec in records:
        if rec.src_ip is None or rec.dst_ip is None:
            continue
        key = (rec.src_ip, rec.dst_ip)
        totals[key] += rec.length if by_bytes else 1
    return [TalkerStat(src=s, dst=d, value=v) for (s, d), v in totals.most_common(limit)]


def top_ports(records: Iterable[PacketRecord], limit: int = 10) -> list[PortStat]:
    """Most frequently used destination ports, with best-effort service names."""
    counts: Counter[int] = Counter()
    for rec in records:
        if rec.dst_port is not None:
            counts[rec.dst_port] += 1
    stats: list[PortStat] = []
    for port, count in counts.most_common(limit):
        stats.append(PortStat(port=port, count=count, service=service_name(port)))
    return stats


def service_name(port: int) -> str:
    """Best-effort mapping from port number to a service name."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


# Suspicious-pattern detectors
def detect_suspicious(records: Iterable[PacketRecord]) -> list[Finding]:
    """Run every heuristic detector and return aggregated findings.

    Each detector is intentionally independent of the others.
    """
    recs = list(records)
    findings: list[Finding] = []
    findings.extend(_detect_plaintext_credentials(recs))
    findings.extend(_detect_syn_scan(recs))
    findings.extend(_detect_dns_tunneling(recs))
    findings.extend(_detect_arp_spoofing(recs))
    return findings


# 1. Plaintext credentials over HTTP 

_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?:pass|pwd|password|passwd|user[_-]?pass|client[_-]?secret)="
)
_AUTH_HEADER = re.compile(r"(?i)^basic\s+")


def _detect_plaintext_credentials(records: list[PacketRecord]) -> list[Finding]:
    """Look for Authorization headers or ``...pass...=`` form fields in plaintext HTTP."""
    hits: list[str] = []
    for rec in records:
        if rec.http_request is None:
            continue
        when = f"packet #{rec.number}"
        headers = rec.http_headers or {}
        auth = headers.get("authorization", "")
        if _AUTH_HEADER.match(auth):
            hits.append(
                f"[{when}] {rec.src_ip} -> {rec.dst_ip}: "
                f"HTTP Basic Authorization header ({rec.http_request.splitlines()[0] if rec.http_request else rec.http_request})"
            )
            continue
        body = rec.http_body or ""
        if _CREDENTIAL_PATTERN.search(body):
            clipped = body.strip().replace("\n", " ")[:120]
            hits.append(
                f"[{when}] {rec.src_ip} -> {rec.dst_ip}: "
                f"possible credential field in request body ({rec.http_request.splitlines()[0] if rec.http_request else rec.http_request}): {clipped}"
            )
    if not hits:
        return []
    return [
        Finding(
            type="plaintext-credentials",
            severity="high",
            summary=f"{len(hits)} plaintext credential exposure(s) in HTTP traffic",
            details=hits,
        )
    ]


# 2. SYN scan 

_SYN_ACK_FLAG = 0x12  # SYN + ACK


def _detect_syn_scan(records: list[PacketRecord], min_syns: int = SYN_SCAN_MIN_SYNS) -> list[Finding]:
    """Flag sources emitting many SYNs with few/no corresponding SYN-ACKs.

    A single source sweeping many ports or hosts with bare SYNs and never
    completing a handshake is a common port-scan signature.
    """
    syn_counts: Counter[str] = Counter()
    for rec in records:
        if rec.flags is not None and rec.flags & 0x02 and not (rec.flags & 0x10):
            syn_counts[rec.src_ip or "?"] += 1

    syn_ack_counts: Counter[str] = Counter()
    for rec in records:
        if rec.flags is not None and rec.flags & _SYN_ACK_FLAG == _SYN_ACK_FLAG:
            syn_ack_counts[rec.dst_ip or "?"] += 1

    hits: list[str] = []
    for src, count in syn_counts.most_common():
        if count < min_syns:
            continue
        got_back = syn_ack_counts.get(src, 0)
        if got_back >= count / 2:
            # Lots of SYNs but the target answered a good chunk of them. This
            # looks more like legitimate behavior than a scan.
            continue
        hits.append(
            f"{src}: {count} SYN(s) sent, only {got_back} SYN-ACK(s) observed in return"
        )

    if not hits:
        return []
    return [
        Finding(
            type="syn-scan",
            severity="medium",
            summary=f"{len(hits)} source(s) with many unanswered SYN packets (possible port scan)",
            details=hits,
        )
    ]


# 3. DNS tunneling / C2 beaconing 

#: Small public-suffix list. Includes multi-label entries (``co.uk``) so the
#: registrable-domain splitter can find the *longest* matching suffix. This
#: is deliberately not the full PSL; see the README's caveats.
_PUBLIC_SUFFIXES = frozenset(
    {
        # Generic single-label
        "com", "net", "org", "io", "info", "biz", "xyz", "top", "cc", "tv",
        "me", "mobi", "pro", "cloud", "app", "dev", "site", "online", "tech",
        "store", "blog", "news", "name", "link", "club", "live", "work",
        "shop", "city", "media", "network", "agency", "design", "guide",
        "world", "services", "email", "games", "group", "health", "host",
        "page", "plus", "space", "systems", "web", "website", "wiki", "zone",
        "ai", "guru",
        # Country codes
        "us", "de", "fr", "ru", "cn", "jp", "br", "in", "ca", "au",
        # Multi-label (common registrars / hosting)
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
        "co.jp", "com.br", "com.cn", "net.cn", "co.in", "co.nz", "com.mx",
    }
)

#: Managed cloud zones: providers control the label directly above the zone
#: (e.g. ``<region>.amazonaws.com`` or ``<distribution>.cloudfront.net`), so for
#: the DNS-tunneling heuristic we fold that label into the "registrable" view.
#: Otherwise ``codewhisperer.us-east-1.amazonaws.com`` would look like a random
#: subdomain of ``amazonaws.com`` and false-positive on every AWS service.
#: Each entry is ``(zone-suffix, extra-labels-to-keep-above-it)``.
_MANAGED_ZONES: tuple[tuple[str, int], ...] = (
    ("amazonaws.com", 1),
    ("cloudfront.net", 1),
    ("azurewebsites.net", 1),
    ("azureedge.net", 1),
    ("googleapis.com", 1),
    ("fastly.net", 1),
    # Microsoft operates shared platform zones (e.g. data.microsoft.com is the
    # canonical telemetry endpoint); mobile.events.data.microsoft.com is a
    # legitimate host, not random <label>.data.microsoft.com tunneling.
    ("microsoft.com", 1),
    ("microsoftonline.com", 1),
)


def _subdomain_component(qname: str) -> tuple[str, Optional[str]]:
    """Split a qname into (subdomain, registered-domain).

    Uses a small internal public-suffix list so ``a.b.example.com`` splits as
    subdomain ``a.b`` + registrable domain ``example.com``. Multi-label
    suffixes (``example.co.uk``) are matched by longest-suffix.
    """
    labels = qname.rstrip(".").split(".")
    if len(labels) < 2:
        return qname, None

    # Managed cloud zones take priority: the provider controls the label above
    # the zone (e.g. ``<region>.amazonaws.com``, ``<rand>.cloudfront.net``), so
    # we fold it into the "registrable" view. Otherwise ``codewhisperer.us-east-1
    # .amazonaws.com`` would be split at the generic `com` suffix and look like a
    # random subdomain of ``amazonaws.com``, which would false-positive on every
    # AWS service.
    for zone, extra in _MANAGED_ZONES:
        zone_labels = zone.split(".")
        if (
            len(labels) >= len(zone_labels) + extra
            and labels[-len(zone_labels) :] == zone_labels
        ):
            keep = len(zone_labels) + extra
            registrable = ".".join(labels[-keep:])
            subdomain = ".".join(labels[:-keep])
            return subdomain, registrable

    # Find the longest public suffix at the *end* of the labels, then take
    # exactly one label above it as the registrable domain.
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in _PUBLIC_SUFFIXES and i > 0:
            registrable = ".".join(labels[i - 1 :])
            subdomain = ".".join(labels[: i - 1])
            return subdomain, registrable

    # No public suffix matched: assume the last two labels are registrable.
    registrable = ".".join(labels[-2:])
    subdomain = ".".join(labels[:-2])
    return subdomain, registrable


def shannon_entropy(text: str) -> float:
    """Shannon entropy (in bits) of a string, ``0`` for empty input."""
    if not text:
        return 0.0
    length = len(text)
    counts: Counter[str] = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _detect_dns_tunneling(
    records: list[PacketRecord],
    entropy_threshold: float = DNS_ENTROPY_THRESHOLD,
    min_length: int = 18,
) -> list[Finding]:
    """Flag DNS queries with high-entropy or overly long subdomains.

    Both length and entropy are computed on the *subdomain* (the part before
    the registrable domain), because a stream of ``<random>.<random>.example.com``
    labels is the classic tunneling / C2 signature. IPv4/IPv6 literals and
    reversed-PTR names are excluded deliberately, even though they can have
    high entropy, since they're routine infrastructure (e.g. ``x.x.x.x.in-addr.arpa``).
    """
    hits: list[str] = []
    seen_qnames: set[str] = set()
    for rec in records:
        qname = rec.dns_qname
        if not qname:
            continue
        # Report each *unique* qname once. Repeated queries are normal (cache
        # misses, retries), and flagging every retry adds noise.
        if qname in seen_qnames:
            continue
        seen_qnames.add(qname)
        if qname.endswith(".in-addr.arpa") or qname.endswith(".ip6.arpa"):
            continue
        if _looks_like_ip_literal(qname):
            continue
        sub, _ = _subdomain_component(qname)
        if not sub:
            continue
        entropy = shannon_entropy(sub)
        if entropy > entropy_threshold and len(sub) >= min_length:
            hits.append(
                f"{qname} (subdomain {sub!r}, len={len(sub)}, entropy={entropy:.2f}, "
                f"packet #{rec.number})"
            )
            continue
        # Long subdomains, even with modest entropy, can indicate base64/hex
        # data streams. Flag the *padding* over a normal label.
        if len(sub) > min_length + SUBNAME_PADDING:
            hits.append(
                f"{qname} (unusually long subdomain {sub!r}, len={len(sub)}, "
                f"packet #{rec.number})"
            )
    if not hits:
        return []
    return [
        Finding(
            type="dns-tunneling-candidate",
            severity="medium",
            summary=(
                f"{len(hits)} DNS quer(ies) with high-entropy or long subdomains "
                f"(threshold entropy>{entropy_threshold} & len>={min_length})"
            ),
            details=hits,
        )
    ]


_HEX_CHARS = set("0123456789abcdef")


def _looks_like_ip_literal(qname: str) -> bool:
    """Best-effort rejection of reversed/hex-encoded IP-literal DNS names."""
    labels = qname.split(".")
    return any(all(c in _HEX_CHARS for c in label) and len(label) == 4 for label in labels[:4])


# 4. ARP spoofing 
def _detect_arp_spoofing(records: list[PacketRecord]) -> list[Finding]:
    """Flag IPs that are claimed by more than one MAC in ARP replies."""
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    for rec in records:
        if rec.is_arp_reply and rec.arp_psrc:
            ip_to_macs[rec.arp_psrc].add(rec.arp_psmac or "?")
    hits: list[str] = []
    for ip, macs in sorted(ip_to_macs.items()):
        if len(macs) > 1:
            hits.append(f"{ip} claimed by MACs: {', '.join(sorted(macs))}")
    if not hits:
        return []
    return [
        Finding(
            type="arp-spoofing-candidate",
            severity="medium",
            summary=f"{len(hits)} IP(s) mapped to multiple MAC addresses in ARP replies",
            details=hits,
        )
    ]


# Export
def _epoch_to_iso(epoch: Optional[float]) -> Optional[str]:
    """Convert an epoch-seconds value to an ISO-8601 UTC string."""
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f+00:00")


def analysis_result_to_dict(result: AnalysisResult) -> dict[str, object]:
    """Serialize an :class:`AnalysisResult` into a JSON-friendly dict."""
    return {
        "summary": {
            "total_packets": result.total_packets,
            "duration_seconds": round(result.duration_seconds, 6),
            "total_bytes": result.total_bytes,
            "avg_packet_size": round(result.avg_packet_size, 2),
            # Epoch seconds of the first/last packet (local capture machine
            # wall clock). pcap files don't store a capture-level clock.
            "start_time": result.start_time,
            "end_time": result.end_time,
            # Same values as readable UTC strings.
            "start_time_utc": _epoch_to_iso(result.start_time),
            "end_time_utc": _epoch_to_iso(result.end_time),
        },
        "protocols": [
            {
                "protocol": p.protocol,
                "count": p.count,
                "percent": round(p.percent, 2),
            }
            for p in result.protocols
        ],
        "top_talkers_by_packets": [
            {"src": t.src, "dst": t.dst, "packets": t.value}
            for t in result.top_talkers_by_count
        ],
        "top_talkers_by_bytes": [
            {"src": t.src, "dst": t.dst, "bytes": t.value}
            for t in result.top_talkers_by_bytes
        ],
        "top_ports": [
            {"port": p.port, "count": p.count, "service": p.service}
            for p in result.top_ports
        ],
        "suspicious_findings": [
            {
                "type": f.type,
                "severity": f.severity,
                "summary": f.summary,
                "details": f.details,
            }
            for f in result.findings
        ],
    }