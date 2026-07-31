"""PCAP parsing layer.

Reads ``.pcap`` / ``.pcapng`` files via Scapy, optionally applies a BPF
filter, and normalizes packets into lightweight :class:`PacketRecord` objects
so the analysis layer never depends on Scapy directly.
"""
from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from typing import Any, Iterator, Optional

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP


@dataclass(frozen=True)
class PacketRecord:
    """Normalized, Scapy-independent view of a single packet."""

    number: int
    timestamp: float
    length: int  # bytes on the wire (frame length)
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str  # normalized protocol label, see PROTO_LABELS
    flags: Optional[int]  # raw TCP flags byte, or None
    dns_qname: Optional[str]  # lowercased, no trailing dot
    http_request: Optional[str]  # raw HTTP request line, e.g. "GET /login HTTP/1.1"
    http_headers: Optional[dict[str, str]]  # lowercased header name -> value
    http_body: Optional[str]  # raw body text (best-effort decode)
    arp_psrc: Optional[str]  # sender protocol (IP) address for ARP packets
    arp_psmac: Optional[str]  # sender hardware (MAC) address for ARP packets
    is_arp_reply: bool = False


#: Normalized protocol labels. A packet may carry several markers (an HTTP
#: request travels inside TCP); the most specific label wins via
#: :func:`_normalize_proto`.
PROTO_LABELS = (
    "TLS",
    "HTTP",
    "DNS",
    "ARP",
    "ICMP",
    "TCP",
    "UDP",
)

#: Map a normalized protocol label to the BPF transport primitive it implies.
_PROTO_TRANSPORT = {
    "TCP": "tcp",
    "HTTP": "tcp",
    "TLS": "tcp",
    "UDP": "udp",
    "DNS": "udp",
    "ICMP": "icmp",
    "ARP": "arp",
}


def _normalize_proto(
    http_request: Optional[str],
    dns_qname: Optional[str],
    tls_client_hello: bool,
    is_arp: bool,
    ip_proto: int,
) -> str:
    """Map layer markers to one of :data:`PROTO_LABELS`.

    TCP/UDP are the fallback labels; higher-level protocols (HTTP, DNS, TLS)
    win when we can spot them in the payload.
    """
    if is_arp:
        return "ARP"
    if http_request is not None:
        return "HTTP"
    if dns_qname is not None:
        return "DNS"
    if tls_client_hello:
        return "TLS"
    if ip_proto == 1:
        return "ICMP"
    if ip_proto == 6:
        return "TCP"
    if ip_proto == 17:
        return "UDP"
    return f"IP[{ip_proto}]"


def _extract_http(
    payload: bytes,
) -> tuple[Optional[str], Optional[dict[str, str]], Optional[str]]:
    """Best-effort extraction of a request line / headers / body.

    Only handles the common case of a plaintext request
    (``METHOD SP path SP HTTP/x.y``). Chunked bodies, keep-alive framing,
    compression and responses are not parsed.
    """
    if not payload:
        return None, None, None
    head, sep, rest = payload.partition(b"\r\n\r\n")
    if not sep:
        head, rest = payload, b""
    head_text = head.decode("utf-8", errors="replace")
    lines = head_text.split("\r\n")
    request_line = lines[0] if lines else ""
    if not request_line.startswith(
        ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "TRACE ")
    ):
        return None, None, None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    body = rest.decode("utf-8", errors="replace") if rest else None
    return request_line, headers, body


def _to_record(pkt: Any, number: int) -> Optional[PacketRecord]:
    """Convert a Scapy packet object into a :class:`PacketRecord`.

    Returns ``None`` for packets with no IP/ARP layer (STP, LLDP, raw 802.11,
    ...) because we have nothing meaningful to say about those.
    """
    length = int(getattr(pkt, "len", 0) or 0)
    timestamp = float(getattr(pkt, "time", 0.0) or 0.0)

    arp = pkt.getlayer(ARP)
    if arp is not None:
        return PacketRecord(
            number=number,
            timestamp=timestamp,
            length=length,
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            proto="ARP",
            flags=None,
            dns_qname=None,
            http_request=None,
            http_headers=None,
            http_body=None,
            arp_psrc=str(arp.psrc),
            arp_psmac=str(arp.hwsrc).lower(),
            is_arp_reply=bool(arp.op == 2),
        )

    ip = pkt.getlayer(IP)
    if ip is None:
        return None

    src_ip = str(ip.src)
    dst_ip = str(ip.dst)
    ip_proto = int(ip.proto)

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: Optional[int] = None
    dns_qname: Optional[str] = None
    http_request: Optional[str] = None
    http_headers: Optional[dict[str, str]] = None
    http_body: Optional[str] = None
    tls_client_hello = False

    tcp = pkt.getlayer(TCP)
    if tcp is not None:
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        flags = int(tcp.flags)
        payload = bytes(tcp.payload)
        if payload:
            http_request, http_headers, http_body = _extract_http(payload)
            # TLS records start with content-type 0x16 (handshake) + version 0x03.
            tls_client_hello = payload.startswith(b"\x16\x03")

    udp = pkt.getlayer(UDP)
    if udp is not None:
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        dns = pkt.getlayer(DNS)
        if dns is not None and dns.qr == 0 and dns.qd is not None:
            qname = getattr(dns.qd, "qname", None)
            if qname:
                # Scapy stores qname as bytes (e.g. b'www.example.com.').
                if isinstance(qname, bytes):
                    qname = qname.decode("ascii", errors="replace")
                dns_qname = str(qname).rstrip(".").lower()

    proto = _normalize_proto(
        http_request=http_request,
        dns_qname=dns_qname,
        tls_client_hello=tls_client_hello,
        is_arp=False,
        ip_proto=ip_proto,
    )

    return PacketRecord(
        number=number,
        timestamp=timestamp,
        length=length,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        flags=flags,
        dns_qname=dns_qname,
        http_request=http_request,
        http_headers=http_headers,
        http_body=http_body,
        arp_psrc=None,
        arp_psmac=None,
        is_arp_reply=False,
    )


# BPF-style filter engine (self-contained, no libpcap/Npcap required)
# Implements a practical tcpdump-subset over our normalized PacketRecord:
#
#   proto primitives:   tcp | udp | icmp | arp | ip
#   address primitives: [src|dst] host <ip>
#                       [src|dst] net <ip/cidr>
#                       [src|dst] port <port>
#                       [src|dst] portrange <lo>-<hi>
#   combinators:        and | or | not  (parenthesized groups allowed)
#
# Example filters: "tcp port 443", "host 10.0.0.5", "src net 192.168.0.0/16",
# "udp port 53 and not src host 8.8.8.8".
#
# Unsupported: ethernet-level primitives (ether host/ether proto), VLAN,
# IPv6 addresses, and the full libpcap language. The subset is applied to
# PacketRecord fields so it works on any platform without Npcap.

_TOKEN_PATTERN = re.compile(
    r"""
    (?P<ws>\s+)|
    (?P<lparen>\()|
    (?P<rparen>\))|
    (?P<and>\band\b|&&)|
    (?P<or>\bor\b|\|\|)|
    (?P<not>\bnot\b|!)|
    (?P<src>\bsrc\b)|
    (?P<dst>\bdst\b)|
    (?P<host>\bhost\b)|
    (?P<net>\bnet\b)|
    (?P<port>\bport\b)|
    (?P<portrange>\bportrange\b)|
    (?P<proto>\b(?:tcp|udp|icmp|arp|ip|ip6|ether)\b)|
    (?P<dash>-)|
    (?P<cidr>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})|
    (?P<addr>\d{1,3}(?:\.\d{1,3}){3})|
    (?P<number>\d{1,5})
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _tokenize(filter_str: str) -> list[tuple[str, str]]:
    """Split a filter string into (kind, value) tokens."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(filter_str):
        match = _TOKEN_PATTERN.match(filter_str, pos)
        if match is None:
            raise ValueError(
                f"unexpected character {filter_str[pos]!r} in BPF filter"
            )
        pos = match.end()
        kind = match.lastgroup
        assert kind is not None
        if kind == "ws":
            continue
        tokens.append((kind, match.group()))
    return tokens


def _and(left: Callable[[PacketRecord], bool], right: Callable[[PacketRecord], bool]) -> Callable[[PacketRecord], bool]:
    return lambda rec: left(rec) and right(rec)


def _or(left: Callable[[PacketRecord], bool], right: Callable[[PacketRecord], bool]) -> Callable[[PacketRecord], bool]:
    return lambda rec: left(rec) or right(rec)


def _not(pred: Callable[[PacketRecord], bool]) -> Callable[[PacketRecord], bool]:
    return lambda rec: not pred(rec)


def _proto_pred(proto: str) -> Callable[[PacketRecord], bool]:
    """Predicate for a transport primitive (tcp/udp/icmp/arp/ip)."""
    if proto == "arp":
        return lambda rec: rec.proto == "ARP"
    if proto == "ip":
        return lambda rec: rec.src_ip is not None
    return lambda rec: _PROTO_TRANSPORT.get(rec.proto) == proto


def _ip_matches(rec: PacketRecord, addr: str) -> bool:
    return rec.src_ip == addr or rec.dst_ip == addr


def _host_pred(qualifier: Optional[str], addr: str) -> Callable[[PacketRecord], bool]:
    if qualifier == "src":
        return lambda rec: rec.src_ip == addr
    if qualifier == "dst":
        return lambda rec: rec.dst_ip == addr
    return lambda rec: _ip_matches(rec, addr)


def _net_pred(qualifier: Optional[str], net: IPv4Network) -> Callable[[PacketRecord], bool]:
    def _addr_in(ip: Optional[str]) -> bool:
        if ip is None:
            return False
        try:
            return IPv4Address(ip) in net
        except AddressValueError:
            return False

    if qualifier == "src":
        return lambda rec: _addr_in(rec.src_ip)
    if qualifier == "dst":
        return lambda rec: _addr_in(rec.dst_ip)
    return lambda rec: _addr_in(rec.src_ip) or _addr_in(rec.dst_ip)


def _port_pred(qualifier: Optional[str], port: int) -> Callable[[PacketRecord], bool]:
    if qualifier == "src":
        return lambda rec: rec.src_port == port
    if qualifier == "dst":
        return lambda rec: rec.dst_port == port
    return lambda rec: rec.src_port == port or rec.dst_port == port


def _portrange_pred(qualifier: Optional[str], lo: int, hi: int) -> Callable[[PacketRecord], bool]:
    def _in_range(port: Optional[int]) -> bool:
        return port is not None and lo <= port <= hi

    if qualifier == "src":
        return lambda rec: _in_range(rec.src_port)
    if qualifier == "dst":
        return lambda rec: _in_range(rec.dst_port)
    return lambda rec: _in_range(rec.src_port) or _in_range(rec.dst_port)


def _check_port(value: int) -> int:
    if not 1 <= value <= 65535:
        raise ValueError(f"invalid port number {value} in BPF filter")
    return value


class _BpfParser:
    """Recursive-descent parser for the filter subset."""

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[tuple[str, str]]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def advance(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise ValueError("unexpected end of BPF filter")
        self.pos += 1
        return tok

    def expect(self, kind: str) -> tuple[str, str]:
        tok = self.advance()
        if tok[0] != kind:
            raise ValueError(
                f"expected {kind!r} but found {tok[1]!r} in BPF filter"
            )
        return tok

    def parse(self) -> Callable[[PacketRecord], bool]:
        pred = self.parse_or()
        if self.peek() is not None:
            raise ValueError(
                f"unexpected token {self.peek()[1]!r} in BPF filter"
            )
        return pred

    def parse_or(self) -> Callable[[PacketRecord], bool]:
        left = self.parse_and()
        while self.peek() is not None and self.peek()[0] == "or":
            self.advance()
            left = _or(left, self.parse_and())
        return left

    def parse_and(self) -> Callable[[PacketRecord], bool]:
        left = self.parse_unary()
        while self.peek() is not None and self.peek()[0] == "and":
            self.advance()
            left = _and(left, self.parse_unary())
        return left

    def parse_unary(self) -> Callable[[PacketRecord], bool]:
        tok = self.peek()
        if tok is None:
            raise ValueError("unexpected end of BPF filter")
        if tok[0] == "not":
            self.advance()
            return _not(self.parse_unary())
        if tok[0] == "lparen":
            self.advance()
            inner = self.parse_or()
            self.expect("rparen")
            return inner
        return self.parse_atom()

    def parse_atom(self) -> Callable[[PacketRecord], bool]:
        tok = self.peek()
        if tok is None:
            raise ValueError("unexpected end of BPF filter")
        if tok[0] == "proto":
            proto = self.advance()[1]
            if proto in ("ip6", "ether"):
                raise ValueError(
                    f"unsupported BPF primitive {proto!r} "
                    "(this tool supports the IPv4 subset: tcp/udp/icmp/arp/ip)"
                )
            pred = _proto_pred(proto)
            nxt = self.peek()
            if nxt is not None and nxt[0] in ("src", "dst", "host", "net", "port", "portrange"):
                _, prim_pred = self.parse_directed_primitive()
                return _and(pred, prim_pred)
            return pred
        _, prim_pred = self.parse_directed_primitive()
        return prim_pred

    def parse_directed_primitive(self) -> tuple[Optional[str], Callable[[PacketRecord], bool]]:
        qualifier: Optional[str] = None
        tok = self.peek()
        if tok is not None and tok[0] in ("src", "dst"):
            qualifier = self.advance()[1]
        tok = self.peek()
        if tok is None:
            raise ValueError("unexpected end of BPF filter")
        kind, _ = tok
        if kind == "host":
            self.advance()
            addr = self.expect("addr")[1]
            try:
                IPv4Address(addr)
            except AddressValueError as exc:
                raise ValueError(f"invalid IPv4 address {addr!r} in BPF filter") from exc
            return qualifier, _host_pred(qualifier, addr)
        if kind == "net":
            self.advance()
            net_tok = self.advance()
            try:
                if net_tok[0] == "cidr":
                    net = IPv4Network(net_tok[1], strict=False)
                elif net_tok[0] == "addr":
                    net = IPv4Network(f"{net_tok[1]}/32", strict=False)
                else:
                    raise ValueError(
                        f"expected address/CIDR after 'net' but found "
                        f"{net_tok[1]!r} in BPF filter"
                    )
            except (AddressValueError, ValueError) as exc:
                raise ValueError(f"invalid network {net_tok[1]!r} in BPF filter") from exc
            return qualifier, _net_pred(qualifier, net)
        if kind == "port":
            self.advance()
            port = _check_port(int(self.expect("number")[1]))
            return qualifier, _port_pred(qualifier, port)
        if kind == "portrange":
            self.advance()
            lo = _check_port(int(self.expect("number")[1]))
            self.expect("dash")
            hi = _check_port(int(self.expect("number")[1]))
            if lo > hi:
                raise ValueError(f"portrange {lo}-{hi} is inverted in BPF filter")
            return qualifier, _portrange_pred(qualifier, lo, hi)
        raise ValueError(
            f"expected host/net/port/portrange primitive but found "
            f"{tok[1]!r} in BPF filter"
        )


def compile_bpf_filter(filter_str: str) -> Callable[[PacketRecord], bool]:
    """Compile a BPF-style filter string into a predicate over PacketRecord.

    Supports a practical tcpdump subset (host/net/port/portrange with
    optional src/dst qualifiers, tcp/udp/icmp/arp/ip primitives, and
    and/or/not combinators). Evaluates over our normalized records, so no
    libpcap/Npcap is required.

    Raises:
        ValueError: If the filter cannot be parsed or references unsupported
            syntax (IPv6, ethernet primitives, ...).
    """
    try:
        tokens = _tokenize(filter_str)
        return _BpfParser(tokens).parse()
    except ValueError as exc:
        raise ValueError(f"invalid BPF filter {filter_str!r}: {exc}") from exc


def _load_packets(path: str, bpf_filter: Optional[str]) -> Iterator[PacketRecord]:
    """Stream packets from a capture file, yielding :class:`PacketRecord`."""
    try:
        # Modern Scapy (>= 2.5) auto-detects classic pcap and pcapng.
        from scapy.utils import PcapReader
    except ImportError:  # pragma: no cover - older Scapy layout
        from scapy.utils.pcap import PcapReader  # type: ignore[no-redef]

    reader: Any = PcapReader(path)
    compile_filter = compile_bpf_filter(bpf_filter) if bpf_filter else None

    number = 0
    while True:
        try:
            pkt = reader.read_packet()
        except EOFError:
            break
        except Exception:
            # Skip corrupt / truncated records instead of aborting the run.
            number += 1
            continue
        if pkt is None:
            # End of stream: scapy's PcapReader returns None at EOF.
            break
        number += 1
        record = _to_record(pkt, number)
        if record is None:
            continue
        if compile_filter is not None and not compile_filter(record):
            continue
        yield record


def parse_capture(path: str, bpf_filter: Optional[str] = None) -> list[PacketRecord]:
    """Parse a capture file into a list of :class:`PacketRecord`.

    Args:
        path: Path to a ``.pcap`` or ``.pcapng`` file.
        bpf_filter: Optional BPF filter string applied while reading.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: If the file cannot be opened as a packet capture.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"capture file not found: {path}")
    try:
        return list(_load_packets(path, bpf_filter))
    except Exception as exc:
        raise ValueError(f"unable to parse capture file {path!r}: {exc}") from exc