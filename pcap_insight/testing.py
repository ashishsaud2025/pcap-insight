"""Synthetic capture builder for tests and README demos.

Generates a small, self-contained PCAP file (no real internet traffic) that
exercises every analysis section: HTTP with plaintext credentials, DNS queries
(one high-entropy), TLS ClientHello, a SYN-scan-like burst, a normal TCP
handshake, ARP replies with a spoofed duplicate, and ICMP.

Used by ``tests/`` as a session fixture, and by the README ``--demo`` command.
Intentionally lives inside the package (rather than ``tests/``) so the CLI can
import it without test-only paths on the user's ``sys.path``.
"""
from __future__ import annotations

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap
from scapy.packet import Packet

#: IPs used by the scenario, exported so tests/README can reference them.
HTTP_TARGET = "93.184.216.34"
SCAN_SOURCE = "10.0.0.50"
SPOOFED_IP = "192.168.1.1"


def build_capture(path: str) -> list[Packet]:
    """Write a deterministic synthetic capture to ``path`` and return its packets."""
    packets: list[Packet] = []

    # 1. Plaintext HTTP POST with Basic Authorization + form password 
    http_payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Authorization: Basic dXNlcjpwYXNz\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"username=jdoe&password=secret123"
    )
    packets.append(
        Ether()
        / IP(src="10.0.0.2", dst=HTTP_TARGET)
        / TCP(sport=50000, dport=80, flags="PA")
        / Raw(load=http_payload)
    )

    # 2. DNS queries: normal, then a high-entropy tunneling-style one 
    packets.append(
        Ether()
        / IP(src="10.0.0.2", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(qr=0, qd=DNSQR(qname="www.example.com."))
    )
    packets.append(
        Ether()
        / IP(src="10.0.0.2", dst="8.8.8.8")
        / UDP(sport=53001, dport=53)
        / DNS(qr=0, qd=DNSQR(qname="a1b2c3d4e5f6a7b8c9d0e1f2.example.com."))
    )

    # 3. TLS ClientHellos both directions 
    packets.append(
        Ether()
        / IP(src="10.0.0.2", dst=HTTP_TARGET)
        / TCP(sport=50001, dport=443, flags="PA")
        / Raw(load=b"\x16\x03\x01" + b"\x00" * 20)
    )
    packets.append(
        Ether()
        / IP(src=HTTP_TARGET, dst="10.0.0.2")
        / TCP(sport=443, dport=50001, flags="PA")
        / Raw(load=b"\x16\x03\x03" + b"\x00" * 20)
    )

    # 4. SYN-scan-like burst (15 bare SYNs, no replies), and one normal
    #    handshake from a different host so the detector isn't the only source 
    for i in range(15):
        packets.append(
            Ether()
            / IP(src=SCAN_SOURCE, dst="10.0.0.1")
            / TCP(sport=40000 + i, dport=1024 + i, flags="S")
        )
    packets.append(
        Ether() / IP(src="10.0.0.60", dst="10.0.0.61") / TCP(sport=42000, dport=80, flags="S")
    )
    packets.append(
        Ether() / IP(src="10.0.0.61", dst="10.0.0.60") / TCP(sport=80, dport=42000, flags="SA")
    )
    packets.append(
        Ether() / IP(src="10.0.0.60", dst="10.0.0.61") / TCP(sport=42000, dport=80, flags="A")
    )

    # 5. ARP: one request + two replies for the same IP with different MACs 
    #    (Ethernet dst is set explicitly so Scapy doesn't warn about the
    #    "is-at" replies lacking a destination MAC.)
    packets.append(
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, psrc="192.168.1.5", hwsrc="aa:bb:cc:dd:ee:02", pdst=SPOOFED_IP)
    )
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:02")
        / ARP(op=2, psrc=SPOOFED_IP, hwsrc="aa:bb:cc:dd:ee:01", pdst="192.168.1.5")
    )
    packets.append(
        Ether(dst="aa:bb:cc:dd:ee:02")
        / ARP(op=2, psrc=SPOOFED_IP, hwsrc="aa:bb:cc:dd:ee:ff", pdst="192.168.1.5")
    )

    # 6. ICMP ping 
    packets.append(
        Ether() / IP(src="10.0.0.2", dst="10.0.0.99") / ICMP()
    )

    # Spread timestamps across 13 seconds so the duration stat is meaningful.
    for i, pkt in enumerate(packets):
        pkt.time = 1_700_000_000.0 + i * 0.5

    wrpcap(path, packets)
    return packets