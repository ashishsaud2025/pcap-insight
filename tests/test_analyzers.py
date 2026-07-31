"""Unit tests for analyzers: entropy, protocol counting, top talkers/ports,
and all four suspicious-pattern detectors. Uses plain synthetic PacketRecords
(no Scapy needed in most tests) plus the shared synthetic capture fixture.
"""
from __future__ import annotations

import math
from typing import Optional

import pytest

from pcap_insight.analyzers import (
    _detect_arp_spoofing,
    _detect_dns_tunneling,
    _detect_plaintext_credentials,
    _detect_syn_scan,
    protocol_breakdown,
    service_name,
    shannon_entropy,
    summarize,
    top_ports,
    top_talkers,
)
from pcap_insight.parser import PacketRecord


def make_record(
    number: int = 1,
    proto: str = "TCP",
    src_ip: Optional[str] = "10.0.0.1",
    dst_ip: Optional[str] = "10.0.0.2",
    length: int = 100,
    timestamp: float = 1000.0,
    flags: Optional[int] = None,
    dns_qname: Optional[str] = None,
    http_request: Optional[str] = None,
    http_headers: Optional[dict[str, str]] = None,
    http_body: Optional[str] = None,
    arp_psrc: Optional[str] = None,
    arp_psmac: Optional[str] = None,
    is_arp_reply: bool = False,
    dst_port: Optional[int] = None,
) -> PacketRecord:
    """Convenience factory for synthetic records in tests."""
    return PacketRecord(
        number=number,
        timestamp=timestamp,
        length=length,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=dst_port,
        proto=proto,
        flags=flags,
        dns_qname=dns_qname,
        http_request=http_request,
        http_headers=http_headers,
        http_body=http_body,
        arp_psrc=arp_psrc,
        arp_psmac=arp_psmac,
        is_arp_reply=is_arp_reply,
    )


# Shannon entropy
class TestShannonEntropy:
    def test_empty_string_is_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_char_is_zero(self) -> None:
        assert shannon_entropy("aaaa") == 0.0

    def test_uniform_random_string_is_high(self) -> None:
        assert shannon_entropy("a1b2c3d4e5f6a7b8") > 3.5

    def test_repeated_english_word_is_low(self) -> None:
        assert shannon_entropy("www") < 2.0

    def test_matches_reference_formula(self) -> None:
        # H = -sum(p * log2(p)); for "ab" -> -(0.5*-1 + 0.5*-1) = 1.0
        assert math.isclose(shannon_entropy("ab"), 1.0, abs_tol=1e-9)


# Protocol counting
class TestProtocolBreakdown:
    def test_counts_and_percentages(self) -> None:
        records = [
            make_record(1, proto="TCP"),
            make_record(2, proto="TCP"),
            make_record(3, proto="UDP"),
            make_record(4, proto="ARP"),
        ]
        stats = protocol_breakdown(records)
        by_proto = {s.protocol: s for s in stats}
        assert by_proto["TCP"].count == 2
        assert by_proto["TCP"].percent == 50.0
        assert by_proto["UDP"].count == 1
        assert by_proto["UDP"].percent == 25.0
        assert by_proto["ARP"].count == 1

    def test_sorted_descending(self) -> None:
        records = [
            make_record(1, proto="TCP"),
            make_record(2, proto="TCP"),
            make_record(3, proto="TCP"),
            make_record(4, proto="UDP"),
            make_record(5, proto="ARP"),
        ]
        stats = protocol_breakdown(records)
        counts = [s.count for s in stats]
        assert counts == sorted(counts, reverse=True)
        assert stats[0].protocol == "TCP"

    def test_empty_input(self) -> None:
        assert protocol_breakdown([]) == []


# Top talkers / ports
class TestTopTalkers:
    def test_counts_packet_counts(self) -> None:
        records = [
            make_record(1, src_ip="A", dst_ip="B", length=10),
            make_record(2, src_ip="A", dst_ip="B", length=10),
            make_record(3, src_ip="A", dst_ip="C", length=10),
            make_record(4, src_ip="B", dst_ip="A", length=10),
        ]
        by_count = top_talkers(records, by_bytes=False)
        assert by_count[0].src == "A" and by_count[0].dst == "B" and by_count[0].value == 2

    def test_bytes_volume(self) -> None:
        records = [
            make_record(1, src_ip="A", dst_ip="B", length=100),
            make_record(2, src_ip="A", dst_ip="B", length=100),
            make_record(3, src_ip="A", dst_ip="C", length=1000),
        ]
        by_bytes = top_talkers(records, by_bytes=True)
        # A->C (1000 bytes) beats A->B (200 bytes)
        assert by_bytes[0].src == "A" and by_bytes[0].dst == "C"
        assert by_bytes[0].value == 1000

    def test_skips_arp_records(self) -> None:
        records = [
            make_record(1, proto="ARP", src_ip=None, dst_ip=None),
            make_record(2, src_ip="A", dst_ip="B"),
        ]
        by_count = top_talkers(records)
        assert len(by_count) == 1


class TestTopPorts:
    def test_counts_destination_ports(self) -> None:
        records = [
            make_record(1, dst_port=443),
            make_record(2, dst_port=443),
            make_record(3, dst_port=80),
            make_record(4, proto="ARP", src_ip=None, dst_ip=None, dst_port=None),
        ]
        ports = top_ports(records)
        assert ports[0].port == 443 and ports[0].count == 2
        assert ports[1].port == 80 and ports[1].count == 1

    def test_service_name_fallback(self) -> None:
        # 443 is in our static dict in case the OS registry lacks it.
        assert service_name(443) in ("https", "unknown")
        # An unassigned port must not raise.
        assert service_name(61234) == "unknown"
        # 3389 is explicitly required by the spec.
        assert service_name(3389) in ("ms-wbt-server", "unknown")


# Plaintext credentials
class TestPlaintextCredentials:
    def test_basic_auth_header_flagged(self) -> None:
        rec = make_record(
            http_request="GET /admin HTTP/1.1",
            http_headers={"authorization": "Basic Zm9vOmJhcg=="},
        )
        findings = _detect_plaintext_credentials([rec])
        assert len(findings) == 1
        assert findings[0].type == "plaintext-credentials"
        assert "Authorization" in findings[0].details[0]

    def test_password_form_field_flagged(self) -> None:
        rec = make_record(
            http_request="POST /login HTTP/1.1",
            http_headers={"content-type": "application/x-www-form-urlencoded"},
            http_body="username=jdoe&password=hunter2",
        )
        findings = _detect_plaintext_credentials([rec])
        assert len(findings) == 1
        assert "password" in findings[0].details[0]

    def test_innocent_request_not_flagged(self) -> None:
        rec = make_record(
            http_request="GET /index.html HTTP/1.1",
            http_headers={"host": "example.com"},
            http_body="",
        )
        assert _detect_plaintext_credentials([rec]) == []

    def test_no_http_traffic(self) -> None:
        assert _detect_plaintext_credentials([make_record()]) == []


# SYN scan
class TestSynScan:
    def test_high_syn_volume_with_no_reply_flagged(self) -> None:
        records = [
            make_record(i, src_ip="10.0.0.9", dst_ip="10.0.0.1", flags=0x02)
            for i in range(1, 16)
        ]
        findings = _detect_syn_scan(records)
        assert len(findings) == 1
        assert findings[0].type == "syn-scan"
        assert "10.0.0.9" in findings[0].details[0]

    def test_low_syn_volume_not_flagged(self) -> None:
        records = [
            make_record(i, src_ip="10.0.0.9", dst_ip="10.0.0.1", flags=0x02)
            for i in range(1, 6)
        ]
        assert _detect_syn_scan(records) == []

    def test_completing_handshakes_not_flagged(self) -> None:
        # 15 SYNs, but a corresponding SYN-ACK stream makes the ratio healthy.
        syns = [make_record(i, src_ip="10.0.0.9", dst_ip="10.0.0.1", flags=0x02) for i in range(1, 16)]
        syn_acks = [
            make_record(100 + i, src_ip="10.0.0.1", dst_ip="10.0.0.9", flags=0x12)
            for i in range(10)
        ]
        assert _detect_syn_scan(syns + syn_acks) == []

    def test_min_syns_parameter_respected(self) -> None:
        records = [
            make_record(i, src_ip="10.0.0.9", dst_ip="10.0.0.1", flags=0x02)
            for i in range(1, 6)
        ]
        assert _detect_syn_scan(records, min_syns=3) != []


# DNS tunneling / C2 beaconing
class TestDnsTunneling:
    def test_high_entropy_subdomain_flagged(self) -> None:
        rec = make_record(
            dns_qname="a1b2c3d4e5f6a7b8c9d0e1f2.example.com",
        )
        findings = _detect_dns_tunneling([rec])
        assert len(findings) == 1
        assert findings[0].type == "dns-tunneling-candidate"
        assert "a1b2c3d4e5f6a7b8c9d0e1f2" in findings[0].details[0]

    def test_normal_domain_not_flagged(self) -> None:
        rec = make_record(dns_qname="www.example.com")
        assert _detect_dns_tunneling([rec]) == []

    def test_very_long_low_entropy_subdomain_flagged(self) -> None:
        # Long but repetitive (low entropy) label still exceeds the length rule.
        rec = make_record(dns_qname=f"{'a' * 50}.example.com")
        findings = _detect_dns_tunneling([rec])
        assert len(findings) == 1

    def test_reversed_ptr_literals_ignored(self) -> None:
        recs = [
            make_record(dns_qname="4.4.8.8.in-addr.arpa"),
            make_record(dns_qname="abcd.ef01.example.com"),
        ]
        # The second one looks like an IP literal and must be excluded too.
        assert _detect_dns_tunneling(recs) == []

    def test_repeated_qname_deduplicated(self) -> None:
        qname = "a1b2c3d4e5f6a7b8c9d0e1f2.example.com"
        recs = [make_record(dns_qname=qname) for _ in range(3)]
        findings = _detect_dns_tunneling(recs)
        assert len(findings) == 1
        # Same unique qname reported once, not once per retry.
        assert len(findings[0].details) == 1

    def test_managed_cloud_zones_not_flagged(self) -> None:
        # Labels directly above managed zones are provider-controlled
        # (region / distribution / app slot), not random tunnel data.
        for qname in (
            "codewhisperer.us-east-1.amazonaws.com",
            "d123abc456.cloudfront.net",
            "myapp.azurewebsites.net",
            "a.b.googleapis.com",
            "mobile.events.data.microsoft.com",
            "login.microsoftonline.com",
        ):
            assert _detect_dns_tunneling([make_record(dns_qname=qname)]) == [], qname

    def test_managed_zone_still_flags_deeper_random_labels(self) -> None:
        # A random 24-char label *above* the managed zone keeps the tunnel
        # shape: <rand>.<rand>.amazonaws.com is exactly what tools generate.
        rec = make_record(dns_qname="a1b2c3d4e5f6a7b8c9d0e1f2.xsrv.amazonaws.com")
        findings = _detect_dns_tunneling([rec])
        assert len(findings) == 1
        assert len(findings[0].details) == 1


# ARP spoofing
class TestArpSpoofing:
    def test_multiple_macs_for_one_ip_flagged(self) -> None:
        records = [
            make_record(
                1, proto="ARP", src_ip=None, dst_ip=None,
                arp_psrc="192.168.1.1", arp_psmac="aa:bb:cc:dd:ee:01",
                is_arp_reply=True,
            ),
            make_record(
                2, proto="ARP", src_ip=None, dst_ip=None,
                arp_psrc="192.168.1.1", arp_psmac="aa:bb:cc:dd:ee:ff",
                is_arp_reply=True,
            ),
        ]
        findings = _detect_arp_spoofing(records)
        assert len(findings) == 1
        assert findings[0].type == "arp-spoofing-candidate"
        assert "192.168.1.1" in findings[0].details[0]
        assert "aa:bb:cc:dd:ee:ff" in findings[0].details[0]

    def test_requests_and_stable_replies_not_flagged(self) -> None:
        records = [
            make_record(
                1, proto="ARP", src_ip=None, dst_ip=None,
                arp_psrc="192.168.1.1", arp_psmac="aa:bb:cc:dd:ee:01",
                is_arp_reply=False,
            ),
            make_record(
                2, proto="ARP", src_ip=None, dst_ip=None,
                arp_psrc="192.168.1.1", arp_psmac="aa:bb:cc:dd:ee:01",
                is_arp_reply=True,
            ),
        ]
        assert _detect_arp_spoofing(records) == []


# End-to-end over the synthetic capture
class TestFullCapture:
    def test_summary_matches_expected_counts(self, records) -> None:
        result = summarize(records)
        assert result.total_packets == 27
        assert result.total_bytes > 0
        assert result.duration_seconds > 1.0
        assert result.avg_packet_size == pytest.approx(
            result.total_bytes / result.total_packets
        )

    def test_protocol_breakdown_covers_all_traffic(self, records) -> None:
        result = summarize(records)
        by_proto = {s.protocol: s.count for s in result.protocols}
        assert by_proto["TCP"] == 18
        assert by_proto["DNS"] == 2
        assert by_proto["ARP"] == 3
        assert by_proto["ICMP"] == 1
        assert by_proto["TLS"] == 2
        assert by_proto["HTTP"] == 1

    def test_all_four_findings_present(self, records) -> None:
        result = summarize(records)
        types = {f.type for f in result.findings}
        assert "plaintext-credentials" in types
        assert "syn-scan" in types
        assert "dns-tunneling-candidate" in types
        assert "arp-spoofing-candidate" in types