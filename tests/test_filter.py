"""Unit tests for the self-contained BPF-style filter engine."""
from __future__ import annotations

from typing import Optional

import pytest

from pcap_insight.parser import PacketRecord, compile_bpf_filter


def rec(
    proto: str = "TCP",
    src_ip: Optional[str] = "10.0.0.1",
    dst_ip: Optional[str] = "10.0.0.2",
    src_port: Optional[int] = 12345,
    dst_port: Optional[int] = 443,
) -> PacketRecord:
    return PacketRecord(
        number=1,
        timestamp=1.0,
        length=100,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        flags=0x02,
        dns_qname=None,
        http_request=None,
        http_headers=None,
        http_body=None,
        arp_psrc=None,
        arp_psmac=None,
        is_arp_reply=False,
    )


def test_tcp_port_filter() -> None:
    pred = compile_bpf_filter("tcp port 443")
    assert pred(rec())
    assert pred(rec(dst_port=8443)) is False


def test_host_filter_any_side() -> None:
    pred = compile_bpf_filter("host 10.0.0.2")
    assert pred(rec())
    assert pred(rec(dst_ip="10.0.0.9")) is False


def test_src_and_dst_qualifiers() -> None:
    assert compile_bpf_filter("src host 10.0.0.1")(rec()) is True
    assert compile_bpf_filter("src host 10.0.0.2")(rec()) is False
    assert compile_bpf_filter("dst host 10.0.0.2")(rec()) is True


def test_net_cidr() -> None:
    pred = compile_bpf_filter("src net 10.0.0.0/24")
    assert pred(rec(src_ip="10.0.0.55")) is True
    assert pred(rec(src_ip="10.0.1.55")) is False


def test_portrange() -> None:
    pred = compile_bpf_filter("dst portrange 1000-2000")
    assert pred(rec(dst_port=1500)) is True
    assert pred(rec(dst_port=3000)) is False


def test_bool_combinators() -> None:
    pred = compile_bpf_filter("tcp and dst port 443 and not host 10.0.0.9")
    assert pred(rec()) is True
    assert pred(rec(dst_ip="10.0.0.9")) is False
    assert pred(rec(proto="UDP")) is False


def test_parenthesized_group() -> None:
    pred = compile_bpf_filter("tcp and (dst port 80 or dst port 443)")
    assert pred(rec(dst_port=80)) is True
    assert pred(rec(dst_port=443)) is True
    assert pred(rec(dst_port=22)) is False


def test_udp_icmp_arp_primitives() -> None:
    assert compile_bpf_filter("udp")(rec(proto="UDP", dst_port=53)) is True
    assert compile_bpf_filter("udp")(rec()) is False
    assert compile_bpf_filter("icmp")(rec(proto="ICMP", dst_port=None)) is True
    assert compile_bpf_filter("arp")(rec(proto="ARP", src_ip=None, dst_ip=None)) is True


def test_proto_label_implies_transport() -> None:
    # Our parser marks HTTP/TLS inside TCP, so a tcp filter must match them.
    assert compile_bpf_filter("tcp")(rec(proto="HTTP")) is True
    assert compile_bpf_filter("tcp")(rec(proto="TLS")) is True
    # DNS is marked over UDP.
    assert compile_bpf_filter("udp")(rec(proto="DNS")) is True


def test_invalid_filters_raise() -> None:
    for bad in (
        "ip6",
        "ether host aa:bb:cc:dd:ee:ff",
        "port 99999",
        "host not-an-ip",
        "tcp and",
        "(tcp",
        "tcp portrange 5000-1000",  # inverted
    ):
        with pytest.raises(ValueError):
            compile_bpf_filter(bad)


def test_empty_filter_raises() -> None:
    with pytest.raises(ValueError):
        compile_bpf_filter("")