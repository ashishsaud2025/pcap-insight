"""Shared pytest fixtures.

A session-scoped synthetic capture is generated with Scapy (no external pcap
files required) and parsed once for the whole suite.
"""
from __future__ import annotations

import pytest

from pcap_insight.parser import parse_capture
from pcap_insight.testing import build_capture, HTTP_TARGET


@pytest.fixture(scope="session")
def capture_path(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Write the synthetic capture to a session-scoped temp file."""
    path = str(tmp_path_factory.mktemp("captures") / "demo.pcap")
    build_capture(path)
    return path


@pytest.fixture(scope="session")
def records(capture_path: str):
    """Parsed PacketRecords from the synthetic capture (unfiltered)."""
    return parse_capture(capture_path)


@pytest.fixture
def http_target() -> str:
    """IP the synthetic HTTP/TLS traffic is addressed to."""
    return HTTP_TARGET