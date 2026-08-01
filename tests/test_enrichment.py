"""Tests for the offline ASN/organization enrichment module.

Covers private-IP short-circuiting (no DB access attempted), the in-memory
lookup cache (a repeated IP must not re-query the database), and graceful
handling of missing/failed backends. All database access is faked; no real
network or MaxMind DB is involved.
"""
from __future__ import annotations

import pytest

from pcap_insight import enrichment


@pytest.fixture(autouse=True)
def _isolated_enrichment_state() -> None:
    """Reset module-level state so tests never share cache/reader state."""
    enrichment.clear_cache()
    enrichment._reader = None
    enrichment._reader_error = None
    yield
    enrichment.clear_cache()
    enrichment._reader = None
    enrichment._reader_error = None


class FakeEntry:
    """Stand-in for `geoip2.records.ASN`."""

    def __init__(self, org: str | None = None, asn: int | None = None) -> None:
        self.autonomous_system_organization = org
        self.autonomous_system_number = asn


class FakeReader:
    """Stand-in for `geoip2.database.Reader` with a call counter."""

    def __init__(self, entry: FakeEntry | None = None) -> None:
        self._entry = entry
        self.calls = 0

    def asn(self, ip: str) -> FakeEntry:
        self.calls += 1
        if self._entry is None:
            # Simulate the AddressNotFoundError path.
            raise Exception(f"no record for {ip}")
        return self._entry


class TestPrivateIpDetection:
    def test_private_ips_return_private_without_any_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """RFC1918 and friends are labeled 'Private' and never hit the DB."""
        def _explode_if_called() -> object:
            raise AssertionError("database should not be queried for private IPs")

        monkeypatch.setattr(enrichment, "_get_reader", _explode_if_called)

        for ip in ("192.168.1.1", "10.0.0.5", "172.16.0.9", "127.0.0.1", "169.254.1.1"):
            assert enrichment.lookup_org(ip) == "Private", ip

    def test_ipv6_private_and_loopback(self) -> None:
        assert enrichment.lookup_org("fd00::1") == "Private"  # ULA
        assert enrichment.lookup_org("::1") == "Private"      # loopback
        assert enrichment.lookup_org("fe80::1") == "Private"  # link-local

    def test_ipv4_mapped_ipv6_treated_as_private(self) -> None:
        """::ffff:10.0.0.5 embeds a private IPv4; must be labeled Private."""
        assert enrichment.lookup_org("::ffff:10.0.0.5") == "Private"

    def test_ipv4_mapped_ipv6_public_reaches_database(self) -> None:
        """::ffff:8.8.8.8 is a public address and must hit the backend."""
        reader = FakeReader(FakeEntry(org="Example Corp", asn=64500))
        enrichment._reader = reader
        assert enrichment.lookup_org("::ffff:8.8.8.8") == "Example Corp (AS64500)"
        assert reader.calls == 1

    def test_6to4_and_teredo_prefixes(self) -> None:
        """Known IPv6 transition prefixes behave per Python's classifications."""
        # 2002:0a00:0000:: is 6to4 for 10.0.0.* (private IPv4 embedded).
        assert enrichment.lookup_org("2002:0a00:0000::") == "Private"
        # 2002:0808:0808:: is 6to4 for 8.8.8.8, but Python 3.11 flags the whole
        # 2002::/16 range as private; we accept that stdlib quirk deliberately
        # (documented in is_private) and therefore never query the DB here.
        assert enrichment.lookup_org("2002:0808:0808::") == "Private"
        # 2001::/32 Teredo also classified private by the stdlib.
        assert enrichment.lookup_org("2001::1") == "Private"

    def test_invalid_ip_returns_unknown_without_raising(self) -> None:
        assert enrichment.lookup_org("not-an-ip") == "Unknown"


class TestCacheBehavior:
    def test_second_lookup_of_same_ip_uses_cache(self) -> None:
        reader = FakeReader(FakeEntry(org="Example Corp", asn=64500))
        # Inject the reader directly, bypassing DB discovery.
        enrichment._reader = reader

        assert enrichment.lookup_org("8.8.8.8") == "Example Corp (AS64500)"
        assert enrichment.lookup_org("8.8.8.8") == "Example Corp (AS64500)"
        assert enrichment.lookup_org("8.8.8.8") == "Example Corp (AS64500)"

        # Three calls, but the backend should only have been hit once.
        assert reader.calls == 1

    def test_cache_is_per_ip(self) -> None:
        reader = FakeReader(FakeEntry(org="Example Corp", asn=64500))
        enrichment._reader = reader

        enrichment.lookup_org("8.8.8.8")
        enrichment.lookup_org("1.1.1.1")
        enrichment.lookup_org("8.8.8.8")
        enrichment.lookup_org("1.1.1.1")

        assert reader.calls == 2

    def test_clear_cache_resets_lookups(self) -> None:
        reader = FakeReader(FakeEntry(org="Example Corp", asn=64500))
        enrichment._reader = reader

        enrichment.lookup_org("8.8.8.8")
        enrichment.clear_cache()
        enrichment.lookup_org("8.8.8.8")

        assert reader.calls == 2


class TestGracefulFailure:
    def test_lookup_failure_returns_unknown(self) -> None:
        reader = FakeReader()  # `asn()` raises
        enrichment._reader = reader

        assert enrichment.lookup_org("8.8.8.8") == "Unknown"

    def test_no_reader_returns_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No GeoLite2-ASN database found anywhere: 'Unknown', never raises."""
        monkeypatch.setattr(enrichment, "_default_db_paths", lambda: [])
        assert enrichment.lookup_org("8.8.8.8") == "Unknown"

    def test_missing_geoip2_package_returns_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """geoip2 not installed: 'Unknown', no ImportError escapes."""

        def _no_geoip() -> None:
            raise ImportError("geoip2 is not installed")

        monkeypatch.setattr(enrichment, "_get_reader", _no_geoip)
        assert enrichment.lookup_org("8.8.8.8") == "Unknown"


class TestBackendStatus:
    def test_status_not_initialized(self) -> None:
        """Before any init, the backend reports 'not-initialized'."""
        assert enrichment.backend_status() == "not-initialized"

    def test_status_ok_with_reader(self) -> None:
        enrichment._reader = FakeReader(FakeEntry(org="Acme", asn=1))
        assert enrichment.backend_status() == "ok"

    def test_status_db_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Force the FileNotFoundError path from _get_reader."""
        monkeypatch.setattr(enrichment, "_default_db_paths", lambda: [])
        enrichment.ensure_backend_initialized()
        assert enrichment.backend_status() == "db-not-found"

    def test_status_db_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A corrupt/unreadable database file path."""
        def _explode() -> None:
            raise Exception("corrupt database")

        monkeypatch.setattr(enrichment, "_get_reader", _explode)
        enrichment.ensure_backend_initialized()
        assert enrichment.backend_status() == "db-error"

    def test_status_geoip2_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The geoip2 package itself is not installed."""
        def _no_geoip() -> None:
            raise ImportError("geoip2 is not installed")

        monkeypatch.setattr(enrichment, "_get_reader", _no_geoip)
        enrichment.ensure_backend_initialized()
        assert enrichment.backend_status() == "geoip2-package-missing"

    def test_get_reader_is_idempotent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The real _get_reader records a failure once and short-circuits."""
        from pathlib import Path

        searches: list[int] = []

        def _counted_paths() -> list[Path]:
            # Simulate "no database anywhere" while counting how many times
            # the filesystem search actually runs.
            searches.append(1)
            return []

        monkeypatch.setattr(enrichment, "_default_db_paths", _counted_paths)
        assert enrichment._get_reader() is None
        assert enrichment._get_reader() is None
        # The failure is recorded; the second call never re-searches.
        assert len(searches) == 1
        assert enrichment.backend_status() == "db-not-found"
        # ensure_backend_initialized uses the same idempotent path.
        enrichment.ensure_backend_initialized()
        assert len(searches) == 1


class TestFormatting:
    def test_org_with_asn(self) -> None:
        enrichment._reader = FakeReader(FakeEntry(org="Acme Networks", asn=12345))
        assert enrichment.lookup_org("8.8.8.8") == "Acme Networks (AS12345)"

    def test_org_without_asn(self) -> None:
        enrichment._reader = FakeReader(FakeEntry(org="Acme Networks", asn=None))
        assert enrichment.lookup_org("8.8.8.8") == "Acme Networks"

    def test_asn_without_org(self) -> None:
        enrichment._reader = FakeReader(FakeEntry(org=None, asn=12345))
        assert enrichment.lookup_org("8.8.8.8") == "AS12345"

    def test_blank_record_returns_unknown(self) -> None:
        enrichment._reader = FakeReader(FakeEntry(org=None, asn=None))
        assert enrichment.lookup_org("8.8.8.8") == "Unknown"