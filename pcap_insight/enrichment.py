"""Offline ASN/organization enrichment for top-talker IPs.

Uses MaxMind's GeoLite2-ASN database (via geoip2) rather than ipwhois RDAP
lookups, since it works fully offline once the database is downloaded --
no network calls or API keys needed at analysis time. Tradeoff: requires a
one-time free MaxMind account and occasional database refresh (see README).

Private/reserved/loopback/link-local IPs return "Private" without touching
the database. Results are cached per-IP in a module-level dict so repeated
IPs across packets/rows only get looked up once. Missing database, corrupt
file, or failed lookup returns "Unknown" rather than raising.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from geoip2.database import Reader

#: Environment variable that overrides the GeoLite2-ASN database location.
ENV_DB_PATH = "PCAP_INSIGHT_ASN_DB"

#: Default candidate locations for ``GeoLite2-ASN.mmdb``, in priority order.
DEFAULT_DB_PATHS = (
    "{cwd}/GeoLite2-ASN.mmdb",
    "{home}/.pcap-insight/GeoLite2-ASN.mmdb",
    "{home}/.local/share/GeoLite2-ASN.mmdb",
)

#: In-memory lookup cache: IP -> resolved label ("Private" / "Unknown" / org).
_cache: dict[str, str] = {}

#: Lazily-initialized geoip2 reader and the first error if init failed.
_reader: Optional[Any] = None
_reader_error: Optional[BaseException] = None


def clear_cache() -> None:
    """Clear the in-memory lookup cache (mainly for tests)."""
    _cache.clear()


def _reset_backend() -> None:
    """Drop the cached geoip2 reader so it is re-opened on next use."""
    global _reader, _reader_error
    _reader = None
    _reader_error = None


def _default_db_paths() -> list[Path]:
    """Candidate ``GeoLite2-ASN.mmdb`` locations, in priority order."""
    paths: list[Path] = []
    env_path = os.environ.get(ENV_DB_PATH)
    if env_path:
        paths.append(Path(env_path))
    for template in DEFAULT_DB_PATHS:
        paths.append(Path(template.format(cwd=Path.cwd(), home=Path.home())))
    return paths


def _get_reader() -> Optional[Any]:
    """Return the geoip2 database reader, or ``None`` if unavailable/failed."""
    global _reader, _reader_error
    if _reader is not None or _reader_error is not None:
        return _reader
    try:
        import geoip2.database
    except ImportError:
        _reader_error = ImportError("geoip2 is not installed")
        return None
    for path in _default_db_paths():
        if not path.is_file():
            continue
        try:
            _reader = geoip2.database.Reader(str(path))
            return _reader
        except Exception as exc:
            # Corrupt / unreadable database file.
            _reader_error = exc
            return None
    _reader_error = FileNotFoundError(
        f"GeoLite2-ASN database not found (set {ENV_DB_PATH} or place the file "
        "in one of the default locations; see README)"
    )
    return None


def is_private(ip: str) -> bool:
    """True for RFC1918 / loopback / link-local / reserved / unspecified IPs.

    These never benefit from a lookup and are labeled ``"Private"``.

    IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are decoded back to their
    embedded IPv4 address first, because Python marks the mapped form
    ``reserved=True`` even when the embedded address is public -- without the
    decode, ``::ffff:8.8.8.8`` would be (incorrectly) treated as private.
    6to4 (``2002::/16``) addresses embed an IPv4 address but Python 3.11
    classifies the entire range as private, so those stay "Private" even when
    the embedded address is public (a known stdlib quirk, accepted here).

    Raises:
        ValueError: If ``ip`` is not a valid IPv4/IPv6 address.
    """
    addr = ipaddress.ip_address(ip)
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        # Decode ::ffff:a.b.c.d before evaluating the private flags.
        addr = mapped
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _format_org(org: Optional[str], asn: Optional[int]) -> Optional[str]:
    """Format ``"ORG (ASnnnn)"``, falling back to ``"ASnnnn"`` or ``None``."""
    if org:
        return f"{org} (AS{asn})" if asn else org
    if asn:
        return f"AS{asn}"
    return None


def backend_status() -> str:
    """Return the current status of the enrichment backend.

    Returns one of ``"ok"``, ``"geoip2-package-missing"``,
    ``"db-not-found"``, ``"db-error"``, or ``"not-initialized"``.
    """
    if _reader is not None:
        return "ok"
    if isinstance(_reader_error, ImportError):
        return "geoip2-package-missing"
    if isinstance(_reader_error, FileNotFoundError):
        return "db-not-found"
    if _reader_error is not None:
        return "db-error"
    return "not-initialized"


def ensure_backend_initialized() -> None:
    """Force the lazy backend initialization to run.

    Used by the CLI so it can emit an early warning when enrichment is
    requested but the database is missing, even if every IP in the capture
    turns out to be private (which would otherwise short-circuit before the
    reader is ever loaded).
    """
    try:
        _get_reader()
    except Exception as exc:  # pragma: no cover - defensive only
        global _reader_error
        _reader_error = exc


def _lookup_db(ip: str, reader: Any) -> Optional[str]:
    """Query the reader for an org/ASN label; any exception maps to ``None``."""
    try:
        entry = reader.asn(ip)
    except Exception:
        # AddressNotFoundError (IP not in DB), malformed responses, timeouts.
        return None
    return _format_org(
        getattr(entry, "autonomous_system_organization", None) or None,
        getattr(entry, "autonomous_system_number", None),
    )


def lookup_org(ip: str) -> str:
    """Return an organization/ASN label for ``ip``.

    Returns:
        ``"Private"`` for private/reserved addresses (no lookup attempted),
        ``"Unknown"`` when no database is configured or the lookup fails, and
        ``"ORG (ASnnnn)"`` / ``"ASnnnn"`` for public addresses on success.

    Results are cached in memory per invocation.
    """
    if ip in _cache:
        return _cache[ip]

    try:
        private = is_private(ip)
    except ValueError:
        # Not a parseable IP address; nothing to look up.
        _cache[ip] = "Unknown"
        return "Unknown"

    if private:
        _cache[ip] = "Private"
        return "Private"

    try:
        reader = _get_reader()
    except Exception:
        # Defensive: never let a backend initialization failure escape.
        _cache[ip] = "Unknown"
        return "Unknown"
    if reader is None:
        _cache[ip] = "Unknown"
        return "Unknown"

    label = _lookup_db(ip, reader) or "Unknown"
    _cache[ip] = label
    return label