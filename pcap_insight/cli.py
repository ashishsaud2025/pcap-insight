"""CLI entry point.

Argparse front-end: parse the capture, run the analysis, and either render
``rich`` tables to stdout or dump a JSON document (``--export json``).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import NoReturn, Optional

from . import __version__
from .analyzers import (
    AnalysisResult,
    analysis_result_to_dict,
    summarize,
)
from .parser import compile_bpf_filter, parse_capture

try:  # rich is a declared dependency, but keep a tiny fallback anyway
    from rich.console import Console
    from rich.table import Table

    _HAS_RICH = True
except ImportError:  # pragma: no cover - exercised only if deps are missing
    _HAS_RICH = False

def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="pcap-insight",
        description=(
            "Analyze a .pcap/.pcapng capture: summary stats, protocol "
            "breakdown, top talkers/ports, and heuristic suspicious-pattern "
            "flags (credentials in plaintext HTTP, SYN scans, DNS tunneling "
            "candidates, ARP spoofing candidates)."
        ),
        epilog=(
            "examples:\n"
            "  pcap-insight capture.pcap\n"
            "  pcap-insight capture.pcap --filter 'tcp port 443'\n"
            "  pcap-insight capture.pcap --export json | jq .summary\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "capture",
        nargs="?",
        default=None,
        help="path to a .pcap or .pcapng file (omit with --demo)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="write a synthetic demo capture to './demo.pcap' and analyze it",
    )
    parser.add_argument(
        "--export",
        choices=("json",),
        help="emit a structured JSON document instead of tables",
    )
    parser.add_argument(
        "--filter",
        help="BPF-style capture filter, e.g. 'tcp port 443' or 'host 10.0.0.5'",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _validate_bpf_filter(filter_str: str) -> None:
    """Validate a BPF filter string by compiling it.

    Raises:
        ValueError: If the filter cannot be parsed (unsupported syntax, bad
            address, out-of-range port, ...).
    """
    try:
        compile_bpf_filter(filter_str)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


def _error(msg: str) -> NoReturn:
    sys.stderr.write(f"pcap-insight: error: {msg}\n")
    sys.exit(2)


# Presentation
def _fmt_bytes(n: float) -> str:
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.2f} GB"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f} MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f} KB"
    return f"{n:.0f} B"


def _fmt_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, secs = divmod(seconds, 60)
    return f"{int(minutes)}m {secs:.1f}s"


def _fmt_utc_timestamp(epoch: float) -> str:
    """Format an epoch-seconds timestamp as a readable UTC string.

    pcap files don't store a capture-level clock; these are the timestamps
    of the first and last packet in the capture (the capture machine's
    wall clock, converted to UTC).
    """
    dt = datetime.fromtimestamp(epoch, timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def _print_section(console: Optional[object], title: str) -> None:
    if console is not None:
        console.print(f"\n[bold]{title}[/bold]")
    else:
        print(f"\n== {title} ==")


def _make_table(console: Optional[object], headers: list[str], rows: list[list[str]]) -> None:
    if console is not None:
        table = Table(show_header=True, header_style="bold", box=None)
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(*row)
        console.print(table)
    else:
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(cell))
        header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
        print(header_line)
        print("-" * len(header_line))
        for row in rows:
            print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))


def render_report(result: AnalysisResult) -> None:
    """Print the full human-readable report."""
    console = Console() if _HAS_RICH else None

    _print_section(console, "Summary")
    rows = [
        ["Total packets", str(result.total_packets)],
        ["Capture duration", _fmt_duration(result.duration_seconds)],
        ["Total bytes", _fmt_bytes(result.total_bytes)],
        ["Average packet size", _fmt_bytes(result.avg_packet_size)],
    ]
    if result.start_time is not None and result.end_time is not None:
        rows.append(["First packet (UTC)", _fmt_utc_timestamp(result.start_time)])
        rows.append(["Last packet (UTC)", _fmt_utc_timestamp(result.end_time)])
    _make_table(console, ["Metric", "Value"], rows)

    _print_section(console, "Protocol breakdown")
    _make_table(
        console,
        ["Protocol", "Packets", "Percent"],
        [
            [p.protocol, str(p.count), f"{p.percent:.1f}%"]
            for p in result.protocols
        ],
    )

    _print_section(console, "Top talkers by packet count")
    _make_table(
        console,
        ["Source", "Destination", "Packets"],
        [[t.src, t.dst, str(t.value)] for t in result.top_talkers_by_count],
    )

    _print_section(console, "Top talkers by byte volume")
    _make_table(
        console,
        ["Source", "Destination", "Bytes"],
        [[t.src, t.dst, _fmt_bytes(t.value)] for t in result.top_talkers_by_bytes],
    )

    _print_section(console, "Top destination ports")
    _make_table(
        console,
        ["Port", "Service", "Packets"],
        [
            [str(p.port), p.service, str(p.count)]
            for p in result.top_ports
        ],
    )

    _print_section(console, "Suspicious patterns (heuristics, not ground truth)")
    if not result.findings:
        _make_table(console, ["Type", "Severity", "Summary"], [["-", "-", "No findings."]])
    else:
        rows = [
            [f.type, f.severity, f.summary]
            for f in result.findings
        ]
        _make_table(console, ["Type", "Severity", "Summary"], rows)
        for f in result.findings:
            if f.details:
                for detail in f.details:
                    print(f"  - {detail}")


# Main
def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point (console_script target)."""
    args = build_parser().parse_args(argv)

    if args.demo and args.capture is not None:
        _error("--demo cannot be combined with a capture file argument")

    if args.demo:
        from .testing import build_capture

        demo_path = "demo.pcap"
        build_capture(demo_path)
        capture_arg = demo_path
        sys.stderr.write(f"pcap-insight: wrote synthetic demo capture to {demo_path!r}\n")
    else:
        capture_arg = args.capture
        if capture_arg is None:
            build_parser().print_usage(sys.stderr)
            _error("a capture file is required (or use --demo)")

    # Validate filter before touching the capture file so users get a clean
    # error instead of thousands of packets silently skipped.
    if args.filter:
        try:
            _validate_bpf_filter(args.filter)
        except ValueError as exc:
            _error(str(exc))

    try:
        records = parse_capture(capture_arg, bpf_filter=args.filter)
    except FileNotFoundError as exc:
        _error(str(exc))
    except ValueError as exc:
        _error(str(exc))

    result = summarize(records)

    if args.export == "json":
        json.dump(analysis_result_to_dict(result), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        render_report(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())