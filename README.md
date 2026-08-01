# pcap-insight 

[![Tests](https://github.com/ashishsaud2025/pcap-insight/actions/workflows/test.yml/badge.svg)](https://github.com/ashishsaud2025/pcap-insight/actions/workflows/test.yml)

A command-line PCAP analyzer that turns a `.pcap` / `.pcapng` capture into a
readable security-and-traffic report:

- **Summary**: packet count, capture duration, total bytes, average packet size
- **Protocol breakdown**: TCP/UDP/ICMP/ARP/DNS/TLS/HTTP counts and percentages
- **Top talkers**: top 10 source-to-destination IP pairs by packet count *and* by byte volume
- **Top ports**: most-used destination ports with best-effort service names
- **ASN/organization enrichment**: top-talker rows annotated with the owning
  organization/ASN (offline via MaxMind's free GeoLite2-ASN database; disable with `--no-enrich`)
- **Suspicious patterns** (flags, not blocks):
  - plaintext credentials over HTTP
  - high-volume unanswered SYN bursts (possible SYN scan)
  - high-entropy / very long DNS subdomains (possible tunneling / C2 beaconing)
  - one IP claimed by multiple MACs in ARP replies (possible ARP spoofing)
- **`--export json`**: machine-readable output for piping into other tools
- **`--filter`**: a BPF-style filter to narrow analysis to specific traffic

It uses [Scapy](https://scapy.net/) to parse captures,
[Rich](https://github.com/Textualize/rich) to render tables, and
[geoip2](https://geoip2.readthedocs.io/) with MaxMind's free GeoLite2-ASN
database for optional offline organization/ASN attribution. Everything else is
standard-library Python (argparse, `socket.getservbyport`, `ipaddress`, ...).

> **What this is not.** `pcap-insight` is a triage/teaching tool. The
> suspicious-pattern detectors are heuristics with real false-positive rates;
> they are not ground truth and they are not an IDS. Read the
> [Suspicious-pattern heuristics](#how-the-suspicious-pattern-heuristics-work-and-when-they-lie) section for
> exactly what each rule does and the scenarios in which it produces false
> positives.

---

## Installation

Requires **Python 3.10+**.

### 1. Clone the repository

```bash
git clone https://github.com/ashishsaud2025/pcap-insight.git 
cd pcap-insight
```

### 2. Create and activate a virtual environment

A virtual environment keeps this project's dependencies isolated from your
system Python and other projects.

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
> If you get an execution-policy error, run PowerShell as your normal user and
> execute `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then
> retry activation.

**Windows (cmd.exe):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

Once activated, your prompt will show a `(venv)` prefix. Every `pip install`
and every run of `pcap-insight` below happens inside this isolated environment.

### 3. Install dependencies

You have two equivalent options:

**Option A: install from `requirements.txt`:**
```bash
pip install -r requirements.txt
```

**Option B: install the package itself (recommended):**
```bash
python -m pip install -e .
```
This installs the `pcap-insight` console entry point, plus `scapy`, `rich`,
and `geoip2` as declared in `pyproject.toml`. The `-e` (editable) flag means
any local code changes take effect immediately without reinstalling.

For development (adds `pytest` for the test suite):
```bash
python -m pip install -e ".[dev]"
```

### 4. Verify the install

```bash
pcap-insight --version
pcap-insight --demo
```

If both commands run, you're set up correctly. `pcap-insight` will now work
from any directory *as long as this venv is activated* — reactivate it with
the `Activate.ps1` / `activate.bat` / `source ... activate` command above each
time you open a new terminal session.

### Optional: organization/ASN enrichment (GeoLite2-ASN)

Top-talker tables are annotated with the owning organization/ASN for each IP.
The lookup is **fully offline** and uses MaxMind's free **GeoLite2-ASN**
database, i.e.  no API key and no network access are needed at analysis time.

To enable real org names (instead of `Unknown`) for public IPs:

1. Sign up at <https://www.maxmind.com/en/geolite2/signup> and download the
   **GeoLite2-ASN** database (`GeoLite2-ASN.mmdb`).
2. Place it in any of these locations (checked in order):
   - `<project>/GeoLite2-ASN.mmdb`
   - `~/.pcap-insight/GeoLite2-ASN.mmdb`
   - `~/.local/share/GeoLite2-ASN.mmdb`
   - or set the `PCAP_INSIGHT_ASN_DB` environment variable to its path

Private/reserved addresses (RFC1918, loopback, link-local, multicast, ...) are
labeled `Private` and never touch the database. A missing or unreadable
database, or an unknown IP, is labeled `Unknown`. Results are cached per IP for
the lifetime of the process, so top-talker enrichment adds only one database
read per unique public IP. Use `pcap-insight capture.pcap --no-enrich` to skip
the lookup entirely (useful fully-offline or in scripts that don't need it).

One edge case is handled explicitly: IPv4-mapped IPv6 addresses
(`::ffff:a.b.c.d`) are decoded back to their embedded IPv4 address before the
private check, because Python marks the mapped form `reserved=True` even when
the embedded address is public. Without the decode, `::ffff:8.8.8.8` would be
(incorrectly) treated as private and never reach the database. 6to4 (`2002::/16`)
and Teredo (`2001::/32`) ranges are labeled `Private` per Python's stdlib
classification even though they can embed public IPv4 addresses -- an accepted
stdlib quirk (see `is_private()` in `pcap_insight/enrichment.py`).

If enrichment is enabled but the database cannot be found or read, the CLI
prints a warning to **stderr** (so JSON/piped output stays clean) explaining
that public IPs will show `Unknown`, along with a pointer to this section.
`--no-enrich` disables both the lookup and the warning.

### Windows / Npcap note

Scapy only needs the **Npcap** driver if you want to *sniff* live traffic.
`pcap-insight` only *reads capture files*, so no admin privileges or Npcap
installation are required.

---

## Usage

```
usage: pcap-insight [-h] [--demo] [--export {json}] [--filter FILTER]
                    [--no-enrich] [--version]
                    [capture]

Analyze a .pcap/.pcapng capture: summary stats, protocol breakdown, top
talkers/ports, and heuristic suspicious-pattern flags (credentials in plaintext
HTTP, SYN scans, DNS tunneling candidates, ARP spoofing candidates).

positional arguments:
  capture          path to a .pcap or .pcapng file (omit with --demo)

options:
  -h, --help       show this help message and exit
  --demo           write a synthetic demo capture to './demo.pcap' and analyze it
  --export {json}  emit a structured JSON document instead of tables
  --filter FILTER  BPF-style capture filter, e.g. 'tcp port 443' or 'host 10.0.0.5'
  --no-enrich      disable ASN/organization enrichment for top-talker tables
                   (default: on, using the GeoLite2-ASN database if present)
  --version        show program's version number and exit
```

### Quick demo (no real packets needed)

The `--demo` flag generates a small, fully synthetic capture (no internet
traffic) that exercises every analysis section, including all four suspicious
patterns, and analyzes it:

```bash
pcap-insight --demo
```

### Analyzing your own capture

```bash
# Full report
pcap-insight capture.pcap

# Narrow to one host
pcap-insight capture.pcap --filter 'host 10.0.0.5'

# Narrow to HTTPS and dump JSON for jq
pcap-insight capture.pcap --filter 'tcp port 443' --export json | jq .summary

# Skip org/ASN lookup (offline environments, scripting, faster runs)
pcap-insight capture.pcap --no-enrich
```

### Sample output

`pcap-insight --demo` produces (Rich is detected, so output is plain text if a
non-Rich terminal is used; columns shown here are abbreviated):

```
Summary
 Metric               Value
 Total packets        27
 Capture duration     13.00 s
 Total bytes          1.2 KB
 Average packet size  45 B
 First packet (UTC)   2023-11-14 22:13:20.000000 UTC
 Last packet (UTC)    2023-11-14 22:13:33.000000 UTC

Protocol breakdown
 Protocol  Packets  Percent
 TCP       18       66.7%
 ARP       3        11.1%
 DNS       2        7.4%
 TLS       2        7.4%
 HTTP      1        3.7%
 ICMP      1        3.7%

Top talkers by packet count
 Source         Source Org  Destination    Dest Org  Packets
 10.0.0.50      Private     10.0.0.1       Private   15
 10.0.0.2       Private     93.184.216.34  Unknown   2
 10.0.0.2       Private     8.8.8.8        Unknown   2
 10.0.0.60      Private     10.0.0.61      Private   2
 93.184.216.34  Unknown     10.0.0.2       Private   1
 10.0.0.61      Private     10.0.0.60      Private   1
 10.0.0.2       Private     10.0.0.99      Private   1

Top talkers by byte volume
 Source         Source Org  Destination    Dest Org  Bytes
 10.0.0.50      Private     10.0.0.1       Private   600 B
 10.0.0.2       Private     93.184.216.34  Unknown   262 B
 10.0.0.2       Private     8.8.8.8        Unknown   143 B
 10.0.0.60      Private     10.0.0.61      Private   80 B
 93.184.216.34  Unknown     10.0.0.2       Private   63 B
 10.0.0.61      Private     10.0.0.60      Private   40 B
 10.0.0.2       Private     10.0.0.99      Private   28 B

Top destination ports
 Port   Service  Packets
 80     http     3
 53     domain   2
 443    https    1
 50001  unknown  1
 1024   unknown  1
 1025   unknown  1
 1026   unknown  1
 1027   unknown  1
 1028   unknown  1
 1029   unknown  1

Suspicious patterns (heuristics, not ground truth)
 Type                     Severity  Summary
 plaintext-credentials    high      1 plaintext credential exposure(s) in HTTP traffic
 syn-scan                 medium    1 source(s) with many unanswered SYN packets (possible port scan)
 dns-tunneling-candidate  medium    1 DNS quer(ies) with high-entropy or long subdomains (threshold entropy>3.5 & len>=18)
 arp-spoofing-candidate   medium    1 IP(s) mapped to multiple MAC addresses in ARP replies
  - [packet #1] 10.0.0.2 -> 93.184.216.34: HTTP Basic Authorization header (POST /login HTTP/1.1)
  - 10.0.0.50: 15 SYN(s) sent, only 0 SYN-ACK(s) observed in return
  - a1b2c3d4e5f6a7b8c9d0e1f2.example.com (subdomain 'a1b2c3d4e5f6a7b8c9d0e1f2', len=24, entropy=3.92, packet #3)
  - 192.168.1.1 claimed by MACs: aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:ff
```

### JSON export

```bash
pcap-insight capture.pcap --export json > report.json
```

```json
{
  "summary": {
    "total_packets": 27,
    "duration_seconds": 13.0,
    "total_bytes": 1216,
    "avg_packet_size": 45.04,
    "start_time": 1700000000.0,
    "end_time": 1700000013.0,
    "start_time_utc": "2023-11-14 22:13:20.000000+00:00",
    "end_time_utc": "2023-11-14 22:13:33.000000+00:00"
  },
  "protocols": [
    {"protocol": "TCP", "count": 18, "percent": 66.67},
    {"protocol": "ARP", "count": 3, "percent": 11.11},
    {"protocol": "DNS", "count": 2, "percent": 7.41},
    {"protocol": "TLS", "count": 2, "percent": 7.41},
    {"protocol": "HTTP", "count": 1, "percent": 3.7},
    {"protocol": "ICMP", "count": 1, "percent": 3.7}
  ],
  "top_talkers_by_packets": [
    {"src": "10.0.0.50", "dst": "10.0.0.1", "src_org": "Private", "dst_org": "Private", "packets": 15}
  ],
  "top_talkers_by_bytes": [
    {"src": "10.0.0.50", "dst": "10.0.0.1", "src_org": "Private", "dst_org": "Private", "bytes": 600}
  ],
  "top_ports": [
    {"port": 80, "count": 3, "service": "http"}
  ],
  "suspicious_findings": [
    {
      "type": "plaintext-credentials",
      "severity": "high",
      "summary": "1 plaintext credential exposure(s) in HTTP traffic",
      "details": ["[packet #1] 10.0.0.2 -> 93.184.216.34: HTTP Basic Authorization header (POST /login HTTP/1.1)"]
    }
  ]
}
```

### BPF filter subset

`--filter` accepts a practical tcpdump subset, applied over our normalized
packet records **without requiring libpcap/Npcap**:

| Primitive | Examples |
|---|---|
| Protocol | `tcp`, `udp`, `icmp`, `arp`, `ip` |
| Host | `host 10.0.0.5`, `src host 10.0.0.5`, `dst host 10.0.0.5` |
| Network | `net 192.168.0.0/16`, `src net 10.0.0.0/8`, `dst net 172.16.0.0/12` |
| Port | `port 443`, `src port 53`, `dst port 22` |
| Port range | `portrange 8000-8080`, `dst portrange 1024-2048` |
| Combinators | `and`, `or`, `not`, `(`, `)` |

Examples:

```bash
pcap-insight capture.pcap --filter 'tcp port 443'
pcap-insight capture.pcap --filter 'udp port 53 and not src host 8.8.8.8'
pcap-insight capture.pcap --filter 'src net 10.0.0.0/8 and dst portrange 1-1024'
```

Not supported (explicit errors): IPv6 addresses, ethernet primitives
(`ether host`, `ether proto`, VLAN), and the full libpcap language. Note that
our protocol labels are transport-aware: `tcp` matches packets marked HTTP or
TLS too, because they ride inside TCP.

---

## How the suspicious-pattern heuristics work (and when they lie)

The four detectors are intentionally simple, deterministic rules. They are
meant to be **flagging heuristics, not ground truth**. Each detector is
unit-tested against a synthetic capture in `tests/`.

### 1. Plaintext credentials over HTTP

**Rule.** For each packet whose payload parses as an HTTP request
(`METHOD SP path SP HTTP/x.y`), flag it if:

- headers contain an `Authorization:` header starting with `Basic ` (base64
  credentials), or
- the request body contains a form field matching `pass|pwd|password|passwd|...=`
  (case-insensitive).

**Why it's noisy / false positives.**

- `pass` matches substrings like `passphrase`, `passcode`, `bypass`, `compass` in
  body field names.
- The detector cannot tell whether `https://` traffic is in scope, whether the
  page is a honeypot, or whether the field is client-side encryption.
- Only *outbound requests* are examined; the detector does not parse chunked
  bodies, gzip, or HTTP/2 (which are not plaintext HTTP/1.1 request lines).
- Capture tools may log login forms that are part of a product demo or
  intentionally public form (e.g. `username=admin&password=admin` on a test rig).

### 2. Unanswered SYN bursts (possible SYN scan)

**Rule.** Count per source IP:

- every TCP packet with `SYN` set and `ACK` clear (the first step of a
  handshake *or* a probe), and
- the number of `SYN+ACK` replies received by that same IP.

Flag sources with ≥ 10 SYNs where fewer than half of them got answered.

**False positives / caveats.**

- TCP retransmissions of a legitimately-unreachable connection will show up as
  repeated unanswered SYNs and can trip the rule.
- An aggressive load balancer or health-checker firing many connections at once
  (e.g. an attacker's *own* NAT egress with short `connect` timeouts) looks
  identical without a response stream.
- Asymmetric captures (SPAN only on one side) will see the SYNs but not the
  replies, producing a false "scan".
- The threshold (10 SYNs, <50% answered) is arbitrary; tune via the
  `SYN_SCAN_MIN_SYNS` constant in `pcap_insight/analyzers.py`.

### 3. DNS tunneling / C2 beaconing

**Rule.** For each DNS query with a qname, strip the registrable domain (using
a small internal public-suffix list, see caveats) and compute the **Shannon
entropy** (in bits) of the subdomain. Flag a query when either:

- subdomain entropy > **3.5 bits** *and* subdomain length ≥ 18 characters, or
- subdomain length exceeds 18 + 20 = 38 characters (long even if low-entropy,
  e.g. repeated `aaaa...`).

Reversed IP-literal names (`4.4.8.8.in-addr.arpa`, `abcd.ef01.example.com`
hex-literal styles) are excluded because they are routine infrastructure.

Managed cloud zones are also folded into the "registrable" side: for AWS,
CloudFront, Azure, Google APIs, Fastly and Microsoft endpoints the label
directly above the provider zone is provider-controlled
(`codewhisperer.us-east-1.amazonaws.com`, `d123abc456.cloudfront.net`,
`mobile.events.data.microsoft.com`), so those are treated as registered
hostnames rather than random subdomains. Random labels *above* the managed
zone (e.g. `<rand>.<rand>.amazonaws.com`) are still flagged.

Repeated queries for the same qname are reported **once**. Retries and cache
misses are normal, and flagging every retry adds noise. The finding counts
unique qnames, not query packets.

**False positives / caveats.**

- Entropy thresholds are approximate. Legitimate random-looking labels such as
  CDN hostnames, tracking query subdomains, unique cache-busting identifiers,
  and `crypto`/`uuid`-style API hostnames regularly exceed 3.5 bits.
- Our public-suffix list is **not** the full
  [Public Suffix List](https://publicsuffix.org/) (which is huge and changes
  frequently), so a domain like `foo.example.co.uk` may be split as a
  registrable domain of `co.uk`, leaving `foo.example` as "subdomain", and a
  short random label there could produce a false positive.
- The managed-zone list is a short allowlist. Zones not on it (other CDNs,
  cloud providers, or a cloud-hosted SaaS you use) will still false-positive on
  their random-looking-but-legitimate hostnames. Extend `_MANAGED_ZONES` in
  `pcap_insight/analyzers.py` for your environment.
- Long base64/hex blobs are the classic tunnel/c2 signature, but the same shape
  appears in legitimate DNS-based CDN sign-ups and DoH/DoT era infra.
- This detector fires on individual queries; real tunneling detection also uses
  per-domain query volume, query-size distribution, and query-timing regularity,
  which this tool does **not** implement.

### 4. ARP replies: one IP claimed by multiple MACs

**Rule.** Collect the set of sender MACs claimed for each sender IP **in ARP
reply packets** (`op=2`). Flag any IP claimed by more than one distinct MAC
within the capture.

**False positives / caveats.**

- **Legitimate multi-MAC scenarios are the most common false positive:**
  - a server NIC with multiple aliases/VLANs advertising the same IP from
    different physical NICs (port channels, load balancers with active/standby);
  - a scripted failover where both the old and new MAC answer during the
    transition window;
  - capture-file merging: two capture files from different network segments
    naturally share IPs but have different MACs.
- ARP requests (`op=1`) are deliberately ignored: a request for `who-has X`
  does *not* mean the sender is claiming `X`.
- The detector needs both replies in the *same* capture; if your capture window
  straddles a legitimate failover, both MACs will appear.

---

## Detector thresholds at a glance

| Detector | Key thresholds (constants in `analyzers.py`) |
|---|---|
| Plaintext credentials | `Basic` auth header OR body regex `(pass|pwd|password|passwd|user_pass|client_secret)=` |
| SYN scan | ≥ `SYN_SCAN_MIN_SYNS` = 10 SYNs; < 50% answered |
| DNS tunneling | subdomain entropy > `DNS_ENTROPY_THRESHOLD` = 3.5 and len ≥ 18; OR len > `SUBNAME_PADDING` + 18 = 38 |
| ARP spoofing | ≥ 2 distinct sender MACs for one sender IP in ARP replies |

These numbers are starting points, not research-backed tuning. Adjust them in
`pcap_insight/analyzers.py` and re-run the test suite.

---

## Development

Assumes you've already created and activated a virtual environment (see
[Installation](#installation) above).

```bash
python -m pip install -e ".[dev]"
python -m pytest -v
```

The suite (78 tests) covers:

- Shannon-entropy correctness against the reference formula and known strings
- protocol counting / percentages / sort order
- top-talker and top-port aggregation, service-name fallback
- each suspicious-pattern detector: hit cases, clean cases, and boundary cases
- the BPF filter engine (parsing, qualifiers, combinators, invalid filters)
- end-to-end CLI tables, JSON export, JSON + filter, and `--demo`
- enrichment behavior (private-IP short-circuit, cache, failure handling)
- parsing of the synthetic `tests/` fixture capture (Scapy-generated in a
  session fixture; no external pcap files)

### Project layout

```
pcap-insight/
  pcap_insight/
    __init__.py     # package metadata / version
    parser.py       # Scapy reading -> PacketRecord, plus the BPF-subset engine
    analyzers.py    # stats + four heuristic detectors (pure, testable)
    cli.py          # argparse, rich rendering, JSON export
    enrichment.py   # offline GeoLite2-ASN org lookup (cache + private detection)
    testing.py      # synthetic capture builder (used by tests and --demo)
  tests/
    conftest.py     # session fixtures (creates the synthetic capture)
    test_analyzers.py
    test_filter.py
    test_cli.py
    test_enrichment.py
  README.md
  requirements.txt
  pyproject.toml    # pip-installable, console script: pcap-insight
```

---

## Requirements

- Python 3.10+
- `scapy` ≥ 2.5
- `rich` ≥ 13
- `geoip2` ≥ 4 (used for optional org/ASN enrichment)
- `pytest` ≥ 8 (dev only)

See `requirements.txt` for pinned minimums.
