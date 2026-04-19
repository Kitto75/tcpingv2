# tcpingv2

A simple TCPing scanner inspired by the **TCPing test in v2rayNG**.

It checks pure TCP connect latency (no HTTP/ICMP), and supports:
- custom IPs
- domains
- CIDR subnets
- customizable timeout in milliseconds
- retry attempts on failures
- saving **successful** results only
- clean, useful logs with optional color output

## Features

- **TCP-only test**: Measures TCP connect success and latency (`ms`).
- **Flexible targets**:
  - Direct list (`--targets`)
  - File input (`--target-list-file`) for CIDR/domain/IP lists
  - Subnet expansion (`192.168.1.0/24`)
  - Built-in defaults if no target is provided: `google.com`, `cloudflare.com`
- **Multi-port scan**:
  - Single port: `443`
  - Comma list: `80,443,8443`
  - Range: `1-1024`
- **Configurable timeout in milliseconds** with `--timeout-ms`.
- **Retry support** with `--retries`.
- **High-speed concurrent testing** (auto worker tuning, configurable with `--workers`).
- **Colored log output** (auto-enabled on TTY; disable with `--no-color`).
- **Save successful results** only to:
  - `.txt`
  - `.json`
  - `.csv`

---

## Requirements

- Python 3.9+
- No external dependencies

---

## Usage

```bash
python tcping_scanner.py --ports 443 --targets google.com 1.1.1.1 8.8.8.0/30
```

### Basic examples

Test domains and IPs on port 443:

```bash
python tcping_scanner.py --targets google.com cloudflare.com 1.1.1.1 --ports 443
```

Test mixed targets and ports with custom timeout (ms):

```bash
python tcping_scanner.py --targets google.com,1.1.1.1,192.168.1.0/30 --ports 80,443 --timeout-ms 1500
```

Run a very fast burst test (similar to v2rayNG behavior) by increasing worker count:

```bash
python tcping_scanner.py --target-list-file cidr_or_domains_targets.txt --ports 443 --timeout-ms 1000 --workers 150
```

Use a clearly named target list file (for CIDR/domains/IPs):

```bash
python tcping_scanner.py --target-list-file cidr_or_domains_targets.txt --ports 443 --timeout-ms 2000
```

Save only successful results:

```bash
python tcping_scanner.py --target-list-file cidr_or_domains_targets.txt --ports 443 --save-success success.json
```

Use default test targets (if you don't pass `--targets` or `--target-list-file`):

```bash
python tcping_scanner.py --ports 443
```

Retry failed checks (2 retries after first failure):

```bash
python tcping_scanner.py --targets google.com cloudflare.com --ports 443 --retries 2 --timeout-ms 1200
```

Disable colors:

```bash
python tcping_scanner.py --targets google.com --ports 443 --no-color
```

---

## Target file format (`cidr_or_domains_targets.txt`)

One target per line. Empty lines and comments are ignored.

```txt
# Domains
google.com
cloudflare.com

# IPs
1.1.1.1
8.8.8.8

# Subnet (CIDR)
192.168.1.0/30
```

Suggested clear file naming:
- `cidr_or_domains_targets.txt` → for your CIDR/domain/IP list used by `--target-list-file`.
- (Optional) keep a separate notes file like `default_test_domains.txt` for quick copy/paste into `--targets`.

---

## Output behavior

During scan, each check prints a line showing:
- input target
- tested endpoint (`host:port`)
- `latency` if success
- `error` if failed

Checks are executed concurrently, so results appear quickly as each worker completes.

At the end, it prints summary with:
- total checks
- success/failed count
- min/avg/max latency (if at least one success)

Exit codes:
- `0`: at least one successful TCP connection
- `1`: scan finished but no successful connection
- `2`: invalid arguments/input errors

---

## Save-success output formats

### TXT (`.txt`)
Human-readable lines:

```txt
google.com (google.com):443 18.42 ms @ 2026-04-19T10:00:00+00:00
```

### JSON (`.json`)
Array of successful result objects.

### CSV (`.csv`)
Columns:
- `input_target`
- `resolved_host`
- `port`
- `success`
- `latency_ms`
- `timestamp_utc`

---

## Complete command help

Run:

```bash
python tcping_scanner.py --help
```

You will see:
- all flags
- examples
- accepted formats for targets and ports

---

## Notes

- This is a **TCP connect test** (like tcping), not ICMP ping.
- Domain resolution is handled by the system resolver used by Python sockets.
- Large subnets can create many checks; start with smaller CIDRs first.
