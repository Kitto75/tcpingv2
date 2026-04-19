# tcpingv2

Simple TCP connect latency scanner inspired by the TCPing experience in v2rayNG.

It measures **TCP connect time only** (not ICMP ping, not HTTP response time).

## Quick start (simplest ways)

Run with built-in defaults:

```bash
python tcping_scanner.py --ports 443
```

Run explicit targets:

```bash
python tcping_scanner.py --targets google.com cloudflare.com 1.1.1.1 --ports 443
```

Run from a target file:

```bash
python tcping_scanner.py --target-list-file cidr_or_domains_targets.txt --ports 443
```

## What it supports

- Domains, IPs, and CIDR subnets.
- Port input as single (`443`), list (`80,443`), or range (`1-1024`).
- Timeout in milliseconds (`--timeout-ms`).
- Retries (`--retries`).
- Concurrent workers (`--workers`).
- Save successful results only (`--save-success`) to `.txt`, `.json`, `.csv`.
- Optional random test order (`--random-order`).

## Ordered by default (not random)

Default behavior is deterministic and follows your input order.

- If you want random execution order, add:

```bash
python tcping_scanner.py --targets google.com cloudflare.com --ports 443 --random-order
```

## v2rayNG-style inner test sample addresses

If you want sample connectivity test URLs often used in proxy apps (including v2ray ecosystem testing), these are common examples:

- `http://www.gstatic.com/generate_204`
- `https://www.gstatic.com/generate_204`
- `http://connectivitycheck.gstatic.com/generate_204`

> Note: this tool is TCP-only, so it tests host:port connectivity (for example `www.gstatic.com:80` or `www.gstatic.com:443`), not URL path response content.

## Target file format (`cidr_or_domains_targets.txt`)

One target per line. Empty lines and lines starting with `#` are ignored.

```txt
# Domains
google.com
cloudflare.com

# IPs
1.1.1.1
8.8.8.8

# CIDR
192.168.1.0/30
```

## Useful examples

Custom timeout and retries:

```bash
python tcping_scanner.py --targets google.com 1.1.1.1 --ports 443 --timeout-ms 1200 --retries 2
```

Multiple ports:

```bash
python tcping_scanner.py --targets google.com --ports 80,443,8443
```

Save successes:

```bash
python tcping_scanner.py --target-list-file cidr_or_domains_targets.txt --ports 443 --save-success success.json
```

Disable colored output:

```bash
python tcping_scanner.py --targets google.com --ports 443 --no-color
```

## Exit codes

- `0`: at least one successful TCP connection.
- `1`: scan finished but no successful connections.
- `2`: invalid arguments/input errors.

## Help

```bash
python tcping_scanner.py --help
```
