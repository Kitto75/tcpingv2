# tcpingv2 (simple)

This checks **TCP connect time** only (not ICMP ping, not HTTP response body).

---

## 1) Fast start

Use default test hosts:

```bash
python tcping_scanner.py -p 443
```

Use your own hosts:

```bash
python tcping_scanner.py -t google.com cloudflare.com 1.1.1.1 -p 443
```

Use a file:

```bash
python tcping_scanner.py -f cidr_or_domains_targets.txt -p 443
```

---

## 2) Live output (now)

When running, you now see:

- each result as soon as it finishes
- a moving spinner (◐ ◓ ◑ ◒)
- live progress (`done/total`)
- estimated remaining time (`eta`)

So you can see that the script is active and not frozen.

---

## 3) Short options (easy)

| Short | Long | Meaning |
|---|---|---|
| `-t` | `--targets` | hosts/subnets in command |
| `-f` | `--target-list-file` | file with targets |
| `-p` | `--ports` | ports (required) |
| `-T` | `--timeout-ms` | timeout in milliseconds |
| `-r` | `--retries` | checks per target/port (`-r 5` = 5 tests each) |
| `-w` | `--workers` | parallel workers |
| `-o` | `--save-success` | save successful checks |
|  | `--retry-report-file` | retry summary output path |
| `-R` | `--random-order` | randomize check order |
| `-C` | `--no-color` | disable colors |

---

## 4) Most useful examples

Timeout + repeated checks:

```bash
python tcping_scanner.py -t google.com -p 443 -T 1200 -r 2
```

When `-r` / `--retries` is greater than `0`, each target/port is tested exactly `r` times and the scanner writes a JSON summary file (`retry_summary.json` by default) with:

- total completed checks
- number of successful checks
- number of failed checks
- success rate percentage
- per-IP score (successful tests vs total tests)
- per-IP successful speeds (`successful_speeds_ms`)

Use a custom path:

```bash
python tcping_scanner.py -t google.com -p 443 -r 2 --retry-report-file reports/retry_summary.json
```

Multiple ports:

```bash
python tcping_scanner.py -t google.com -p 80,443,8443
```

CIDR:

```bash
python tcping_scanner.py -t 192.168.1.0/30 -p 443
```

High concurrency (recommended for big scans):

```bash
python tcping_scanner.py -t 192.168.1.0/30 -p 443 -w 1000
```

Save successes:

```bash
python tcping_scanner.py -f cidr_or_domains_targets.txt -p 443 -o success.json
```

---

## 5) Target file format

One target per line:

```txt
# domain
google.com

# ip
1.1.1.1

# cidr
192.168.1.0/30
```

---

## 6) Exit codes

- `0` = at least one success
- `1` = finished but no success
- `2` = bad input/arguments

---

## Help

```bash
python tcping_scanner.py --help
```
