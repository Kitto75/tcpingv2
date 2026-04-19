#!/usr/bin/env python3
"""Simple TCP ping scanner for IPs, domains, and CIDR subnets."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import random
import socket
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Sequence


@dataclass
class ScanResult:
    input_target: str
    resolved_host: str
    port: int
    success: bool
    latency_ms: float | None
    error: str | None
    timestamp_utc: str


class Colors:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"


class Logger:
    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color

    def _paint(self, text: str, color: str) -> str:
        if not self.use_color:
            return text
        return f"{color}{text}{Colors.RESET}"

    def info(self, msg: str) -> None:
        print(self._paint("[INFO]", Colors.CYAN), msg)

    def ok(self, msg: str) -> None:
        print(self._paint("[ OK ]", Colors.GREEN), msg)

    def warn(self, msg: str) -> None:
        print(self._paint("[WARN]", Colors.YELLOW), msg)

    def error(self, msg: str) -> None:
        print(self._paint("[FAIL]", Colors.RED), msg)

    def summary(self, msg: str) -> None:
        print(self._paint("[DONE]", Colors.BOLD), msg)


def parse_ports(ports_raw: str) -> List[int]:
    ports: list[int] = []
    for part in ports_raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", maxsplit=1)
            a, b = int(start), int(end)
            if a > b:
                a, b = b, a
            ports.extend(range(a, b + 1))
        else:
            ports.append(int(part))

    unique: list[int] = []
    seen = set()
    for p in ports:
        if p < 1 or p > 65535:
            raise ValueError(f"Invalid port: {p}")
        if p not in seen:
            seen.add(p)
            unique.append(p)
    if not unique:
        raise ValueError("No valid ports were provided")
    return unique


DEFAULT_TEST_TARGETS = ["google.com", "cloudflare.com"]


def parse_targets(raw_targets: Sequence[str], target_list_file: str | None, logger: Logger) -> List[str]:
    targets: list[str] = []

    for raw in raw_targets:
        targets.extend(item.strip() for item in raw.split(",") if item.strip())

    if target_list_file:
        file_path = Path(target_list_file)
        if not file_path.exists():
            raise FileNotFoundError(f"Target list file does not exist: {target_list_file}")
        for line in file_path.read_text(encoding="utf-8").splitlines():
            item = line.strip()
            if not item or item.startswith("#"):
                continue
            targets.append(item)

    if not targets:
        logger.info(
            "No targets provided, using default test targets: "
            + ", ".join(DEFAULT_TEST_TARGETS)
        )
        targets.extend(DEFAULT_TEST_TARGETS)

    expanded: list[str] = []
    for target in targets:
        if "/" in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                logger.warn(f"Skipping invalid subnet: {target}")
                continue
            hosts = [str(ip) for ip in net.hosts()]
            if not hosts:
                hosts = [str(net.network_address)]
            logger.info(f"Expanded subnet {target} -> {len(hosts)} host(s)")
            expanded.extend(hosts)
        else:
            expanded.append(target)

    deduped: list[str] = []
    seen = set()
    for item in expanded:
        if item not in seen:
            seen.add(item)
            deduped.append(item)

    return deduped


def tcping(host: str, port: int, timeout_seconds: float) -> tuple[bool, float | None, str | None, str]:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            elapsed_ms = (time.perf_counter() - started) * 1000
            return True, elapsed_ms, None, timestamp
    except OSError as exc:
        return False, None, str(exc), timestamp


def save_successful(results: Sequence[ScanResult], out_path: str, logger: Logger) -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    success_rows = [r for r in results if r.success]

    if path.suffix.lower() == ".json":
        payload = [r.__dict__ for r in success_rows]
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "input_target",
                    "resolved_host",
                    "port",
                    "success",
                    "latency_ms",
                    "timestamp_utc",
                ],
            )
            writer.writeheader()
            for row in success_rows:
                writer.writerow(
                    {
                        "input_target": row.input_target,
                        "resolved_host": row.resolved_host,
                        "port": row.port,
                        "success": row.success,
                        "latency_ms": f"{row.latency_ms:.2f}" if row.latency_ms is not None else "",
                        "timestamp_utc": row.timestamp_utc,
                    }
                )
    else:
        lines = []
        for row in success_rows:
            lines.append(
                f"{row.input_target} ({row.resolved_host}):{row.port} {row.latency_ms:.2f} ms @ {row.timestamp_utc}"
            )
        path.write_text("\n".join(lines), encoding="utf-8")

    logger.ok(f"Saved {len(success_rows)} successful result(s) to {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tcping_scanner.py",
        description=(
            "TCPing scanner (v2rayNG-style TCP connect latency check) for domains, IPs, and CIDR subnets."
        ),
        epilog=(
            "Examples:\n"
            "  python tcping_scanner.py --targets google.com,1.1.1.1,192.168.1.0/30 --ports 443,80 --timeout-ms 2000\n"
            "  python tcping_scanner.py --target-list-file cidr_or_domains_targets.txt --ports 443 --save-success successes.json\n"
            "  python tcping_scanner.py --ports 443  # Uses default test targets (google.com, cloudflare.com)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        default=[],
        help="Targets separated by comma and/or spaces. Supports domains, IPs, and subnets (CIDR).",
    )
    parser.add_argument(
        "--target-list-file",
        "--target-file",
        dest="target_list_file",
        help=(
            "Optional file with one target per line (# for comments). "
            "Use this for CIDR, domain, or IP target lists."
        ),
    )
    parser.add_argument(
        "--ports",
        required=True,
        help="Port list, e.g. 443 or 80,443 or 1-1024",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=2000,
        help="TCP connection timeout in milliseconds (default: 2000)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Retry attempts per target/port after the first failed attempt (default: 0).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help=(
            "Number of concurrent workers. Default (0) auto-tunes based on workload "
            "for faster v2rayNG-style burst testing."
        ),
    )
    parser.add_argument(
        "--save-success",
        help="Output file for successful results (.txt, .json, .csv).",
    )
    parser.add_argument(
        "--random-order",
        action="store_true",
        help="Run checks in random order. Default is deterministic input order.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored logs.",
    )
    return parser


def print_result(result: ScanResult, logger: Logger) -> None:
    endpoint = f"{result.input_target} -> {result.resolved_host}:{result.port}"
    if result.success:
        logger.ok(f"{endpoint}  latency={result.latency_ms:.2f} ms")
    else:
        logger.error(f"{endpoint}  error={result.error}")


def choose_workers(total_checks: int, requested_workers: int) -> int:
    if requested_workers > 0:
        return requested_workers

    # TCPing is network-bound; allow high parallelism by default so results appear quickly.
    return max(1, min(200, total_checks))


def run_scan(
    targets: Sequence[str],
    ports: Sequence[int],
    timeout_ms: int,
    retries: int,
    workers: int,
    random_order: bool,
    logger: Logger,
) -> list[ScanResult]:
    indexed_checks = [
        (target, port, index) for index, (target, port) in enumerate((t, p) for t in targets for p in ports)
    ]
    if random_order:
        random.shuffle(indexed_checks)
    results_by_index: dict[int, ScanResult] = {}

    def run_one(target: str, port: int) -> ScanResult:
        timeout_seconds = timeout_ms / 1000.0
        last_error: str | None = None
        last_timestamp: str | None = None

        for attempt in range(retries + 1):
            success, latency_ms, error, timestamp = tcping(target, port, timeout_seconds)
            if success:
                return ScanResult(
                    input_target=target,
                    resolved_host=target,
                    port=port,
                    success=True,
                    latency_ms=latency_ms,
                    error=None,
                    timestamp_utc=timestamp,
                )
            last_error = error
            last_timestamp = timestamp
            if attempt < retries:
                continue

        return ScanResult(
            input_target=target,
            resolved_host=target,
            port=port,
            success=False,
            latency_ms=None,
            error=last_error,
            timestamp_utc=last_timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map: dict[Future[ScanResult], int] = {
            executor.submit(run_one, target, port): index for target, port, index in indexed_checks
        }
        for future in as_completed(future_map):
            index = future_map[future]
            row = future.result()
            results_by_index[index] = row
    ordered_results = [results_by_index[i] for i in range(len(indexed_checks))]
    for row in ordered_results:
        print_result(row, logger)
    return ordered_results


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    color_enabled = (not args.no_color) and sys.stdout.isatty()
    logger = Logger(use_color=color_enabled)

    if args.timeout_ms <= 0:
        logger.error("--timeout-ms must be > 0")
        return 2
    if args.workers < 0:
        logger.error("--workers must be >= 0")
        return 2
    if args.retries < 0:
        logger.error("--retries must be >= 0")
        return 2

    try:
        ports = parse_ports(args.ports)
        targets = parse_targets(args.targets, args.target_list_file, logger)
    except (ValueError, FileNotFoundError) as exc:
        logger.error(str(exc))
        return 2

    total_checks = len(targets) * len(ports)
    workers = choose_workers(total_checks=total_checks, requested_workers=args.workers)
    logger.info(
        "Starting TCPing scan: "
        f"{len(targets)} target(s), {len(ports)} port(s), timeout={args.timeout_ms}ms, "
        f"retries={args.retries}, workers={workers}, random_order={args.random_order}"
    )

    results = run_scan(
        targets=targets,
        ports=ports,
        timeout_ms=args.timeout_ms,
        retries=args.retries,
        workers=workers,
        random_order=args.random_order,
        logger=logger,
    )

    total = len(results)
    success_count = sum(1 for r in results if r.success)
    fail_count = total - success_count

    latencies = [r.latency_ms for r in results if r.success and r.latency_ms is not None]
    if latencies:
        min_ms = min(latencies)
        avg_ms = sum(latencies) / len(latencies)
        max_ms = max(latencies)
        logger.summary(
            f"Total={total}  Success={success_count}  Failed={fail_count}  Latency(ms): min={min_ms:.2f} avg={avg_ms:.2f} max={max_ms:.2f}"
        )
    else:
        logger.summary(f"Total={total}  Success={success_count}  Failed={fail_count}")

    if args.save_success:
        save_successful(results, args.save_success, logger)

    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
