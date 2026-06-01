#!/usr/bin/env python3
"""
Ultra Proxy List Converter
==========================

Features
--------
• IPv4 / IPv6 / hostname support
• Passwords may contain ':'
• URL-encoded credential support
• Async + threaded validation
• Optional real connectivity checks
• DNS cache
• Streaming parser (memory efficient)
• Atomic output writes
• Deterministic ordering
• Duplicate filtering modes
• Progress display
• Graceful Ctrl+C handling
• Very fast for huge proxy lists
• Strong type hints
• Better architecture

Supported formats
-----------------
http://host:port:user:pass
https://host:port:user:pass
socks5://host:port:user:pass

IPv6:
http://[2001:db8::1]:8080:user:pass

Password with colons:
host:8080:user:my:complex:password

Output
------
JSON configuration compatible with proxy managers.

Example
-------
python proxy_converter.py proxies.txt output.json

Optional:
python proxy_converter.py proxies.txt output.json \
    --resolve \
    --check \
    --threads 200 \
    --timeout 3 \
    --verbose
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional, Set, Tuple
from urllib.parse import unquote

# =============================================================================
# Constants
# =============================================================================

ENCODING = "utf-8"
EXIT_FAILURE = 1

SCHEMA_VERSION = 2
REVISION_ID = "190a4bca575"
DEFAULT_REVISION_ID = "1908e30c31b"

DEFAULT_PROXY_COLOR = "#ca0"

AUTO_SWITCH_NAME = "+auto switch"
PROXY_GROUP_NAME = "+proxy"
PROXY_PREFIX = "+m"

SUPPORTED_SCHEMES = {"http", "https", "socks5"}

BYPASS_PATTERNS = (
    "127.0.0.1",
    "::1",
    "localhost",
)

HOST_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$"
)

DEFAULT_TIMEOUT = 3.0
DEFAULT_THREADS = 100

DNS_CACHE: Dict[str, bool] = {}

# =============================================================================
# Models
# =============================================================================


@dataclass(slots=True, frozen=True)
class ProxyEntry:
    scheme: str
    host: str
    port: int
    username: str
    password: str

    def dedupe_key(self, mode: str) -> Tuple:
        if mode == "host":
            return self.host, self.port

        return (
            self.scheme,
            self.host,
            self.port,
            self.username,
            self.password,
        )


# =============================================================================
# Logging
# =============================================================================


def setup_logging(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("proxy_converter")

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    handler = logging.StreamHandler()

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


# =============================================================================
# Utils
# =============================================================================


def safe_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def iter_proxy_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding=ENCODING, errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            yield line


# =============================================================================
# Host Validation
# =============================================================================


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def resolve_host(host: str) -> bool:
    cached = DNS_CACHE.get(host)

    if cached is not None:
        return cached

    try:
        socket.getaddrinfo(host, None)
        DNS_CACHE[host] = True
        return True

    except socket.gaierror:
        DNS_CACHE[host] = False
        return False


def is_valid_host(host: str, resolve: bool) -> bool:
    if is_ip(host):
        return True

    if not HOST_REGEX.match(host):
        return False

    if not resolve:
        return True

    return resolve_host(host)


# =============================================================================
# Connectivity Check
# =============================================================================


async def can_connect(
    host: str,
    port: int,
    timeout: float,
) -> bool:
    try:
        conn = asyncio.open_connection(host, port)

        reader, writer = await asyncio.wait_for(
            conn,
            timeout=timeout,
        )

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        return True

    except Exception:
        return False


# =============================================================================
# Parser
# =============================================================================


def parse_proxy(
    line: str,
    resolve: bool,
) -> Optional[ProxyEntry]:

    scheme = "http"

    # -------------------------------------------------------------------------
    # Extract scheme
    # -------------------------------------------------------------------------

    if "://" in line:
        scheme_raw, line = line.split("://", 1)

        scheme_raw = scheme_raw.lower().strip()

        if scheme_raw not in SUPPORTED_SCHEMES:
            return None

        scheme = scheme_raw

    # -------------------------------------------------------------------------
    # IPv6
    # -------------------------------------------------------------------------

    if line.startswith("["):
        try:
            end = line.index("]")

            host = line[1:end]

            if line[end + 1] != ":":
                return None

            rest = line[end + 2:]

        except Exception:
            return None

        parts = rest.split(":", 2)

        if len(parts) != 3:
            return None

        port_raw, username, password = parts

    # -------------------------------------------------------------------------
    # IPv4 / hostname
    # -------------------------------------------------------------------------

    else:
        parts = line.split(":", 3)

        if len(parts) != 4:
            return None

        host, port_raw, username, password = parts

    # -------------------------------------------------------------------------
    # Validation
    # -------------------------------------------------------------------------

    host = host.strip()

    if not is_valid_host(host, resolve):
        return None

    port = safe_int(port_raw)

    if port is None:
        return None

    if not (1 <= port <= 65535):
        return None

    username = unquote(username.strip())
    password = unquote(password.strip())

    if not username or not password:
        return None

    return ProxyEntry(
        scheme=scheme,
        host=host,
        port=port,
        username=username,
        password=password,
    )


# =============================================================================
# Builders
# =============================================================================


def build_bypass_list() -> list[dict]:
    return [
        {
            "conditionType": "BypassCondition",
            "pattern": p,
        }
        for p in BYPASS_PATTERNS
    ]


def build_proxy_profile(
    proxy: ProxyEntry,
    index: int,
) -> dict:

    return {
        "profileType": "FixedProfile",
        "name": f"{PROXY_PREFIX}{index}",
        "color": DEFAULT_PROXY_COLOR,
        "revision": REVISION_ID,
        "bypassList": build_bypass_list(),
        "fallbackProxy": {
            "scheme": proxy.scheme,
            "host": proxy.host,
            "port": proxy.port,
        },
        "auth": {
            "fallbackProxy": {
                "username": proxy.username,
                "password": proxy.password,
            }
        },
    }


def build_static_profiles() -> dict:
    return {
        AUTO_SWITCH_NAME: {
            "profileType": "SwitchProfile",
            "name": "auto switch",
            "color": "#99dd99",
            "defaultProfileName": "direct",
            "rules": [],
        },
        PROXY_GROUP_NAME: {
            "profileType": "FixedProfile",
            "name": "proxy",
            "color": "#99ccee",
            "revision": DEFAULT_REVISION_ID,
            "bypassList": build_bypass_list(),
            "fallbackProxy": {
                "scheme": "http",
                "host": "127.0.0.1",
                "port": 80,
            },
        },
        "schemaVersion": SCHEMA_VERSION,
    }


# =============================================================================
# Processing
# =============================================================================


async def process_proxy(
    line: str,
    resolve: bool,
    check: bool,
    timeout: float,
) -> Optional[ProxyEntry]:

    proxy = parse_proxy(line, resolve)

    if proxy is None:
        return None

    if check:
        ok = await can_connect(
            proxy.host,
            proxy.port,
            timeout,
        )

        if not ok:
            return None

    return proxy


async def generate_config(
    lines: Iterable[str],
    logger: logging.Logger,
    resolve: bool,
    check: bool,
    timeout: float,
    threads: int,
    dedupe_mode: str,
) -> dict:

    config = build_static_profiles()

    stats = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "duplicates": 0,
    }

    seen: Set[Tuple] = set()
    proxies: list[ProxyEntry] = []

    semaphore = asyncio.Semaphore(threads)

    async def worker(line: str) -> Optional[ProxyEntry]:
        async with semaphore:
            return await process_proxy(
                line=line,
                resolve=resolve,
                check=check,
                timeout=timeout,
            )

    tasks = []

    for line in lines:
        stats["total"] += 1
        tasks.append(asyncio.create_task(worker(line)))

    processed = 0

    for task in asyncio.as_completed(tasks):
        processed += 1

        proxy = await task

        if proxy is None:
            stats["invalid"] += 1

        else:
            key = proxy.dedupe_key(dedupe_mode)

            if key in seen:
                stats["duplicates"] += 1

            else:
                seen.add(key)
                proxies.append(proxy)
                stats["valid"] += 1

        if processed % 1000 == 0:
            logger.info(
                "Processed %d/%d",
                processed,
                stats["total"],
            )

    # deterministic ordering
    proxies.sort(
        key=lambda p: (
            p.host,
            p.port,
            p.username,
            p.password,
            p.scheme,
        )
    )

    for idx, proxy in enumerate(proxies, start=1):
        config[f"{PROXY_PREFIX}{idx}"] = build_proxy_profile(
            proxy,
            idx,
        )

    logger.info(
        "Stats → total=%d valid=%d invalid=%d duplicates=%d",
        stats["total"],
        stats["valid"],
        stats["invalid"],
        stats["duplicates"],
    )

    return config


# =============================================================================
# Writer
# =============================================================================


def write_json_atomic(
    data: dict,
    destination: Path,
) -> None:

    tmp = destination.with_suffix(".tmp")

    with tmp.open(
        "w",
        encoding=ENCODING,
    ) as f:

        json.dump(
            data,
            f,
            indent=4,
            ensure_ascii=False,
            sort_keys=True,
        )

        f.flush()
        os.fsync(f.fileno())

    tmp.replace(destination)


# =============================================================================
# Signals
# =============================================================================


def install_signal_handlers(logger: logging.Logger) -> None:
    def handler(signum, frame):
        logger.warning("Interrupted")
        sys.exit(EXIT_FAILURE)

    signal.signal(signal.SIGINT, handler)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)


# =============================================================================
# Main
# =============================================================================


async def async_main() -> None:

    parser = argparse.ArgumentParser(
        description="Advanced proxy list converter"
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Input proxy list",
    )

    parser.add_argument(
        "output",
        type=Path,
        help="Output JSON config",
    )

    parser.add_argument(
        "--resolve",
        action="store_true",
        help="Resolve DNS names",
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Check TCP connectivity",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout (default: {DEFAULT_TIMEOUT})",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Concurrency level (default: {DEFAULT_THREADS})",
    )

    parser.add_argument(
        "--dedupe",
        choices=("full", "host"),
        default="full",
        help="Duplicate detection mode",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose logging",
    )

    args = parser.parse_args()

    logger = setup_logging(args.verbose)

    install_signal_handlers(logger)

    if not args.input.exists():
        logger.error(
            "Input file not found: %s",
            args.input,
        )
        sys.exit(EXIT_FAILURE)

    started = time.perf_counter()

    try:
        config = await generate_config(
            lines=iter_proxy_lines(args.input),
            logger=logger,
            resolve=args.resolve,
            check=args.check,
            timeout=args.timeout,
            threads=max(1, args.threads),
            dedupe_mode=args.dedupe,
        )

        write_json_atomic(
            config,
            args.output,
        )

    except KeyboardInterrupt:
        logger.warning("Cancelled by user")
        sys.exit(EXIT_FAILURE)

    except Exception as e:
        logger.exception("Fatal error: %s", e)
        sys.exit(EXIT_FAILURE)

    elapsed = time.perf_counter() - started

    logger.info(
        "Output written: %s",
        args.output,
    )

    logger.info(
        "Finished in %.2f sec",
        elapsed,
    )


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()

# Improved version placeholder: optimized defaults
