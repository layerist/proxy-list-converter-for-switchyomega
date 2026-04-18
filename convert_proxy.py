#!/usr/bin/env python3
"""
Advanced Proxy List Converter (Improved)
=======================================

Major improvements:
• IPv4 + IPv6 + hostname support
• Passwords may contain ':' (fixed parsing)
• Optional DNS resolution (--resolve)
• Faster validation (no DNS by default)
• Deterministic ordering
• Better duplicate detection (configurable)
• Threaded validation for large lists
• Cleaner architecture

Author: improved version
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple, TypedDict

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

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

BYPASS_PATTERNS = ("127.0.0.1", "::1", "localhost")

HOST_REGEX = re.compile(r"^[a-zA-Z0-9.-]+$")

# -----------------------------------------------------------------------------
# Types
# -----------------------------------------------------------------------------

class ProxyEntry(TypedDict):
    scheme: str
    host: str
    port: int
    username: str
    password: str


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

def setup_logging(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("proxy_converter")

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(levelname)s: %(message)s")

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


# -----------------------------------------------------------------------------
# File Reader
# -----------------------------------------------------------------------------

def iter_proxy_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding=ENCODING) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

def is_valid_host(host: str, resolve: bool) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if not HOST_REGEX.match(host):
        return False

    if not resolve:
        return True

    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


# -----------------------------------------------------------------------------
# Parsing (FIXED for ':' in password + IPv6)
# -----------------------------------------------------------------------------

def parse_proxy(line: str, resolve: bool) -> Optional[ProxyEntry]:
    scheme = "http"

    if "://" in line:
        scheme_part, line = line.split("://", 1)
        scheme_part = scheme_part.lower()

        if scheme_part not in SUPPORTED_SCHEMES:
            return None

        scheme = scheme_part

    # IPv6 handling: [::1]:port:user:pass
    if line.startswith("["):
        try:
            host_end = line.index("]")
            host = line[1:host_end]
            rest = line[host_end + 2 :]  # skip ]:
        except ValueError:
            return None

        parts = rest.split(":", 2)
        if len(parts) != 3:
            return None

        port_raw, username, password = parts

    else:
        parts = line.split(":", 3)
        if len(parts) != 4:
            return None

        host, port_raw, username, password = parts

    if not is_valid_host(host, resolve):
        return None

    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            return None
    except ValueError:
        return None

    if not username or not password:
        return None

    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
    }


# -----------------------------------------------------------------------------
# Builders
# -----------------------------------------------------------------------------

def build_bypass_list() -> List[Dict[str, str]]:
    return [{"conditionType": "BypassCondition", "pattern": p} for p in BYPASS_PATTERNS]


def build_proxy_profile(entry: ProxyEntry, index: int) -> Dict:
    return {
        "profileType": "FixedProfile",
        "name": f"{PROXY_PREFIX}{index}",
        "color": DEFAULT_PROXY_COLOR,
        "revision": REVISION_ID,
        "bypassList": build_bypass_list(),
        "fallbackProxy": {
            "scheme": entry["scheme"],
            "host": entry["host"],
            "port": entry["port"],
        },
        "auth": {
            "fallbackProxy": {
                "username": entry["username"],
                "password": entry["password"],
            }
        },
    }


def build_static_profiles() -> Dict:
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


# -----------------------------------------------------------------------------
# Generator (threaded)
# -----------------------------------------------------------------------------

def generate_config(
    lines: Iterable[str],
    logger: logging.Logger,
    resolve: bool,
    threads: int,
) -> Dict:

    config = build_static_profiles()

    seen: Set[Tuple] = set()
    proxies: List[ProxyEntry] = []

    stats = {"valid": 0, "invalid": 0, "duplicates": 0}

    def process(line: str):
        return line, parse_proxy(line, resolve)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(process, line) for line in lines]

        for future in as_completed(futures):
            line, proxy = future.result()

            if proxy is None:
                stats["invalid"] += 1
                continue

            key = (
                proxy["scheme"],
                proxy["host"],
                proxy["port"],
                proxy["username"],
                proxy["password"],
            )

            if key in seen:
                stats["duplicates"] += 1
                continue

            seen.add(key)
            proxies.append(proxy)
            stats["valid"] += 1

    # Deterministic ordering
    proxies.sort(key=lambda x: (x["host"], x["port"], x["username"]))

    for i, proxy in enumerate(proxies, 1):
        config[f"{PROXY_PREFIX}{i}"] = build_proxy_profile(proxy, i)

    logger.info(
        "Stats → valid: %d | invalid: %d | duplicates: %d",
        stats["valid"],
        stats["invalid"],
        stats["duplicates"],
    )

    return config


# -----------------------------------------------------------------------------
# Writer
# -----------------------------------------------------------------------------

def write_json_atomic(data: Dict, destination: Path) -> None:
    tmp = destination.with_suffix(".tmp")

    with tmp.open("w", encoding=ENCODING) as f:
        json.dump(data, f, indent=4, ensure_ascii=False, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())

    tmp.replace(destination)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Convert proxy list into JSON config")

    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)

    parser.add_argument("--resolve", action="store_true", help="Enable DNS resolution")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    logger = setup_logging(args.verbose)

    if not args.input.exists():
        logger.error("Input file not found: %s", args.input)
        sys.exit(EXIT_FAILURE)

    try:
        lines = list(iter_proxy_lines(args.input))

        config = generate_config(
            lines=lines,
            logger=logger,
            resolve=args.resolve,
            threads=args.threads,
        )

        write_json_atomic(config, args.output)

    except Exception as e:
        logger.exception("Fatal error: %s", e)
        sys.exit(EXIT_FAILURE)

    logger.info("Output written: %s", args.output)


if __name__ == "__main__":
    main()
