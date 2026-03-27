#!/usr/bin/env python3
"""
Advanced Proxy List Converter
=============================

Converts plaintext proxy lists into structured JSON configuration.

Supported input formats:
    IP:PORT:USERNAME:PASSWORD
    HOST:PORT:USERNAME:PASSWORD
    [scheme://]IP:PORT:USERNAME:PASSWORD

Examples:
    1.2.3.4:8080:user:pass
    socks5://1.2.3.4:1080:user:pass

Features
--------
• Strict validation (IP + hostname support)
• Protocol detection (http/https/socks5)
• Duplicate detection (strong key)
• Stats reporting
• Atomic JSON writing with fsync
• Deterministic output
• Optional colored logging
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
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, TypedDict

ENCODING = "utf-8"
EXIT_FAILURE = 1

SCHEMA_VERSION = 2
REVISION_ID = "190a4bca575"
DEFAULT_REVISION_ID = "1908e30c31b"

DEFAULT_PROXY_COLOR = "#ca0"

AUTO_SWITCH_NAME = "+auto switch"
PROXY_GROUP_NAME = "+proxy"
PROXY_PREFIX = "+m"

BYPASS_PATTERNS = (
    "127.0.0.1",
    "::1",
    "localhost",
)

SUPPORTED_SCHEMES = {"http", "https", "socks5"}


class ProxyEntry(TypedDict):
    scheme: str
    host: str
    port: int
    username: str
    password: str


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

def setup_logging(verbose: bool, colored: bool) -> logging.Logger:
    logger = logging.getLogger("proxy_converter")

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler()

    if colored:
        try:
            from colorama import Fore, Style, init
            init()

            class ColorFormatter(logging.Formatter):
                COLORS = {
                    logging.DEBUG: Fore.CYAN,
                    logging.INFO: Fore.GREEN,
                    logging.WARNING: Fore.YELLOW,
                    logging.ERROR: Fore.RED,
                    logging.CRITICAL: Fore.MAGENTA,
                }

                def format(self, record):
                    color = self.COLORS.get(record.levelno, "")
                    return f"{color}{super().format(record)}{Style.RESET_ALL}"

            formatter = ColorFormatter("%(levelname)s: %(message)s")

        except ImportError:
            formatter = logging.Formatter("%(levelname)s: %(message)s")
    else:
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

            if not line or line.startswith("#"):
                continue

            yield line


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

HOST_REGEX = re.compile(r"^[a-zA-Z0-9.-]+$")


def is_valid_host(host: str) -> bool:
    # Try IP first
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Validate hostname
    if not HOST_REGEX.match(host):
        return False

    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


def parse_proxy(line: str) -> Optional[ProxyEntry]:
    scheme = "http"

    if "://" in line:
        scheme_part, line = line.split("://", 1)
        if scheme_part.lower() not in SUPPORTED_SCHEMES:
            return None
        scheme = scheme_part.lower()

    parts = line.split(":")

    if len(parts) != 4:
        return None

    host, port_raw, username, password = parts

    if not is_valid_host(host):
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
    return [
        {"conditionType": "BypassCondition", "pattern": p}
        for p in BYPASS_PATTERNS
    ]


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
# Generator
# -----------------------------------------------------------------------------

def generate_config(lines: Iterable[str], logger: logging.Logger) -> Dict:
    config = build_static_profiles()

    seen = set()
    index = 1

    stats = {
        "valid": 0,
        "invalid": 0,
        "duplicates": 0,
    }

    for line in lines:
        proxy = parse_proxy(line)

        if proxy is None:
            stats["invalid"] += 1
            logger.warning("Invalid proxy: %s", line)
            continue

        key = (
            proxy["scheme"],
            proxy["host"],
            proxy["port"],
            proxy["username"],
        )

        if key in seen:
            stats["duplicates"] += 1
            logger.debug("Duplicate skipped: %s", line)
            continue

        seen.add(key)

        config[f"{PROXY_PREFIX}{index}"] = build_proxy_profile(proxy, index)
        index += 1
        stats["valid"] += 1

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
    parser = argparse.ArgumentParser(
        description="Convert proxy list into JSON configuration."
    )

    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)

    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--color", action="store_true")

    args = parser.parse_args()

    logger = setup_logging(args.verbose, args.color)

    if not args.input.exists():
        logger.error("Input file not found: %s", args.input)
        sys.exit(EXIT_FAILURE)

    try:
        lines = iter_proxy_lines(args.input)
        config = generate_config(lines, logger)
        write_json_atomic(config, args.output)

    except Exception as e:
        logger.exception("Fatal error: %s", e)
        sys.exit(EXIT_FAILURE)

    logger.info("Output written: %s", args.output)


if __name__ == "__main__":
    main()
