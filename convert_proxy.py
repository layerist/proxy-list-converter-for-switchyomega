#!/usr/bin/env python3
"""
Proxy List Converter
====================

Convert plaintext proxy lists:

    IP:PORT:USERNAME:PASSWORD

into structured JSON configuration.

Features
--------
• Strict proxy validation
• Duplicate proxy detection
• Comment and whitespace filtering
• Atomic JSON writing
• Deterministic output ordering
• Optional colored and verbose logging
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
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


class ProxyEntry(TypedDict):
    ip: str
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

    formatter: logging.Formatter

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

                def format(self, record: logging.LogRecord) -> str:
                    color = self.COLORS.get(record.levelno, "")
                    message = super().format(record)
                    return f"{color}{message}{Style.RESET_ALL}"

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
    """Yield sanitized proxy lines."""
    with path.open("r", encoding=ENCODING) as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            yield line


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

def parse_proxy(line: str) -> Optional[ProxyEntry]:
    parts = line.split(":")

    if len(parts) != 4:
        return None

    ip_raw, port_raw, username, password = parts

    try:
        ipaddress.ip_address(ip_raw)
    except ValueError:
        return None

    try:
        port = int(port_raw)
        if not 1 <= port <= 65535:
            return None
    except ValueError:
        return None

    if not username or not password:
        return None

    return {
        "ip": ip_raw,
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
            "scheme": "http",
            "host": entry["ip"],
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
            "rules": [
                {
                    "condition": {
                        "conditionType": "HostWildcardCondition",
                        "pattern": "internal.example.com",
                    },
                    "profileName": "direct",
                },
                {
                    "condition": {
                        "conditionType": "HostWildcardCondition",
                        "pattern": "*.example.com",
                    },
                    "profileName": "proxy",
                },
            ],
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

    for line in lines:
        proxy = parse_proxy(line)

        if proxy is None:
            logger.warning("Invalid proxy: %s", line)
            continue

        key = (proxy["ip"], proxy["port"], proxy["username"])

        if key in seen:
            logger.debug("Duplicate proxy skipped: %s", line)
            continue

        seen.add(key)

        config[f"{PROXY_PREFIX}{index}"] = build_proxy_profile(proxy, index)
        index += 1

    logger.info("Valid proxies: %d", index - 1)

    return config


# -----------------------------------------------------------------------------
# Writer
# -----------------------------------------------------------------------------

def write_json_atomic(data: Dict, destination: Path) -> None:
    tmp = destination.with_suffix(".tmp")

    with tmp.open("w", encoding=ENCODING) as f:
        json.dump(data, f, indent=4, ensure_ascii=False, sort_keys=True)

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

    lines = iter_proxy_lines(args.input)

    config = generate_config(lines, logger)

    write_json_atomic(config, args.output)

    logger.info("Output written: %s", args.output)


if __name__ == "__main__":
    main()
