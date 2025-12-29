#!/usr/bin/env python3
"""
Proxy List Converter

Converts plaintext proxy lists in the format:
    IP:PORT:USERNAME:PASSWORD

Into a structured JSON configuration compatible with custom proxy tools.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict, Union

# ==================================================
# Constants
# ==================================================

ENCODING: str = "utf-8"

SCHEMA_VERSION: int = 2

REVISION_ID: str = "190a4bca575"
DEFAULT_REVISION_ID: str = "1908e30c31b"

DEFAULT_PROXY_COLOR: str = "#ca0"

AUTO_SWITCH_NAME: str = "+auto switch"
PROXY_GROUP_NAME: str = "+proxy"
PROXY_PREFIX: str = "+m"

BYPASS_PATTERNS: List[str] = [
    "127.0.0.1",
    "::1",
    "localhost",
]

# ==================================================
# Typed Structures
# ==================================================

class ProxyEntry(TypedDict):
    ip: str
    port: int
    username: str
    password: str


# ==================================================
# Logging
# ==================================================

def setup_logging(*, verbose: bool, colored: bool) -> logging.Logger:
    """Configure and return a module-local logger."""
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("proxy_converter")
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)

    if colored:
        try:
            from colorama import Fore, Style, init

            init(autoreset=True)

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
                    msg = super().format(record)
                    return f"{color}{msg}{Style.RESET_ALL}"

            handler.setFormatter(ColorFormatter("%(levelname)s: %(message)s"))

        except ImportError:
            handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False

    return logger


# ==================================================
# File Handling
# ==================================================

def load_proxy_list(path: Union[str, Path], logger: logging.Logger) -> List[str]:
    """Load and sanitize proxy entries from file."""
    file_path = Path(path)

    if not file_path.is_file():
        logger.error("Proxy list not found: %s", file_path)
        return []

    try:
        raw_lines = file_path.read_text(encoding=ENCODING).splitlines()
    except Exception:
        logger.exception("Failed to read proxy list: %s", file_path)
        return []

    entries = [
        line.strip()
        for line in raw_lines
        if line.strip() and not line.lstrip().startswith("#")
    ]

    logger.info("Loaded %d candidate entries", len(entries))
    return entries


# ==================================================
# Parsing & Validation
# ==================================================

def parse_proxy(line: str, logger: logging.Logger) -> Optional[ProxyEntry]:
    """Parse and validate a single proxy entry."""
    parts = [p.strip() for p in line.split(":")]

    if len(parts) != 4:
        logger.warning("Invalid format (expected 4 fields): %s", line)
        return None

    ip_raw, port_raw, username, password = parts

    try:
        ipaddress.ip_address(ip_raw)
    except ValueError:
        logger.warning("Invalid IP address: %s", ip_raw)
        return None

    try:
        port = int(port_raw)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        logger.warning("Invalid port: %s", port_raw)
        return None

    if not username or not password:
        logger.warning("Missing credentials in entry: %s", line)
        return None

    return ProxyEntry(
        ip=ip_raw,
        port=port,
        username=username,
        password=password,
    )


def build_bypass_list() -> List[Dict[str, str]]:
    return [
        {"conditionType": "BypassCondition", "pattern": pattern}
        for pattern in BYPASS_PATTERNS
    ]


# ==================================================
# Profile Builders
# ==================================================

def build_proxy_profile(entry: ProxyEntry, index: int) -> Dict[str, Any]:
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


def build_static_profiles() -> Dict[str, Any]:
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


# ==================================================
# JSON Generation
# ==================================================

def generate_config(lines: List[str], logger: logging.Logger) -> Dict[str, Any]:
    config = build_static_profiles()
    index = 1

    for line in lines:
        proxy = parse_proxy(line, logger)
        if not proxy:
            continue

        config[f"{PROXY_PREFIX}{index}"] = build_proxy_profile(proxy, index)
        index += 1

    logger.info("Generated %d valid proxy profiles", index - 1)
    return config


def write_json_atomic(data: Dict[str, Any], destination: Union[str, Path], logger: logging.Logger) -> None:
    path = Path(destination)
    tmp_path = path.with_suffix(path.suffix + ".tmp")

    try:
        tmp_path.write_text(
            json.dumps(data, indent=4, ensure_ascii=False),
            encoding=ENCODING,
        )
        tmp_path.replace(path)
        logger.info("Configuration saved: %s", path)
    except Exception:
        logger.exception("Failed to write output file: %s", path)


# ==================================================
# Main
# ==================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a proxy list into a structured JSON configuration."
    )
    parser.add_argument("input", help="Input proxy list file")
    parser.add_argument("output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--color", action="store_true", help="Enable colored log output")

    args = parser.parse_args()
    logger = setup_logging(verbose=args.verbose, colored=args.color)

    lines = load_proxy_list(args.input, logger)
    if not lines:
        logger.error("No valid proxy entries found. Aborting.")
        sys.exit(1)

    config = generate_config(lines, logger)
    write_json_atomic(config, args.output, logger)


if __name__ == "__main__":
    main()
