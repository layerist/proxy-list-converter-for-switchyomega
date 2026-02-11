#!/usr/bin/env python3
"""
Proxy List Converter
====================

Converts plaintext proxy lists in the format:

    IP:PORT:USERNAME:PASSWORD

into a structured JSON configuration compatible with custom proxy tools.

Features:
  • Strict proxy validation (IP, port, credentials)
  • Comment and whitespace filtering
  • Atomic JSON output writing
  • Optional colored and verbose logging
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict, Union

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

BYPASS_PATTERNS: List[str] = [
    "127.0.0.1",
    "::1",
    "localhost",
]

# =============================================================================
# Typed Structures
# =============================================================================

class ProxyEntry(TypedDict):
    ip: str
    port: int
    username: str
    password: str

# =============================================================================
# Logging
# =============================================================================

def setup_logging(*, verbose: bool, colored: bool) -> logging.Logger:
    """Configure and return an isolated logger instance."""
    logger = logging.getLogger("proxy_converter")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

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
                    return f"{color}{super().format(record)}{Style.RESET_ALL}"

            formatter: logging.Formatter = ColorFormatter("%(levelname)s: %(message)s")

        except ImportError:
            formatter = logging.Formatter("%(levelname)s: %(message)s")
    else:
        formatter = logging.Formatter("%(levelname)s: %(message)s")

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

# =============================================================================
# File Handling
# =============================================================================

def load_proxy_list(path: Union[str, Path], logger: logging.Logger) -> List[str]:
    """Load, sanitize, and return proxy entries from a file."""
    file_path = Path(path)

    if not file_path.is_file():
        logger.error("Proxy list file not found: %s", file_path)
        return []

    try:
        raw_lines = file_path.read_text(encoding=ENCODING).splitlines()
    except OSError as exc:
        logger.exception("Failed to read proxy list: %s", exc)
        return []

    entries = [
        line.strip()
        for line in raw_lines
        if line.strip() and not line.lstrip().startswith("#")
    ]

    logger.info("Loaded %d candidate proxy entries", len(entries))
    return entries

# =============================================================================
# Parsing & Validation
# =============================================================================

def parse_proxy(line: str, logger: logging.Logger) -> Optional[ProxyEntry]:
    """Parse and validate a single proxy line."""
    parts = [p.strip() for p in line.split(":")]

    if len(parts) != 4:
        logger.warning("Invalid format (expected IP:PORT:USER:PASS): %s", line)
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
        logger.warning("Invalid port number: %s", port_raw)
        return None

    if not username or not password:
        logger.warning("Empty username or password: %s", line)
        return None

    return ProxyEntry(
        ip=ip_raw,
        port=port,
        username=username,
        password=password,
    )

def build_bypass_list() -> List[Dict[str, str]]:
    """Return a standard bypass list configuration."""
    return [
        {"conditionType": "BypassCondition", "pattern": pattern}
        for pattern in BYPASS_PATTERNS
    ]

# =============================================================================
# Profile Builders
# =============================================================================

def build_proxy_profile(entry: ProxyEntry, index: int) -> Dict[str, Any]:
    """Build a fixed proxy profile definition."""
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
    """Build static (non-generated) profiles and schema metadata."""
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

# =============================================================================
# JSON Generation
# =============================================================================

def generate_config(lines: List[str], logger: logging.Logger) -> Dict[str, Any]:
    """Generate the full JSON configuration."""
    config = build_static_profiles()
    index = 1

    for line in lines:
        proxy = parse_proxy(line, logger)
        if proxy is None:
            continue

        config[f"{PROXY_PREFIX}{index}"] = build_proxy_profile(proxy, index)
        index += 1

    logger.info("Generated %d valid proxy profiles", index - 1)
    return config

def write_json_atomic(
    data: Dict[str, Any],
    destination: Union[str, Path],
    logger: logging.Logger,
) -> None:
    """Write JSON output atomically."""
    path = Path(destination)
    tmp_path = path.with_suffix(path.suffix + ".tmp")

    try:
        tmp_path.write_text(
            json.dumps(data, indent=4, ensure_ascii=False),
            encoding=ENCODING,
        )
        tmp_path.replace(path)
        logger.info("Configuration written to %s", path)
    except OSError as exc:
        logger.exception("Failed to write output file: %s", exc)

# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a proxy list into a structured JSON configuration."
    )
    parser.add_argument("input", help="Input proxy list file")
    parser.add_argument("output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--color", action="store_true", help="Enable colored logging")

    args = parser.parse_args()
    logger = setup_logging(verbose=args.verbose, colored=args.color)

    lines = load_proxy_list(args.input, logger)
    if not lines:
        logger.error("No valid proxy entries found. Aborting.")
        sys.exit(EXIT_FAILURE)

    config = generate_config(lines, logger)
    write_json_atomic(config, args.output, logger)

if __name__ == "__main__":
    main()
