#!/usr/bin/env python3
"""
Proxy List Converter

Converts a plaintext proxy list (IP:PORT:USERNAME:PASSWORD)
into a structured JSON configuration compatible with custom proxy tools.

Usage:
    python proxy_converter.py proxies.txt output.json [-v] [--color]
"""

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# ============================================
# Constants
# ============================================
ENCODING: str = "utf-8"
BYPASS_PATTERNS: List[str] = ["127.0.0.1", "::1", "localhost"]

SCHEMA_VERSION: int = 2

REVISION_ID: str = "190a4bca575"
DEFAULT_REVISION_ID: str = "1908e30c31b"

DEFAULT_PROXY_COLOR: str = "#ca0"
AUTO_SWITCH_NAME: str = "+auto switch"
PROXY_GROUP_NAME: str = "+proxy"
PROXY_PREFIX: str = "+m"   # name prefix for generated proxies

# ============================================
# Logging
# ============================================
def setup_logging(verbose: bool = False, colored: bool = False) -> None:
    """Initialize global logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO

    if colored:
        try:
            from colorama import init, Fore, Style
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

            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(ColorFormatter("%(levelname)s: %(message)s"))
            logging.basicConfig(level=level, handlers=[handler])
            return
        except ImportError:
            pass

    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


logger = logging.getLogger(__name__)

# ============================================
# File Handling
# ============================================
def load_proxy_list(file_path: Union[str, Path]) -> List[str]:
    """
    Load proxy lines from file, skipping comments (#) and empty lines.
    Format: IP:PORT:USER:PASS
    """
    path = Path(file_path)

    if not path.is_file():
        logger.error("Proxy list not found: %s", path)
        return []

    try:
        text = path.read_text(encoding=ENCODING)
    except Exception as e:
        logger.exception("Failed to read '%s': %s", path, e)
        return []

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    logger.info("Loaded %d raw entries from %s", len(lines), path)
    return lines


# ============================================
# Proxy Parsing
# ============================================
def make_bypass_list() -> List[Dict[str, str]]:
    return [{"conditionType": "BypassCondition", "pattern": p} for p in BYPASS_PATTERNS]


def parse_proxy_entry(entry: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Parse IP:PORT:USER:PASS line.
    Returns None if invalid.
    """
    parts = entry.split(":")
    if len(parts) != 4:
        logger.warning("Invalid format (expected 4 fields): '%s'", entry)
        return None

    ip, port_str, user, pwd = map(str.strip, parts)

    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Invalid IP: %s", ip)
        return None

    # Validate port
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        logger.warning("Invalid port: %s", port_str)
        return None

    # Validate credentials
    if not user or not pwd:
        logger.warning("Missing username or password: '%s'", entry)
        return None

    return {"ip": ip, "port": port, "username": user, "password": pwd}


# ============================================
# Profile Builders
# ============================================
def create_proxy_profile(proxy: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Create JSON entry for a single proxy."""
    return {
        "profileType": "FixedProfile",
        "name": f"{PROXY_PREFIX}{index}",
        "bypassList": make_bypass_list(),
        "color": DEFAULT_PROXY_COLOR,
        "revision": REVISION_ID,
        "fallbackProxy": {
            "scheme": "http",
            "host": proxy["ip"],
            "port": proxy["port"],
        },
        "auth": {
            "fallbackProxy": {
                "username": proxy["username"],
                "password": proxy["password"],
            }
        },
    }


def build_static_profiles() -> Dict[str, Any]:
    """Base profiles that are always included."""
    return {
        AUTO_SWITCH_NAME: {
            "profileType": "SwitchProfile",
            "name": "auto switch",
            "color": "#99dd99",
            "defaultProfileName": "direct",
            "rules": [
                {
                    "condition": {"conditionType": "HostWildcardCondition", "pattern": "internal.example.com"},
                    "profileName": "direct",
                },
                {
                    "condition": {"conditionType": "HostWildcardCondition", "pattern": "*.example.com"},
                    "profileName": "proxy",
                },
            ],
        },
        PROXY_GROUP_NAME: {
            "profileType": "FixedProfile",
            "name": "proxy",
            "color": "#99ccee",
            "revision": DEFAULT_REVISION_ID,
            "bypassList": make_bypass_list(),
            "fallbackProxy": {"scheme": "http", "host": "127.0.0.1", "port": 80},
        },
        "schemaVersion": SCHEMA_VERSION,
    }


# ============================================
# JSON Generator
# ============================================
def generate_config(lines: List[str]) -> Dict[str, Any]:
    """Build final JSON configuration."""
    config = build_static_profiles()
    valid_idx = 1

    for entry in lines:
        parsed = parse_proxy_entry(entry)
        if not parsed:
            continue

        config[f"{PROXY_PREFIX}{valid_idx}"] = create_proxy_profile(parsed, valid_idx)
        valid_idx += 1

    logger.info("Generated %d valid proxy entries", valid_idx - 1)
    return config


def write_json_atomic(data: Dict[str, Any], output_path: Union[str, Path]) -> None:
    """Atomic write to file."""
    path = Path(output_path)
    tmp = path.with_suffix(".tmp")

    try:
        tmp.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding=ENCODING)
        tmp.replace(path)
        logger.info("Saved to %s", path)
    except Exception as e:
        logger.exception("Failed writing to '%s': %s", path, e)


# ============================================
# Main Logic
# ============================================
def convert_proxy_file(src: Union[str, Path], dst: Union[str, Path]) -> None:
    lines = load_proxy_list(src)
    if not lines:
        logger.error("No input proxies found — aborting.")
        return

    config = generate_config(lines)
    write_json_atomic(config, dst)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert proxies into JSON config.")
    parser.add_argument("input", help="Input proxy list file")
    parser.add_argument("output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    parser.add_argument("--color", action="store_true", help="Colored output")

    args = parser.parse_args()

    setup_logging(verbose=args.verbose, colored=args.color)
    convert_proxy_file(args.input, args.output)


if __name__ == "__main__":
    main()
