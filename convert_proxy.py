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

# ==============================
# Constants
# ==============================
ENCODING: str = "utf-8"
BYPASS_PATTERNS: List[str] = ["127.0.0.1", "::1", "localhost"]

SCHEMA_VERSION: int = 2
REVISION_ID: str = "190a4bca575"
DEFAULT_REVISION_ID: str = "1908e30c31b"

DEFAULT_PROXY_COLOR: str = "#ca0"
AUTO_SWITCH_NAME: str = "+auto switch"
PROXY_GROUP_NAME: str = "+proxy"

# ==============================
# Logging Setup
# ==============================
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
                    message = super().format(record)
                    return f"{color}{message}{Style.RESET_ALL}"

            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(ColorFormatter("%(levelname)s: %(message)s"))
            logging.basicConfig(level=level, handlers=[handler])
        except ImportError:
            logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


logger = logging.getLogger(__name__)

# ==============================
# File Handling
# ==============================
def load_proxy_list(file_path: Union[str, Path]) -> List[str]:
    """
    Load proxy entries from a text file, ignoring comments and empty lines.

    Expected format per line:
        IP:PORT:USERNAME:PASSWORD
    """
    path = Path(file_path)
    if not path.is_file():
        logger.error("Proxy list file not found: %s", path)
        return []

    try:
        lines = [
            line.strip()
            for line in path.read_text(encoding=ENCODING).splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except Exception as e:
        logger.exception("Failed to read proxy list from '%s': %s", path, e)
        return []

    if not lines:
        logger.warning("Proxy list is empty: %s", path)
    else:
        logger.info("Loaded %d proxies from %s", len(lines), path)
    return lines

# ==============================
# Proxy Parsing
# ==============================
def make_bypass_list() -> List[Dict[str, str]]:
    """Return standard bypass conditions for local addresses."""
    return [{"conditionType": "BypassCondition", "pattern": pattern} for pattern in BYPASS_PATTERNS]


def parse_proxy_entry(entry: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Parse a proxy entry string into a structured dict.

    Args:
        entry: Proxy string in the format IP:PORT:USERNAME:PASSWORD

    Returns:
        Dict with keys: ip, port, username, password
    """
    parts = entry.split(":")
    if len(parts) != 4:
        logger.warning("Invalid proxy format (expected 4 parts): '%s'", entry)
        return None

    ip, port_str, username, password = map(str.strip, parts)

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Invalid IP address: %s", ip)
        return None

    try:
        port = int(port_str)
        if not (0 < port < 65536):
            raise ValueError
    except ValueError:
        logger.warning("Invalid port number: %s", port_str)
        return None

    if not username or not password:
        logger.warning("Missing username or password: '%s'", entry)
        return None

    return {"ip": ip, "port": port, "username": username, "password": password}

# ==============================
# Profile Builders
# ==============================
def create_proxy_profile(proxy: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Generate a single proxy profile entry."""
    return {
        "profileType": "FixedProfile",
        "name": f"+m{index + 1}",
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
    """Return base profiles (auto-switch and proxy group)."""
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

# ==============================
# JSON Configuration
# ==============================
def generate_config(proxies: List[str]) -> Dict[str, Any]:
    """Combine parsed proxies into full configuration."""
    config = build_static_profiles()
    valid_count = 0
    for index, entry in enumerate(proxies):
        parsed = parse_proxy_entry(entry)
        if parsed:
            config[f"+m{index + 1}"] = create_proxy_profile(parsed, index)
            valid_count += 1
    logger.info("Generated %d valid proxy profiles", valid_count)
    return config


def write_json_file(data: Dict[str, Any], output_path: Union[str, Path]) -> None:
    """Write configuration to disk atomically."""
    path = Path(output_path)
    tmp_path = path.with_suffix(".tmp")

    try:
        tmp_path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding=ENCODING)
        tmp_path.replace(path)
        logger.info("Configuration written to %s", path)
    except Exception as e:
        logger.exception("Failed to write configuration to '%s': %s", path, e)

# ==============================
# Main Conversion Logic
# ==============================
def convert_proxy_file(input_path: Union[str, Path], output_path: Union[str, Path]) -> None:
    """Convert a proxy list file into structured JSON."""
    proxies = load_proxy_list(input_path)
    if not proxies:
        logger.error("No valid proxies found — aborting.")
        return

    config = generate_config(proxies)
    write_json_file(config, output_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert a proxy list (IP:PORT:USER:PASS) to structured JSON config.")
    parser.add_argument("input", help="Path to the input proxy list file")
    parser.add_argument("output", help="Path to the output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug-level logging")
    parser.add_argument("--color", action="store_true", help="Enable colored log output (requires colorama)")

    args = parser.parse_args()

    setup_logging(verbose=args.verbose, colored=args.color)
    convert_proxy_file(args.input, args.output)


if __name__ == "__main__":
    main()
