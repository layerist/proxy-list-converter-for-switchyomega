#!/usr/bin/env python3
"""
Proxy List Converter
Converts plaintext proxy lists (IP:PORT:USER:PASS)
into a structured JSON configuration for custom proxy tools.
"""

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, TypedDict

# ============================================
# Constants
# ============================================

ENCODING = "utf-8"

BYPASS_PATTERNS = ["127.0.0.1", "::1", "localhost"]

SCHEMA_VERSION = 2

REVISION_ID = "190a4bca575"
DEFAULT_REVISION_ID = "1908e30c31b"

DEFAULT_PROXY_COLOR = "#ca0"

AUTO_SWITCH_NAME = "+auto switch"
PROXY_GROUP_NAME = "+proxy"
PROXY_PREFIX = "+m"

# ============================================
# Typed Structures
# ============================================

class ProxyEntry(TypedDict):
    ip: str
    port: int
    username: str
    password: str


# ============================================
# Logging Setup
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
                    return f"{color}{super().format(record)}{Style.RESET_ALL}"

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

def load_proxy_list(path: Union[str, Path]) -> List[str]:
    """Load proxy lines from file, skipping comments and blank lines."""
    file = Path(path)

    if not file.is_file():
        logger.error("Proxy list not found: %s", file)
        return []

    try:
        content = file.read_text(encoding=ENCODING)
    except Exception as e:
        logger.exception("Failed to read '%s': %s", file, e)
        return []

    lines = []
    for raw in content.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)

    logger.info("Loaded %d raw entries from %s", len(lines), file)
    return lines


# ============================================
# Parsing Logic
# ============================================

def make_bypass_list() -> List[Dict[str, str]]:
    return [{"conditionType": "BypassCondition", "pattern": p} for p in BYPASS_PATTERNS]


def parse_proxy(entry: str) -> Optional[ProxyEntry]:
    """Parse IP:PORT:USER:PASS -> ProxyEntry."""
    parts = [p.strip() for p in entry.split(":")]

    if len(parts) != 4:
        logger.warning("Invalid entry (expected 4 fields): %s", entry)
        return None

    ip, port_raw, user, pwd = parts

    # IP validation
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Invalid IP address '%s' in entry '%s'", ip, entry)
        return None

    # Port validation
    try:
        port = int(port_raw)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        logger.warning("Invalid port '%s' in entry '%s'", port_raw, entry)
        return None

    if not user or not pwd:
        logger.warning("Missing username/password in entry '%s'", entry)
        return None

    return ProxyEntry(ip=ip, port=port, username=user, password=pwd)


# ============================================
# Profile Builders
# ============================================

def build_proxy_profile(p: ProxyEntry, idx: int) -> Dict[str, Any]:
    return {
        "profileType": "FixedProfile",
        "name": f"{PROXY_PREFIX}{idx}",
        "color": DEFAULT_PROXY_COLOR,
        "revision": REVISION_ID,
        "bypassList": make_bypass_list(),
        "fallbackProxy": {
            "scheme": "http",
            "host": p["ip"],
            "port": p["port"],
        },
        "auth": {
            "fallbackProxy": {
                "username": p["username"],
                "password": p["password"],
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
    config = build_static_profiles()
    index = 1

    for line in lines:
        parsed = parse_proxy(line)
        if not parsed:
            continue

        config[f"{PROXY_PREFIX}{index}"] = build_proxy_profile(parsed, index)
        index += 1

    logger.info("Generated %d valid proxy entries", index - 1)
    return config


def write_json_atomic(data: Dict[str, Any], dest: Union[str, Path]) -> None:
    path = Path(dest)
    temp = path.with_suffix(".tmp")

    try:
        temp.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding=ENCODING)
        temp.replace(path)
        logger.info("Saved configuration: %s", path)
    except Exception as e:
        logger.exception("Failed to write '%s': %s", path, e)


# ============================================
# Main Logic
# ============================================

def convert_proxy_file(src: Union[str, Path], dst: Union[str, Path]) -> None:
    lines = load_proxy_list(src)
    if not lines:
        logger.error("No valid proxies found — aborting.")
        return

    data = generate_config(lines)
    write_json_atomic(data, dst)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert proxy list into JSON config.")
    parser.add_argument("input", help="Input proxy list file")
    parser.add_argument("output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--color", action="store_true", help="Colored logging output")

    args = parser.parse_args()

    setup_logging(verbose=args.verbose, colored=args.color)
    convert_proxy_file(args.input, args.output)


if __name__ == "__main__":
    main()
