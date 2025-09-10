import json
import logging
import argparse
import ipaddress
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Constants
BYPASS_PATTERNS: List[str] = ["127.0.0.1", "::1", "localhost"]
SCHEMA_VERSION: int = 2
REVISION_ID: str = "190a4bca575"
DEFAULT_REVISION_ID: str = "1908e30c31b"
DEFAULT_PROXY_COLOR: str = "#ca0"
AUTO_SWITCH_NAME: str = "+auto switch"
PROXY_GROUP_NAME: str = "+proxy"


def load_proxy_list(file_path: Union[str, Path]) -> List[str]:
    """
    Load non-empty proxy entries from a text file.
    Each line is expected to be in the format: IP:PORT:USERNAME:PASSWORD

    Args:
        file_path: Path to the proxy list file.

    Returns:
        A list of cleaned proxy strings.
    """
    path = Path(file_path)
    if not path.is_file():
        logger.error("Proxy list file not found: '%s'", file_path)
        return []

    try:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except Exception:
        logger.exception("Failed to read proxy list from '%s'", file_path)
        return []

    if not lines:
        logger.warning("The proxy list at '%s' is empty.", file_path)
    return lines


def make_bypass_list() -> List[Dict[str, str]]:
    """Return a list of bypass conditions."""
    return [{"conditionType": "BypassCondition", "pattern": pattern} for pattern in BYPASS_PATTERNS]


def parse_proxy_entry(entry: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Parse a proxy string in the format: IP:PORT:USERNAME:PASSWORD

    Args:
        entry: Raw proxy string.

    Returns:
        Dict with parsed proxy details or None if invalid.
    """
    parts = entry.split(":")
    if len(parts) != 4:
        logger.warning("Invalid proxy format (expected 4 fields): '%s'", entry)
        return None

    ip, port, username, password = map(str.strip, parts)

    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Invalid IP address: '%s'", ip)
        return None

    # Validate port and credentials
    if not port.isdigit() or not username or not password:
        logger.warning("Malformed proxy entry: '%s'", entry)
        return None

    return {"ip": ip, "port": int(port), "username": username, "password": password}


def create_proxy_profile(proxy: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Generate a proxy profile configuration."""
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
    """Create static base profiles including the auto-switch and proxy group."""
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
            "fallbackProxy": {
                "scheme": "http",
                "host": "127.0.0.1",
                "port": 80,
            },
        },
        "schemaVersion": SCHEMA_VERSION,
    }


def generate_config(proxies: List[str]) -> Dict[str, Any]:
    """Generate the complete configuration dictionary."""
    config = build_static_profiles()
    for index, entry in enumerate(proxies):
        parsed = parse_proxy_entry(entry)
        if parsed:
            profile = create_proxy_profile(parsed, index)
            config[profile["name"]] = profile
        else:
            logger.debug("Skipping invalid proxy entry at index %d", index)
    return config


def write_json_file(data: Dict[str, Any], output_path: Union[str, Path]) -> None:
    """Write configuration to a JSON file."""
    try:
        Path(output_path).write_text(
            json.dumps(data, indent=4, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Configuration successfully written to '%s'", output_path)
    except Exception:
        logger.exception("Failed to write configuration to '%s'", output_path)


def convert_proxy_file(input_path: Union[str, Path], output_path: Union[str, Path]) -> None:
    """Convert a raw proxy list file to a structured JSON configuration."""
    proxies = load_proxy_list(input_path)
    if not proxies:
        logger.error("No proxies found. Aborting.")
        return

    config = generate_config(proxies)
    write_json_file(config, output_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a proxy list (IP:PORT:USER:PASS) to structured JSON configuration."
    )
    parser.add_argument("input", help="Path to the input proxy list file")
    parser.add_argument("output", help="Path to the output JSON configuration file")
    args = parser.parse_args()

    convert_proxy_file(args.input, args.output)


if __name__ == "__main__":
    main()
