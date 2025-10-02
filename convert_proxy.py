import argparse
import ipaddress
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Constants
ENCODING: str = "utf-8"
BYPASS_PATTERNS: List[str] = ["127.0.0.1", "::1", "localhost"]
SCHEMA_VERSION: int = 2
REVISION_ID: str = "190a4bca575"
DEFAULT_REVISION_ID: str = "1908e30c31b"
DEFAULT_PROXY_COLOR: str = "#ca0"
AUTO_SWITCH_NAME: str = "+auto switch"
PROXY_GROUP_NAME: str = "+proxy"

# Logging setup
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def load_proxy_list(file_path: Union[str, Path]) -> List[str]:
    """
    Load proxy entries from a text file, skipping empty lines.

    Each line should be in the format:
        IP:PORT:USERNAME:PASSWORD

    Args:
        file_path: Path to the proxy list file.

    Returns:
        A list of proxy strings.
    """
    path = Path(file_path)
    if not path.is_file():
        logger.error("Proxy list file not found: %s", path)
        return []

    try:
        lines = [
            line.strip()
            for line in path.read_text(encoding=ENCODING).splitlines()
            if line.strip()
        ]
    except Exception as e:
        logger.exception("Failed to read proxy list from '%s': %s", path, e)
        return []

    if not lines:
        logger.warning("Proxy list is empty: %s", path)
    return lines


def make_bypass_list() -> List[Dict[str, str]]:
    """Return a list of bypass conditions for known local addresses."""
    return [
        {"conditionType": "BypassCondition", "pattern": pattern}
        for pattern in BYPASS_PATTERNS
    ]


def parse_proxy_entry(entry: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Parse a proxy entry string into structured fields.

    Args:
        entry: Proxy string in the format IP:PORT:USERNAME:PASSWORD

    Returns:
        A dictionary with parsed fields, or None if invalid.
    """
    parts = entry.split(":")
    if len(parts) != 4:
        logger.warning("Invalid proxy format (expected 4 fields): '%s'", entry)
        return None

    ip, port, username, password = map(str.strip, parts)

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Invalid IP address: %s", ip)
        return None

    if not port.isdigit():
        logger.warning("Invalid port number: %s", port)
        return None

    if not username or not password:
        logger.warning("Missing username or password: '%s'", entry)
        return None

    return {"ip": ip, "port": int(port), "username": username, "password": password}


def create_proxy_profile(proxy: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Generate a proxy profile configuration entry."""
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
    """Return static base profiles including the auto-switch and proxy group."""
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
            "bypassList": make_bypass_list(),
            "fallbackProxy": {"scheme": "http", "host": "127.0.0.1", "port": 80},
        },
        "schemaVersion": SCHEMA_VERSION,
    }


def generate_config(proxies: List[str]) -> Dict[str, Any]:
    """Build the complete configuration dictionary from a proxy list."""
    config = build_static_profiles()
    for index, entry in enumerate(proxies):
        parsed = parse_proxy_entry(entry)
        if parsed:
            config[f"+m{index + 1}"] = create_proxy_profile(parsed, index)
        else:
            logger.debug("Skipping invalid proxy entry at index %d", index)
    return config


def write_json_file(data: Dict[str, Any], output_path: Union[str, Path]) -> None:
    """Safely write JSON data to a file."""
    path = Path(output_path)
    tmp_path = path.with_suffix(".tmp")

    try:
        tmp_path.write_text(
            json.dumps(data, indent=4, ensure_ascii=False), encoding=ENCODING
        )
        tmp_path.replace(path)
        logger.info("Configuration successfully written to %s", path)
    except Exception as e:
        logger.exception("Failed to write configuration to '%s': %s", path, e)


def convert_proxy_file(input_path: Union[str, Path], output_path: Union[str, Path]) -> None:
    """Convert a proxy list file into a structured JSON configuration."""
    proxies = load_proxy_list(input_path)
    if not proxies:
        logger.error("No proxies found. Aborting.")
        return

    config = generate_config(proxies)
    write_json_file(config, output_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a proxy list (IP:PORT:USER:PASS) into a structured JSON configuration."
    )
    parser.add_argument("input", help="Path to the input proxy list file")
    parser.add_argument("output", help="Path to the output JSON configuration file")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug-level logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    convert_proxy_file(args.input, args.output)


if __name__ == "__main__":
    main()
