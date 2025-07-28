import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Constants
BYPASS_PATTERNS = ["127.0.0.1", "::1", "localhost"]
SCHEMA_VERSION = 2
REVISION_ID = "190a4bca575"
DEFAULT_REVISION_ID = "1908e30c31b"
DEFAULT_PROXY_COLOR = "#ca0"
AUTO_SWITCH_NAME = "+auto switch"
PROXY_GROUP_NAME = "+proxy"

def load_proxy_list(file_path: str) -> List[str]:
    """
    Load non-empty proxy entries from a text file.

    Args:
        file_path: Path to the proxy list file.

    Returns:
        A list of proxy strings.
    """
    path = Path(file_path)
    if not path.is_file():
        logger.error(f"Proxy list file not found: '{file_path}'")
        return []

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        logger.warning(f"The proxy list at '{file_path}' is empty.")
    return lines

def make_bypass_list() -> List[Dict[str, str]]:
    """Create a list of bypass conditions."""
    return [{"conditionType": "BypassCondition", "pattern": pattern} for pattern in BYPASS_PATTERNS]

def parse_proxy_entry(entry: str) -> Optional[Dict[str, str]]:
    """
    Parse a proxy string in the format: IP:PORT:USERNAME:PASSWORD

    Args:
        entry: The raw proxy string.

    Returns:
        A dictionary with proxy details or None if invalid.
    """
    parts = entry.split(":")
    if len(parts) != 4:
        logger.warning(f"Invalid proxy format (expected 4 fields): '{entry}'")
        return None

    ip, port, username, password = map(str.strip, parts)
    if not ip or not port.isdigit() or not username or not password:
        logger.warning(f"Malformed proxy entry: '{entry}'")
        return None

    return {"ip": ip, "port": port, "username": username, "password": password}

def create_proxy_profile(proxy: Dict[str, str], index: int) -> Dict[str, Any]:
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
            "port": int(proxy["port"]),
        },
        "auth": {
            "fallbackProxy": {
                "username": proxy["username"],
                "password": proxy["password"],
            }
        },
    }

def build_static_profiles() -> Dict[str, Any]:
    """Create static base profiles including the switch and proxy group."""
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
    """Generate the full configuration dictionary."""
    config = build_static_profiles()
    for index, proxy_entry in enumerate(proxies):
        parsed = parse_proxy_entry(proxy_entry)
        if parsed:
            profile = create_proxy_profile(parsed, index)
            config[profile["name"]] = profile
    return config

def write_json_file(data: Dict[str, Any], output_path: str) -> None:
    """Write configuration to JSON file."""
    try:
        Path(output_path).write_text(
            json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8"
        )
        logger.info(f"Configuration successfully written to '{output_path}'")
    except Exception as e:
        logger.exception(f"Failed to write configuration to '{output_path}': {e}")

def convert_proxy_file(input_path: str, output_path: str) -> None:
    """Convert a raw proxy list file to a structured JSON configuration."""
    proxies = load_proxy_list(input_path)
    if not proxies:
        logger.error("No proxies found. Aborting.")
        return

    config = generate_config(proxies)
    write_json_file(config, output_path)

def main():
    parser = argparse.ArgumentParser(description="Convert proxy list to JSON configuration.")
    parser.add_argument("input", help="Path to the input proxy list file")
    parser.add_argument("output", help="Path to the output JSON configuration file")
    args = parser.parse_args()

    convert_proxy_file(args.input, args.output)

if __name__ == "__main__":
    main()
