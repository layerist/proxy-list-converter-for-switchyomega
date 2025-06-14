import json
import logging
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
    """Load and return non-empty proxy lines from a file."""
    path = Path(file_path)
    if not path.is_file():
        logger.error(f"Proxy list file not found: '{file_path}'")
        return []

    proxies = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not proxies:
        logger.warning("The proxy list is empty.")
    return proxies

def make_bypass_list() -> List[Dict[str, str]]:
    """Return a list of bypass condition dictionaries."""
    return [{"conditionType": "BypassCondition", "pattern": pattern} for pattern in BYPASS_PATTERNS]

def parse_proxy_entry(entry: str) -> Optional[Dict[str, str]]:
    """
    Parse a proxy string of the format IP:PORT:USERNAME:PASSWORD.

    Returns:
        A dictionary with keys: ip, port, username, password — or None if invalid.
    """
    parts = entry.split(":")
    if len(parts) != 4:
        logger.warning(f"Invalid format (expected 4 parts): '{entry}'")
        return None

    ip, port, username, password = map(str.strip, parts)
    if not ip or not port.isdigit() or not username or not password:
        logger.warning(f"Malformed proxy entry: '{entry}'")
        return None

    return {"ip": ip, "port": port, "username": username, "password": password}

def create_proxy_profile(proxy: Dict[str, str], index: int) -> Dict[str, Any]:
    """
    Create a configuration dictionary for a single proxy.

    Args:
        proxy: Parsed proxy dictionary.
        index: Index for naming the profile.

    Returns:
        A dictionary representing a proxy profile.
    """
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
    """
    Construct static base profiles including switch and proxy group.

    Returns:
        A dictionary containing base profile configurations.
    """
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
            "fallbackProxy": {
                "scheme": "http",
                "host": "127.0.0.1",
                "port": 80,
            },
        },
        "schemaVersion": SCHEMA_VERSION,
    }

def generate_config(proxies: List[str]) -> Dict[str, Any]:
    """
    Generate a full configuration from a list of raw proxy strings.

    Returns:
        A dictionary representing the complete configuration.
    """
    config = build_static_profiles()
    for index, raw_proxy in enumerate(proxies):
        parsed = parse_proxy_entry(raw_proxy)
        if parsed:
            profile = create_proxy_profile(parsed, index)
            config[profile["name"]] = profile
    return config

def write_json_file(data: Dict[str, Any], output_path: str) -> None:
    """
    Write the configuration dictionary as a formatted JSON file.

    Args:
        data: The data to write.
        output_path: Path to the output JSON file.
    """
    try:
        Path(output_path).write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
        logger.info(f"Configuration written to '{output_path}'")
    except Exception as e:
        logger.exception(f"Error writing to '{output_path}': {e}")

def convert_proxy_file(input_path: str, output_path: str) -> None:
    """
    Read a proxy list file, convert to config, and write to output JSON.

    Args:
        input_path: Path to the input text file containing proxies.
        output_path: Path where the output JSON will be saved.
    """
    proxies = load_proxy_list(input_path)
    if not proxies:
        logger.error("No valid proxies loaded. Aborting.")
        return

    config = generate_config(proxies)
    write_json_file(config, output_path)

if __name__ == "__main__":
    convert_proxy_file("proxy_list.txt", "output.json")
