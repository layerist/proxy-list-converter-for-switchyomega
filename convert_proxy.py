import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

# Configure logging
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

def load_proxies(file_path: str) -> List[str]:
    """Load proxy strings from file, skipping empty lines."""
    path = Path(file_path)
    if not path.is_file():
        logger.error(f"Proxy list file not found: '{file_path}'")
        return []

    proxies = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not proxies:
        logger.warning("The proxy list is empty.")
    return proxies

def make_bypass_list() -> List[Dict[str, str]]:
    """Create a list of proxy bypass patterns."""
    return [{"conditionType": "BypassCondition", "pattern": pattern} for pattern in BYPASS_PATTERNS]

def parse_proxy(proxy: str) -> Optional[Dict[str, str]]:
    """
    Parse a proxy string in the format IP:PORT:USERNAME:PASSWORD.
    Returns a dict or None if the format is invalid.
    """
    parts = proxy.split(":")
    if len(parts) != 4:
        logger.warning(f"Invalid proxy format skipped: '{proxy}'")
        return None

    ip, port, username, password = parts
    if not (ip and port.isdigit() and username and password):
        logger.warning(f"Malformed proxy entry skipped: '{proxy}'")
        return None

    return {"ip": ip, "port": port, "username": username, "password": password}

def create_proxy_profile(proxy_info: Dict[str, str], index: int) -> Dict[str, Any]:
    """Generate a proxy profile configuration dictionary."""
    return {
        "profileType": "FixedProfile",
        "name": f"+m{index + 1}",
        "bypassList": make_bypass_list(),
        "color": DEFAULT_PROXY_COLOR,
        "revision": REVISION_ID,
        "fallbackProxy": {
            "scheme": "http",
            "host": proxy_info["ip"],
            "port": int(proxy_info["port"]),
        },
        "auth": {
            "fallbackProxy": {
                "username": proxy_info["username"],
                "password": proxy_info["password"],
            }
        },
    }

def build_base_profiles() -> Dict[str, Any]:
    """Construct static parts of the configuration (switch and proxy group)."""
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

def generate_output_data(proxies: List[str]) -> Dict[str, Any]:
    """Generate the full proxy configuration from a list of proxies."""
    output = build_base_profiles()
    for index, proxy_str in enumerate(proxies):
        proxy_info = parse_proxy(proxy_str)
        if proxy_info:
            profile = create_proxy_profile(proxy_info, index)
            output[profile["name"]] = profile
    return output

def write_output_file(data: Dict[str, Any], file_path: str) -> None:
    """Write JSON configuration data to a file."""
    try:
        Path(file_path).write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
        logger.info(f"Successfully wrote configuration to '{file_path}'")
    except Exception:
        logger.exception(f"Failed to write configuration to '{file_path}'")

def convert_proxy_list(input_path: str, output_path: str) -> None:
    """Read proxies from input, generate configuration, and write to output."""
    proxies = load_proxies(input_path)
    if not proxies:
        logger.error("No valid proxies found. Aborting.")
        return

    config = generate_output_data(proxies)
    write_output_file(config, output_path)

if __name__ == "__main__":
    convert_proxy_list("proxy_list.txt", "output.json")
