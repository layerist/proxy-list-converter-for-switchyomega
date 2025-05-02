import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Constants
BYPASS_PATTERNS = ["127.0.0.1", "::1", "localhost"]
SCHEMA_VERSION = 2
REVISION_ID = "190a4bca575"
DEFAULT_PROXY_COLOR = "#ca0"
AUTO_SWITCH_NAME = "+auto switch"
PROXY_GROUP_NAME = "+proxy"
DEFAULT_REVISION_ID = "1908e30c31b"

def load_proxies(file_path: str) -> List[str]:
    """Load non-empty lines from the proxy list file."""
    path = Path(file_path)
    if not path.is_file():
        logger.error(f"Proxy list file not found: '{file_path}'")
        return []

    with path.open(encoding="utf-8") as file:
        proxies = [line.strip() for line in file if line.strip()]

    if not proxies:
        logger.warning("The proxy list is empty.")
    return proxies

def make_bypass_list() -> List[Dict[str, str]]:
    """Generate a list of bypass condition dictionaries."""
    return [{"conditionType": "BypassCondition", "pattern": pattern} for pattern in BYPASS_PATTERNS]

def parse_proxy(proxy: str) -> Optional[Dict[str, str]]:
    """Split proxy string into components."""
    parts = proxy.split(":")
    if len(parts) != 4:
        logger.warning(f"Invalid proxy format skipped: '{proxy}'")
        return None

    ip, port, username, password = parts
    return {"ip": ip, "port": port, "username": username, "password": password}

def create_proxy_profile(proxy_info: Dict[str, str], index: int) -> Dict[str, Any]:
    """Create a single proxy profile entry."""
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

def generate_output_data(proxies: List[str]) -> Dict[str, Any]:
    """Build the full proxy configuration structure."""
    output = {
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

    for index, proxy in enumerate(proxies):
        proxy_info = parse_proxy(proxy)
        if proxy_info:
            profile = create_proxy_profile(proxy_info, index)
            output[profile["name"]] = profile

    return output

def write_output_file(data: Dict[str, Any], file_path: str) -> None:
    """Save configuration data to a JSON file."""
    try:
        json_output = json.dumps(data, indent=4, ensure_ascii=False)
        Path(file_path).write_text(json_output, encoding="utf-8")
        logger.info(f"Successfully wrote configuration to '{file_path}'")
    except Exception:
        logger.exception(f"Error writing to output file '{file_path}'")

def convert_proxy_list(input_path: str, output_path: str) -> None:
    """Main function to process proxy list and save the structured JSON."""
    proxies = load_proxies(input_path)
    if not proxies:
        logger.error("No valid proxies to process. Aborting.")
        return

    output_data = generate_output_data(proxies)
    write_output_file(output_data, output_path)

if __name__ == "__main__":
    convert_proxy_list("proxy_list.txt", "output.json")
