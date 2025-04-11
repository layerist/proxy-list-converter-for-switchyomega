import json
import logging
from pathlib import Path
from typing import List, Dict, Any

# Initialize logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Constants
BYPASS_PATTERNS = ["127.0.0.1", "::1", "localhost"]
REVISION_ID = "190a4bca575"
PROXY_COLOR = "#ca0"
SCHEMA_VERSION = 2

def load_proxies(file_path: str) -> List[str]:
    """Load non-empty proxy lines from a file."""
    path = Path(file_path)
    if not path.is_file():
        logger.error(f"Input file '{file_path}' not found.")
        return []

    with path.open(encoding='utf-8') as f:
        proxies = [line.strip() for line in f if line.strip()]

    if not proxies:
        logger.warning("No valid proxies found.")
    return proxies

def make_bypass_list() -> List[Dict[str, str]]:
    """Create the default bypass list for profiles."""
    return [{"conditionType": "BypassCondition", "pattern": pattern} for pattern in BYPASS_PATTERNS]

def create_proxy_data(proxy: str, index: int) -> Dict[str, Any]:
    """Convert a proxy string into a profile dictionary."""
    parts = proxy.split(':')
    if len(parts) != 4:
        logger.warning(f"Skipping invalid proxy format: '{proxy}'")
        return {}

    ip, port, username, password = parts
    return {
        "profileType": "FixedProfile",
        "name": f"+m{index + 1}",
        "bypassList": make_bypass_list(),
        "color": PROXY_COLOR,
        "revision": REVISION_ID,
        "fallbackProxy": {"scheme": "http", "host": ip, "port": int(port)},
        "auth": {"fallbackProxy": {"username": username, "password": password}},
    }

def generate_output_data(proxies: List[str]) -> Dict[str, Any]:
    """Generate the output configuration dictionary."""
    output: Dict[str, Any] = {
        "+auto switch": {
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
        "+proxy": {
            "profileType": "FixedProfile",
            "name": "proxy",
            "color": "#99ccee",
            "revision": "1908e30c31b",
            "bypassList": make_bypass_list(),
            "fallbackProxy": {"scheme": "http", "host": "127.0.0.1", "port": 80},
        },
        "schemaVersion": SCHEMA_VERSION,
    }

    # Append valid proxy entries
    for index, proxy in enumerate(proxies):
        proxy_config = create_proxy_data(proxy, index)
        if proxy_config:
            output[proxy_config["name"]] = proxy_config

    return output

def write_output_file(data: Dict[str, Any], file_path: str) -> None:
    """Write the structured proxy configuration to a JSON file."""
    try:
        Path(file_path).write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding='utf-8')
        logger.info(f"Configuration written to '{file_path}'")
    except Exception as e:
        logger.error(f"Failed to write to '{file_path}': {e}")

def convert_proxy_list(input_path: str, output_path: str) -> None:
    """Process proxy list file into structured JSON format."""
    proxies = load_proxies(input_path)
    if not proxies:
        logger.error("No proxies to process. Aborting.")
        return

    output_data = generate_output_data(proxies)
    write_output_file(output_data, output_path)

# Entry point
if __name__ == "__main__":
    convert_proxy_list("proxy_list.txt", "output.json")
