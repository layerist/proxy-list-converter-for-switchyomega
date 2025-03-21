import json
import logging
from pathlib import Path
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Constants
BYPASS_PATTERNS = ["127.0.0.1", "::1", "localhost"]

def load_proxies(input_file: str) -> List[str]:
    """Load proxies from a file, filtering out empty lines."""
    path = Path(input_file)
    if not path.is_file():
        logging.error(f"File '{input_file}' not found.")
        return []
    
    with path.open('r', encoding='utf-8') as file:
        proxies = [line.strip() for line in file if line.strip()]
    
    if not proxies:
        logging.warning("No proxies found in the file.")
    return proxies

def create_proxy_data(proxy: str, index: int) -> Dict[str, Any]:
    """Create a dictionary for a proxy configuration."""
    parts = proxy.split(':')
    if len(parts) != 4:
        logging.warning(f"Proxy '{proxy}' is incorrectly formatted. Skipping.")
        return {}
    
    ip, port, username, password = parts
    return {
        "profileType": "FixedProfile",
        "name": f"+m{index + 1}",
        "bypassList": [{"conditionType": "BypassCondition", "pattern": pattern} for pattern in BYPASS_PATTERNS],
        "color": "#ca0",
        "revision": "190a4bca575",
        "fallbackProxy": {"scheme": "http", "host": ip, "port": int(port)},
        "auth": {"fallbackProxy": {"username": username, "password": password}},
    }

def generate_output_data(proxies: List[str]) -> Dict[str, Any]:
    """Generate the output JSON structure from a list of proxies."""
    output_data = {
        "+auto switch": {
            "color": "#99dd99",
            "defaultProfileName": "direct",
            "name": "auto switch",
            "profileType": "SwitchProfile",
            "rules": [
                {"condition": {"conditionType": "HostWildcardCondition", "pattern": "internal.example.com"}, "profileName": "direct"},
                {"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.example.com"}, "profileName": "proxy"},
            ],
        },
        "+proxy": {
            "bypassList": [{"conditionType": "BypassCondition", "pattern": pattern} for pattern in BYPASS_PATTERNS],
            "color": "#99ccee",
            "fallbackProxy": {"host": "127.0.0.1", "port": 80, "scheme": "http"},
            "name": "proxy",
            "profileType": "FixedProfile",
            "revision": "1908e30c31b",
        },
        "schemaVersion": 2,
    }
    
    proxy_entries = {f"+m{index + 1}": data for index, proxy in enumerate(proxies) if (data := create_proxy_data(proxy, index))}
    output_data.update(proxy_entries)
    
    return output_data

def write_output_file(output_data: Dict[str, Any], output_file: str) -> None:
    """Write the output data structure to a JSON file."""
    try:
        Path(output_file).write_text(json.dumps(output_data, indent=4, ensure_ascii=False), encoding='utf-8')
        logging.info(f"Output successfully written to '{output_file}'")
    except IOError as e:
        logging.error(f"Error writing to the file '{output_file}': {e}")

def convert_proxy_list(input_file: str, output_file: str) -> None:
    """Convert a proxy list from a file to a structured JSON configuration."""
    proxies = load_proxies(input_file)
    if not proxies:
        logging.error("No valid proxies loaded. Exiting.")
        return
    
    output_data = generate_output_data(proxies)
    write_output_file(output_data, output_file)

# Entry point
if __name__ == "__main__":
    convert_proxy_list("proxy_list.txt", "output.json")
