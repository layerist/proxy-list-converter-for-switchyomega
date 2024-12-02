import json
from typing import List, Dict


def load_proxies(input_file: str) -> List[str]:
    """Load proxies from a file and return a list of non-empty lines."""
    try:
        with open(input_file, 'r') as file:
            proxies = [line.strip() for line in file if line.strip()]
        if not proxies:
            print("Warning: No proxies found in the file.")
        return proxies
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
    except Exception as e:
        print(f"Error reading the file '{input_file}': {e}")
    return []


def create_proxy_data(ip: str, port: str, username: str, password: str, index: int) -> Dict:
    """Create a dictionary for a proxy configuration."""
    return {
        "profileType": "FixedProfile",
        "name": f"+m{index + 1}",
        "bypassList": [
            {"conditionType": "BypassCondition", "pattern": pattern}
            for pattern in ["127.0.0.1", "::1", "localhost"]
        ],
        "color": "#ca0",
        "revision": "190a4bca575",
        "fallbackProxy": {"scheme": "http", "host": ip, "port": int(port)},
        "auth": {"fallbackProxy": {"username": username, "password": password}},
    }


def generate_output_data(proxies: List[str]) -> Dict:
    """Generate the output JSON structure from the proxy list."""
    output_data = {
        "+auto switch": {
            "color": "#99dd99",
            "defaultProfileName": "direct",
            "name": "auto switch",
            "profileType": "SwitchProfile",
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
        "+proxy": {
            "auth": {},
            "bypassList": [
                {"conditionType": "BypassCondition", "pattern": pattern}
                for pattern in ["127.0.0.1", "::1", "localhost"]
            ],
            "color": "#99ccee",
            "fallbackProxy": {"host": "127.0.0.1", "port": 80, "scheme": "http"},
            "name": "proxy",
            "profileType": "FixedProfile",
            "revision": "1908e30c31b",
        },
        "-addConditionsToBottom": False,
        "-confirmDeletion": True,
        "-downloadInterval": 1440,
        "-enableQuickSwitch": False,
        "-monitorWebRequests": True,
        "-quickSwitchProfiles": [],
        "-refreshOnProfileChange": True,
        "-revertProxyChanges": True,
        "-showExternalProfile": True,
        "-showInspectMenu": True,
        "-startupProfileName": "",
        "schemaVersion": 2,
    }

    for index, proxy in enumerate(proxies):
        try:
            ip, port, username, password = proxy.split(':')
            output_data[f"+m{index + 1}"] = create_proxy_data(ip, port, username, password, index)
        except ValueError:
            print(f"Warning: Proxy '{proxy}' is incorrectly formatted. Skipping.")

    return output_data


def write_output_file(output_data: Dict, output_file: str) -> None:
    """Write the output data structure to a JSON file."""
    try:
        with open(output_file, 'w') as file:
            json.dump(output_data, file, indent=4)
        print(f"Output successfully written to '{output_file}'")
    except IOError as e:
        print(f"Error writing to the file '{output_file}': {e}")


def convert_proxy_list(input_file: str, output_file: str) -> None:
    """Convert a proxy list from a file to a JSON configuration."""
    proxies = load_proxies(input_file)
    if proxies:
        output_data = generate_output_data(proxies)
        write_output_file(output_data, output_file)
    else:
        print("No valid proxies loaded. Exiting.")


# Entry point
if __name__ == "__main__":
    input_file = "proxy_list.txt"  # Replace with your input file name
    output_file = "output.json"    # Replace with your desired output file name
    convert_proxy_list(input_file, output_file)
