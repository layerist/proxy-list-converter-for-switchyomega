import json

def load_proxies(input_file):
    """Load proxies from a file and return a list of proxies."""
    try:
        with open(input_file, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
    except Exception as e:
        print(f"Error reading the file '{input_file}': {e}")
    return []

def create_proxy_data(ip, port, username, password, index):
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
        "fallbackProxy": {
            "scheme": "http",
            "host": ip,
            "port": int(port)
        },
        "auth": {
            "fallbackProxy": {
                "username": username,
                "password": password
            }
        }
    }

def generate_output_data(proxies):
    """Generate the output data structure for JSON export."""
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
                        "pattern": "internal.example.com"
                    },
                    "profileName": "direct"
                },
                {
                    "condition": {
                        "conditionType": "HostWildcardCondition",
                        "pattern": "*.example.com"
                    },
                    "profileName": "proxy"
                }
            ]
        },
        "+proxy": {
            "auth": {},
            "bypassList": [
                {"conditionType": "BypassCondition", "pattern": pattern}
                for pattern in ["127.0.0.1", "::1", "localhost"]
            ],
            "color": "#99ccee",
            "fallbackProxy": {
                "host": "127.0.0.1",
                "port": 80,
                "scheme": "http"
            },
            "name": "proxy",
            "profileType": "FixedProfile",
            "revision": "1908e30c31b"
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
        "schemaVersion": 2
    }

    for index, proxy in enumerate(proxies):
        try:
            ip, port, username, password = proxy.split(':')
            proxy_data = create_proxy_data(ip, port, username, password, index)
            output_data[proxy_data["name"]] = proxy_data
        except ValueError:
            print(f"Error: Proxy '{proxy}' is incorrectly formatted. Skipping.")

    return output_data

def write_output_file(output_data, output_file):
    """Write the output data to a JSON file."""
    try:
        with open(output_file, 'w') as file:
            json.dump(output_data, file, indent=4)
        print(f"Output successfully written to '{output_file}'")
    except IOError as e:
        print(f"Error writing to the file '{output_file}': {e}")

def convert_proxy_list(input_file, output_file):
    """Convert a list of proxies from a text file into a JSON configuration."""
    proxies = load_proxies(input_file)
    if proxies:
        output_data = generate_output_data(proxies)
        write_output_file(output_data, output_file)
    else:
        print("No valid proxies loaded. Exiting.")

# Usage
if __name__ == "__main__":
    input_file = 'proxy_list.txt'  # Replace with your input file name
    output_file = 'output.json'    # Replace with your desired output file name
    convert_proxy_list(input_file, output_file)
