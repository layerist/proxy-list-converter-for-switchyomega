import json

def convert_proxy_list(input_file, output_file):
    with open(input_file, 'r') as file:
        proxies = file.readlines()
    
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
                {"conditionType": "BypassCondition", "pattern": "127.0.0.1"},
                {"conditionType": "BypassCondition", "pattern": "::1"},
                {"conditionType": "BypassCondition", "pattern": "localhost"}
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
        ip, port, username, password = proxy.strip().split(':')
        proxy_num = f"+m{index+1}"
        
        proxy_data = {
            "profileType": "FixedProfile",
            "name": proxy_num,
            "bypassList": [
                {"conditionType": "BypassCondition", "pattern": "127.0.0.1"},
                {"conditionType": "BypassCondition", "pattern": "[::1]"},
                {"conditionType": "BypassCondition", "pattern": "localhost"}
            ],
            "color": "#ca0",
            "revision": "190a4bca575",
            "fallbackProxy": {
                "scheme": "http",
                "port": int(port),
                "host": ip
            },
            "auth": {
                "fallbackProxy": {
                    "username": username,
                    "password": password
                }
            }
        }
        
        output_data[proxy_num] = proxy_data
    
    with open(output_file, 'w') as file:
        json.dump(output_data, file, indent=4)
        
    print(f"Output written to {output_file}")

# Usage
input_file = 'proxy_list.txt'  # Replace with your input file name
output_file = 'output.json'  # Replace with your desired output file name
convert_proxy_list(input_file, output_file)
