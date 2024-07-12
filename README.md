# Proxy List Converter for SwitchyOmega

This Python script converts a list of proxies from a text file into a JSON format suitable for import/export in the Chrome extension Proxy SwitchyOmega.

## Features

- Reads proxy details from a text file in the format `ip:port:username:password`.
- Converts the proxies into a JSON structure that can be directly imported into Proxy SwitchyOmega.
- Adds default profiles and rules for a complete SwitchyOmega configuration.

## Usage

1. **Prepare your proxy list**: Create a text file (e.g., `proxy_list.txt`) where each line contains a proxy in the format `ip:port:username:password`.

2. **Run the script**: Use the provided script to convert your proxy list into the JSON format.

### Requirements

- Python 3.x

### How to Run

1. Save the script to a file, for example, `convert_proxy.py`.
2. Ensure your proxy list file (e.g., `proxy_list.txt`) is in the same directory as the script.
3. Run the script:
   ```bash
   python convert_proxy.py
   ```
4. The output JSON file (`output.json`) will be created in the same directory.

### License

This project is licensed under the MIT License. See the LICENSE file for details.
