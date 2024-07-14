# Simple Port Scanner

Simple Port Scanner is a Python-based utility that allows users to scan network ports on a specified IP address. The tool is designed to be easy to use and provides a range of scanning options to suit different needs.

## Features

- **Multiple Scanning Ranges**: Users can choose to scan well-known ports, registered ports, dynamic/private ports, or all ports.
- **Concurrent Scanning**: Utilizes multi-threading to scan multiple ports simultaneously, significantly speeding up the scanning process.
- **Customizable Output**: Users can specify an output file to save the scan results, either with an absolute or relative path.
- **Help Menu**: Includes a help menu that provides usage information and available options.
- **Keyboard Interrupt Handling**: Gracefully handles keyboard interrupts, allowing the user to stop the scan at any time.

## Usage

To use Simple Port Scanner, you need to have Python installed on your system. Run the script from the command line, providing the target IP address and any desired options.

```bash
python3 scanner.py <IP_Address> [Option]
```

## Options

- -wn, --well-known: Scan for well-known ports (0-1023)
- -r, --registered: Scan for registered ports (1024-49151)
- -d, --dynamic: Scan for dynamic/private ports (49152-65535)
- -wnr: Scan for well-known and registered ports (0-49151)
- -f, --full: Scan for all ports (0-65535)
- -h, --help: Show the help message and exit
- -o, --output: Save the results to a specified path

## Examples

Scan well-known ports on a given IP address:

`python3 scanner.py 192.168.1.1 --well-known`

Save the scan results to a specific file:

`python3 scanner.py 192.168.1.1 -wn -o /path/to/folder/results.txt`

# Requirements

- Python 3.x
- Access to the network and permissions to perform port scanning

# Demo
- ![image](https://github.com/user-attachments/assets/88d4abd0-f727-4e2f-adb0-dcd8fe611220)
- ![image](https://github.com/user-attachments/assets/50675378-d712-46c7-b8e6-9a10a930b951)

# Disclaimer

Ensure you have the necessary permissions to scan the target system. Unauthorized scanning can be illegal or considered malicious activity.

# License

This project is licensed under the MIT License - see the LICENSE.md file for details.
