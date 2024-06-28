#!/bin/python3
import sys
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import os
import nmap

PORT_RANGES = {
    "well-known": (0, 1023),
    "registered": (1024, 49151),
    "dynamic": (49152, 65535),
    "wnr": (0, 49151),
    "full": (0, 65535),
}


def print_banner():
    print("\n\n\n\033[1;32;40m" + "*" * 50)
    print("*" + " " * 16 + "Alpha Port Scanner" + " " * 14 + "*")
    print("*" * 50)
    print("\033[0m")


def print_help():
    print("\n\033[1;37;40mUsage:\033[0m python3 scanner.py <IP_Address> [Option]")
    print("\n\033[1;34;40mOptions:\033[0m")
    print("  -wn, --well-known   Scan for well-known ports (0-1023)")
    print("  -r, --registered    Scan for registered ports (1024-49151)")
    print("  -d, --dynamic       Scan for dynamic/private ports (49152-65535)")
    print("  -wnr                Scan for well-known and registered ports (0-49151)")
    print("  -f, --full          Scan for all ports (0-65535)")
    print("  -h, --help          Show this help message and exit")
    print(
        "  -o, --output        Save the results to a specified path Example -o /home/user/output.txt"
    )
    print("\n\033[1;34;40mExample:\033[0m python3 scanner.py 192.168.1.1 --well-known")
    print(
        "\n\033[1;31;40mNote:\033[0m Ensure you have the necessary permissions to scan the target system."
    )


def scan_port(ip, port, output_file=None):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, str(port))
        if nm[ip]["tcp"][port]["state"] == "open":
            service = nm[ip]["tcp"][port]["name"]
            port_info = f"{port}\topen\t{service}"
            print(port_info)
            if output_file:
                with open(output_file, "a") as file:
                    if file.tell() == 0:  # Check if the file is empty
                        file.write("Port Status Service\n")  # Write the header
                    file.write(port_info + "\n")

    except Exception as e:
        print(f"Error scanning port {port}: {e}")


# Parse arguments and set port range
if len(sys.argv) < 2:
    print_banner()
    print_help()
    print("\n\n\033[1;31;40mInvalid number of arguments.\033[0m\n\n")
    sys.exit()
elif sys.argv[1] in ("-h", "--help"):
    print_banner()
    print_help()
    sys.exit()

target = socket.gethostbyname(sys.argv[1])  # Translate hostname to IPv4
port_range = PORT_RANGES["well-known"]  # Default to well-known range
output_path = None

# Parse arguments and set port range
if len(sys.argv) < 2:
    print_banner()
    print_help()
    print("Invalid number of arguments.")
    sys.exit()
elif sys.argv[1] in ("-h", "--help"):
    print_banner()
    print_help()
    sys.exit()

for arg in sys.argv[2:]:
    if arg in ("-wn", "--well-known"):
        port_range = PORT_RANGES["well-known"]
    elif arg in ("-r", "--registered"):
        port_range = PORT_RANGES["registered"]
    elif arg in ("-d", "--dynamic"):
        port_range = PORT_RANGES["dynamic"]
    elif arg == "-wnr":
        port_range = PORT_RANGES["wnr"]
    elif arg in ("-f", "--full"):
        port_range = PORT_RANGES["full"]
    elif arg in ("-o", "--output"):
        output_flag = "-o" if "-o" in sys.argv else "--output"
        output_index = sys.argv.index(output_flag)
        try:
            output_path = sys.argv[output_index + 1]
            # Resolve the relative path to an absolute path
            output_path = os.path.abspath(output_path)
            # Check if the provided path includes a filename
            if not os.path.splitext(output_path)[1]:
                print("Please provide a file name with the extension for the output.")
                sys.exit()
        except IndexError:
            print("Please provide a specific path with a file name for the output.")
            sys.exit()

print_banner()

print("-" * 50)
print("Scanning target: " + target)
print("Time started: " + str(datetime.now()))
print("Scanning port range: {}-{}".format(port_range[0], port_range[1]))
print("-" * 50)
print("\n")
print("port\tstatus\tservice")

with ThreadPoolExecutor(max_workers=100) as executor:  # Adjust max_workers as needed
    for port in range(port_range[0], port_range[1] + 1):
        executor.submit(scan_port, target, port, output_path)

try:
    pass
except KeyboardInterrupt:
    print("\nExiting program!")
    sys.exit()

# Handle exceptions
except socket.gaierror:
    print("Hostname could not be resolved!")
    sys.exit()

except socket.error:
    print("Could not connect to server.")
    sys.exit()
