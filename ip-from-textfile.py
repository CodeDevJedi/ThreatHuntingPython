"""
Extract Unique IPv4 Addresses from Text File
--------------------------------------------
Reads a text file, extracts all unique IPv4 addresses, and writes them to an output file.

Usage:
    Place this script in the same folder as your input file (e.g., 'vt_details.txt').
    Adjust INPUT_FILE and OUTPUT_FILE as needed.

Requirements:
    Standard Python library only.
"""

import re
import sys

INPUT_FILE = "vt_details.txt"
OUTPUT_FILE = "output_ips.txt"

def extract_ips(input_file, output_file):
    """Extract all unique IPv4 addresses from input_file and write to output_file."""
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ip_addresses = set()
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            for line in f:
                ips = ip_pattern.findall(line)
                ip_addresses.update(ips)
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    with open(output_file, "w", encoding="utf-8") as f:
        for ip in sorted(ip_addresses):
            f.write(f"{ip}\n")

    print(f"Extracted {len(ip_addresses)} unique IP addresses to '{output_file}'.")

if __name__ == "__main__":
    extract_ips(INPUT_FILE, OUTPUT_FILE)
