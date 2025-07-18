"""
VirusTotal Batch IP Metadata Query
----------------------------------
Fetches metadata and JSON for a list of IP addresses using the VirusTotal API.

Instructions:
- Place your IP list (one per line) in a local file, e.g., 'ip_list.txt'.
- Set your VirusTotal API key as an environment variable (VT_API_KEY) or enter at the prompt.
- Outputs:
    - vt_details.txt: Text summary of network/reputation for each IP.
    - ip_json_vt.txt: Raw JSON response for each IP (one per line, compact).

Requirements:
    pip install requests
"""

import os
import requests
import json

def get_api_key():
    """Fetch VirusTotal API key from environment or user input."""
    key = os.environ.get("VT_API_KEY")
    if not key:
        key = input("Enter your VirusTotal API key: ").strip()
    return key

def read_ip_list(filename):
    """Read IP addresses from a file, one per line."""
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading '{filename}': {e}")
        exit(1)

def query_vt_ip(api_key, ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            print(f"VirusTotal HTTP error for {ip}: {response.status_code}")
            return None
        return response.json()
    except Exception as e:
        print(f"Error querying VirusTotal for {ip}: {e}")
        return None

def main():
    print("\nVirusTotal Batch IP Metadata Query\n")
    ip_file = input("Enter the path to your IP list file: ").strip()
    api_key = get_api_key()
    ip_list = read_ip_list(ip_file)
    if not ip_list:
        print("No IPs found in the file.")
        return

    with open("vt_details.txt", "w", encoding="utf-8") as vt_out, \
         open("ip_json_vt.txt", "w", encoding="utf-8") as json_out:

        for ip in ip_list:
            data = query_vt_ip(api_key, ip)
            if not data or "data" not in data:
                print(f"No data found for IP: {ip}")
                continue

            # Write raw JSON (one line per IP)
            json.dump(data, json_out)
            json_out.write('\n')

            attributes = data["data"].get("attributes", {})
            network = attributes.get("network", "N/A")
            reputation = attributes.get("reputation", "N/A")
            vt_out.write(f"IP address: {ip}\n")
            vt_out.write(f"Network: {network}\n")
            vt_out.write(f"Reputation: {reputation}\n\n")

    print("\nQuery complete. Results saved as 'vt_details.txt' and 'ip_json_vt.txt'.")

if __name__ == "__main__":
    main()
