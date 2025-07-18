"""
VirusTotal Domain Resolution Lookup
-----------------------------------
Fetches latest DNS resolutions for domains from a file, using VirusTotal API.

Instructions:
- Place your domain list (one per line) in a local file (e.g., "domains.txt").
- Do not include API keys in public repositories. Supply your VirusTotal API key at runtime or via environment variable VT_API_KEY.
- Output files: vt_details.txt (verbose), output_ips.txt (just resolved IPs).

Requirements:
    pip install requests
"""

import os
import requests

def get_api_key():
    """Get API key from env or user input."""
    key = os.environ.get("VT_API_KEY")
    if not key:
        key = input("Enter your VirusTotal API key: ").strip()
    return key

def read_domains(filename):
    """Read domain list from file."""
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading '{filename}': {e}")
        exit(1)

def get_domain_ips(api_key, domains):
    """Query VirusTotal for each domain's latest resolutions."""
    base_url = "https://www.virustotal.com/api/v3/domains/"
    tail = "/relationships/resolutions?limit=10"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    results = []
    with open("vt_details.txt", "w", encoding="utf-8") as detail_out, \
         open("output_ips.txt", "w", encoding="utf-8") as ip_out:
        for domain in domains:
            url = base_url + domain + tail
            try:
                response = requests.get(url, headers=headers, timeout=30)
                if response.status_code != 200:
                    print(f"HTTP error {response.status_code} for {domain}: {response.text}")
                    continue
                resp_json = response.json()
            except Exception as e:
                print(f"Request error for {domain}: {e}")
                continue

            # Extract IPs from resolutions
            ips = []
            if resp_json.get("data"):
                for res in resp_json["data"]:
                    ip = res.get("id", "")
                    if ip:
                        ips.append(ip)
                        detail_out.write(f"Domain: {domain}\nResolved IP: {ip}\n\n")
                # Write just the IPs to output_ips.txt
                for ip in ips:
                    ip_out.write(f"{ip}\n")
            else:
                print(f"No resolution data for domain: {domain}")
                detail_out.write(f"Domain: {domain}\nNo IPs found.\n\n")

    print("\nLookup complete. Results saved to 'vt_details.txt' and 'output_ips.txt'.")

if __name__ == "__main__":
    print("VirusTotal Domain Resolution Lookup\n")
    domain_file = input("Enter the path to your domain list file: ").strip()
    vt_api_key = get_api_key()
    domains = read_domains(domain_file)
    get_domain_ips(vt_api_key, domains)
