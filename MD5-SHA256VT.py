"""
VirusTotal Batch Hash Metadata Query
------------------------------------
Looks up a list of hashes (MD5/SHA1/SHA256) via the VirusTotal API, outputs relevant details and filenames.

Instructions:
- Place a text file of hashes (one per line) in the working directory.
- Supply your VirusTotal API key at runtime or as the VT_API_KEY environment variable.
- Outputs:
    - vt_details.txt: Full VirusTotal details per hash.
    - files.txt: All distinct filenames (from 'names').
    - output_sha256.txt: SHA256 values for all hashes found.

Requirements:
    pip install requests
"""

import os
import requests

def get_api_key():
    """Obtain VirusTotal API key from environment or user prompt."""
    key = os.environ.get("VT_API_KEY")
    if not key:
        key = input("Enter your VirusTotal API key: ").strip()
    return key

def read_hashes(filename):
    """Read hashes from a local file, one per line."""
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading '{filename}': {e}")
        exit(1)

def query_virustotal(api_key, hash_value):
    url = f"https://www.virustotal.com/api/v3/search?query={hash_value}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            print(f"VirusTotal HTTP error for {hash_value}: {response.status_code}")
            return None
        return response.json()
    except Exception as e:
        print(f"Error querying VirusTotal for {hash_value}: {e}")
        return None

def main():
    print("\nVirusTotal Batch Hash Metadata Query\n")
    hash_file = input("Enter the path to your hash list file: ").strip()
    api_key = get_api_key()
    hashes = read_hashes(hash_file)
    if not hashes:
        print("No hashes found in the file.")
        return

    names_seen = set()
    sha256s_seen = set()

    with open("vt_details.txt", "w", encoding="utf-8") as vt_out, \
         open("files.txt", "w", encoding="utf-8") as files_out, \
         open("output_sha256.txt", "w", encoding="utf-8") as sha256_out:
        
        for hash_value in hashes:
            vt_data = query_virustotal(api_key, hash_value)
            if not vt_data or not vt_data.get("data"):
                print(f"No data found for query: {hash_value}")
                continue

            attr = vt_data["data"][0]["attributes"]
            names = attr.get("names", [])
            malicious = attr.get("last_analysis_stats", {}).get("malicious", 0)
            ms_analysis = attr.get("last_analysis_results", {}).get("Microsoft", {})
            category = ms_analysis.get("category", "N/A")
            result = ms_analysis.get("result", "N/A")
            sha256 = attr.get("sha256", "N/A")
            last_date = attr.get("last_analysis_date", "N/A")

            # Write to vt_details.txt
            vt_out.write(f"Query: {hash_value}\n")
            vt_out.write(f"Names: {names}\n")
            vt_out.write(f"Popular Threat Classification: {malicious}\n")
            vt_out.write("Microsoft:\n")
            vt_out.write(f"\tCategory: {category}\n")
            vt_out.write(f"\tResult: {result}\n")
            vt_out.write(f"SHA256: {sha256}\n")
            vt_out.write(f"Last Analysis Date: {last_date}\n\n")

            # Write unique file names
            for name in names:
                if name not in names_seen:
                    files_out.write(name + "\n")
                    names_seen.add(name)

            # Write unique SHA256s
            if sha256 not in sha256s_seen:
                sha256_out.write(sha256 + "\n")
                sha256s_seen.add(sha256)

    print("\nQuery complete. Results saved as 'vt_details.txt', 'files.txt', and 'output_sha256.txt'.")

if __name__ == "__main__":
    main()
