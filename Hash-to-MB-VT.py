"""
Threat Intelligence Hash Query Script
-------------------------------------
Looks up a list of hashes using VirusTotal and MalwareBazaar APIs, then writes summary details to output files.

Instructions:
- Prepare a text file (one hash per line) in the working directory.
- You must supply your own VirusTotal and MalwareBazaar API keys (do not publish your keys).
- Run the script and follow prompts.

Requirements:
    pip install requests
"""

import requests
import time
import os

def get_api_key(env_var, prompt):
    """Safely gets an API key from environment or user prompt."""
    key = os.environ.get(env_var)
    if not key:
        key = input(f"{prompt}: ").strip()
    return key

def read_hashes(filename):
    """Reads hashes from a text file, one per line."""
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
            print(f"VirusTotal error for {hash_value}: {response.status_code}")
            return None
        return response.json()
    except Exception as e:
        print(f"Error querying VirusTotal for {hash_value}: {e}")
        return None

def query_malwarebazaar(api_key, hash_value):
    url = "https://mb-api.abuse.ch/api/v1/"
    params = {
        'query': 'get_info',
        'hash': hash_value,
        'apikey': api_key
    }
    try:
        response = requests.post(url, data=params, timeout=30)
        if response.status_code != 200:
            print(f"MalwareBazaar error for {hash_value}: {response.status_code}")
            return None
        return response.json()
    except Exception as e:
        print(f"Error querying MalwareBazaar for {hash_value}: {e}")
        return None

def main():
    print("\nThreat Intelligence Multi-Source Hash Query")
    hash_file = input("Enter the path to your hash list file: ").strip()
    vt_api_key = get_api_key("VT_API_KEY", "Enter your VirusTotal API key")
    mb_api_key = get_api_key("MB_API_KEY", "Enter your MalwareBazaar API key")

    hashes = read_hashes(hash_file)
    if not hashes:
        print("No hashes found in the file.")
        return

    unique_hashes = set()

    with open("vt_details.txt", "w", encoding="utf-8") as vt_out, \
         open("output_sha256.txt", "w", encoding="utf-8") as sha_out, \
         open("mb_details.txt", "w", encoding="utf-8") as mb_out:

        for hash_value in hashes:
            print(f"Querying VirusTotal for: {hash_value}")
            vt_data = query_virustotal(vt_api_key, hash_value)
            time.sleep(16)  # Respect VT community API rate limits (max 4 requests/minute)

            if vt_data and vt_data.get("data"):
                attributes = vt_data["data"][0]["attributes"]
                sha256 = attributes.get("sha256", "N/A")
                vt_out.write(f"Query: {hash_value}\n")
                vt_out.write(f"Names: {attributes.get('names', [])}\n")
                stats = attributes.get("last_analysis_stats", {})
                vt_out.write(f"Malicious Count: {stats.get('malicious', 0)}\n")
                ms = attributes.get("last_analysis_results", {}).get("Microsoft", {})
                vt_out.write(f"Microsoft:\n\tCategory: {ms.get('category', 'N/A')}\n\tResult: {ms.get('result', 'N/A')}\n")
                vt_out.write(f"SHA256: {sha256}\n")
                vt_out.write(f"Last Analysis Date: {attributes.get('last_analysis_date', 'N/A')}\n\n")
                unique_hashes.add(sha256)
            else:
                print(f"No data in VirusTotal for: {hash_value}. Querying MalwareBazaar.")
                mb_data = query_malwarebazaar(mb_api_key, hash_value)
                if mb_data and "data" in mb_data:
                    sample = mb_data["data"].get("sample", "N/A")
                    tags = mb_data["data"].get("tags", [])
                    mb_out.write(f"Query: {hash_value}\n")
                    mb_out.write(f"Sample: {sample}\n")
                    mb_out.write(f"Tags: {tags}\n\n")
                    unique_hashes.add(hash_value)
                else:
                    mb_out.write(f"Query: {hash_value}\nNo data found in MalwareBazaar.\n\n")

        # Write all unique SHA256 hashes
        for unique_hash in unique_hashes:
            sha_out.write(f"{unique_hash}\n")

    print("\nCompleted. Output files:")
    print(" - vt_details.txt (VirusTotal responses)")
    print(" - mb_details.txt (MalwareBazaar responses)")
    print(" - output_sha256.txt (unique hashes)")

if __name__ == "__main__":
    main()
