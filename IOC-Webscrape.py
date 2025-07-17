"""
IOC Extractor (Generic, Safe Version)
-------------------------------------
Extracts IOCs (hashes, IPs, domains, emails, file names) from a web page.

Requirements:
    pip install requests

Usage:
    python ioc_extractor.py
    (Enter the target URL at the prompt.)

Outputs:
    Text files for each IOC type in the current directory.
"""

import re
import requests
from urllib.parse import urlparse

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def search_iocs(url):
    """Download a web page and extract common IOCs."""
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
    except Exception as e:
        print(f"Error fetching '{url}': {e}")
        return

    content = response.text

    # Hashes
    sha256_iocs = set(re.findall(r'\b[A-Fa-f0-9]{64}\b', content))
    sha1_iocs   = set(re.findall(r'\b[A-Fa-f0-9]{40}\b', content))
    md5_iocs    = set(re.findall(r'\b[A-Fa-f0-9]{32}\b', content))

    # Remove overlaps (SHA256 > SHA1 > MD5)
    sha1_iocs -= sha256_iocs
    md5_iocs -= (sha1_iocs | sha256_iocs)

    # IPv4 addresses (simple, does not check for public/private)
    ip_iocs = set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', content))
    ip_iocs = {ip.replace('[.]', '.') for ip in ip_iocs}

    # Domains (basic, case-insensitive, skips common file extensions)
    domain_iocs = set(re.findall(
        r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', content, re.IGNORECASE
    ))
    domain_iocs = {d.replace('[.]', '.') for d in domain_iocs}
    # Remove file matches from domains
    domain_iocs = {d for d in domain_iocs if not re.search(
        r'\.(dll|txt|ttf|xll|png|exe|odt|ods|odp|odm|odc|odb|docx?|docm|wps|xlsx?|xlsm|xlsb|xlk|pptx?|pptm|mdb|accdb|pst|dwg|dxf|dxg|wpd|rtf|wb2|mdf|dbf|psd|pdd|pdf|eps|ai|indd|cdr|jpe?g|dng|3fr|arw|srf|sr2|bay|crw|cr2|dcr|kdc|erf|mef|mrw|nef|nrw|orf|raf|raw|rwl|rw2|r3d|ptx|pef|srw|x3f|der|cer|crt|pem|pfx|p12|p7b|p7c|ini|ja|plg|rar)$', d, re.IGNORECASE)
    }

    # Emails
    email_iocs = set(re.findall(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', content
    ))

    # Files
    file_iocs = set(re.findall(
        r'\b[\w-]+\.(?:dll|txt|xml|xll|png|exe|odt|ods|odp|odm|odc|odb|docx?|docm|wps|xlsx?|xlsm|xlsb|xlk|pptx?|pptm|mdb|accdb|pst|dwg|dxf|dxg|wpd|rtf|wb2|mdf|dbf|psd|pdd|pdf|eps|ai|indd|cdr|jpe?g|dng|3fr|arw|srf|sr2|bay|crw|cr2|dcr|kdc|erf|mef|mrw|nef|nrw|orf|raf|raw|rwl|rw2|r3d|ptx|pef|srw|x3f|der|cer|crt|pem|pfx|p12|p7b|p7c|ini|ja|plg|rar)\b',
        content, re.IGNORECASE
    ))

    # Output mapping
    outputs = [
        ('sha256.txt', sha256_iocs),
        ('sha1.txt', sha1_iocs),
        ('md5.txt', md5_iocs),
        ('ip.txt', ip_iocs),
        ('domain.txt', domain_iocs),
        ('email.txt', email_iocs),
        ('file.txt', file_iocs),
    ]

    total = 0
    for filename, dataset in outputs:
        with open(filename, 'w', encoding='utf-8') as f:
            for ioc in sorted(dataset):
                f.write(ioc + '\n')
        print(f"Saved {len(dataset)} entries to '{filename}'")
        total += len(dataset)

    print(f"\nCompleted: {total} unique IOCs extracted and saved.")
    print("Files are in the current working directory.")

if __name__ == "__main__":
    url = input("Enter the URL to search for IOCs: ").strip()
    if not validate_url(url):
        print("Invalid URL format. Please enter a URL beginning with http:// or https://")
    else:
        search_iocs(url)
