"""
KQL Email Address Query Generator (URL or Local File)
-----------------------------------------------------
Prompts the user for either a URL to a plain text email list or a local file path,
then generates a readable multi-line KQL query for those addresses.

Output: 'email_output.txt' (ready to paste into Sentinel, etc.)

Requirements:
    pip install requests
"""

import re
import requests

def validate_email(email):
    """Simple validation for email address format."""
    pattern = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    return bool(pattern.match(email))

def get_email_list():
    print("Would you like to:")
    print("  1) Enter a URL to a text file of email addresses")
    print("  2) Upload or specify a local file")
    choice = input("Enter 1 or 2: ").strip()
    if choice == "1":
        url = input("Paste the URL to your email list: ").strip()
        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            emails = [line.strip() for line in response.text.splitlines() if validate_email(line.strip())]
        except Exception as e:
            print(f"Error fetching or processing URL: {e}")
            return []
    elif choice == "2":
        file_path = input("Enter the path to your email list file: ").strip()
        try:
            with open(file_path, "r") as f:
                emails = [line.strip() for line in f if validate_email(line.strip())]
        except Exception as e:
            print(f"Error reading file '{file_path}': {e}")
            return []
    else:
        print("Invalid selection. Please run the script again and choose 1 or 2.")
        return []
    return emails

def build_kql(emails):
    kql_conditions = []
    for email in emails:
        domain = email.split('@')[1]
        user = email.split('@')[0]
        kql_conditions.extend([
            f"EmailRecipient == '{email}'",
            f"EmailSenderAddress == '{email}'",
            f"EmailSourceDomain == '{domain}'",
            f"RecipientEmailAddress == '{email}'",
            f"SenderMailFromDomain == '{domain}'",
            f"SenderMailFromAddress == '{email}'",
            f"UserEmail == '{email}'",
            f"EmailSenderName == '{user}'",
        ])
    # Format for readability
    return (
        "search *\n"
        "| where TimeGenerated > ago(90d)\n"
        "| where " +
        "\n    or ".join(kql_conditions) +
        "\n"
    )

def main():
    emails = get_email_list()
    if not emails:
        print("No valid email addresses found or unable to load file.")
        return
    kql = build_kql(emails)
    with open("email_output.txt", "w") as f:
        f.write(kql)
    print(f"KQL query generated and saved as 'email_output.txt'.")

if __name__ == "__main__":
    main()
