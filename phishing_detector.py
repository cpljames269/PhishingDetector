import csv
from pathlib import Path

EMAIL_FILE = Path("sample_emails.csv")
OUTPUT_FILE = Path("phishing_report.csv")

def read_emails(file_path):
    emails = []
    with open(file_path, "r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            emails.append(row)
    return emails

def detect_suspicious(emails):
    flagged = []
    for email in emails:
        # Flag if SPF or DKIM failed
        if email["spf"].lower() == "fail" or email["dkim"].lower() == "fail":
            flagged.append(email)
            continue
        # Flag if sender domain is obviously suspicious (fake top-level domains)
        sender_domain = email["sender"].split("@")[-1]
        if sender_domain.endswith((".xyz", ".biz", ".net", "123.com")):
            flagged.append(email)
            continue
        # Flag if link domain does not match sender domain
        link_domain = email["links"].split("/")[2] if "://" in email["links"] else email["links"]
        if link_domain != sender_domain:
            flagged.append(email)
            continue
    return flagged

def print_summary(flagged):
    print("\n=== Phishing Email Detection Summary ===\n")
    if not flagged:
        print("No suspicious emails detected.")
        return
    print(f"Suspicious emails detected: {len(flagged)}\n")
    for email in flagged:
        print(
            f"{email['timestamp']} | {email['sender']} | {email['subject']} | SPF:{email['spf']} DKIM:{email['dkim']} | Link: {email['links']}"
        )

def write_csv(flagged):
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=flagged[0].keys())
        writer.writeheader()
        for email in flagged:
            writer.writerow(email)
    return OUTPUT_FILE

if __name__ == "__main__":
    if not EMAIL_FILE.exists():
        print(f"Email CSV file {EMAIL_FILE} not found.")
        exit(1)

    emails = read_emails(EMAIL_FILE)
    flagged = detect_suspicious(emails)
    print_summary(flagged)
    if flagged:
        output_file = write_csv(flagged)
        print(f"\nSuspicious email report written to {output_file}")
