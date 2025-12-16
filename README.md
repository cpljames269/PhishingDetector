Phishing Email Detector – Security Alert Triage

This Python project simulates a basic phishing email detection workflow. It reads email headers from a CSV, flags suspicious messages, and produces both a console summary and a CSV report. A sample CSV (sample_emails.csv) is included for immediate testing and demonstration.

Features

Reads a CSV of email alerts with fields:

Timestamp

Sender address

Subject

SPF/DKIM results

Links in the email

Flags suspicious emails if:

SPF or DKIM fails

Sender domain is unusual or fake

Links don’t match sender domain

Outputs:

Console summary for quick review

CSV report (phishing_report.csv) for follow-up analysis

Sample Data

sample_emails.csv includes fake email addresses, domains, and links:

Obvious fake domains like .xyz, .biz, .net, 123.com

SPF/DKIM simulation (pass/fail)

Mix of safe and suspicious messages for testing

This allows safe demonstration of phishing detection skills.

Installation

Clone the repository:

git clone https://github.com/cpljames269/phishing-detector.git
cd phishing-detector


Ensure Python 3 is installed

No external dependencies required

Usage

Run the script with the sample CSV in the same folder:

python phishing_detector.py


Expected output:

Console summary highlighting suspicious emails

CSV report phishing_report.csv containing flagged emails

Example Console Output
=== Phishing Email Detection Summary ===

Suspicious emails detected: 5

2025-12-15 08:05:12 | service@notrealbiz.xyz | Invoice Attached | SPF:fail DKIM:fail | Link: http://notrealbiz.xyz/invoice
2025-12-15 08:15:45 | info@fakebank123.com | Account Suspended | SPF:fail DKIM:pass | Link: http://fakebank123.com/login
...
Report written to phishing_report.csv
