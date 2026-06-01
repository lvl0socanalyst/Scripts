#!/usr/bin/env python3
"""
Check a list of emails against Hudson Rock's Cavalier infostealer API.

Usage:
    python check_emails.py emails.txt
    python check_emails.py emails.txt --csv out.csv
    python check_emails.py emails.txt --delay 2
"""

import argparse
import csv
import re
import sys
import time
import requests

API_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def load_emails(path):
    emails = []
    seen = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            email = line.strip().lower()
            if not email or email.startswith("#"):
                continue
            if not EMAIL_RE.match(email):
                print(f"  skipping invalid email: {email}", file=sys.stderr)
                continue
            if email not in seen:
                seen.add(email)
                emails.append(email)
    return emails


def check_email(session, email, timeout=30):
    for attempt in range(3):
        try:
            resp = session.get(API_URL, params={"email": email}, timeout=timeout)
        except requests.RequestException as exc:
            time.sleep(2)
            last_error = str(exc)
            continue

        if resp.status_code in (429, 500, 502, 503, 504):
            time.sleep(3 * (attempt + 1))
            last_error = f"HTTP {resp.status_code}"
            continue

        if resp.status_code != 200:
            return {"email": email, "status": "error",
                    "stealers": 0, "last_seen": "",
                    "error": f"HTTP {resp.status_code}"}

        try:
            data = resp.json()
        except ValueError:
            return {"email": email, "status": "error",
                    "stealers": 0, "last_seen": "",
                    "error": "bad JSON response"}

        return parse_result(email, data)

    return {"email": email, "status": "error",
            "stealers": 0, "last_seen": "", "error": last_error}


def parse_result(email, data):
    message = (data.get("message") or "").lower()
    if "not found" in message:
        return {"email": email, "status": "clean",
                "stealers": 0, "last_seen": "", "error": ""}

    stealers = data.get("stealers") or data.get("data") or []
    if isinstance(stealers, dict):
        stealers = stealers.get("stealers", [])

    if not stealers:
        status = "compromised" if data.get("compromised") else "clean"
        return {"email": email, "status": status,
                "stealers": 0, "last_seen": "", "error": ""}

    dates = [s.get("date_compromised") or s.get("date")
             for s in stealers if isinstance(s, dict)]
    dates = [d for d in dates if d]

    return {"email": email, "status": "compromised",
            "stealers": len(stealers),
            "last_seen": max(dates) if dates else "",
            "error": ""}


def main():
    parser = argparse.ArgumentParser(
        description="Check emails against Hudson Rock's Cavalier API.")
    parser.add_argument("emails_file", help="text file with one email per line")
    parser.add_argument("--csv", help="save results to a CSV file")
    parser.add_argument("--delay", type=float, default=1.5,
                        help="seconds to wait between requests (default 1.5)")
    args = parser.parse_args()

    try:
        emails = load_emails(args.emails_file)
    except FileNotFoundError:
        sys.exit(f"File not found: {args.emails_file}")

    if not emails:
        sys.exit("No valid emails to check.")

    print(f"Checking {len(emails)} email(s)...\n")

    session = requests.Session()
    session.headers.update({"Accept": "application/json"})

    results = []
    hits = 0
    for i, email in enumerate(emails, 1):
        res = check_email(session, email)
        results.append(res)

        if res["status"] == "compromised":
            hits += 1
            note = f"{res['stealers']} record(s)"
            if res["last_seen"]:
                note += f", last seen {res['last_seen']}"
            print(f"[{i}/{len(emails)}] COMPROMISED  {email}  ({note})")
        elif res["status"] == "clean":
            print(f"[{i}/{len(emails)}] clean        {email}")
        else:
            print(f"[{i}/{len(emails)}] error        {email}  ({res['error']})")

        if i < len(emails):
            time.sleep(args.delay)

    print(f"\nDone. {hits} of {len(emails)} found in infostealer logs.")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["email", "status", "stealers", "last_seen", "error"])
            for r in results:
                writer.writerow([r["email"], r["status"], r["stealers"],
                                 r["last_seen"], r["error"]])
        print(f"Saved CSV to {args.csv}")


if __name__ == "__main__":
    main()
