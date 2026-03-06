#!/usr/env/python3
import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/"

HEADERS = {
    "accept": "application/json",
    "x-apikey": VT_API_KEY
}

def scan(file_hash):
    res = requests.get(f"{VT_URL}{file_hash}", headers=HEADERS)
    if res.status_code == 200:
        data = res.json().get("data", {})
        get_detection(data)
        get_behavior(data)
        get_relations(data)
        print(f"\n"{'='*51})
    elif res.status_code == 404:
        print(f"[-] Hash {file_hash} not found.")
    else:
        print(f"[-] Error: {res.status_code}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vt_harvester.py <MALWARE HASH>")
        sys.exit(1)

    if not VT_API_KEY:
        print("Missing API KEY.")
    else:
        target_hash = sys.argv[1]
        scan(target_hash)