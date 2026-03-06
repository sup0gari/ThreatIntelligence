#!/usr/env/python3
import os
import sys
import requests
import shodan
import whois
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files"
HEADERS = {"accept": "application/json", "x-apikey": VT_API_KEY}

shodan_client = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None

def get_detection(data):
    attr = data.get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    results = attr.get("last_analysis_results", {})
    print(f"\n{'='*20} DETECTION {'='*20}")
    print(f"Summary: {stats.get('malicious')} Malicious / {stats.get('undetected')} Undetected")
    print(f"Suggested Label: {attr.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')}")
    print(f"\n[+] Detected Vendors & Signatures:")
    for vendor, detail in results.items():
        if detail.get("result"):
            print(f"  - {vendor:20}: {detail.get('result')}")

def get_osint_info(ip, hostname):
    print(f"    >>> OSINT Investigation for {ip}")
    if shodan_client:
        try:
            host = shodan_client.host(ip)
            print(f"      [Shodan] Ports: {host.get('ports')} | OS: {host.get('os', 'N/A')}")
            if host.get('vulns'):
                print(f"      [Shodan] Vulns: {host.get('vulns')[:3]}")
        except:
            print("      [Shodan] No data.")

    target = hostname if hostname != "N/A" else ip
    try:
        w = whois.whois(target)
        c_date = w.creation_date
        if isinstance(c_date, list): c_date = c_date[0]
        if c_date:
            days = (datetime.now() - c_date).days
            print(f"      [Whois]  Created: {c_date.strftime('%Y-%m-%d')} ({days} days ago)")
            print(f"      [Whois]  Registrar: {w.registrar}")
    except:
        print("      [Whois]  No data.")

def get_relations(file_hash):
    print(f"\n{'='*20} RELATIONS {'='*20}")
    url = f"{VT_URL}/{file_hash}/contacted_ips"
    res = requests.get(url, headers=HEADERS)
    if res.status_code == 200:
        ips_list = res.json().get("data", [])
        for entry in ips_list:
            ip = entry.get("id")
            res_ip = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=HEADERS)
            country, owner = "Unknown", "Unknown"
            if res_ip.status_code == 200:
                attr = res_ip.json().get("data", {}).get("attributes", {})
                country = attr.get("country", "Unknown")
                owner = attr.get("as_owner", "Unknown")
            
            res_dns = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions", headers=HEADERS)
            hostname = "N/A"
            if res_dns.status_code == 200:
                dns_data = res_dns.json().get("data", [])
                if dns_data: hostname = dns_data[0].get("attributes", {}).get("host_name", "N/A")
            
            print(f"  - {ip:15} [{country}] | {owner[:20]}")
            print(f"    └ Host: {hostname}")
            get_osint_info(ip, hostname)

def get_behavior(data):
    attr = data.get("attributes", {})
    print(f"\n{'='*20} BEHAVIOR {'='*20}")
    tags = attr.get("tags", [])
    if tags: print(f"  Tags: {', '.join(tags[:15])}")
    if "sigma_analysis_stats" in attr:
        sigma = attr.get("sigma_analysis_stats")
        print(f"  Sigma Rules: {sum(sigma.values())} hits")

def scan(file_hash):
    res = requests.get(f"{VT_URL}/{file_hash}", headers=HEADERS)
    if res.status_code == 200:
        data = res.json().get("data", {})
        get_detection(data)
        get_behavior(data)
        get_relations(file_hash)
        print(f"\n{'='*51}")
    else:
        print(f"[-] Error: {res.status_code}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    scan(sys.argv[1])