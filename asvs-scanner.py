#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import sys
import argparse
import socket
from urllib.parse import urlparse
import requests
import dns.resolver
from bs4 import BeautifulSoup
from wafw00f.main import WafW00F

# Subdomain scanner function
def subdomain_scan(domain, subdomains_input):
    subdomains = []

    if subdomains_input and os.path.isfile(subdomains_input):
        with open(subdomains_input, 'r') as file:
            subdomains_list = [line.strip() for line in file]
    elif subdomains_input:
        subdomains_list = [subdomains_input]
    else:
        subdomains_list = []

    for subdomain in subdomains_list:
        try:
            dns.resolver.query(subdomain, 'A')
            subdomains.append(subdomain)
            print(f"Found subdomain: {subdomain}")
        except dns.resolver.NXDOMAIN:
            continue

    with open('subdomains.txt', 'w') as file:
        for subdomain in subdomains:
            file.write(f"{subdomain}\n")

    return subdomains

# OSINT information gathering function
def osint_info(domain):
    url = f"https://www.whois.com/whois/{domain}"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    whois_data = soup.find(id="registryData").prettify()
    print("\nOSINT Info:")
    print(whois_data)

# WAF detection function using wafw00f
def waf_detection(target):
    waf_detector = WafW00F(target)
    detected_waf, waf_name = waf_detector.identify()
    print("\nWAF Detection:")
    if detected_waf:
        print(f"WAF Detected: {waf_name}")
    else:
        print("No WAF detected")

def main():
    parser = argparse.ArgumentParser(description="Security testing based on OWASP ASVS methodology")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target URL or IP address")
    parser.add_argument("-s", "--subdomains", type=str, help="Subdomains file or specified subdomain")
    args = parser.parse_args()

    target = args.target
    subdomains_input = args.subdomains
    parsed_url = urlparse(target)

    if not parsed_url.scheme:
        target = f"http://{target}"
        parsed_url = urlparse(target)

    domain = parsed_url.netloc

    # Perform subdomain scanning
    subdomains = subdomain_scan(domain, subdomains_input)

    # Perform OSINT information gathering
    osint_info(domain)

    # Perform WAF detection
    waf_detection(target)

if __name__ == "__main__":
    main()
