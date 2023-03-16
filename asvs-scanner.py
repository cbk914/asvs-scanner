import sys
import argparse
import socket
from urllib.parse import urlparse
import requests
import dns.resolver
from bs4 import BeautifulSoup
from wafw00f import WafW00F

# Subdomain scanner function
def subdomain_scan(domain, subdomain_file=None):
    subdomains = []
    if subdomain_file:
        with open(subdomain_file, 'r') as file:
            for line in file:
                subdomain = line.strip()
                if subdomain.endswith(domain):
                    subdomains.append(subdomain)
                    print(f"Found subdomain: {subdomain}")
    else:
        with open('subdomains_list.txt', 'r') as file:
            for line in file:
                subdomain = f"{line.strip()}.{domain}"
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
    print("\nWAF Detection:")
    waf_detector = WafW00F(target)
    success, wafs = waf_detector.identify()
    if success and wafs:
        for waf in wafs:
            print(f"WAF Detected: {waf}")
    else:
        print("No WAF detected")

def main():
    parser = argparse.ArgumentParser(description="Security testing based on OWASP ASVS methodology")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target URL or IP address")
    parser.add_argument("-s", "--subdomains", type=str, help="Path to subdomains file or specific subdomain")
    args = parser.parse_args()

    target = args.target
    subdomains_arg = args.subdomains
    parsed_url = urlparse(target)

    if not parsed_url.scheme:
        target = f"http://{target}"
        parsed_url = urlparse(target)

    domain = parsed_url.netloc

    # Perform subdomain scanning
    if subdomains_arg and "." in subdomains_arg:
        subdomains = [subdomains_arg]
    else:
        subdomains = subdomain_scan(domain, subdomain_file=subdomains_arg)

    # Perform OSINT information gathering
    osint_info(domain)

    # Perform WAF detection
    waf_detection(target)

if __name__ == "__main__":
    main()
