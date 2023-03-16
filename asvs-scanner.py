#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914
import sys
import os
import argparse
import socket
from urllib.parse import urlparse
import requests
import dns.resolver
from bs4 import BeautifulSoup
import nmap
import shodan
import vulners
from dotenv import load_dotenv
import json
import openai
import urllib3
from datetime import datetime

try:
    from wafw00f import WafDetector
    wafw00f_installed = True
except ImportError:
    wafw00f_installed = False

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

api_key_names = ['OPENAI', 'SHODAN', 'VULNERS']

# Load API keys from .env file
api_keys = {}

if os.path.isfile('.env'):
    with open('.env', 'r') as env_file:
        api_keys = dict(
            line.strip().split('=') for line in env_file if not line.startswith("#") and '=' in line
        )
else:
    with open('.env', 'w') as env_file:
        env_file.write("# API keys\n")
    for api_key_name in api_key_names:
        api_key = input(f"Please enter your {api_key_name} API key: ")
        api_keys[api_key_name] = api_key
        with open('.env', 'a') as env_file:
            env_file.write(f"{api_key_name}={api_key}\n")

# OpenAI API initialization
if 'OPENAI_API_KEY' in os.environ:
    openai.api_key = os.environ['OPENAI_API_KEY']
    openai_models = {
        "gpt-4": "gpt-4",
        "gpt-4-32k": "gpt-4-32k",
        "davinci": "text-davinci-002",
        "davinci-003": "text-davinci-003",
        "curie": "text-curie-001",
        "babbage": "text-babbage-001",
        "ada": "text-ada-001",
        "curie-instruct-beta": "text-curie-instruct-beta-001",
        "curie-instruct-2": "text-curie-instruct-2-001",
        "curie-instruct-3": "text-curie-instruct-3-001",
        "curie-instruct-4": "text-curie-instruct-4-001",
        "davinci-codex": "davinci-codex-001"
    }
def get_max_tokens(model):
    model_map = {
        "davinci": 2058,
        "davinci-003": 4096,
        "curie": 2048,
        "babbage": 1024,
        "ada": 1024,
        "text-davinci-002": 2048,
        "text-curie-001": 2048,
        "text-babbage-001": 1024,
        "text-ada-001": 1024,
        "davinci-codex": 2048,
        "gpt-4": 8192,
        "curie-instruct-beta": 2048,
        "curie-instruct-2": 2048,
        "curie-instruct-3": 2048,
        "curie-instruct-4": 8192
    }
    return model_map.get(model, 1024)

# Shodan API initialization
if 'SHODAN_API_KEY' in os.environ:
    shodan_api_key = os.environ['SHODAN_API_KEY']
    shodan_api = shodan.Shodan(shodan_api_key)

# Vulners API key initialization
if api_keys.get('VULNERS'):
    vulners_api_key = api_keys['VULNERS']

# Subdomain scanning function
def subdomain_scan(target, subdomains_input, api_keys, args):
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

    # Use OpenAI's GPT to generate a prompt for subdomain scanning
    prompt = f"Scan for subdomains for {target}"
    response = generate_chatgpt_response(args.openai_model, prompt)
    subdomains.extend(response.strip().split("\n"))

    return subdomains

# OSINT information gathering function
def osint_info(target, api_keys):
    # Perform WHOIS lookup using requests and BeautifulSoup
    url = f"https://www.whois.com/whois/{target}"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    whois_data = soup.find(id="registryData").prettify()
    print("\nWHOIS Info:")
    print(whois_data)

    # Perform Shodan search using Shodan API
    if 'SHODAN_API_KEY' in api_keys:
        shodan_api = shodan.Shodan(api_keys['SHODAN_API_KEY'])
        try:
            result = shodan_api.search(target)
            print("\nShodan Info:")
            for r in result['matches']:
                print(r['ip_str'])
                print(r['data'])
                print("\n")
        except shodan.APIError as e:
            print(f"Shodan API error:")
            print(f"Error: {e}")

    # Perform Google dorking search using requests and BeautifulSoup
    url = f"https://www.google.com/search?q=site:{target}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.content, "html.parser")
    search_results = soup.find_all('div', class_='BNeawe iBp4i AP7Wnd')
    print("\nGoogle Dorking Info:")
    for result in search_results:
        print(result.text)

def waf_detection(target, api_keys, args):
    detected_waf = False
    waf_name = ""
    try:
        # Use wafw00f to detect the WAF
        waf_detector = WafDetector()
        waf_detector.set_target(target)
        waf_detector.set_api_keys(api_keys)
        waf_detector.detect_waf()
        if waf_detector.is_waf_detected():
            detected_waf = True
            waf_name = waf_detector.get_waf_name()
    except Exception as e:
        print(f"Error detecting WAF: {e}")
    
    # Use OpenAI's GPT to generate a prompt for detecting WAF
    if not detected_waf:
        prompt = f"Detect the WAF for {target}"
        response = generate_openai_response(prompt, api_keys, args.openai_model)
        waf_name = response.strip()
        if waf_name:
            detected_waf = True

    print("\nWAF Detection:")
    if detected_waf:
        print(f"WAF Detected: {waf_name}")
    else:
        print("No WAF detected")

# Nmap scanning function using nmap module and Vulners script
def nmap_scan(target):
    api_key = os.environ.get('VULNERS_API_KEY')
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-p- --script vulners' + (f' --script-args vulners.api_key={api_key}' if api_key else ''))
    print("\nNmap Scan Results:")
    print(nm.csv())

    # Perform vulnerability scanning using OpenAI ChatGPT
    if 'OPENAI_API_KEY' in os.environ:
        model_engine = openai_models.get(args.om, openai_models["davinci"])
        prompt = f"Perform vulnerability analysis of {target} and return a vulnerability report in JSON format."
        response = generate_chatgpt_response(model_engine, prompt)
        # Parse response and print vulnerabilities
        vulnerabilities = parse_vulnerabilities(response)
        print("\nVulnerabilities Detected:")
        for vuln in vulnerabilities:
            print(vuln)

    # Generate report
    if args.format:
        generate_report(target, nm.csv(), vulnerabilities, args.format)
    else:
        generate_report(target, nm.csv(), vulnerabilities, "txt")

# Generate report function based on format argument
def generate_report(target, nm_csv, vulnerabilities, format):
    # Write Nmap scan results to file
    with open(f"{target}-nmap.txt", 'w') as file:
        file.write(nm_csv)

    report_data = {
        "target": target,
        "nmap_scan_results": nm_csv,
        "vulnerabilities": vulnerabilities,
        "date": str(datetime.now())
    }

    if format == "json":
        with open(f"{target}-{report_data['date']}-full-report.json", 'w') as file:
            json.dump(report_data, file, indent=4)
    elif format == "xml":
        with open(f"{target}-{report_data['date']}-full-report.xml", 'w') as file:
            file.write(dicttoxml(report_data, custom_root="report", attr_type=False).decode())
    elif format == "csv":
        with open(f"{target}-{report_data['date']}-full-report.csv", 'w') as file:
            writer = csv.writer(file)
            writer.writerow(['host', 'hostname', 'hostname_type', 'protocol', 'port', 'name', 'state', 'product', 'extrainfo', 'reason', 'version', 'conf', 'cpe'])
            for line in nm_csv.split('\n'):
                if line.startswith('#') or not line.strip():
                    continue
                writer.writerow(line.split(';'))
    else:
        with open(f"{target}-{report_data['date']}-full-report.txt", 'w') as file:
            file.write("Nmap Scan Results:\n")
            file.write(nm_csv)
            file.write("\nVulnerabilities Detected:\n")
            for vuln in vulnerabilities:
                file.write(vuln)
                file.write("\n")

# OpenAI ChatGPT prompt generator
def generate_chatgpt_response(model_engine, prompt):
    completion = openai.Completion.create(
        engine=model_engine,
        prompt=prompt,
        max_tokens=get_max_tokens(model_engine),
        n=1 
    )
    response = completion.choices[0].text.strip()
    return response

# Vulnerability parsing function
def parse_vulnerabilities(response):
    vulnerabilities = []
    try:
        json_response = json.loads(response)
        if "vulnerabilities" in json_response:
            for vuln in json_response["vulnerabilities"]:
                vulnerabilities.append(vuln["title"])
    except:
        print("Error parsing vulnerabilities from response")
    return vulnerabilities

# Main function
def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Security testing based on OWASP ASVS methodology")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target URL or IP address")
    parser.add_argument("-s", "--subdomains", type=str, help="Subdomains file or specified subdomain")
    parser.add_argument("-f", "--format", type=str, help="Report format (txt, json, xml, csv)")
    parser.add_argument("-om", "--openai-model", type=str, default="davinci", choices=openai_models.keys(), help="OpenAI GPT model to use")
    parser.add_argument("-as", "--shodan-api-key", type=str, help="Shodan API key")
    args = parser.parse_args()

    # Check if API keys exist, if not prompt user to input them
    if not os.path.isfile('.env'):
        with open('.env', 'w') as env_file:
            env_file.write("# API keys\n")
        api_keys = {}
        for api_key_name in api_key_names:
            api_key = input(f"Please enter your {api_key_name} API key: ")
            api_keys[api_key_name.upper()] = api_key
            with open('.env', 'a') as env_file:
                env_file.write(f"{api_key_name.upper()}={api_key}\n")
    else:
        with open('.env', 'r') as env_file:
            api_keys = dict(
                line.strip().split('=') for line in env_file if not line.startswith("#") and '=' in line
            )

    # Perform subdomain scanning
    subdomains = subdomain_scan(args.target, args.subdomains, api_keys, args)

    # Perform OSINT information gathering
    osint_info(args.target, api_keys)

    # Perform WAF detection
    waf_detection(args.target, api_keys, args.openai_model)

    # Perform Nmap scanning
    nmap_scan(args.target, api_keys, args.format, args.openai_model)

if __name__ == "__main__":
    main()


