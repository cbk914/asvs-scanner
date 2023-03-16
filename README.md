# asvs-scanner

# Description:
The ASVS scanner is a Python script that performs various security tests based on the OWASP ASVS methodology. It includes subdomain scanning, OSINT information gathering, WAF detection, and Nmap scans with Vulners script.

# Installation:

Make sure you have Python 3 installed on your system. You can download Python from the official website: https://www.python.org/downloads/
Clone the repository or download the ASVS scanner script from the source.
Install the required dependencies by running the following command in the terminal: pip install -r requirements.txt

# Execution:

Open a terminal and navigate to the directory where the ASVS scanner script is located.
Run the script by executing the following command: python asvs-scanner.py -t <target>
Replace <target> with the URL or IP address of the target you want to scan.
You can also provide optional arguments:
-s, --subdomains to specify a subdomains file or a specific subdomain.
-a, --apikey to provide a Vulners API key for the Nmap scans.
Press Enter to start the scan.
The scanner will display the results of the subdomain scan, OSINT information gathering, WAF detection, and Nmap scans.

# Note:

The ASVS scanner script is intended for security testing purposes only. Do not use it to perform any illegal activities.
The scanner may generate a high volume of network traffic and cause performance issues. Use it with caution and obtain permission before scanning any target.