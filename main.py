# fixed_main.py (with ipinfo optional + ipapi fallback)
import requests
import whois
import threading
import socket
import json
import os
from datetime import datetime
import ipaddress
from termcolor import colored
from subdomain import count_subdomains
from pyfiglet import figlet_format
from dotenv import load_dotenv
from urllib.parse import urlparse

# Terminal Colors
RED = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
RESET = '\033[0m'

# Banner
version = "1.1"
logo = f"""
{CYAN}{figlet_format("URL ANALYZER", font="slant")}{YELLOW}
                   [ v{version}]
{GREEN}                      by R05HAN
{RESET}
"""
print(logo)

lock = threading.Lock()

# Load environment variables and request IPInfo token if not present
load_dotenv()
token = os.getenv("ipInfo_token")

if not token:
    token = input("Enter your IPInfo token (or press Enter to skip and use free IP API): ").strip()
    if token:
        with open(".env", "a") as f:
            f.write(f"ipInfo_token={token}\n")

# SSRF Protection
def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True

# IP Info with token-based or fallback API
def get_ip_info(ip):
    if token:
        try:
            import ipinfo
            handler = ipinfo.getHandler(token)
            return handler.getDetails(ip).all
        except Exception as e:
            print(f"IPInfo token fetch failed, falling back: {e}")
    # Fallback to free API
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        return res.json()
    except Exception as e:
        print(f"Free IP API fetch failed: {e}")
        return {}

# Handle each URL
def url_handle(input_url):
    parsed_url = urlparse(input_url)
    domain = parsed_url.netloc

    try:
        ip = socket.gethostbyname(domain)
        if is_private_ip(ip):
            with lock:
                print(colored(f"\n⚠️ Skipped private/internal IP: {ip}", 'red'))
            return
    except socket.gaierror:
        with lock:
            print(colored(f"\n❌ Invalid domain: {domain}", 'red'))
        return

    output = f"\n--- Result for: {input_url} ---\n"

    # HTTP Request
    try:
        response = requests.get(input_url, timeout=5)
        output += f"HTTP Status: {response.status_code} {'(Success)' if response.ok else '(Failed)'}\n"
    except requests.RequestException as e:
        output += f"Request failed: {str(e)}\n"
        with lock:
            print(output)
        return

    # WHOIS Info
    try:
        domain_info = whois.whois(domain)
    except Exception as e:
        domain_info = f"Error retrieving WHOIS info: {e}"

    # IP Info
    ip_info = get_ip_info(ip)
    ip_info_str = json.dumps(ip_info, indent=4)

    with lock:
        with open(f"urlInfo.txt", "a", encoding="utf-8") as f:
            f.write(f"URL: {input_url}\nDomain: {domain}\nIP: {ip}\n\nWHOIS:\n{domain_info}\n\nIPInfo:\n{ip_info_str}\n")

        print(output)

# Validate and analyze phishing characteristics
def is_phishy(url):
    flags = []
    parsed = urlparse(url)

    if len(url) > 100:
        flags.append("Length > 100")

    if parsed.scheme not in ["http", "https"] or not parsed.netloc:
        flags.append("Invalid scheme")

    if count_subdomains(url) > 2:
        flags.append("Too many subdomains")

    if '@' in url:
        flags.append("Uses @ in URL")

    if '-' in parsed.netloc:
        flags.append("Hyphen in domain")

    return flags

# Main Execution
def main():
    try:
        n = int(input("Number of URLs to analyze: "))
    except ValueError:
        print("❌ Invalid input. Please enter a number.")
        return

    threads = []

    for i in range(n):
        input_url = input(f"URL {i+1}: ").strip()

        phishy_flags = is_phishy(input_url)
        if phishy_flags:
            print(colored("⚠️ Potentially suspicious URL:", 'red', attrs=['bold']))
            for flag in phishy_flags:
                print(colored(f"- {flag}", 'yellow'))

        thread = threading.Thread(target=url_handle, args=(input_url,))
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
