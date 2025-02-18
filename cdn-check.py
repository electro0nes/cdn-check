import requests
import yaml
import ipaddress
import sys
import json
import csv
import re
import xml.etree.ElementTree as ET
import threading
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}Cdn-Check - A tool to check if an IP is behind a CDN or thirdparty{Style.RESET_ALL}
{Fore.YELLOW}Author: Moein Erfanian{Style.RESET_ALL}
{Fore.GREEN}GitHub: github.com/moeinerfanian{Style.RESET_ALL}
"""

def fetch_cidr_from_urls(urls):
    """ Fetch CIDR ranges from URLs """
    cidr_ranges = set()
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.text
                content_type = response.headers.get('Content-Type', '')
                if url.endswith('.json') or "application/json" in content_type:
                    cidr_ranges.update(extract_cidr_from_json(data))
                elif url.endswith('.csv') or "text/csv" in content_type:
                    cidr_ranges.update(extract_cidr_from_csv(data))
                elif url.endswith('.xml') or "application/xml" in content_type or "text/xml" in content_type:
                    cidr_ranges.update(extract_cidr_from_xml(data))
                else:
                    cidr_ranges.update(extract_cidr(data))
        except requests.exceptions.RequestException:
            pass
    return cidr_ranges

def extract_cidr(data):
    """ Extract CIDR and IPs from raw text """
    cidr_list = set()
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
    for match in ip_pattern.findall(data):
        try:
            cidr_list.add(str(ipaddress.ip_network(match, strict=False)))
        except ValueError:
            pass
    return cidr_list

def extract_cidr_from_json(data):
    """ Extract CIDR and IPs from JSON """
    cidr_list = set()
    try:
        json_data = json.loads(data)
        def extract_nested(obj):
            if isinstance(obj, dict):
                for value in obj.values():
                    extract_nested(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_nested(item)
            elif isinstance(obj, str):
                try:
                    cidr_list.add(str(ipaddress.ip_network(obj, strict=False)))
                except ValueError:
                    pass
        extract_nested(json_data)
    except json.JSONDecodeError:
        pass
    return cidr_list

def extract_cidr_from_csv(data):
    """ Extract CIDR and IPs from CSV """
    cidr_list = set()
    csv_reader = csv.reader(data.splitlines())
    for row in csv_reader:
        for cell in row:
            cell = cell.strip()
            try:
                cidr_list.add(str(ipaddress.ip_network(cell, strict=False)))
            except ValueError:
                pass
    return cidr_list

def extract_cidr_from_xml(data):
    """ Extract CIDR and IPs from XML """
    cidr_list = set()
    try:
        root = ET.fromstring(data)
        for elem in root.iter():
            if elem.text:
                text = elem.text.strip()
                try:
                    cidr_list.add(str(ipaddress.ip_network(text, strict=False)))
                except ValueError:
                    pass
    except ET.ParseError:
        pass
    return cidr_list

def load_providers(provider_file):
    """ Load provider URLs from YAML file """
    with open(provider_file, 'r') as f:
        data = yaml.safe_load(f)
    return data.get("SendRequest", []), data.get("ReadFileUrl", [])

def check_ip_against_cdn(ip, cidr_ranges):
    """ Check if the given IP is behind a CDN """
    ip_obj = ipaddress.ip_address(ip)
    for cidr in cidr_ranges:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False

def process_ips(ip_list, cidr_ranges, output_file):
    """ Process IPs and write to output if needed """
    results = []
    for ip in ip_list:
        if not check_ip_against_cdn(ip, cidr_ranges):
            results.append(ip)
    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(results) + '\n')
    else:
        for ip in results:
            print(ip)

def worker(ip_list, cidr_ranges, output_file):
    process_ips(ip_list, cidr_ranges, output_file)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Cdn-Chekc - A tool to check if an IP is behind a CDN or thirdparty")
    parser.add_argument("-i", "--ip", help="Single IP address to check")
    parser.add_argument("-l", "--list", help="File containing a list of IPs to check")
    parser.add_argument("-p", "--providers",default="files/providers.yaml", required=False, help="YAML file containing provider URLs")
    parser.add_argument("--silent", action="store_true", help="Suppress banner output")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads (default: 1)")
    parser.add_argument("-o", "--output", help="Output file (default: CLI output)")
    args = parser.parse_args()
    
    if not args.silent:
        print(BANNER)
    
    ip_list = []
    if args.ip:
        ip_list.append(args.ip)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                ip_list = [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            print(f"File {args.list} not found.")
            sys.exit(1)
    else:
        print("You must specify either -i (single IP) or -l (IP list file)")
        sys.exit(1)
    
    send_request_urls, read_file_urls = load_providers(args.providers)
    cidr_ranges = fetch_cidr_from_urls(send_request_urls)
    cidr_ranges.update(fetch_cidr_from_urls(read_file_urls))
    
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(ip_list, cidr_ranges, args.output))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
