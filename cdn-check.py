import requests
import yaml
import ipaddress
import sys
import json
import csv
import re
import xml.etree.ElementTree as ET
import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}Cdn-Check - A tool to check if an IP is behind a CDN or thirdparty{Style.RESET_ALL}
{Fore.YELLOW}Author: Moein Erfanian{Style.RESET_ALL}
{Fore.GREEN}GitHub: github.com/moeinerfanian{Style.RESET_ALL}
"""

def fetch_cidr_from_urls(urls):
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
    cidr_list = set()
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
    for match in ip_pattern.findall(data):
        try:
            cidr_list.add(str(ipaddress.ip_network(match, strict=False)))
        except ValueError:
            pass
    return cidr_list

def extract_cidr_from_json(data):
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
    with open(provider_file, 'r') as f:
        data = yaml.safe_load(f)
    return data.get("Request", []), data.get("Read", [])

def prepare_networks(cidr_ranges):
    networks = []
    for cidr in cidr_ranges:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks

def get_ptr_record(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]]
    except socket.herror:
        return []

def get_http_server_header(ip):
    try:
        response = requests.get(f"http://{ip}", timeout=3)
        return response.headers.get('Server', '')
    except requests.RequestException:
        return ''

def check_ip_against_cdn(ip, networks, active_mode=False):
    ip_obj = ipaddress.ip_address(ip)

    for network in networks:
        if ip_obj in network:
            return True

    if active_mode:
        # PTR lookup
        ptrs = get_ptr_record(ip)
        for ptr in ptrs:
            if any(cdn in ptr.lower() for cdn in ["akamaitechnologies.com", "cloudflare", "fastly.net", "edgesuite.net"]):
                return True

        # HTTP header check
        server_header = get_http_server_header(ip).lower()
        if any(cdn in server_header for cdn in ["akamai", "cloudfront", "cloudflare", "fastly", "incapsula"]):
            return True

    return False

def split_list(lst, n):
    k, m = divmod(len(lst), n)
    return [lst[i*k + min(i, m):(i+1)*k + min(i+1, m)] for i in range(n)]

def process_chunk(chunk, networks, active_mode=False):
    results = []
    for ip in chunk:
        if not check_ip_against_cdn(ip, networks, active_mode):
            results.append(ip)
    return results

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Cdn-Check - A tool to check if an IP is behind a CDN or thirdparty")
    parser.add_argument("-i", "--ip", help="Single IP address to check")
    parser.add_argument("-l", "--list", help="File containing a list of IPs to check")
    parser.add_argument("-p", "--providers", default="files/providers.yaml", help="YAML file containing provider URLs")
    parser.add_argument("--silent", action="store_true", help="Suppress banner output")
    parser.add_argument("--active", action="store_true", help="Enable active checks like PTR and HTTP headers")
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
                ip_list = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"File {args.list} not found.")
            sys.exit(1)
    else:
        print("You must specify either -i (single IP) or -l (IP list file)")
        sys.exit(1)

    send_request_urls, read_file_urls = load_providers(args.providers)
    cidr_ranges = fetch_cidr_from_urls(send_request_urls)
    cidr_ranges.update(fetch_cidr_from_urls(read_file_urls))
    networks = prepare_networks(cidr_ranges)

    num_threads = args.threads if args.threads > 0 else 1
    ip_chunks = split_list(ip_list, num_threads)

    all_results = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(process_chunk, chunk, networks, args.active) for chunk in ip_chunks]
        for future in futures:
            all_results.extend(future.result())

    if args.output:
        with open(args.output, 'w') as f:
            f.write('\n'.join(all_results) + '\n')
    else:
        for ip in all_results:
            print(ip)

if __name__ == "__main__":
    main()