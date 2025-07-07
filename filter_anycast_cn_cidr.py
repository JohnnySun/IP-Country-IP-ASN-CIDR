#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import ipaddress
import requests
import sys
import os
from get_asn_cidr import ip_to_int_v4, ip_to_int_v6, check_ip_version

# --- Configuration ---
COUNTRY_ASN_FILE = 'country_asn.csv'
TARGET_COUNTRY = 'CN'
URLS_TO_PROCESS = [
    'https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v4-prefixes.txt',
    'https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v6-prefixes.txt'
]
OUTPUT_DIR = 'output/filtered_anycast'

def load_country_ip_ranges(file_path, country_code):
    """
    Loads IP ranges for a specific country from the CSV file.
    Returns a dictionary with 'v4' and 'v6' keys, containing lists of (start_ip_int, end_ip_int) tuples.
    """
    print(f"Loading IP ranges for country: {country_code} from {file_path}...")
    country_ranges = {'v4': [], 'v6': []}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('country') == country_code:
                    start_ip = row['start_ip']
                    end_ip = row['end_ip']
                    ip_ver = check_ip_version(start_ip)
                    if ip_ver == 4:
                        country_ranges['v4'].append((ip_to_int_v4(start_ip), ip_to_int_v4(end_ip)))
                    elif ip_ver == 6:
                        country_ranges['v6'].append((ip_to_int_v6(start_ip), ip_to_int_v6(end_ip)))
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        print("Please ensure you have downloaded the necessary data files.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading {file_path}: {e}")
        sys.exit(1)

    print(f"Loaded {len(country_ranges['v4'])} IPv4 and {len(country_ranges['v6'])} IPv6 ranges for {country_code}.")
    return country_ranges

def is_cidr_in_country(cidr, country_ranges_v4, country_ranges_v6):
    """
    Checks if a CIDR overlaps with any of the IP ranges for the target country.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        cidr_start = int(network.network_address)
        cidr_end = int(network.broadcast_address)
        country_ranges = country_ranges_v4 if network.version == 4 else country_ranges_v6

        for country_start, country_end in country_ranges:
            if cidr_start <= country_end and cidr_end >= country_start:
                return True
    except ValueError:
        return False
    return False

def fetch_cidrs_from_url(url):
    """
    Fetches a list of CIDRs from a URL.
    """
    print(f"Fetching CIDRs from {url}...")
    try:
        response = requests.get(url)
        response.raise_for_status()
        cidrs = response.text.splitlines()
        return [c.strip() for c in cidrs if c.strip() and not c.startswith('#')]
    except requests.RequestException as e:
        print(f"Error fetching CIDR list from {url}: {e}")
        return []

def main():
    """ Main function """
    cn_ip_ranges = load_country_ip_ranges(COUNTRY_ASN_FILE, TARGET_COUNTRY)

    if not cn_ip_ranges['v4'] and not cn_ip_ranges['v6']:
        print(f"No IP ranges found for {TARGET_COUNTRY}. Cannot perform filtering.")
        return

    all_cidrs = []
    for url in URLS_TO_PROCESS:
        all_cidrs.extend(fetch_cidrs_from_url(url))

    print(f"\nTotal CIDRs fetched: {len(all_cidrs)}")
    print(f"Filtering out CIDRs belonging to {TARGET_COUNTRY}...")

    filtered_cidrs_v4 = []
    filtered_cidrs_v6 = []

    for cidr in all_cidrs:
        if not is_cidr_in_country(cidr, cn_ip_ranges['v4'], cn_ip_ranges['v6']):
            try:
                ip_ver = ipaddress.ip_network(cidr, strict=False).version
                if ip_ver == 4:
                    filtered_cidrs_v4.append(cidr)
                elif ip_ver == 6:
                    filtered_cidrs_v6.append(cidr)
            except ValueError:
                print(f"  -> Skipping invalid CIDR: {cidr}")
        else:
            print(f"  -> Filtering out {cidr} (belongs to {TARGET_COUNTRY}) ")

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    output_file_v4 = os.path.join(OUTPUT_DIR, 'anycast_ipv4_cn_filtered.txt')
    with open(output_file_v4, 'w') as f:
        for cidr in filtered_cidrs_v4:
            f.write(f"{cidr}\n")
    print(f"\nFiltered IPv4 CIDRs saved to: {output_file_v4} ({len(filtered_cidrs_v4)} entries)")

    output_file_v6 = os.path.join(OUTPUT_DIR, 'anycast_ipv6_cn_filtered.txt')
    with open(output_file_v6, 'w') as f:
        for cidr in filtered_cidrs_v6:
            f.write(f"{cidr}\n")
    print(f"Filtered IPv6 CIDRs saved to: {output_file_v6} ({len(filtered_cidrs_v6)} entries)")

if __name__ == "__main__":
    main()