#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from io import StringIO
import os
import requests
import ipaddress
import csv
import json
import re
import subprocess
import sys

def ip_to_int_v4(ip):
    import struct
    import socket
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip_v4(ip_int):
    import struct
    import socket
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def ip_range_to_cidr_v4(start_ip, end_ip):
    start_int = ip_to_int_v4(start_ip)
    end_int = ip_to_int_v4(end_ip)

    cidr_list = []

    while start_int <= end_int:
        max_size = 32
        while max_size > 0:
            mask = 0xFFFFFFFF << (32 - max_size) & 0xFFFFFFFF
            if (start_int & mask) != start_int:
                break
            broadcast = start_int + (1 << (32 - max_size)) - 1
            if broadcast > end_int:
                break
            max_size -= 1
        max_size += 1
        cidr_list.append(f"{int_to_ip_v4(start_int)}/{max_size}")
        start_int += (1 << (32 - max_size))

    return "\n".join(cidr_list)

def ip_to_int_v6(ip):
    import ipaddress
    return int(ipaddress.IPv6Address(ip))

def int_to_ip_v6(ip_int):
    import ipaddress
    return str(ipaddress.IPv6Address(ip_int))

def ip_range_to_cidr_v6(start_ip, end_ip):
    start_int = ip_to_int_v6(start_ip)
    end_int = ip_to_int_v6(end_ip)

    cidr_list = []

    while start_int <= end_int:
        max_size = 128
        while max_size > 0:
            mask = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF << (128 - max_size)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            if (start_int & mask) != start_int:
                break
            broadcast = start_int + (1 << (128 - max_size)) - 1
            if broadcast > end_int:
                break
            max_size -= 1
        max_size += 1
        cidr_list.append(f"{int_to_ip_v6(start_int)}/{max_size}")
        start_int += (1 << (128 - max_size))

    return "\n".join(cidr_list)

def fetch_cidr_list_from_url(url):
    """
    Fetch a list of CIDR ranges from a given URL.

    :param url: str, URL to fetch the CIDR list from
    :return: list of str, CIDR ranges
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        cidr_list = response.text.splitlines()
        return [cidr.strip() for cidr in cidr_list if cidr.strip()]
    except requests.RequestException as e:
        print(f"Error fetching CIDR list from URL: {e}")
        return []

def is_cidr_in_cidr_list(input_cidr, cidr_list):
    """
    Check if the given IP address is in any of the given CIDR ranges.

    :param ip: str, IP address (IPv4 or IPv6) to check
    :param cidr_list: list of str, CIDR ranges to check against
    :return: bool, True if IP is in any CIDR range, False otherwise
    """
    for cidr in cidr_list:
        if is_cidr_in_cidr(input_cidr, cidr):
            return True
    return False

def is_cidr_in_cidr(cidr1, cidr2):
    """
    Check if the given CIDR range cidr1 is within the given CIDR range cidr2, or if they are equal.

    :param cidr1: str, CIDR range to check if it's within or equal to cidr2
    :param cidr2: str, CIDR range to check against
    :return: bool, True if cidr1 is within or equal to cidr2, False otherwise
    """
    try:
        cidr1_obj = ipaddress.ip_network(cidr1, strict=False)
        cidr2_obj = ipaddress.ip_network(cidr2, strict=False)
        return cidr1_obj.subnet_of(cidr2_obj) or cidr1_obj == cidr2_obj
    except ValueError:
        return False

def check_ip_version(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return 4
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return 6
    except ValueError:
        return "Invalid IP address"

    
def find_asn_lines(file_path, target_asn):
    pattern = re.compile(rf'^{target_asn},|,{target_asn},|,{target_asn}$')
    
    with open(file_path, 'r', buffering=1) as file:
        header = file.readline().strip()
        yield header
    try:
        result = subprocess.run(['grep', target_asn, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        lines = result.stdout.splitlines()
        for line in lines:
            yield line
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e.stderr}")

# calc and output ipcidr
def save_ipcidr(start_ip, end_ip, ip_version, file, exclude_v4_cidrs, exclude_v6_cidrs):
    start_ip_version = check_ip_version(start_ip)
    if int(start_ip_version) == 4 and int(ip_version) == int(start_ip_version) :
        cidr = ip_range_to_cidr_v4(start_ip, end_ip)
        if exclude_v4_cidrs is None or not is_cidr_in_cidr_list(cidr, exclude_v4_cidrs) :
            # if cidr not in exculde_cidr_list, save it to files
            file.write(''.join(cidr) + '\n')
    elif int(start_ip_version) == 6 and int(ip_version) == int(start_ip_version) :
        cidr = ip_range_to_cidr_v6(start_ip, end_ip)
        if exclude_v6_cidrs is None or not is_cidr_in_cidr_list(cidr, exclude_v6_cidrs) :
            # if cidr not in exculde_cidr_list, save it to files
            file.write(''.join(cidr) + '\n')

# start_ip,end_ip,asn,name,domain
def get_asn_ipcidr(file_path, asn, ip_version):
    matching_lines = find_asn_lines(file_path, asn)
    header = next(matching_lines)
    csv_reader = csv.DictReader(StringIO('\n'.join([header] + list(matching_lines))))
    directory = f"output/{asn}"
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(f"{directory}/IPV{ip_version}.cidr", 'w') as file:
        for row in csv_reader:
            if row['asn'] == str(asn) or str(asn) == "ALL" :
                save_ipcidr(row['start_ip'], row['end_ip'], ip_version, file, None, None)
     

# start_ip,end_ip,country,country_name,continent,continent_name,asn,as_name,as_domain
def get_asn_ipcidr_for_specific_area(file_path, asn, continent, country, ip_version, exclude_v4_cidrs, exclude_v6_cidrs, exclude_country):
    if str(country) != "ALL":
        # if country is not ALL, do not use exclude_country.
        exclude_country == ""

    matching_lines = find_asn_lines(file_path, asn)
    header = next(matching_lines)
    csv_reader = csv.DictReader(StringIO('\n'.join([header] + list(matching_lines))))
    directory = f"output/{asn}"
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(f"{directory}/{continent}_{country}_IPV{ip_version}.cidr", 'w') as file:
        for row in csv_reader:
            if  ( row['asn'] == str(asn) or str(asn) == "ALL" ) \
            and ( row['continent'] == str(continent) or str(continent) == "ALL" ) \
            and ( row['country'] == str(country) or str(country) == "ALL" ) \
            and ( row['country'] != str(exclude_country) ):
                save_ipcidr(row['start_ip'], row['end_ip'], ip_version, file, exclude_v4_cidrs, exclude_v6_cidrs)

def func_asn_ipcidr(target_asn, ip_version) :
    file_path = "asn.csv"
    if int(ip_version) != 4 and int(ip_version) != 6:
        print(f"Error: ip_version must be 4 or 6, but you give {ip_version}")
    else:
        get_asn_ipcidr(file_path, target_asn, ip_version)

def func_asn_ipcidr_for_specific_area(target_asn, continent, country, ip_version, exclude_v4_cidrs, exclude_v6_cidrs, exclude_country) :
    file_path = "country_asn.csv"
    if int(ip_version) != 4 and int(ip_version) != 6:
        print(f"Error: ip_version must be 4 or 6, but you give {ip_version}")
    else:
        get_asn_ipcidr_for_specific_area(file_path, target_asn, continent, country, ip_version, exclude_v4_cidrs, exclude_v6_cidrs, exclude_country)

if __name__ == "__main__":
    if len(sys.argv) != 2 and len(sys.argv) != 3 and len(sys.argv) != 5:
        print(f"Usage: python3 {sys.argv[0]} <arg_list_file>")
        print(f"Usage: python3 {sys.argv[0]} <asn> <ip_version 4 or 6>")
        print(f"Usage: python3 {sys.argv[0]} <asn> <continent> <country> <ip_version 4 or 6>")
        sys.exit(1)

    anycatch_v4_prefixes_url = "https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v4-prefixes.txt"
    anycatch_v6_prefixes_url = "https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v6-prefixes.txt"
    anycast_v4_cidr_list = fetch_cidr_list_from_url(anycatch_v4_prefixes_url)
    anycast_v6_cidr_list = fetch_cidr_list_from_url(anycatch_v6_prefixes_url)
    exclude_country = "CN"

    if len(sys.argv) == 2 :
    with open(sys.argv[1], 'r') as file:
            lines = file.readlines()
            for line in lines:
                stripped_line = line.strip()
                if not stripped_line or stripped_line.startswith('#'):
                    continue
                # split line into argv
                argv = stripped_line.split()
                if len(argv) == 2:
                    func_asn_ipcidr(argv[0], argv[1])
                elif len(argv) == 4:
                    func_asn_ipcidr_for_specific_area(argv[0], argv[1], argv[2], argv[3], anycast_v4_cidr_list, anycast_v6_cidr_list, exclude_country)

            

    if len(sys.argv) == 3 :
        func_asn_ipcidr(sys.argv[1], sys.argv[2])

    if len(sys.argv) == 5 :
        func_asn_ipcidr_for_specific_area(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], anycast_v4_cidr_list, anycast_v6_cidr_list, exclude_country)
