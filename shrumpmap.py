#!/usr/bin/env python3
import os 
import argparse
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor
import subprocess
import time
import socket
from colored import Fore, Back, Style
from scapy.all import IP, TCP, sr1
start_time = time.time()
parser = argparse.ArgumentParser(description='Shrump Network Mapper')
group = parser.add_mutually_exclusive_group()
group.add_argument('--ping', '-p', action='store_true', help='Pings every host in a subnet to check for shrump')
group.add_argument('--scan', '-s', action='store_true', help='Scans a given host for open ports to check for shrump')
group.add_argument('--lemon', '-l', action='store_true', help='Lemon?')
parser.add_argument('ip', help='IP address to ping')
args = parser.parse_args()
network = ipaddress.ip_network(args.ip)
arr = []
def pingHost (ip):
    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        print(f'{Fore.green}[+]\tShrump Detected at {ip}{Style.reset}')
        arr.append(ip)
        return 1
    else:
        print(f'{Fore.red}[-]\tNo Shrump at {ip}{Style.reset}')
        return 0

def ping(network):
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(pingHost, network.hosts()))
    print('--------------------------------------')
    print(f'Total Shrump Detected: {sum(results)}')
    print(f'Time Taken: {time.time() - start_time:.2f} seconds')

def scan_port(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return port if s.connect_ex((target, port)) == 0 else None

def portScan(target):
    open_ports = []
    packet = IP(dst=target)/TCP(dport=80, flags='S')
    response = sr1(packet, timeout=1, verbose=0)
    print(f'Scan completed on Target: {target}')
    if response is None:
        print("[-] No response. Host may be down or filtered.")
    else:
        ttl = response.ttl
        window = response[TCP].window
        dfFlag = bool(response.flags & 0x40)
        tos = response.tos
        print(f"TTL: {ttl}, Window Size: {window}, DF Flag: {dfFlag}, TOS: {tos}")
        if ttl <= 64 and window in [32120, 5840]:
            print("Likely OS: Linux/FreeBSD")
        elif ttl <= 128:
            print("Likely OS: Windows")
        elif ttl >= 200:
            print("Likely OS: Cisco/Network Device")
        else:
            print("OS detection uncertain.")

    with ThreadPoolExecutor(max_workers=200) as executor:
        for port in executor.map(lambda p: scan_port(target, p), range(1, 1000)):
            if port:
                try:
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service = 'unknown'
                    banner = ''
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1.0)
                        if s.connect_ex((target, port)) == 0:
                            try:
                                banner = s.recv(4096).decode(errors='ignore').strip()
                            except Exception:
                                banner = ''
                    if banner:
                        print(f"{Fore.green}[+] Port {port} is open ({service}) Version: {banner}{Style.reset}")
                    else:
                        print(f"{Fore.yellow}[~] Port {port} is open ({service}) Version: not detected{Style.reset}")
                    open_ports.append(port)
                except Exception:
                    open_ports.append(port)
    if not open_ports:
        print(f'{Fore.red}[-] No Open Ports Found (could be higher than port 1000){Style.reset}')
    print('\n') 
try:
    if args.ping:
        ping(network)
        user_input = input("Scan the Live Hosts?(yes/no): ")
        if user_input.lower() in ["yes", "y"]:
            print("Continuing...")
            for ip in arr:
                portScan(str(ip))
            print(f'Time taken: {time.time() - start_time:.2f} seconds')
        elif user_input.lower() in ["no", "n"]:
            print("Exiting...")
            sys.exit()
        else:
            print("Invalid input. Please enter yes/no.")
    if args.scan:
        target = args.ip
        portScan(target)
        print(f'Time taken: {time.time() - start_time:.2f} seconds')
    if args.lemon:
        print(f'{Fore.yellow}Lemon?{Style.reset}')
except KeyboardInterrupt:
    print('Shrumping off...')
    sys.exit()
