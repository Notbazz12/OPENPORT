import socket
import argparse
import ipaddress
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict
import requests

class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'

# Diccionario ampliado de puertos comunes y sus servicios asociados
COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB", 6667: "IRC", 9200: "Elasticsearch", 11211: "Memcached"
}

# Diccionario ampliado de vulnerabilidades conocidas por servicio
VULNERABILITIES = {
    "FTP": ["Anonymous FTP access", "FTP Bounce attack", "Cleartext transmission"],
    "SSH": ["Weak encryption algorithms", "SSH protocol version 1", "Brute-force attacks"],
    "Telnet": ["Clear text transmission", "Lack of encryption", "Man-in-the-middle attacks"],
    "SMTP": ["Open relay", "SMTP command injection", "Email spoofing"],
    "DNS": ["DNS cache poisoning", "DNS amplification", "Zone transfer vulnerabilities"],
    "HTTP": ["SQL injection", "Cross-site scripting (XSS)", "CSRF", "Directory traversal"],
    "POP3": ["Clear text authentication", "POP3 buffer overflow", "Man-in-the-middle attacks"],
    "IMAP": ["IMAP authentication weakness", "IMAP buffer overflow", "Cleartext transmission"],
    "HTTPS": ["SSL/TLS vulnerabilities", "Heartbleed", "POODLE", "BEAST"],
    "SMB": ["EternalBlue", "SMBGhost", "SMBleed"],
    "MySQL": ["SQL injection", "Weak authentication", "Privilege escalation"],
    "RDP": ["BlueKeep", "DejaBlue", "Brute-force attacks"],
    "PostgreSQL": ["SQL injection", "Weak authentication", "Privilege escalation"],
    "VNC": ["Weak authentication", "Unencrypted communication", "Man-in-the-middle attacks"],
    "Redis": ["Unauthenticated access", "Remote code execution", "Data exposure"],
    "MongoDB": ["Unauthenticated access", "Data exposure", "NoSQL injection"],
    "Elasticsearch": ["Unauthenticated access", "Remote code execution", "Data exposure"],
    "Memcached": ["Unauthenticated access", "Data exposure", "DDoS amplification"]
}

def is_port_open(ip: str, port: int, timeout: float) -> bool:
    """Check if a port is open on a given IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_port(ip: str, port: int, timeout: float) -> Tuple[str, int, str, List[str]]:
    """Scan a specific port on an IP address."""
    if is_port_open(ip, port, timeout):
        service = COMMON_PORTS.get(port, "Unknown")
        vulnerabilities = VULNERABILITIES.get(service, ["No known vulnerabilities"])
        return ip, port, service, vulnerabilities
    return ip, port, "Closed", []

def scan_ports(targets: List[str], timeout: float, output_format: str = None, output_file: str = None, max_threads: int = 100) -> None:
    """Scan common ports on multiple targets and optionally write results to a file."""
    ips = []
    for target in targets:
        try:
            with open(target, 'r') as file:
                ips.extend(file.readlines())
        except IOError:
            if '/' in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    ips.extend([str(ip) for ip in network.hosts()])
                except ValueError:
                    print(f"{Color.RED}[-] Invalid: {target}{Color.RESET}")
            else:
                ips.append(target.strip())

    ips = list(set(ips))  # Remove duplicates
    total_scanned = len(ips) * len(COMMON_PORTS)
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_scan = {executor.submit(scan_port, ip.strip(), port, timeout): (ip.strip(), port) for ip in ips for port in COMMON_PORTS}
        for future in as_completed(future_to_scan):
            ip, port = future_to_scan[future]
            try:
                result = future.result()
                if result[2] != "Closed":
                    open_ports.append(result)
                    print(f"{Color.GREEN}[+] Open port found: {ip}:{port} - {result[2]}{Color.RESET}")
            except Exception as exc:
                print(f'{Color.RED}[-] {ip}:{port} generated an exception: {exc}{Color.RESET}')

    print(f"\n{Color.GREEN}Open ports found: {len(open_ports)}{Color.RESET}\n")
    for ip, port, service, vulns in open_ports:
        print(f"{Color.YELLOW}[!] Open port at {ip}:{port} - {service}{Color.RESET}")
        for vuln in vulns:
            print(f"   - Potential vulnerability: {vuln}")
    
    print(f"\n{Color.CYAN}Summary:{Color.RESET}")
    print(f"Total scanned: {Color.GREEN}{total_scanned}{Color.RESET} ports")
    print(f"Open ports: {Color.YELLOW}{len(open_ports)}{Color.RESET}")

    if output_format and output_file:
        save_results(output_format, output_file, open_ports)

def save_results(output_format: str, output_file: str, open_ports: List[Tuple[str, int, str, List[str]]]) -> None:
    """Save scan results to a file in the specified format."""
    if output_format == 'csv':
        with open(output_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(['IP', 'Port', 'Service', 'Potential Vulnerabilities'])
            for ip, port, service, vulns in open_ports:
                csv_writer.writerow([ip, port, service, '; '.join(vulns)])
        print(f"\n{Color.CYAN}✅ Results saved to {output_file} in CSV format.{Color.RESET}")
    
    elif output_format == 'txt':
        with open(output_file, 'w') as txtfile:
            txtfile.write(f"Open ports found: {len(open_ports)}\n\n")
            for ip, port, service, vulns in open_ports:
                txtfile.write(f"Open port at {ip}:{port} - {service}\n")
                for vuln in vulns:
                    txtfile.write(f"   - Potential vulnerability: {vuln}\n")
        print(f"\n{Color.CYAN}✅ Results saved to {output_file} in TXT format.{Color.RESET}")

    elif output_format == 'json':
        output_dict = {
            'Open ports': [{
                'ip': ip,
                'port': port,
                'service': service,
                'vulnerabilities': vulns
            } for ip, port, service, vulns in open_ports]
        }
        with open(output_file, 'w') as jsonfile:
            json.dump(output_dict, jsonfile, indent=4)
        print(f"\n{Color.CYAN}✅ Results saved to {output_file} in JSON format.{Color.RESET}")

def check_for_updates():
    """Check for updates on GitHub."""
    try:
        response = requests.get("https://api.github.com/repos/Notbanzz12/OpenPorts/releases/latest")
        if response.status_code == 200:
            latest_version = response.json()["tag_name"]
            print(f"{Color.CYAN}Latest version available: {latest_version}{Color.RESET}")
            print(f"{Color.CYAN}Check https://github.com/Notbanzz12/OpenPorts for updates.{Color.RESET}")
    except:
        print(f"{Color.YELLOW}Unable to check for updates.{Color.RESET}")

def main():
    banner = f"""{Color.GREEN}
 ██████╗ ██████╗ ███████╗███╗   ██╗██████╗  ██████╗ ██████╗ ████████╗███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║██████╔╝██║   ██║██████╔╝   ██║   ███████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║
╚██████╔╝██║     ███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║   ██║   ███████║
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
   Common Ports Scanner
    {Color.RESET}"""
    print(banner)
    print(f"{Color.MAGENTA}Created by Notbanzz12{Color.RESET}")
    print(f"{Color.BLUE}https://github.com/Notbanzz12{Color.RESET}\n")

    parser = argparse.ArgumentParser(description="Scan for open common ports and potential vulnerabilities.",
    epilog='Example usage: python3 openports.py <targets> -t 3 -o json -f scan_results.json')
    parser.add_argument("targets", nargs='+', help="IP addresses, hostnames, or files containing targets to scan")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1 second).")
    parser.add_argument("-o", "--output", choices=['csv', 'txt', 'json'], help="Output format for results.")
    parser.add_argument("-f", "--output-file", help="File to save results to. (e.g., results.json)")
    parser.add_argument("-m", "--max-threads", type=int, default=100, help="Maximum number of threads to use (default: 100)")
    parser.add_argument("-u", "--check-updates", action="store_true", help="Check for updates")

    args = parser.parse_args()
    targets = args.targets
    timeout = args.timeout
    max_threads = args.max_threads

    output_format = args.output if args.output else None
    output_file = args.output_file if args.output_file else None

    if args.check_updates:
        check_for_updates()

    start_time = time.time()
    try:
        scan_ports(targets, timeout, output_format, output_file, max_threads)
    except KeyboardInterrupt:
        print(f"\n{Color.RED}Scan interrupted by user. Exiting...{Color.RESET}")
    finally:
        end_time = time.time()
        print(f"\n{Color.CYAN}Scan completed in {end_time - start_time:.2f} seconds.{Color.RESET}")

if __name__ == "__main__":
    main()