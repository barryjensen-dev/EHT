#!/usr/bin/env python3
"""
Port Scanner

This script provides a simple yet powerful port scanner to identify open ports on target hosts.
It supports various scanning techniques and can be used to identify services running on network
systems.

This tool is intended for educational purposes and authorized network testing only.
"""

import argparse
import socket
import sys
import time
import ipaddress
import logging
import random
from concurrent.futures import ThreadPoolExecutor
from scripts.utils.disclaimer import print_disclaimer, require_confirmation, require_legal_confirmation

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP (Alternate)",
    8443: "HTTPS (Alternate)",
    27017: "MongoDB"
}

def get_ip_address(host):
    """
    Resolve hostname to IP address.
    
    Parameters:
    -----------
    host : str
        The hostname or IP address to resolve
        
    Returns:
    --------
    str:
        The resolved IP address
    """
    try:
        ip_address = socket.gethostbyname(host)
        return ip_address
    except socket.gaierror as e:
        logger.error(f"Error resolving hostname {host}: {str(e)}")
        raise

def scan_port(ip, port, timeout=1):
    """
    Scan a single port on the specified IP address.
    
    Parameters:
    -----------
    ip : str
        The IP address to scan
    port : int
        The port number to scan
    timeout : float
        Socket timeout in seconds
        
    Returns:
    --------
    dict:
        Result of the port scan including port status and banner if available
    """
    result = {
        'port': port,
        'state': 'closed',
        'service': COMMON_PORTS.get(port, "Unknown"),
        'banner': None
    }
    
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    
    try:
        # Try to connect to the port
        start_time = time.time()
        connection = s.connect_ex((ip, port))
        end_time = time.time()
        
        response_time = end_time - start_time
        
        # Check if the connection was successful
        if connection == 0:
            result['state'] = 'open'
            result['response_time'] = f"{response_time:.4f}s"
            
            # Try to grab a banner
            try:
                s.send(b'Hello\r\n')
                banner = s.recv(1024)
                if banner:
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
            except (socket.timeout, ConnectionResetError, UnicodeDecodeError):
                # Couldn't get a banner, which is common for many services
                pass
    
    except (socket.timeout, ConnectionRefusedError):
        # Port is likely closed or filtered
        pass
    except Exception as e:
        logger.debug(f"Error scanning port {port}: {str(e)}")
    finally:
        s.close()
    
    return result

def scan_host(host, ports=None, timeout=1, threads=100):
    """
    Scan specified ports on a host.
    
    Parameters:
    -----------
    host : str
        The hostname or IP address to scan
    ports : list
        List of ports to scan
    timeout : float
        Socket timeout in seconds
    threads : int
        Number of concurrent scanning threads
        
    Returns:
    --------
    dict:
        Results of the host scan including open ports
    """
    if ports is None:
        # Default to scanning common ports
        ports = list(COMMON_PORTS.keys())
    
    ip = get_ip_address(host)
    logger.info(f"Starting port scan on {host} ({ip}) - scanning {len(ports)} ports")
    
    results = {
        'host': host,
        'ip': ip,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'open_ports': [],
        'scan_time': None
    }
    
    start_time = time.time()
    
    # Randomize port order to be less predictable
    random.shuffle(ports)
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in future_to_port:
            result = future.result()
            if result['state'] == 'open':
                results['open_ports'].append(result)
    
    end_time = time.time()
    results['scan_time'] = end_time - start_time
    
    # Sort open ports by port number
    results['open_ports'].sort(key=lambda x: x['port'])
    
    return results

def parse_port_range(port_range):
    """
    Parse port range string into a list of ports.
    
    Parameters:
    -----------
    port_range : str
        Port range string (e.g., "80,443,8000-8080")
        
    Returns:
    --------
    list:
        List of port numbers
    """
    ports = []
    
    for part in port_range.split(','):
        if '-' in part:
            # Handle range like "1000-2000"
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            # Handle single port
            ports.append(int(part))
    
    return ports

def scan_network(network, ports=None, timeout=1, threads=50):
    """
    Scan all hosts in a network range.
    
    Parameters:
    -----------
    network : str
        Network range in CIDR notation (e.g., "192.168.1.0/24")
    ports : list
        List of ports to scan
    timeout : float
        Socket timeout in seconds
    threads : int
        Number of concurrent scanning threads
        
    Returns:
    --------
    dict:
        Results of the network scan including hosts with open ports
    """
    network_range = ipaddress.ip_network(network)
    hosts = [str(ip) for ip in network_range.hosts()]
    
    results = {
        'network': network,
        'hosts_count': len(hosts),
        'hosts_with_open_ports': [],
        'scan_time': None
    }
    
    logger.info(f"Starting network scan on {network} - {len(hosts)} hosts")
    start_time = time.time()
    
    max_hosts = min(254, len(hosts))  # Limit to 254 hosts for safety
    
    for i, host in enumerate(hosts[:max_hosts]):
        logger.info(f"Scanning host {host} ({i+1}/{max_hosts})")
        host_result = scan_host(host, ports, timeout, threads)
        
        if host_result['open_ports']:
            results['hosts_with_open_ports'].append(host_result)
            
    end_time = time.time()
    results['scan_time'] = end_time - start_time
    
    return results

def print_host_scan_results(results):
    """
    Print the host scan results in a readable format.
    
    Parameters:
    -----------
    results : dict
        The scan results to print
        
    Returns:
    --------
    None
    """
    print("\n" + "=" * 80)
    print(f"PORT SCAN RESULTS FOR: {results['host']} ({results['ip']})")
    print(f"Scan Time: {results['scan_time']:.2f} seconds")
    print(f"Timestamp: {results['timestamp']}")
    print("=" * 80)
    
    if not results['open_ports']:
        print("\nNo open ports were detected.")
    else:
        print(f"\nOpen Ports: {len(results['open_ports'])}")
        print("\nPORT     STATE    SERVICE     RESPONSE TIME    BANNER")
        print("-" * 80)
        
        for port_info in results['open_ports']:
            port = port_info['port']
            state = port_info['state']
            service = port_info['service']
            response_time = port_info.get('response_time', 'N/A')
            
            banner = port_info['banner']
            if banner:
                # Truncate long banners
                if len(banner) > 40:
                    banner = banner[:37] + "..."
                # Replace newlines with spaces
                banner = banner.replace('\n', ' ').replace('\r', '')
            else:
                banner = "No banner"
            
            print(f"{port:<8} {state:<8} {service:<12} {response_time:<15} {banner}")
    
    print("\n" + "=" * 80)

def print_network_scan_results(results):
    """
    Print the network scan results in a readable format.
    
    Parameters:
    -----------
    results : dict
        The scan results to print
        
    Returns:
    --------
    None
    """
    print("\n" + "=" * 80)
    print(f"NETWORK SCAN RESULTS FOR: {results['network']}")
    print(f"Hosts Scanned: {results['hosts_count']}")
    print(f"Hosts with Open Ports: {len(results['hosts_with_open_ports'])}")
    print(f"Total Scan Time: {results['scan_time']:.2f} seconds")
    print("=" * 80)
    
    if not results['hosts_with_open_ports']:
        print("\nNo hosts with open ports were detected.")
    else:
        for host_result in results['hosts_with_open_ports']:
            print(f"\nHOST: {host_result['host']} ({host_result['ip']})")
            print(f"Open Ports: {len(host_result['open_ports'])}")
            print("\nPORT     SERVICE     STATE")
            print("-" * 40)
            
            for port_info in host_result['open_ports']:
                port = port_info['port']
                service = port_info['service']
                state = port_info['state']
                
                print(f"{port:<8} {service:<12} {state}")
            
            print("-" * 40)
    
    print("\n" + "=" * 80)
    print("EDUCATIONAL INFORMATION:")
    print("Port scanning is a technique used to identify open ports and running services")
    print("on network hosts. Understanding your network's exposed services is crucial for")
    print("maintaining proper security posture and reducing attack surface.")
    print("\nRecommended actions:")
    print("1. Close unnecessary ports and disable unused services")
    print("2. Implement proper firewall rules")
    print("3. Use intrusion detection/prevention systems")
    print("4. Apply the principle of least privilege for network services")
    print("5. Regularly scan your network to identify unauthorized services")
    print("=" * 80 + "\n")

def main():
    """Main function to run the port scanner from the command line."""
    parser = argparse.ArgumentParser(
        description="Port Scanner for Educational Purposes",
        epilog="This tool is for educational and authorized testing only."
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--target", 
        help="Target IP address or hostname"
    )
    target_group.add_argument(
        "-n", "--network",
        help="Network range to scan in CIDR notation (e.g., 192.168.1.0/24)"
    )
    
    parser.add_argument(
        "-p", "--ports",
        default="21,22,23,25,53,80,110,123,143,443,445,3306,3389,8080",
        help=("Ports to scan, can be a list or range (e.g., '80,443,8000-8100'). "
              "Default is common ports.")
    )
    
    parser.add_argument(
        "-to", "--timeout",
        type=float,
        default=1.0,
        help="Timeout in seconds for each port scan (default: 1.0)"
    )
    
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads for scanning (default: 100)"
    )
    
    parser.add_argument(
        "--common",
        action="store_true",
        help="Scan only common ports (overrides --ports)"
    )
    
    args = parser.parse_args()
    
    # Display disclaimer and require confirmation
    print_disclaimer(
        script_name="Port Scanner",
        description="Scans network hosts for open ports and services",
        additional_warning="Port scanning without authorization may be illegal in many jurisdictions."
    )
    
    if not require_confirmation():
        return
    
    if not require_legal_confirmation():
        return
    
    # Parse ports
    if args.common:
        ports = list(COMMON_PORTS.keys())
    else:
        try:
            ports = parse_port_range(args.ports)
        except ValueError as e:
            logger.error(f"Invalid port specification: {str(e)}")
            return 1
    
    try:
        # Perform the scan
        if args.target:
            results = scan_host(
                args.target,
                ports=ports,
                timeout=args.timeout,
                threads=args.threads
            )
            print_host_scan_results(results)
        else:  # Network scan
            results = scan_network(
                args.network,
                ports=ports,
                timeout=args.timeout,
                threads=args.threads
            )
            print_network_scan_results(results)
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
