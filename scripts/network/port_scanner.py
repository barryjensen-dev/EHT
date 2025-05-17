"""
Port Scanner

This script provides a comprehensive port scanning tool for network reconnaissance and
security assessment. It can scan for open ports on a single host or a range of hosts,
identify running services, and detect potential vulnerabilities.

This tool is intended for educational purposes and authorized security assessment only.
"""

import socket
import threading
import ipaddress
import time
import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Common ports and services dictionary
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    115: 'SFTP',
    135: 'MS-RPC',
    139: 'NetBIOS',
    143: 'IMAP',
    194: 'IRC',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    587: 'SMTP (Submission)',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle DB',
    1723: 'PPTP',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    5901: 'VNC-1',
    5902: 'VNC-2',
    5903: 'VNC-3',
    6379: 'Redis',
    8080: 'HTTP Proxy',
    8443: 'HTTPS Alt',
    8888: 'HTTP Alt',
    27017: 'MongoDB'
}

class PortScanner:
    """Class for performing port scanning operations."""
    
    def __init__(self, timeout=1, num_threads=100, verbose=False):
        """
        Initialize the port scanner.
        
        Parameters:
        -----------
        timeout : float
            Socket timeout in seconds
        num_threads : int
            Maximum number of concurrent threads
        verbose : bool
            Enable verbose output
        """
        self.timeout = timeout
        self.num_threads = num_threads
        self.verbose = verbose
        self.scan_results = {}
        
    def scan_port(self, target, port):
        """
        Scan a single port on a target.
        
        Parameters:
        -----------
        target : str
            Target IP or hostname
        port : int
            Port number to scan
            
        Returns:
        --------
        dict:
            Port scan result
        """
        result = {
            'port': port,
            'state': 'closed',
            'service': COMMON_PORTS.get(port, 'unknown'),
            'banner': None
        }
        
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        
        try:
            # Attempt to connect
            start_time = time.time()
            connection = s.connect_ex((target, port))
            response_time = time.time() - start_time
            
            # Check if port is open
            if connection == 0:
                result['state'] = 'open'
                result['response_time'] = round(response_time * 1000, 2)  # in ms
                
                # Try to grab banner
                try:
                    s.send(b'\\r\\n\\r\\n')
                    banner = s.recv(1024)
                    if banner:
                        result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                except:
                    pass
        except socket.error:
            result['state'] = 'filtered'
        finally:
            s.close()
            
        return result
        
    def scan_target_ports(self, target, ports=None, port_range=None):
        """
        Scan multiple ports on a target.
        
        Parameters:
        -----------
        target : str
            Target IP or hostname
        ports : list
            List of specific ports to scan
        port_range : tuple
            (start_port, end_port) for range scanning
            
        Returns:
        --------
        dict:
            Scan results for the target
        """
        if ports is None and port_range is None:
            # Default: Scan common ports
            ports = list(COMMON_PORTS.keys())
        elif port_range:
            # Generate port range
            ports = list(range(port_range[0], port_range[1] + 1))
        
        # Resolve hostname to IP if applicable
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            logger.error(f"Could not resolve hostname: {target}")
            return {
                'target': target,
                'ip': None,
                'hostname': target,
                'status': 'error',
                'error': 'Could not resolve hostname',
                'ports': []
            }
        
        # Get hostname if IP provided
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = None
        
        # Prepare result structure
        result = {
            'target': target,
            'ip': ip,
            'hostname': hostname if hostname else target,
            'status': 'up',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ports': []
        }
        
        # Log start of scan
        logger.info(f"Starting scan of {len(ports)} ports on {target} ({ip})")
        start_time = time.time()
        
        # Scan ports using thread pool
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port for port in ports
            }
            
            # Collect results as they complete
            for future in future_to_port:
                port_result = future.result()
                if port_result['state'] == 'open':
                    result['ports'].append(port_result)
                    if self.verbose:
                        logger.info(f"Found open port {port_result['port']}/{port_result['service']} on {target}")
        
        # Sort results by port number
        result['ports'].sort(key=lambda x: x['port'])
        
        # Calculate scan time
        result['scan_time'] = round(time.time() - start_time, 2)
        result['open_ports_count'] = len(result['ports'])
        
        logger.info(f"Scan completed for {target}: found {len(result['ports'])} open ports in {result['scan_time']}s")
        
        return result
        
    def scan_network(self, network, ports=None, port_range=None):
        """
        Scan all hosts in a network.
        
        Parameters:
        -----------
        network : str
            Network in CIDR notation (e.g., '192.168.1.0/24')
        ports : list
            List of specific ports to scan
        port_range : tuple
            (start_port, end_port) for range scanning
            
        Returns:
        --------
        dict:
            Scan results for the network
        """
        try:
            # Parse network
            ip_network = ipaddress.ip_network(network, strict=False)
            
            # Prepare result structure
            result = {
                'network': str(ip_network),
                'hosts_count': ip_network.num_addresses,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hosts': []
            }
            
            logger.info(f"Starting scan of {ip_network.num_addresses} hosts in {network}")
            start_time = time.time()
            
            # Scan hosts
            for ip in ip_network.hosts():
                host_result = self.scan_target_ports(str(ip), ports, port_range)
                if host_result['status'] == 'up' and host_result['open_ports_count'] > 0:
                    result['hosts'].append(host_result)
            
            # Calculate scan time
            result['scan_time'] = round(time.time() - start_time, 2)
            result['hosts_with_open_ports'] = len(result['hosts'])
            
            logger.info(f"Network scan completed: found {len(result['hosts'])} hosts with open ports")
            
            return result
            
        except ValueError as e:
            logger.error(f"Invalid network format: {e}")
            return {
                'network': network,
                'status': 'error',
                'error': str(e),
                'hosts': []
            }
    
    def generate_report(self, scan_results, report_format='text'):
        """
        Generate a report from scan results.
        
        Parameters:
        -----------
        scan_results : dict
            Results from scan_target_ports or scan_network
        report_format : str
            Format of the report ('text', 'json')
            
        Returns:
        --------
        str:
            Formatted report
        """
        if report_format == 'json':
            return json.dumps(scan_results, indent=2)
        
        # Text report
        if 'network' in scan_results:
            # Network scan report
            report = [
                f"Port Scan Report for Network: {scan_results['network']}",
                f"Scan Time: {scan_results['timestamp']}",
                f"Duration: {scan_results['scan_time']} seconds",
                f"Hosts with Open Ports: {scan_results['hosts_with_open_ports']} / {scan_results['hosts_count']}",
                "=" * 60
            ]
            
            # Add details for each host
            for host in scan_results['hosts']:
                report.append(f"\nHost: {host['target']} ({host['ip']})")
                if host['hostname'] and host['hostname'] != host['target']:
                    report.append(f"Hostname: {host['hostname']}")
                report.append(f"Open Ports: {host['open_ports_count']}")
                
                # List open ports
                report.append("\nPORT       STATE  SERVICE     BANNER")
                report.append("-" * 60)
                for port_info in host['ports']:
                    port_str = f"{port_info['port']}/tcp".ljust(10)
                    state_str = port_info['state'].ljust(6)
                    service_str = port_info['service'].ljust(11)
                    banner = port_info.get('banner', '')
                    if banner and len(banner) > 40:
                        banner = banner[:37] + "..."
                    report.append(f"{port_str} {state_str} {service_str} {banner}")
                
                report.append("-" * 60)
                
        else:
            # Single host report
            target = scan_results['target']
            ip = scan_results['ip']
            report = [
                f"Port Scan Report for Host: {target}",
                f"IP Address: {ip}",
                f"Scan Time: {scan_results['timestamp']}",
                f"Duration: {scan_results['scan_time']} seconds",
                f"Open Ports: {scan_results['open_ports_count']}",
                "=" * 60,
                "\nPORT       STATE  SERVICE     BANNER",
                "-" * 60
            ]
            
            # List open ports
            for port_info in scan_results['ports']:
                port_str = f"{port_info['port']}/tcp".ljust(10)
                state_str = port_info['state'].ljust(6)
                service_str = port_info['service'].ljust(11)
                banner = port_info.get('banner', '')
                if banner and len(banner) > 40:
                    banner = banner[:37] + "..."
                report.append(f"{port_str} {state_str} {service_str} {banner}")
                
            report.append("-" * 60)
        
        return "\n".join(report)

def scan_target(target, ports=None, port_range=None, timeout=1, threads=100, verbose=False):
    """
    Scan a single target for open ports.
    
    Parameters:
    -----------
    target : str
        Target IP or hostname
    ports : list
        List of specific ports to scan
    port_range : tuple
        (start_port, end_port) for range scanning
    timeout : float
        Socket timeout in seconds
    threads : int
        Maximum number of concurrent threads
    verbose : bool
        Enable verbose output
        
    Returns:
    --------
    dict:
        Scan results
    """
    scanner = PortScanner(timeout=timeout, num_threads=threads, verbose=verbose)
    return scanner.scan_target_ports(target, ports, port_range)

def scan_network_targets(network, ports=None, port_range=None, timeout=1, threads=100, verbose=False):
    """
    Scan a network for hosts with open ports.
    
    Parameters:
    -----------
    network : str
        Network in CIDR notation (e.g., '192.168.1.0/24')
    ports : list
        List of specific ports to scan
    port_range : tuple
        (start_port, end_port) for range scanning
    timeout : float
        Socket timeout in seconds
    threads : int
        Maximum number of concurrent threads
    verbose : bool
        Enable verbose output
        
    Returns:
    --------
    dict:
        Scan results
    """
    scanner = PortScanner(timeout=timeout, num_threads=threads, verbose=verbose)
    return scanner.scan_network(network, ports, port_range)

def main():
    """Main function to run the port scanner from the command line."""
    parser = argparse.ArgumentParser(description='Port Scanner (Educational Tool)')
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Single target to scan (IP or hostname)')
    target_group.add_argument('-n', '--network', help='Network to scan in CIDR notation (e.g., 192.168.1.0/24)')
    
    # Port options
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-p', '--ports', help='Comma-separated list of ports to scan (e.g., 80,443,8080)')
    port_group.add_argument('-r', '--range', help='Port range to scan (e.g., 1-1024)')
    
    # Scan options
    parser.add_argument('--timeout', type=float, default=1, help='Timeout in seconds (default: 1)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output file for scan results')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text', help='Output format (default: text)')
    
    args = parser.parse_args()
    
    # Parse ports
    ports = None
    port_range = None
    
    if args.ports:
        ports = [int(p) for p in args.ports.split(',')]
    elif args.range:
        start, end = map(int, args.range.split('-'))
        port_range = (start, end)
    
    # Initialize scanner
    scanner = PortScanner(timeout=args.timeout, num_threads=args.threads, verbose=args.verbose)
    
    # Run scan
    if args.target:
        logger.info(f"Starting scan on target: {args.target}")
        result = scanner.scan_target_ports(args.target, ports, port_range)
    else:
        logger.info(f"Starting scan on network: {args.network}")
        result = scanner.scan_network(args.network, ports, port_range)
    
    # Generate report
    report = scanner.generate_report(result, args.format)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        logger.info(f"Scan results saved to: {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()