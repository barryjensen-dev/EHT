#!/usr/bin/env python3
"""
IoT Device Scanner

This script provides tools to discover and fingerprint IoT devices on a network.
It scans networks for devices, identifies common IoT protocols, and performs basic
security checks on discovered devices.

This tool is intended for educational purposes and authorized security assessment only.
"""

import argparse
import socket
import struct
import sys
import time
import ipaddress
import logging
import random
import json
import re
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from urllib.parse import urlparse
import requests
import zeroconf
from scripts.utils.disclaimer import print_disclaimer, require_confirmation, require_legal_confirmation

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Common IoT service ports
IOT_COMMON_PORTS = {
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    1883: "MQTT",
    5683: "CoAP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTT-SSL",
    9000: "HTTP-Alt",
    5000: "HTTP-Alt"
}

# Common IoT device manufacturers based on MAC address prefixes
# Format: First 3 bytes of MAC address (OUI) -> Manufacturer
MAC_PREFIXES = {
    '00:1a:22': 'Xanboo (IoT cameras)',
    '00:17:88': 'Philips Lighting/Hue',
    '00:0d:4b': 'Roku/TV devices',
    '00:12:fb': 'Samsung Electronics',
    '18:b4:30': 'Nest Labs',
    '70:b3:d5': 'Ring',
    '74:da:38': 'EDIMAX',
    'b8:27:eb': 'Raspberry Pi',
    'ec:fa:bc': 'Xiaomi IoT devices',
    'd0:52:a8': 'Netgear',
    '44:d9:e7': 'Ubiquiti',
    '00:90:4c': 'Epson',
    'd8:0d:17': 'TP-Link',
    '00:24:e4': 'Withings',
    'b0:c5:54': 'D-Link',
    '00:1d:c9': 'GainSpan (IoT modules)',
    'ac:23:3f': 'Shenzhen RF Technology (IoT products)',
    '00:12:fb': 'Samsung Electronics',
    '00:24:b2': 'NETGEAR',
    '00:13:a2': 'Maxstream (IoT/M2M modules)',
    'ec:a8:6b': 'ELUX (Electrolux Smart Appliances)'
}

# Default credentials for common IoT devices
DEFAULT_CREDENTIALS = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": ""},
    {"username": "root", "password": "root"},
    {"username": "admin", "password": "1234"},
    {"username": "admin", "password": "12345"},
    {"username": "Admin", "password": "Admin"},
    {"username": "admin", "password": "admin123"},
    {"username": "ubnt", "password": "ubnt"},
    {"username": "user", "password": "user"}
]

# Regex patterns for device fingerprinting from HTTP responses
DEVICE_FINGERPRINT_PATTERNS = [
    (r'<title>(.*?)</title>', 'title'),
    (r'server:\s*(.*?)[\r\n]', 'server'),
    (r'www-authenticate:\s*(.*?)[\r\n]', 'auth'),
    (r'<meta.*?name=["\']description["\'].*?content=["\']([^"\']*)["\']', 'description'),
    (r'<meta.*?name=["\']manufacturer["\'].*?content=["\']([^"\']*)["\']', 'manufacturer'),
    (r'<meta.*?name=["\']model["\'].*?content=["\']([^"\']*)["\']', 'model')
]

class IoTServiceListener:
    """Listener for mDNS/Bonjour service discovery"""
    
    def __init__(self):
        self.devices = []
        
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info:
            device = {
                'name': name,
                'type': type_,
                'address': socket.inet_ntoa(info.addresses[0]) if info.addresses else '',
                'port': info.port,
                'properties': dict(info.properties) if info.properties else {}
            }
            self.devices.append(device)
            logger.info(f"mDNS: Found device - {name} at {device['address']}:{device['port']}")

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
        Result of the port scan including port status and service
    """
    result = {
        'port': port,
        'state': 'closed',
        'service': IOT_COMMON_PORTS.get(port, "Unknown"),
        'banner': None
    }
    
    # Create a socket
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
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
                    s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = s.recv(1024)
                    if banner:
                        result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                except:
                    # Couldn't get a banner, which is common for many services
                    pass
        
        except (socket.timeout, ConnectionRefusedError):
            # Port is likely closed or filtered
            pass
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {str(e)}")
    
    return result

def get_mac_address(ip, timeout=1):
    """
    Attempt to get MAC address for an IP using ARP.
    This is a simplified approach and may not work on all systems.
    
    Parameters:
    -----------
    ip : str
        The IP address to lookup
    timeout : float
        Timeout in seconds
        
    Returns:
    --------
    str:
        MAC address if found, None otherwise
    """
    try:
        # This approach only works on Linux/Unix systems
        import subprocess
        output = subprocess.check_output(['arp', '-n', ip], timeout=timeout).decode('utf-8')
        mac_matches = re.search(r'(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))', output)
        if mac_matches:
            return mac_matches.group(1).lower().replace('-', ':')
    except:
        # Fall back to a dummy MAC for educational demonstration
        # In a real scenario, proper ARP or other techniques would be used
        logger.debug(f"Could not determine MAC address for {ip}")
    
    return None

def get_manufacturer_from_mac(mac):
    """
    Get manufacturer name from MAC address OUI.
    
    Parameters:
    -----------
    mac : str
        MAC address
        
    Returns:
    --------
    str:
        Manufacturer name if found, 'Unknown' otherwise
    """
    if not mac:
        return "Unknown"
    
    # Get first 8 characters (first 3 bytes) of MAC address
    oui = mac[:8].lower()
    
    # Check our local database
    return MAC_PREFIXES.get(oui, "Unknown")

def get_http_device_info(ip, port=80, timeout=3):
    """
    Get device information from HTTP headers and content.
    
    Parameters:
    -----------
    ip : str
        The IP address to connect to
    port : int
        The port to connect to
    timeout : float
        Request timeout in seconds
        
    Returns:
    --------
    dict:
        Device information from HTTP response
    """
    device_info = {
        'title': None,
        'server': None,
        'auth': None,
        'description': None,
        'manufacturer': None,
        'model': None
    }
    
    url = f"http://{ip}:{port}/"
    
    try:
        response = requests.get(
            url, 
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; IoTDeviceScanner/1.0; +https://example.com)'
            }
        )
        
        # Check headers for server info
        server = response.headers.get('Server')
        if server:
            device_info['server'] = server
        
        www_auth = response.headers.get('WWW-Authenticate')
        if www_auth:
            device_info['auth'] = www_auth
        
        # Parse HTML content for device information
        if response.text:
            for pattern, key in DEVICE_FINGERPRINT_PATTERNS:
                matches = re.search(pattern, response.text, re.IGNORECASE)
                if matches:
                    device_info[key] = matches.group(1).strip()
    
    except requests.RequestException:
        # HTTP request failed, which is common for many devices
        pass
    
    return device_info

def check_default_credentials(ip, port=80, use_https=False, timeout=3):
    """
    Check if device accepts default credentials over HTTP basic auth.
    This is for educational purposes to demonstrate the importance of
    changing default credentials.
    
    Parameters:
    -----------
    ip : str
        The IP address to connect to
    port : int
        The port to connect to
    use_https : bool
        Whether to use HTTPS instead of HTTP
    timeout : float
        Request timeout in seconds
        
    Returns:
    --------
    dict:
        Default credential check results
    """
    results = []
    
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}:{port}/"
    
    # First check if the device requires authentication
    try:
        response = requests.get(
            url, 
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; IoTDeviceScanner/1.0; +https://example.com)'
            },
            verify=False  # Skip SSL verification for educational purposes
        )
        
        # If no 401 response, the device might not use basic auth
        if response.status_code != 401:
            return results
    
    except requests.RequestException:
        # HTTP request failed
        return results
    
    # Try default credentials
    for cred in DEFAULT_CREDENTIALS:
        try:
            auth_response = requests.get(
                url,
                auth=(cred["username"], cred["password"]),
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (compatible; IoTDeviceScanner/1.0; +https://example.com)'
                },
                verify=False  # Skip SSL verification for educational purposes
            )
            
            if auth_response.status_code == 200:
                results.append({
                    'username': cred["username"],
                    'password': cred["password"],
                    'url': url
                })
                
                # No need to try more credentials if we found working ones
                break
        
        except requests.RequestException:
            # HTTP request failed
            continue
    
    return results

def scan_device(ip, ports=None, scan_default_creds=False, timeout=2):
    """
    Scan an IoT device for open ports and gather information.
    
    Parameters:
    -----------
    ip : str
        The IP address to scan
    ports : list
        List of ports to scan
    scan_default_creds : bool
        Whether to check for default credentials
    timeout : float
        Timeout in seconds
        
    Returns:
    --------
    dict:
        Device scan results
    """
    if ports is None:
        # Default to scanning common IoT ports
        ports = list(IOT_COMMON_PORTS.keys())
    
    logger.info(f"Scanning device at {ip}")
    
    # Get MAC address for the device
    mac_address = get_mac_address(ip)
    manufacturer = get_manufacturer_from_mac(mac_address) if mac_address else "Unknown"
    
    device_info = {
        'ip': ip,
        'mac_address': mac_address,
        'manufacturer': manufacturer,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'open_ports': [],
        'http_info': None,
        'default_credentials': []
    }
    
    # Randomize port order to be less predictable
    random.shuffle(ports)
    
    # Scan ports
    with ThreadPoolExecutor(max_workers=10) as executor:
        port_results = list(executor.map(
            lambda port: scan_port(ip, port, timeout),
            ports
        ))
    
    # Filter for open ports
    open_ports = [result for result in port_results if result['state'] == 'open']
    device_info['open_ports'] = open_ports
    
    # If port 80 is open, get HTTP information
    if any(p['port'] == 80 and p['state'] == 'open' for p in open_ports):
        device_info['http_info'] = get_http_device_info(ip, 80, timeout)
    
    # Alternative HTTP ports
    elif any(p['port'] == 8080 and p['state'] == 'open' for p in open_ports):
        device_info['http_info'] = get_http_device_info(ip, 8080, timeout)
    
    # Check for default credentials if requested
    if scan_default_creds:
        http_ports = [p['port'] for p in open_ports if p['service'] in ['HTTP', 'HTTP-Alt']]
        for port in http_ports:
            creds = check_default_credentials(ip, port, False, timeout)
            if creds:
                device_info['default_credentials'].extend(creds)
        
        # Check HTTPS ports
        https_ports = [p['port'] for p in open_ports if p['service'] in ['HTTPS', 'HTTPS-Alt']]
        for port in https_ports:
            creds = check_default_credentials(ip, port, True, timeout)
            if creds:
                device_info['default_credentials'].extend(creds)
    
    return device_info

def discover_mdns_devices(timeout=10):
    """
    Discover IoT devices using mDNS/Bonjour.
    
    Parameters:
    -----------
    timeout : int
        Discovery timeout in seconds
        
    Returns:
    --------
    list:
        List of discovered devices
    """
    logger.info("Starting mDNS/Bonjour device discovery")
    
    # Common IoT service types
    service_types = [
        "_http._tcp.local.",
        "_hue._tcp.local.",
        "_ipp._tcp.local.",
        "_spotify-connect._tcp.local.",
        "_googlecast._tcp.local.",
        "_nest-camera._tcp.local.",
        "_homekit._tcp.local.",
        "_airplay._tcp.local.",
        "_printer._tcp.local.",
        "_axis-video._tcp.local.",
        "_ssh._tcp.local."
    ]
    
    listener = IoTServiceListener()
    zc = zeroconf.Zeroconf()
    
    # Register the listener for all service types
    browsers = []
    for service_type in service_types:
        browsers.append(zeroconf.ServiceBrowser(zc, service_type, listener))
    
    # Give some time for discovery
    time.sleep(timeout)
    
    # Clean up
    zc.close()
    
    return listener.devices

def scan_network_for_iot(network, ports=None, scan_default_creds=False, timeout=2, threads=50, discover_mdns=False):
    """
    Scan a network range for IoT devices.
    
    Parameters:
    -----------
    network : str
        Network range in CIDR notation (e.g., "192.168.1.0/24")
    ports : list
        List of ports to scan
    scan_default_creds : bool
        Whether to check for default credentials
    timeout : float
        Port scan timeout in seconds
    threads : int
        Number of concurrent scanning threads
    discover_mdns : bool
        Whether to use mDNS discovery
        
    Returns:
    --------
    dict:
        Network scan results with discovered devices
    """
    network_range = ipaddress.ip_network(network)
    hosts = [str(ip) for ip in network_range.hosts()]
    
    results = {
        'network': network,
        'hosts_count': len(hosts),
        'devices': [],
        'mdns_devices': [],
        'scan_time': None,
        'scan_timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    logger.info(f"Starting IoT device scan on {network} - {len(hosts)} hosts")
    start_time = time.time()
    
    # Use mDNS discovery if requested
    if discover_mdns:
        mdns_devices = discover_mdns_devices(10)  # 10-second discovery
        results['mdns_devices'] = mdns_devices
        
        # Add mDNS-discovered IPs to our priority scanning list
        mdns_ips = [device['address'] for device in mdns_devices if device['address']]
        
        # Reorder hosts to scan mDNS-discovered IPs first
        for ip in mdns_ips:
            if ip in hosts:
                hosts.remove(ip)
                hosts.insert(0, ip)
    
    max_hosts = min(254, len(hosts))  # Limit to 254 hosts for safety
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for host in hosts[:max_hosts]:
            futures.append(
                executor.submit(
                    scan_device, 
                    host, 
                    ports, 
                    scan_default_creds, 
                    timeout
                )
            )
        
        for i, future in enumerate(futures):
            try:
                device_info = future.result()
                if device_info['open_ports']:  # Only include devices with open ports
                    results['devices'].append(device_info)
                    logger.info(f"Found device at {device_info['ip']} with {len(device_info['open_ports'])} open ports")
            except Exception as e:
                logger.error(f"Error scanning host {hosts[i]}: {str(e)}")
            
    end_time = time.time()
    results['scan_time'] = end_time - start_time
    
    return results

def print_device_scan_results(device_info):
    """
    Print the device scan results in a readable format.
    
    Parameters:
    -----------
    device_info : dict
        The device scan results to print
        
    Returns:
    --------
    None
    """
    print("\n" + "=" * 80)
    print(f"DEVICE SCAN RESULTS FOR: {device_info['ip']}")
    if device_info['mac_address']:
        print(f"MAC Address: {device_info['mac_address']} (Manufacturer: {device_info['manufacturer']})")
    print(f"Timestamp: {device_info['timestamp']}")
    print("=" * 80)
    
    if not device_info['open_ports']:
        print("\nNo open ports were detected.")
    else:
        print(f"\nOpen Ports: {len(device_info['open_ports'])}")
        print("\nPORT     SERVICE     STATE")
        print("-" * 40)
        
        for port_info in device_info['open_ports']:
            port = port_info['port']
            service = port_info['service']
            state = port_info['state']
            
            print(f"{port:<8} {service:<12} {state}")
    
    if device_info['http_info'] and any(device_info['http_info'].values()):
        print("\nHTTP Device Information:")
        for key, value in device_info['http_info'].items():
            if value:
                print(f"  {key.capitalize()}: {value}")
    
    if device_info['default_credentials']:
        print("\nDEFAULT CREDENTIALS DETECTED:")
        print("WARNING: The following default credentials were accepted by the device:")
        for cred in device_info['default_credentials']:
            print(f"  Username: {cred['username']}, Password: {cred['password']}, URL: {cred['url']}")
        print("\nRECOMMENDATION: Change these credentials immediately!")
    
    print("\n" + "=" * 80)

def print_network_scan_results(results):
    """
    Print the network scan results in a readable format.
    
    Parameters:
    -----------
    results : dict
        The network scan results to print
        
    Returns:
    --------
    None
    """
    print("\n" + "=" * 80)
    print(f"IOT DEVICE SCAN RESULTS FOR NETWORK: {results['network']}")
    print(f"Hosts Scanned: {results['hosts_count']}")
    print(f"Devices Found: {len(results['devices'])}")
    print(f"Total Scan Time: {results['scan_time']:.2f} seconds")
    print(f"Scan Timestamp: {results['scan_timestamp']}")
    print("=" * 80)
    
    if results['mdns_devices']:
        print(f"\nmDNS/Bonjour Discovered Devices: {len(results['mdns_devices'])}")
        for device in results['mdns_devices']:
            print(f"  {device['name']} - {device['address']}:{device['port']} ({device['type']})")
    
    if not results['devices']:
        print("\nNo IoT devices were detected.")
    else:
        print("\nDiscovered Devices:")
        
        for i, device in enumerate(results['devices'], 1):
            print(f"\n{i}. IP: {device['ip']}")
            
            if device['mac_address']:
                print(f"   MAC: {device['mac_address']} (Manufacturer: {device['manufacturer']})")
            
            ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in device['open_ports']])
            print(f"   Open Ports: {ports_str}")
            
            if device['http_info'] and device['http_info'].get('title'):
                print(f"   Web Title: {device['http_info']['title']}")
            
            if device['http_info'] and device['http_info'].get('server'):
                print(f"   Server: {device['http_info']['server']}")
            
            if device['default_credentials']:
                print(f"   DEFAULT CREDENTIALS DETECTED: {len(device['default_credentials'])}")
    
    print("\n" + "=" * 80)
    print("EDUCATIONAL INFORMATION:")
    print("IoT device scanning helps identify potentially vulnerable devices on")
    print("your network. Many IoT devices have minimal security, use default")
    print("credentials, or run outdated firmware with known vulnerabilities.")
    print("\nRecommended actions:")
    print("1. Change default credentials on all devices")
    print("2. Update firmware/software to the latest version")
    print("3. Use network segmentation to isolate IoT devices")
    print("4. Disable unnecessary services and close unused ports")
    print("5. Implement strong Wi-Fi encryption and unique passwords")
    print("=" * 80 + "\n")

def save_results_to_file(results, filename):
    """
    Save scan results to a JSON file.
    
    Parameters:
    -----------
    results : dict
        Scan results to save
    filename : str
        Output filename
        
    Returns:
    --------
    bool:
        True if successful, False otherwise
    """
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {filename}")
        return True
    except Exception as e:
        logger.error(f"Error saving results to {filename}: {str(e)}")
        return False

def main():
    """Main function to run the IoT device scanner from the command line."""
    parser = argparse.ArgumentParser(
        description="IoT Device Scanner for Educational Purposes",
        epilog="This tool is for educational and authorized testing only."
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--target", 
        help="Target IP address of the IoT device"
    )
    target_group.add_argument(
        "-n", "--network",
        help="Network range to scan in CIDR notation (e.g., 192.168.1.0/24)"
    )
    
    parser.add_argument(
        "-p", "--ports",
        default="21,22,23,25,80,443,554,1883,5683,8080,8443,8883,9000",
        help=("Ports to scan, can be a list or range (e.g., '80,443,8000-8100'). "
              "Default is common IoT ports.")
    )
    
    parser.add_argument(
        "--check-default-creds",
        action="store_true",
        help="Check for default credentials on discovered web services"
    )
    
    parser.add_argument(
        "--mdns",
        action="store_true",
        help="Use mDNS/Bonjour for device discovery"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Save results to the specified JSON file"
    )
    
    parser.add_argument(
        "-to", "--timeout",
        type=float,
        default=2.0,
        help="Timeout in seconds for each port scan (default: 2.0)"
    )
    
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads for scanning (default: 50)"
    )
    
    args = parser.parse_args()
    
    # Display disclaimer and require confirmation
    print_disclaimer(
        script_name="IoT Device Scanner",
        description="Discovers and fingerprints IoT devices on a network",
        additional_warning="Scanning devices without authorization may violate laws and policies."
    )
    
    if not require_confirmation():
        return
    
    if not require_legal_confirmation():
        return
    
    # Parse ports
    try:
        from scripts.network.port_scanner import parse_port_range
        ports = parse_port_range(args.ports)
    except ImportError:
        # If the port_scanner module is not available, parse ports manually
        ports = []
        for part in args.ports.split(','):
            if '-' in part:
                # Handle range like "1000-2000"
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                # Handle single port
                ports.append(int(part))
    
    try:
        # Perform the scan
        if args.target:
            device_info = scan_device(
                args.target,
                ports=ports,
                scan_default_creds=args.check_default_creds,
                timeout=args.timeout
            )
            print_device_scan_results(device_info)
            
            # Save results if requested
            if args.output:
                save_results_to_file(device_info, args.output)
                print(f"\nResults saved to {args.output}")
        
        else:  # Network scan
            results = scan_network_for_iot(
                args.network,
                ports=ports,
                scan_default_creds=args.check_default_creds,
                timeout=args.timeout,
                threads=args.threads,
                discover_mdns=args.mdns
            )
            print_network_scan_results(results)
            
            # Save results if requested
            if args.output:
                save_results_to_file(results, args.output)
                print(f"\nResults saved to {args.output}")
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
