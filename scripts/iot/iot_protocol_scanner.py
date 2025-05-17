"""
IoT Protocol Scanner (MQTT/CoAP)

This script provides tools for scanning and analyzing IoT protocols such as MQTT and CoAP.
It can identify devices using these protocols, analyze their configuration, and detect
potential security vulnerabilities in their implementation.

This tool is intended for educational purposes and authorized security assessment only.
"""

import socket
import struct
import random
import time
import json
from contextlib import closing
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants for protocols
MQTT_PORTS = [1883, 8883]  # Standard MQTT, MQTT over TLS
COAP_PORTS = [5683, 5684]  # Standard CoAP, CoAP over DTLS

class MQTTScanner:
    """Class for scanning and analyzing MQTT protocol implementations."""
    
    def __init__(self, timeout=2):
        """
        Initialize the MQTT scanner.
        
        Parameters:
        -----------
        timeout : int
            Socket timeout in seconds
        """
        self.timeout = timeout
    
    def scan_mqtt_broker(self, target, port=1883):
        """
        Scan a target for MQTT broker and attempt to gather information.
        
        Parameters:
        -----------
        target : str
            Target IP or hostname
        port : int
            Target port
            
        Returns:
        --------
        dict:
            Results of the MQTT scan
        """
        results = {
            'host': target,
            'port': port,
            'protocol': 'MQTT',
            'is_broker': False,
            'version': None,
            'auth_required': None,
            'tls_support': None,
            'anonymous_access': None,
            'topics': [],
            'vulnerabilities': []
        }
        
        # Check if port is open
        if not self._is_port_open(target, port):
            results['status'] = 'Port closed'
            return results
        
        results['status'] = 'Port open'
        
        # Try to connect to the MQTT broker
        try:
            # This is a simplified educational example
            # In a real implementation, we would use the paho-mqtt library
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Craft a simple MQTT CONNECT packet
            client_id = f"scanner_{random.randint(1000, 9999)}"
            connect_packet = self._craft_mqtt_connect(client_id)
            sock.send(connect_packet)
            
            # Try to receive CONNACK
            response = sock.recv(4)
            if len(response) >= 4:
                # Check if it's a CONNACK packet
                if response[0] & 0xF0 == 0x20:
                    results['is_broker'] = True
                    results['version'] = 'MQTT 3.1.1'  # Assuming v3.1.1
                    
                    # Check return code
                    return_code = response[3]
                    if return_code == 0:
                        results['anonymous_access'] = True
                        results['auth_required'] = False
                        results['vulnerabilities'].append('Allows anonymous connections')
                    else:
                        results['anonymous_access'] = False
                        results['auth_required'] = True
            
            sock.close()
            
            # If port is 8883, assume TLS
            if port == 8883:
                results['tls_support'] = True
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _craft_mqtt_connect(self, client_id):
        """
        Craft an MQTT CONNECT packet.
        
        Parameters:
        -----------
        client_id : str
            Client identifier
            
        Returns:
        --------
        bytes:
            MQTT CONNECT packet
        """
        # Protocol name
        protocol_name = "MQTT"
        protocol_name_len = len(protocol_name)
        
        # Fixed header
        fixed_header = bytes([0x10])  # CONNECT packet
        
        # Variable header
        var_header = struct.pack("!H", protocol_name_len) + protocol_name.encode()
        var_header += bytes([0x04])  # Protocol version 4 (MQTT 3.1.1)
        var_header += bytes([0x02])  # Clean session flag
        var_header += struct.pack("!H", 60)  # Keep-alive 60 seconds
        
        # Payload
        payload = struct.pack("!H", len(client_id)) + client_id.encode()
        
        # Remaining length
        packet_len = len(var_header) + len(payload)
        
        # Encode remaining length in variable byte integer format
        remaining_bytes = []
        while packet_len > 0:
            byte = packet_len % 128
            packet_len = packet_len // 128
            if packet_len > 0:
                byte |= 0x80
            remaining_bytes.append(byte)
        
        # Complete packet
        packet = fixed_header + bytes(remaining_bytes) + var_header + payload
        return packet
    
    def _is_port_open(self, host, port):
        """
        Check if a port is open on the target host.
        
        Parameters:
        -----------
        host : str
            Target host
        port : int
            Target port
            
        Returns:
        --------
        bool:
            True if port is open, False otherwise
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            return result == 0


class CoAPScanner:
    """Class for scanning and analyzing CoAP protocol implementations."""
    
    def __init__(self, timeout=2):
        """
        Initialize the CoAP scanner.
        
        Parameters:
        -----------
        timeout : int
            Socket timeout in seconds
        """
        self.timeout = timeout
    
    def scan_coap_server(self, target, port=5683):
        """
        Scan a target for CoAP server and attempt to gather information.
        
        Parameters:
        -----------
        target : str
            Target IP or hostname
        port : int
            Target port
            
        Returns:
        --------
        dict:
            Results of the CoAP scan
        """
        results = {
            'host': target,
            'port': port,
            'protocol': 'CoAP',
            'is_server': False,
            'version': None,
            'resources': [],
            'vulnerabilities': []
        }
        
        # CoAP uses UDP
        try:
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Craft a simple CoAP GET request for the well-known resources
            coap_request = self._craft_coap_request()
            sock.sendto(coap_request, (target, port))
            
            # Try to receive a response
            try:
                data, addr = sock.recvfrom(1024)
                if data:
                    results['is_server'] = True
                    
                    # Parse response
                    if len(data) >= 4:
                        version_type = data[0] >> 6
                        results['version'] = f"CoAP {version_type}"
                        
                        # Check for payload
                        if len(data) > 4:
                            payload_marker_index = None
                            for i in range(4, len(data)):
                                if data[i] == 0xFF:  # Payload marker
                                    payload_marker_index = i
                                    break
                            
                            if payload_marker_index:
                                payload = data[payload_marker_index + 1:]
                                try:
                                    # Try to parse as JSON or text
                                    resources = payload.decode('utf-8')
                                    results['resources_raw'] = resources
                                    
                                    # Extract resources
                                    if resources.startswith('<') and '>' in resources:
                                        # Parse link-format
                                        links = resources.split(',')
                                        for link in links:
                                            if '<' in link and '>' in link:
                                                resource = link.split('<')[1].split('>')[0]
                                                results['resources'].append(resource)
                                except:
                                    pass
            except socket.timeout:
                pass
            
            sock.close()
            
            # Check for DTLS support
            if port == 5683:  # Standard CoAP port
                dtls_results = self._check_dtls_support(target)
                results.update(dtls_results)
                
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _craft_coap_request(self):
        """
        Craft a simple CoAP GET request for the well-known resources.
        
        Returns:
        --------
        bytes:
            CoAP request packet
        """
        # CoAP header (Version 1, GET method, Message ID)
        header = bytes([0x40])  # Version 1, Confirmable, GET method
        header += bytes([0x01])  # Code: GET
        header += struct.pack("!H", random.randint(0, 65535))  # Message ID
        
        # Token (random)
        token_length = 4
        # Create new header with token length set - need to rebuild since bytes are immutable
        new_header_byte = header[0] | token_length
        header = bytes([new_header_byte]) + header[1:]
        # Generate random token
        token = bytes([random.randint(0, 255) for _ in range(token_length)])
        
        # Options
        # Uri-Path option for /.well-known/core
        well_known_path = ".well-known/core"
        path_parts = well_known_path.split('/')
        
        options = b""
        option_number = 11  # Uri-Path option number
        
        for part in path_parts:
            if part:
                # Delta encoding
                option_delta = option_number
                option_length = len(part)
                
                # Format option delta and length
                options += bytes([((option_delta & 0x0F) << 4) | (option_length & 0x0F)])
                options += part.encode()
                
                # Reset option number for delta encoding
                option_number = 0
        
        # Complete packet
        packet = header + token + options
        return packet
    
    def _check_dtls_support(self, target):
        """
        Check if the target supports DTLS for CoAP.
        
        Parameters:
        -----------
        target : str
            Target host
            
        Returns:
        --------
        dict:
            Results of DTLS check
        """
        results = {
            'dtls_support': False,
            'dtls_version': None
        }
        
        # This is a simplified educational check
        # In a real implementation, we would send a DTLS ClientHello and analyze the response
        # For educational purposes, we'll just check if port 5684 is open
        
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.sendto(b"\x00", (target, 5684))
                data, _ = sock.recvfrom(1024)
                if data:
                    results['dtls_support'] = True
                    # We can't determine version without proper DTLS handshake
            except:
                pass
        
        return results


def scan_for_iot_protocols(target, ports=None, timeout=2):
    """
    Scan a target for IoT protocols.
    
    Parameters:
    -----------
    target : str
        Target IP or hostname
    ports : list
        List of ports to scan, defaults to common IoT protocol ports
    timeout : int
        Socket timeout in seconds
        
    Returns:
    --------
    dict:
        Scan results for each protocol
    """
    if ports is None:
        ports = MQTT_PORTS + COAP_PORTS
    
    results = {
        'target': target,
        'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'protocols': {
            'mqtt': [],
            'coap': []
        }
    }
    
    # Scan for MQTT
    mqtt_scanner = MQTTScanner(timeout=timeout)
    for port in MQTT_PORTS:
        if port in ports:
            logger.info(f"Scanning {target}:{port} for MQTT")
            mqtt_result = mqtt_scanner.scan_mqtt_broker(target, port)
            results['protocols']['mqtt'].append(mqtt_result)
    
    # Scan for CoAP
    coap_scanner = CoAPScanner(timeout=timeout)
    for port in COAP_PORTS:
        if port in ports:
            logger.info(f"Scanning {target}:{port} for CoAP")
            coap_result = coap_scanner.scan_coap_server(target, port)
            results['protocols']['coap'].append(coap_result)
    
    return results


def generate_report(scan_results):
    """
    Generate a human-readable report from scan results.
    
    Parameters:
    -----------
    scan_results : dict
        Results from scan_for_iot_protocols
        
    Returns:
    --------
    str:
        Formatted report
    """
    target = scan_results['target']
    scan_time = scan_results['scan_time']
    
    report = [
        f"IoT Protocol Scan Report for {target}",
        f"Scan Time: {scan_time}",
        "-" * 50
    ]
    
    # MQTT results
    report.append("\nMQTT Protocol Scan Results:")
    if not scan_results['protocols']['mqtt']:
        report.append("  No MQTT ports were scanned")
    else:
        for result in scan_results['protocols']['mqtt']:
            report.append(f"  Host: {result['host']}:{result['port']}")
            report.append(f"  Status: {result.get('status', 'Unknown')}")
            
            if result.get('is_broker'):
                report.append("  MQTT Broker: Detected")
                report.append(f"  Version: {result.get('version', 'Unknown')}")
                report.append(f"  Authentication Required: {result.get('auth_required', 'Unknown')}")
                report.append(f"  Anonymous Access: {result.get('anonymous_access', 'Unknown')}")
                report.append(f"  TLS Support: {result.get('tls_support', 'Unknown')}")
                
                if result.get('vulnerabilities'):
                    report.append("  Potential Vulnerabilities:")
                    for vuln in result['vulnerabilities']:
                        report.append(f"    - {vuln}")
            else:
                report.append("  MQTT Broker: Not detected")
                
            if result.get('error'):
                report.append(f"  Error: {result['error']}")
            
            report.append("")
    
    # CoAP results
    report.append("\nCoAP Protocol Scan Results:")
    if not scan_results['protocols']['coap']:
        report.append("  No CoAP ports were scanned")
    else:
        for result in scan_results['protocols']['coap']:
            report.append(f"  Host: {result['host']}:{result['port']}")
            
            if result.get('is_server'):
                report.append("  CoAP Server: Detected")
                report.append(f"  Version: {result.get('version', 'Unknown')}")
                report.append(f"  DTLS Support: {result.get('dtls_support', 'Unknown')}")
                
                if result.get('resources'):
                    report.append("  Resources:")
                    for resource in result['resources']:
                        report.append(f"    - {resource}")
                        
                if result.get('vulnerabilities'):
                    report.append("  Potential Vulnerabilities:")
                    for vuln in result['vulnerabilities']:
                        report.append(f"    - {vuln}")
            else:
                report.append("  CoAP Server: Not detected")
                
            if result.get('error'):
                report.append(f"  Error: {result['error']}")
            
            report.append("")
    
    report.append("-" * 50)
    report.append("\nEducational Notes:")
    report.append("- MQTT and CoAP are common protocols used in IoT environments")
    report.append("- MQTT is a publish/subscribe protocol often used for device telemetry")
    report.append("- CoAP is a lightweight HTTP-like protocol designed for constrained devices")
    report.append("- Secure these protocols with proper authentication and encryption")
    report.append("- Consider using MQTT over TLS (port 8883) and CoAP over DTLS (port 5684)")
    report.append("- Implement proper access controls to prevent unauthorized access")
    
    return "\n".join(report)


def main():
    """Main function to run the IoT protocol scanner from the command line."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Scan for IoT protocols (MQTT, CoAP)')
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('--ports', help='Comma-separated list of ports to scan')
    parser.add_argument('--timeout', type=int, default=2, help='Socket timeout in seconds')
    parser.add_argument('--output', help='Output file for scan results')
    args = parser.parse_args()
    
    # Parse ports if provided
    if args.ports:
        ports = [int(p) for p in args.ports.split(',')]
    else:
        ports = None
    
    # Run the scan
    results = scan_for_iot_protocols(args.target, ports, args.timeout)
    
    # Generate and display report
    report = generate_report(results)
    print(report)
    
    # Save results if output file is specified
    if args.output:
        if args.output.endswith('.json'):
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nScan results saved to {args.output}")
        else:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\nScan report saved to {args.output}")


if __name__ == "__main__":
    main()