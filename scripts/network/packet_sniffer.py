#!/usr/bin/env python3
"""
Network Packet Sniffer

This script provides a tool to capture and analyze network packets. It can be used to
inspect network traffic, understand protocols, and identify potential security issues.

This tool is intended for educational purposes and authorized network analysis only.
"""

import argparse
import sys
import time
import logging
import socket
import struct
import textwrap
import binascii
from datetime import datetime
from scripts.utils.disclaimer import print_disclaimer, require_confirmation, require_legal_confirmation

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def unpack_ethernet_frame(data):
    """
    Unpacks ethernet frame from raw data.
    
    Parameters:
    -----------
    data : bytes
        Raw ethernet frame data
        
    Returns:
    --------
    tuple:
        (dest_mac, src_mac, eth_proto, data)
    """
    # Unpack the first 14 bytes which contain the Ethernet header
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    
    # Format MAC addresses
    dest_mac = ':'.join('%02x' % b for b in dest_mac)
    src_mac = ':'.join('%02x' % b for b in src_mac)
    
    # Convert protocol to standard format (big endian)
    eth_proto = socket.htons(eth_proto)
    
    # Return the unpacked data
    return dest_mac, src_mac, eth_proto, data[14:]

def unpack_ipv4_packet(data):
    """
    Unpacks IPv4 packet from raw data.
    
    Parameters:
    -----------
    data : bytes
        Raw IPv4 packet data
        
    Returns:
    --------
    tuple:
        (version, header_length, ttl, proto, src_ip, dest_ip, data)
    """
    # First byte contains version (4 bits) and header length (4 bits)
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4  # Header length in bytes
    
    # Unpack the IPv4 header
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    # Convert IP addresses to string format
    src_ip = '.'.join(map(str, data[12:16]))
    dest_ip = '.'.join(map(str, data[16:20]))
    
    # Return the unpacked data
    return version, header_len, ttl, proto, src_ip, dest_ip, data[header_len:]

def unpack_tcp_segment(data):
    """
    Unpacks TCP segment from raw data.
    
    Parameters:
    -----------
    data : bytes
        Raw TCP segment data
        
    Returns:
    --------
    tuple:
        (src_port, dest_port, sequence, acknowledgment, flags, data)
    """
    # Unpack the TCP header
    src_port, dest_port, sequence, acknowledgment, offset_flags = struct.unpack('! H H L L H', data[:14])
    
    # Extract flags and offset
    offset = (offset_flags >> 12) * 4
    flag_urg = (offset_flags & 32) >> 5
    flag_ack = (offset_flags & 16) >> 4
    flag_psh = (offset_flags & 8) >> 3
    flag_rst = (offset_flags & 4) >> 2
    flag_syn = (offset_flags & 2) >> 1
    flag_fin = offset_flags & 1
    
    # Combine flags into a dictionary
    flags = {
        'URG': flag_urg,
        'ACK': flag_ack,
        'PSH': flag_psh,
        'RST': flag_rst,
        'SYN': flag_syn,
        'FIN': flag_fin
    }
    
    # Return the unpacked data
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def unpack_udp_segment(data):
    """
    Unpacks UDP segment from raw data.
    
    Parameters:
    -----------
    data : bytes
        Raw UDP segment data
        
    Returns:
    --------
    tuple:
        (src_port, dest_port, length, data)
    """
    # Unpack the UDP header
    src_port, dest_port, length = struct.unpack('! H H H 2x', data[:8])
    
    # Return the unpacked data
    return src_port, dest_port, length, data[8:]

def unpack_icmp_packet(data):
    """
    Unpacks ICMP packet from raw data.
    
    Parameters:
    -----------
    data : bytes
        Raw ICMP packet data
        
    Returns:
    --------
    tuple:
        (icmp_type, icmp_code, checksum, data)
    """
    # Unpack the ICMP header
    icmp_type, icmp_code, checksum = struct.unpack('! B B H', data[:4])
    
    # Return the unpacked data
    return icmp_type, icmp_code, checksum, data[4:]

def format_multi_line(data, prefix=''):
    """
    Formats binary data for display with line prefix.
    
    Parameters:
    -----------
    data : bytes
        Raw data to format
    prefix : str
        Prefix to add to each line
        
    Returns:
    --------
    str:
        Formatted data string
    """
    if not data:
        return ""
    
    # Convert binary data to hex and ASCII representation
    hex_data = binascii.hexlify(data).decode('utf-8')
    
    # Group hex data into 2-character chunks and then 8-chunk groups
    chunks = [hex_data[i:i+2] for i in range(0, len(hex_data), 2)]
    lines = [' '.join(chunks[i:i+8]) for i in range(0, len(chunks), 8)]
    
    # Add ASCII representation
    for i in range(len(lines)):
        start = i * 8
        end = min(start + 8, len(chunks))
        hex_line = ' '.join(chunks[start:end])
        
        # Create ASCII representation
        ascii_line = ''
        for j in range(start, end):
            if j * 2 + 1 < len(hex_data):
                char_code = int(hex_data[j*2:j*2+2], 16)
                if 32 <= char_code <= 126:  # Printable ASCII
                    ascii_line += chr(char_code)
                else:
                    ascii_line += '.'
            else:
                break
        
        # Pad hex line for alignment
        padding = ' ' * (24 - len(hex_line))
        lines[i] = f"{prefix}{hex_line}{padding} | {ascii_line}"
    
    return '\n'.join(lines)

def analyze_packet(data, packet_num, file=None, verbose=False):
    """
    Analyzes a network packet and prints or writes its details.
    
    Parameters:
    -----------
    data : bytes
        Raw packet data
    packet_num : int
        Packet number in the capture
    file : file object, optional
        File to write output to
    verbose : bool
        Whether to print verbose details
        
    Returns:
    --------
    dict:
        Packet information dictionary
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    packet_info = {
        'packet_num': packet_num,
        'timestamp': timestamp,
        'protocol': 'Unknown',
        'ip_version': None,
        'src_mac': None,
        'dest_mac': None,
        'src_ip': None,
        'dest_ip': None,
        'src_port': None,
        'dest_port': None,
        'length': len(data)
    }
    
    # Output header
    output = f"\n{'=' * 80}\nPacket #{packet_num} | {timestamp} | Length: {len(data)} bytes\n{'=' * 80}\n"
    
    try:
        # Unpack Ethernet frame
        dest_mac, src_mac, eth_proto, eth_data = unpack_ethernet_frame(data)
        packet_info['src_mac'] = src_mac
        packet_info['dest_mac'] = dest_mac
        
        output += f"Ethernet Frame:\n"
        output += f"  Destination MAC: {dest_mac}\n"
        output += f"  Source MAC: {src_mac}\n"
        output += f"  Protocol: {eth_proto}\n"
        
        # Handle different protocols inside Ethernet frame
        if eth_proto == 8:  # IPv4
            version, header_len, ttl, proto, src_ip, dest_ip, ip_data = unpack_ipv4_packet(eth_data)
            packet_info['ip_version'] = 4
            packet_info['src_ip'] = src_ip
            packet_info['dest_ip'] = dest_ip
            
            output += f"IPv4 Packet:\n"
            output += f"  Version: {version}\n"
            output += f"  Header Length: {header_len} bytes\n"
            output += f"  TTL: {ttl}\n"
            output += f"  Protocol: {proto}\n"
            output += f"  Source IP: {src_ip}\n"
            output += f"  Destination IP: {dest_ip}\n"
            
            # Handle different protocols inside IPv4 packet
            if proto == 1:  # ICMP
                icmp_type, icmp_code, checksum, icmp_data = unpack_icmp_packet(ip_data)
                packet_info['protocol'] = 'ICMP'
                
                output += f"ICMP Packet:\n"
                output += f"  Type: {icmp_type}\n"
                output += f"  Code: {icmp_code}\n"
                output += f"  Checksum: {checksum}\n"
                
                if verbose:
                    output += f"ICMP Data:\n"
                    output += format_multi_line(icmp_data, '  ')
                    output += "\n"
                
            elif proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, flags, tcp_data = unpack_tcp_segment(ip_data)
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = src_port
                packet_info['dest_port'] = dest_port
                
                output += f"TCP Segment:\n"
                output += f"  Source Port: {src_port}\n"
                output += f"  Destination Port: {dest_port}\n"
                output += f"  Sequence: {sequence}\n"
                output += f"  Acknowledgment: {acknowledgment}\n"
                output += f"  Flags: "
                for flag, value in flags.items():
                    if value:
                        output += f"{flag} "
                output += "\n"
                
                if verbose and tcp_data:
                    output += f"TCP Data:\n"
                    output += format_multi_line(tcp_data, '  ')
                    output += "\n"
                
            elif proto == 17:  # UDP
                src_port, dest_port, length, udp_data = unpack_udp_segment(ip_data)
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = src_port
                packet_info['dest_port'] = dest_port
                
                output += f"UDP Segment:\n"
                output += f"  Source Port: {src_port}\n"
                output += f"  Destination Port: {dest_port}\n"
                output += f"  Length: {length}\n"
                
                if verbose and udp_data:
                    output += f"UDP Data:\n"
                    output += format_multi_line(udp_data, '  ')
                    output += "\n"
            else:
                packet_info['protocol'] = f'IPv4-{proto}'
                output += f"Protocol not decoded: {proto}\n"
                
                if verbose:
                    output += f"Data:\n"
                    output += format_multi_line(ip_data, '  ')
                    output += "\n"
        else:
            packet_info['protocol'] = f'ETH-{eth_proto}'
            output += f"Protocol not decoded: {eth_proto}\n"
            
            if verbose:
                output += f"Data:\n"
                output += format_multi_line(eth_data, '  ')
                output += "\n"
    
    except Exception as e:
        output += f"Error analyzing packet: {str(e)}\n"
        logger.error(f"Error analyzing packet #{packet_num}: {str(e)}")
    
    # Print or write output
    if file:
        file.write(output)
    else:
        print(output)
    
    return packet_info

def capture_packets(interface, count=None, filter_ip=None, output_file=None, timeout=None, verbose=False):
    """
    Captures network packets on the specified interface.
    
    Parameters:
    -----------
    interface : str
        Network interface to capture on
    count : int, optional
        Number of packets to capture
    filter_ip : str, optional
        IP address to filter packets
    output_file : str, optional
        File to write output to
    timeout : int, optional
        Capture timeout in seconds
    verbose : bool
        Whether to print verbose details
        
    Returns:
    --------
    list:
        List of captured packet information
    """
    try:
        # Create a raw socket
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        if interface:
            # Bind to the specified interface
            conn.bind((interface, 0))
        
        logger.info(f"Packet capture started on interface {interface or 'any'}")
        print(f"\nStarting packet capture on interface: {interface or 'any'}")
        if count:
            print(f"Will capture {count} packets")
        if filter_ip:
            print(f"Filtering for IP: {filter_ip}")
        if timeout:
            print(f"Capture will timeout after {timeout} seconds")
        print("Press Ctrl+C to stop the capture")
        print("\nWaiting for packets...")
        
        # Open output file if specified
        file_obj = None
        if output_file:
            file_obj = open(output_file, 'w')
            file_obj.write(f"Packet Capture - Started at: {datetime.now()}\n")
            file_obj.write(f"Interface: {interface or 'any'}\n")
            if filter_ip:
                file_obj.write(f"IP Filter: {filter_ip}\n")
        
        packet_num = 0
        start_time = time.time()
        captured_packets = []
        
        try:
            while True:
                # Check if we've reached the packet count limit
                if count and packet_num >= count:
                    break
                
                # Check if we've reached the timeout
                if timeout and (time.time() - start_time) > timeout:
                    print(f"\nCapture timeout reached ({timeout} seconds)")
                    break
                
                # Set socket timeout to allow keyboard interrupt
                conn.settimeout(1.0)
                
                try:
                    # Receive packet
                    raw_data, addr = conn.recvfrom(65536)
                    
                    # Check IP filter if specified
                    if filter_ip:
                        try:
                            # Unpack the packet to check IPs
                            _, _, eth_proto, eth_data = unpack_ethernet_frame(raw_data)
                            if eth_proto == 8:  # IPv4
                                _, _, _, _, src_ip, dest_ip, _ = unpack_ipv4_packet(eth_data)
                                if filter_ip not in [src_ip, dest_ip]:
                                    continue  # Skip this packet
                        except:
                            continue  # Skip on any error
                    
                    # Increment packet counter
                    packet_num += 1
                    
                    # Analyze the packet
                    packet_info = analyze_packet(raw_data, packet_num, file_obj, verbose)
                    captured_packets.append(packet_info)
                    
                except socket.timeout:
                    # This is expected for the 1-second timeout
                    continue
        
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
        
        finally:
            if file_obj:
                file_obj.write(f"\nCapture completed at: {datetime.now()}\n")
                file_obj.write(f"Total packets captured: {packet_num}\n")
                file_obj.close()
                print(f"\nOutput written to: {output_file}")
            
            conn.close()
            print(f"\nCapture complete. Captured {packet_num} packets.")
        
        return captured_packets
    
    except socket.error as e:
        logger.error(f"Socket error: {str(e)}")
        print(f"\nError: {str(e)}")
        print("Note: This script requires root/administrator privileges to capture packets.")
        return []
    
    except Exception as e:
        logger.error(f"Capture error: {str(e)}")
        print(f"\nError: {str(e)}")
        return []

def print_capture_summary(packets):
    """
    Prints a summary of captured packets.
    
    Parameters:
    -----------
    packets : list
        List of packet information dictionaries
        
    Returns:
    --------
    None
    """
    if not packets:
        print("No packets captured.")
        return
    
    # Protocol statistics
    protocols = {}
    ip_addresses = set()
    ports = set()
    
    for packet in packets:
        proto = packet.get('protocol', 'Unknown')
        src_ip = packet.get('src_ip')
        dest_ip = packet.get('dest_ip')
        src_port = packet.get('src_port')
        dest_port = packet.get('dest_port')
        
        # Count protocols
        protocols[proto] = protocols.get(proto, 0) + 1
        
        # Collect unique IPs
        if src_ip:
            ip_addresses.add(src_ip)
        if dest_ip:
            ip_addresses.add(dest_ip)
        
        # Collect unique ports
        if src_port:
            ports.add(src_port)
        if dest_port:
            ports.add(dest_port)
    
    print("\n" + "=" * 80)
    print(f"CAPTURE SUMMARY: {len(packets)} packets")
    print("=" * 80)
    
    print("\nProtocol Distribution:")
    for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / len(packets)) * 100
        print(f"  {proto}: {count} packets ({percentage:.1f}%)")
    
    print(f"\nUnique IP Addresses: {len(ip_addresses)}")
    if len(ip_addresses) <= 10:  # Only show if not too many
        for ip in sorted(ip_addresses):
            print(f"  {ip}")
    
    if ports:
        print(f"\nUnique Ports: {len(ports)}")
        if len(ports) <= 20:  # Only show if not too many
            for port in sorted(ports):
                print(f"  {port}")
    
    print("\n" + "=" * 80)
    print("EDUCATIONAL INFORMATION:")
    print("Packet analysis allows understanding of network traffic patterns and")
    print("can help identify security issues, network performance problems, and")
    print("unauthorized communication.")
    print("\nCommon applications of packet analysis:")
    print("1. Network troubleshooting")
    print("2. Security monitoring")
    print("3. Performance optimization")
    print("4. Protocol analysis and development")
    print("=" * 80 + "\n")

def get_available_interfaces():
    """
    Returns a list of available network interfaces.
    
    Returns:
    --------
    list:
        List of interface names
    """
    interfaces = []
    
    try:
        # This is a simple approach that works on Linux/Unix
        # For Windows, a different approach would be needed
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if ':' in line:
                    interface = line.split(':')[0].strip()
                    if interface != 'lo':  # Skip loopback
                        interfaces.append(interface)
    except Exception as e:
        logger.error(f"Error getting interfaces: {str(e)}")
        # Fallback to common interface names
        interfaces = ['eth0', 'wlan0', 'en0', 'en1']
    
    return interfaces

def main():
    """Main function to run the packet sniffer from the command line."""
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer for Educational Purposes",
        epilog="This tool is for educational and authorized testing only."
    )
    
    parser.add_argument(
        "-i", "--interface", 
        help="Network interface to capture on (default: first available)"
    )
    
    parser.add_argument(
        "-c", "--count",
        type=int,
        help="Number of packets to capture"
    )
    
    parser.add_argument(
        "-f", "--filter",
        help="Filter by IP address"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file to write capture results"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        help="Capture timeout in seconds"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose output including packet data"
    )
    
    parser.add_argument(
        "-l", "--list-interfaces",
        action="store_true",
        help="List available network interfaces"
    )
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        print("Available network interfaces:")
        for interface in interfaces:
            print(f"  {interface}")
        return 0
    
    # Set default interface if not specified
    if not args.interface:
        interfaces = get_available_interfaces()
        if interfaces:
            args.interface = interfaces[0]
            print(f"No interface specified, using: {args.interface}")
    
    # Display disclaimer and require confirmation
    print_disclaimer(
        script_name="Network Packet Sniffer",
        description="Captures and analyzes network packets for educational purposes",
        additional_warning="Capturing network traffic without authorization may violate privacy laws and regulations."
    )
    
    if not require_confirmation():
        return
    
    if not require_legal_confirmation():
        return
    
    try:
        # Perform packet capture
        captured_packets = capture_packets(
            interface=args.interface,
            count=args.count,
            filter_ip=args.filter,
            output_file=args.output,
            timeout=args.timeout,
            verbose=args.verbose
        )
        
        # Print capture summary
        print_capture_summary(captured_packets)
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
