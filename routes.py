import os
import importlib
import inspect
import logging
import json
import re
import socket
import hashlib
import time
import random
import threading
import queue
import subprocess
import importlib.util
import contextlib
import io
from functools import wraps

from flask import render_template, request, redirect, url_for, abort, jsonify
from app import app, db
from models import Category, Script
import scripts

logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """Home page route that displays all script categories."""
    categories = Category.query.all()
    return render_template('index.html', categories=categories)

@app.route('/about')
def about():
    """About page with information about the project."""
    return render_template('about.html')

@app.route('/category/<int:category_id>')
def category(category_id):
    """Display all scripts in a specific category."""
    category = Category.query.get_or_404(category_id)
    return render_template('category.html', category=category)

@app.route('/script/<int:script_id>')
def script_view(script_id):
    """Display a specific script's details, code, and documentation."""
    script = Script.query.get_or_404(script_id)
    
    try:
        # Dynamically import the script module
        module_path = script.module_path
        module = importlib.import_module(module_path)
        
        # Get the source code
        source_code = inspect.getsource(module)
        
        # Get the module docstring if available
        module_doc = module.__doc__ or "No documentation available"
        
        # Get function details from the module
        functions = []
        for name, obj in inspect.getmembers(module):
            if inspect.isfunction(obj) and not name.startswith('_'):
                func_doc = obj.__doc__ or "No documentation available"
                func_source = inspect.getsource(obj)
                functions.append({
                    'name': name,
                    'doc': func_doc,
                    'source': func_source
                })
        
        return render_template('script_view.html', 
                               script=script, 
                               source_code=source_code,
                               module_doc=module_doc,
                               functions=functions)
    
    except Exception as e:
        logger.error(f"Error loading script {script.module_path}: {str(e)}")
        abort(500, description=f"Error loading script: {str(e)}")

@app.route('/api/scripts')
def api_scripts():
    """API endpoint to get all scripts as JSON."""
    scripts = Script.query.all()
    result = []
    for script in scripts:
        result.append({
            'id': script.id,
            'title': script.title,
            'description': script.description,
            'category_id': script.category_id,
            'module_path': script.module_path
        })
    return jsonify(result)

@app.route('/run_script/<int:script_id>', methods=['POST'])
def run_script(script_id):
    """Run a script with the given parameters in a controlled, educational environment."""
    script = Script.query.get_or_404(script_id)
    
    # Security check - ensure we're only running in educational mode
    if not request.form.get('ethicsCheckbox', False) and 'default_params' not in request.form:
        return jsonify({
            'success': False,
            'error': 'You must confirm the ethical use disclaimer to run this tool.'
        })
    
    try:
        # Get script parameters from the form
        parameters = dict(request.form)
        
        # Remove the ethics checkbox from parameters
        if 'ethicsCheckbox' in parameters:
            del parameters['ethicsCheckbox']
        
        # Get simulated results based on the script type
        results = simulate_script_execution(script, parameters)
        
        return jsonify({
            'success': True,
            'results': results
        })
    
    except Exception as e:
        logger.error(f"Error running script {script.module_path}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Error running script: {str(e)}"
        })

# Simulated script execution function
def simulate_script_execution(script, parameters):
    """
    Simulate the execution of a script with provided parameters.
    This is for educational purposes and ensures safe execution in the web environment.
    """
    # Add a slight delay to simulate processing
    time.sleep(0.5)
    
    # Sanitize input parameters for security
    sanitized_params = {k: sanitize_input(v) for k, v in parameters.items()}
    
    # Handle different script types with appropriate simulated responses
    if script.title == 'Port Scanner':
        return simulate_port_scanner(sanitized_params)
    elif script.title == 'Hash Cracker':
        return simulate_hash_cracker(sanitized_params)
    elif script.title == 'SQL Injection Tester':
        return simulate_sql_injection_tester(sanitized_params)
    elif script.title == 'XSS Scanner':
        return simulate_xss_scanner(sanitized_params)
    elif script.title == 'IoT Device Scanner':
        return simulate_iot_scanner(sanitized_params)
    elif 'default_params' in sanitized_params:
        # For other tools, provide a generic educational demo
        return generate_generic_demo_output(script)
    else:
        return "This tool simulation is not yet implemented. Educational demo mode only."

def sanitize_input(value):
    """Sanitize user input to prevent security issues."""
    if isinstance(value, str):
        # Remove potentially dangerous characters
        return re.sub(r'[;<>|&$]', '', value)
    return value

def simulate_port_scanner(params):
    """Simulate port scanner execution with safe parameters."""
    target = params.get('target', 'localhost')
    ports_str = params.get('ports', '80,443,8080')
    
    # Restrict to safe targets
    safe_targets = ['localhost', '127.0.0.1', 'demo-server.local', 'test-target.example.com']
    if not any(target == safe_target or target.endswith('.example.com') for safe_target in safe_targets):
        target = 'demo-server.local'  # Redirect to a safe demo target
    
    # Parse ports
    try:
        if ',' in ports_str:
            ports = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]
        elif '-' in ports_str:
            start, end = ports_str.split('-')
            ports = list(range(int(start), int(end) + 1))
        else:
            ports = [int(ports_str)]
        
        # Limit number of ports for performance
        ports = ports[:20]
    except Exception:
        ports = [80, 443, 8080]
    
    # Simulate port scanning results
    results = []
    results.append(f"Starting port scan on target: {target}")
    results.append(f"Scanning {len(ports)} ports: {', '.join(map(str, ports))}")
    results.append("\nResults:")
    
    # Generate simulated results
    for port in ports:
        state = random.choice(['open', 'closed', 'filtered'] if port != 80 and port != 443 else ['open'])
        service = get_simulated_service(port)
        results.append(f"Port {port}: {state.upper()} - {service}")
    
    results.append("\nScan completed successfully.")
    return "\n".join(results)

def get_simulated_service(port):
    """Return a simulated service name for a given port."""
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        465: 'SMTPS',
        587: 'SMTP',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt'
    }
    return common_ports.get(port, 'Unknown')

def simulate_hash_cracker(params):
    """Simulate hash cracking with predefined educational examples."""
    hash_value = params.get('hash', '').lower()
    algorithm = params.get('algorithm', 'md5')
    
    # Educational hash examples
    educational_hashes = {
        '5f4dcc3b5aa765d61d8327deb882cf99': 'password',  # MD5
        'e10adc3949ba59abbe56e057f20f883e': '123456',    # MD5
        '098f6bcd4621d373cade4e832627b4f6': 'test',      # MD5
        '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8': 'password',  # SHA1
        '8cb2237d0679ca88db6464eac60da96345513964': '12345',     # SHA1
    }
    
    # Simulate the hash cracking process
    results = []
    results.append(f"Starting hash cracking simulation for: {hash_value}")
    results.append(f"Using algorithm: {algorithm.upper()}")
    results.append("\nAttempting dictionary attack...")
    
    # Simulate progress
    for i in range(3):
        results.append(f"Trying password list {i+1}... {random.randint(5000, 20000)} passwords checked")
    
    # Check if we have a match in our educational examples
    if hash_value in educational_hashes:
        password = educational_hashes[hash_value]
        results.append("\n[SUCCESS] Password found!")
        results.append(f"The hash {hash_value} corresponds to: {password}")
    else:
        results.append("\n[INFO] This is a simulation. In a real scenario, the cracking process could take minutes to years depending on:")
        results.append("- Hash algorithm strength")
        results.append("- Password complexity")
        results.append("- Computing resources available")
        results.append("\nFor educational purposes, try these example hashes:")
        results.append("- MD5 of 'password': 5f4dcc3b5aa765d61d8327deb882cf99")
        results.append("- MD5 of '123456': e10adc3949ba59abbe56e057f20f883e")
    
    return "\n".join(results)

def simulate_sql_injection_tester(params):
    """Simulate SQL injection testing on a demo target."""
    url = params.get('url', 'https://demo-target.com/login.php?id=1')
    
    # Ensure we're using a demo target
    if not url.startswith('https://demo-target.com'):
        url = 'https://demo-target.com/login.php?id=1'
    
    results = []
    results.append(f"Starting SQL injection vulnerability assessment on: {url}")
    results.append("\nTesting various injection payloads:")
    
    # Simulate injection tests
    payloads = [
        "id=1' OR '1'='1", 
        "id=1; DROP TABLE users", 
        "id=1 UNION SELECT username,password FROM users",
        "id=1' OR 1=1 --",
        "id=1') OR ('1'='1"
    ]
    
    for i, payload in enumerate(payloads):
        test_url = url.replace('id=1', payload)
        results.append(f"\n[Test {i+1}] Trying: {test_url}")
        
        # Simulate vulnerability detection for educational purposes
        if i == 0 or i == 3:  # Make some tests "find" vulnerabilities
            results.append("[VULNERABLE] The application responded with user data when it shouldn't")
            results.append("Sample response (simulated): \n  {\"status\":\"success\",\"data\":[{\"id\":1,\"name\":\"admin\"}]}")
        else:
            results.append("[SECURE] No vulnerability detected with this payload")
    
    results.append("\nEducational notes:")
    results.append("- Always use prepared statements to prevent SQL injection")
    results.append("- Validate and sanitize all user input")
    results.append("- Implement proper error handling to avoid leaking database information")
    results.append("- Use a Web Application Firewall (WAF) for additional protection")
    
    return "\n".join(results)

def simulate_xss_scanner(params):
    """Simulate XSS scanning on a demo target."""
    url = params.get('url', 'https://demo-target.com/search.php?q=test')
    
    # Ensure we're using a demo target
    if not url.startswith('https://demo-target.com'):
        url = 'https://demo-target.com/search.php?q=test'
    
    results = []
    results.append(f"Starting Cross-Site Scripting (XSS) vulnerability assessment on: {url}")
    results.append("\nTesting various XSS payloads:")
    
    # Simulate XSS tests
    payloads = [
        "<script>alert('XSS')</script>", 
        "<img src='x' onerror='alert(\"XSS\")'/>", 
        "<body onload='alert(\"XSS\")'></body>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')"
    ]
    
    for i, payload in enumerate(payloads):
        test_url = url.replace('q=test', f"q={payload}")
        results.append(f"\n[Test {i+1}] Trying: {payload}")
        
        # Simulate vulnerability detection for educational purposes
        if i == 1 or i == 3:  # Make some tests "find" vulnerabilities
            results.append("[VULNERABLE] The payload was reflected in the response without proper encoding")
            results.append(f"The application returned the payload in the HTML response:")
            results.append(f"  <div class='search-result'>Results for: {payload}</div>")
        else:
            results.append("[SECURE] Payload was properly sanitized or blocked")
    
    results.append("\nEducational notes:")
    results.append("- Always validate and sanitize user input")
    results.append("- Use context-appropriate encoding (HTML, JavaScript, CSS, URL)")
    results.append("- Implement Content Security Policy (CSP) headers")
    results.append("- Consider using modern frameworks that automatically escape output")
    results.append("- Use the HTTPOnly flag for sensitive cookies to prevent access from JavaScript")
    
    return "\n".join(results)

def simulate_iot_scanner(params):
    """Simulate IoT device scanning on a demo network."""
    network = params.get('network', '192.168.1.0/24')
    
    results = []
    results.append(f"Starting IoT device scan on network: {network}")
    results.append("Using simulated environment for educational purposes")
    results.append("\nDiscovering devices...")
    
    # Simulate device discovery
    devices = [
        {"ip": "192.168.1.10", "mac": "A1:B2:C3:D4:E5:F6", "manufacturer": "IoT Camera Co.", "type": "IP Camera"},
        {"ip": "192.168.1.15", "mac": "F1:E2:D3:C4:B5:A6", "manufacturer": "Smart Home Ltd.", "type": "Smart Speaker"},
        {"ip": "192.168.1.20", "mac": "11:22:33:44:55:66", "manufacturer": "Connect Devices Inc.", "type": "Smart Thermostat"},
        {"ip": "192.168.1.25", "mac": "AA:BB:CC:DD:EE:FF", "manufacturer": "Security Systems", "type": "Door Lock Controller"},
        {"ip": "192.168.1.30", "mac": "12:34:56:78:90:AB", "manufacturer": "Smart TV Corp.", "type": "Smart TV"}
    ]
    
    results.append(f"Found {len(devices)} IoT devices")
    
    # Show device details
    results.append("\nDevice Details:")
    for i, device in enumerate(devices):
        results.append(f"\n[Device {i+1}]")
        results.append(f"  IP Address: {device['ip']}")
        results.append(f"  MAC Address: {device['mac']}")
        results.append(f"  Manufacturer: {device['manufacturer']}")
        results.append(f"  Device Type: {device['type']}")
        
        # Add random open ports
        open_ports = random.sample(range(1, 10000), random.randint(2, 5))
        results.append(f"  Open Ports: {', '.join(map(str, sorted(open_ports)))}")
        
        # Add some vulnerabilities for educational purposes
        if i % 2 == 0:  # Add vulnerabilities to some devices
            vulns = random.sample([
                "Default credentials (admin/admin)",
                "Outdated firmware (v1.2.3)",
                "Telnet enabled on port 23",
                "Unencrypted HTTP management interface",
                "UPnP vulnerability CVE-2020-12345"
            ], 2)
            results.append(f"  Potential Vulnerabilities:")
            for vuln in vulns:
                results.append(f"    - {vuln}")
    
    results.append("\nEducational notes:")
    results.append("- Keep IoT device firmware updated")
    results.append("- Change default credentials")
    results.append("- Use network segmentation for IoT devices")
    results.append("- Disable unnecessary services (Telnet, UPnP, etc.)")
    results.append("- Monitor IoT device network traffic for anomalies")
    
    return "\n".join(results)

def generate_generic_demo_output(script):
    """Generate generic demo output for scripts without specific implementations."""
    results = []
    results.append(f"Educational demonstration for: {script.title}")
    results.append("This is a simulated output for educational purposes only.")
    results.append("\nTool Summary:")
    results.append(f"- Category: {script.category.name}")
    results.append(f"- Description: {script.description}")
    
    # Generate educational content based on category and tool name
    if script.category.name == 'Web Application Security':
        results.append("\nWeb Security Best Practices:")
        results.append("- Implement input validation and sanitization")
        results.append("- Use parameterized queries for database operations")
        results.append("- Apply the principle of least privilege")
        results.append("- Implement proper session management")
        results.append("- Use HTTPS for all communications")
        
        # Add specific content for certain web app security tools
        if "CSRF" in script.title:
            results.append("\nCSRF Prevention Techniques:")
            results.append("- Implement anti-CSRF tokens in forms")
            results.append("- Use SameSite cookies to limit cross-origin requests")
            results.append("- Verify the origin and referrer headers")
            results.append("- Apply custom headers for AJAX requests")
            results.append("- Implement CSRF protection at the framework level")
        elif "JWT" in script.title:
            results.append("\nJWT Security Best Practices:")
            results.append("- Use strong signing keys")
            results.append("- Implement proper algorithm selection (RS256 over HS256)")
            results.append("- Set appropriate expiration times")
            results.append("- Validate all claims, including 'aud' and 'iss'")
            results.append("- Implement token rotation and revocation mechanisms")
        elif "WAF" in script.title:
            results.append("\nWAF Bypass Prevention:")
            results.append("- Regularly update WAF rules")
            results.append("- Implement custom rules for specific applications")
            results.append("- Use multiple layers of security (defense in depth)")
            results.append("- Monitor WAF logs for potential bypass attempts")
            results.append("- Test WAF configurations against known bypass techniques")
            
    elif script.category.name == 'Network Security':
        results.append("\nNetwork Security Controls:")
        results.append("- Implement network segmentation")
        results.append("- Use firewalls and IDS/IPS")
        results.append("- Monitor network traffic for anomalies")
        results.append("- Encrypt sensitive data in transit")
        results.append("- Regularly scan for vulnerabilities")
        
        # Add specific content for certain network security tools
        if "ARP" in script.title:
            results.append("\nProtecting Against ARP Spoofing:")
            results.append("- Use static ARP entries for critical systems")
            results.append("- Implement ARP spoofing detection tools")
            results.append("- Use encrypted protocols (SSH, HTTPS, etc.)")
            results.append("- Use VLANs to limit the scope of ARP broadcasts")
            results.append("- Consider using Dynamic ARP Inspection (DAI) on switches")
        elif "DNS" in script.title:
            results.append("\nDNS Security Best Practices:")
            results.append("- Implement DNSSEC to verify DNS responses")
            results.append("- Use DNS over HTTPS (DoH) or DNS over TLS (DoT)")
            results.append("- Monitor for unexpected DNS queries")
            results.append("- Restrict zone transfers to authorized servers")
            results.append("- Use split-horizon DNS to limit internal information exposure")
        elif "Firewall" in script.title:
            results.append("\nFirewall Hardening Guidelines:")
            results.append("- Apply the principle of least privilege to rule sets")
            results.append("- Use stateful inspection for connection tracking")
            results.append("- Implement proper ingress and egress filtering")
            results.append("- Regularly audit and review firewall rules")
            results.append("- Consider using next-generation firewalls with application awareness")
            
    elif script.category.name == 'Cryptography':
        results.append("\nCryptographic Security Guidelines:")
        results.append("- Use strong, standardized algorithms")
        results.append("- Implement proper key management")
        results.append("- Never roll your own crypto")
        results.append("- Use sufficient key lengths")
        results.append("- Regularly rotate encryption keys")
        
        # Add specific content for certain cryptography tools
        if "Symmetric" in script.title:
            results.append("\nSymmetric Encryption Best Practices:")
            results.append("- Use AES-256 for strong encryption")
            results.append("- Implement secure key exchange mechanisms")
            results.append("- Use appropriate modes of operation (GCM, CBC with HMAC)")
            results.append("- Never reuse initialization vectors (IVs)")
            results.append("- Consider authenticated encryption modes")
        elif "Asymmetric" in script.title:
            results.append("\nAsymmetric Encryption Recommendations:")
            results.append("- Use RSA with at least 2048-bit keys")
            results.append("- Consider ECC for better performance with smaller keys")
            results.append("- Keep private keys securely stored")
            results.append("- Implement proper certificate validation")
            results.append("- Use forward secrecy in key exchange when possible")
        elif "Hash" in script.title and "Hash Cracker" not in script.title:
            results.append("\nSecure Hashing Guidelines:")
            results.append("- Use modern hash functions (SHA-256, SHA-3, BLAKE2)")
            results.append("- Always salt password hashes")
            results.append("- Implement key stretching (bcrypt, Argon2, PBKDF2)")
            results.append("- Verify hash integrity with HMACs when appropriate")
            results.append("- Don't use MD5 or SHA-1 for security purposes")
            
    elif script.category.name == 'Mobile Security':
        results.append("\nMobile Security Recommendations:")
        results.append("- Implement proper data encryption")
        results.append("- Use secure communication protocols")
        results.append("- Apply principle of least privilege for permissions")
        results.append("- Secure data storage and prevent leakage")
        results.append("- Implement proper authentication and session management")
        
        # Add specific content for certain mobile security tools
        if "APK" in script.title:
            results.append("\nAndroid App Security Best Practices:")
            results.append("- Implement proper ProGuard obfuscation")
            results.append("- Avoid hardcoded secrets in code")
            results.append("- Use Android Keystore for secure key storage")
            results.append("- Implement SSL pinning for network communications")
            results.append("- Properly validate intents and content providers")
        elif "iOS" in script.title:
            results.append("\niOS App Security Best Practices:")
            results.append("- Use App Transport Security (ATS)")
            results.append("- Implement proper Keychain usage")
            results.append("- Apply Data Protection API for secure storage")
            results.append("- Check for jailbreak detection")
            results.append("- Implement secure authentication mechanisms")
            
    elif script.category.name == 'IoT Security':
        results.append("\nIoT Security Best Practices:")
        results.append("- Change default credentials")
        results.append("- Keep firmware updated")
        results.append("- Use network segmentation for IoT devices")
        results.append("- Implement encrypted communications")
        results.append("- Apply the principle of least functionality")
        
        # Add specific content for certain IoT security tools
        if "Firmware" in script.title:
            results.append("\nIoT Firmware Security Guidelines:")
            results.append("- Implement secure boot mechanisms")
            results.append("- Sign firmware updates")
            results.append("- Use secure update processes")
            results.append("- Remove debug interfaces in production")
            results.append("- Encrypt sensitive sections of firmware")
        elif "Zigbee" in script.title or "BLE" in script.title:
            results.append("\nWireless IoT Security Recommendations:")
            results.append("- Use strong encryption for wireless communications")
            results.append("- Implement proper key management")
            results.append("- Apply frequency hopping when available")
            results.append("- Use the latest protocol security features")
            results.append("- Limit wireless range to what's necessary")
            
    elif script.category.name == 'Blockchain & Smart Contract Security':
        results.append("\nBlockchain Security Best Practices:")
        results.append("- Implement proper access controls")
        results.append("- Use secure key management")
        results.append("- Follow smart contract security patterns")
        results.append("- Conduct thorough security audits")
        results.append("- Monitor for unusual blockchain activities")
        
        # Add specific content for certain blockchain security tools
        if "Smart Contract" in script.title:
            results.append("\nSmart Contract Security Guidelines:")
            results.append("- Check for re-entrancy vulnerabilities")
            results.append("- Avoid integer overflow/underflow")
            results.append("- Implement proper access controls")
            results.append("- Use secure randomness sources")
            results.append("- Follow the checks-effects-interactions pattern")
        elif "Wallet" in script.title:
            results.append("\nCrypto Wallet Security Recommendations:")
            results.append("- Use hardware wallets for large holdings")
            results.append("- Implement multi-signature requirements")
            results.append("- Secure private key storage")
            results.append("- Use hierarchical deterministic wallets")
            results.append("- Regularly verify wallet code integrity")
            
    elif script.category.name == 'Malware Analysis & Forensics':
        results.append("\nMalware Analysis Best Practices:")
        results.append("- Use isolated analysis environments")
        results.append("- Implement proper containment procedures")
        results.append("- Document all findings thoroughly")
        results.append("- Use both static and dynamic analysis")
        results.append("- Establish proper malware sample handling")
        
        # Add specific content for certain malware analysis tools
        if "YARA" in script.title:
            results.append("\nYARA Rule Development Guidelines:")
            results.append("- Create specific rules to minimize false positives")
            results.append("- Use multiple condition sections for complex detection")
            results.append("- Include metadata for rule identification")
            results.append("- Test rules against known benign samples")
            results.append("- Share rules with the security community when appropriate")
        elif "Memory" in script.title:
            results.append("\nMemory Forensics Recommendations:")
            results.append("- Capture memory as early as possible")
            results.append("- Use write blockers for forensically sound acquisition")
            results.append("- Look for process injection techniques")
            results.append("- Analyze the process list for anomalies")
            results.append("- Check for rootkit indicators in memory structures")
            
    elif script.category.name == 'Red Team Toolkit':
        results.append("\nRed Team Operation Guidelines:")
        results.append("- Establish clear scope and rules of engagement")
        results.append("- Maintain detailed documentation")
        results.append("- Use secure communications channels")
        results.append("- Implement proper safeguards to prevent damage")
        results.append("- Provide actionable remediation recommendations")
        
        # Add specific content for certain red team tools
        if "Phishing" in script.title:
            results.append("\nEthical Phishing Simulation Guidelines:")
            results.append("- Obtain proper authorization")
            results.append("- Define clear objectives and success metrics")
            results.append("- Provide immediate education for users who fall victim")
            results.append("- Avoid overly personal or sensitive lures")
            results.append("- Follow up with training and awareness programs")
        elif "Shell" in script.title or "Payload" in script.title:
            results.append("\nPayload Development Security Considerations:")
            results.append("- Use encryption for command and control")
            results.append("- Implement timeout and self-termination features")
            results.append("- Avoid destructive testing without explicit approval")
            results.append("- Document all deployed payloads")
            results.append("- Ensure complete removal at the end of testing")
            
    elif script.category.name == 'Blue Team Toolkit':
        results.append("\nBlue Team Defense Strategies:")
        results.append("- Implement defense in depth")
        results.append("- Maintain comprehensive logging")
        results.append("- Develop and test incident response plans")
        results.append("- Conduct regular security assessments")
        results.append("- Keep systems and applications updated")
        
        # Add specific content for certain blue team tools
        if "Log" in script.title:
            results.append("\nLog Management Best Practices:")
            results.append("- Centralize log collection")
            results.append("- Implement proper log retention policies")
            results.append("- Set up automated alerting for suspicious events")
            results.append("- Ensure log integrity and tamper protection")
            results.append("- Regularly review and analyze logs")
        elif "Honeypot" in script.title:
            results.append("\nHoneypot Deployment Guidelines:")
            results.append("- Make honeypots appear realistic")
            results.append("- Isolate honeypots from production networks")
            results.append("- Implement extensive monitoring")
            results.append("- Analyze captured attack techniques")
            results.append("- Use deception technology strategically")
            
    elif script.category.name == 'Social Engineering':
        results.append("\nSocial Engineering Defense Strategies:")
        results.append("- Implement security awareness training")
        results.append("- Develop verification procedures for sensitive requests")
        results.append("- Create a culture of security consciousness")
        results.append("- Implement technical controls to supplement training")
        results.append("- Regularly test defenses with authorized simulations")
        
        # Add specific content for certain social engineering tools
        if "Email" in script.title:
            results.append("\nEmail Security Best Practices:")
            results.append("- Implement SPF, DKIM, and DMARC")
            results.append("- Use email filtering and scanning")
            results.append("- Train users to identify phishing attempts")
            results.append("- Develop procedures for reporting suspicious emails")
            results.append("- Use email authentication for sensitive communications")
        elif "Social Media" in script.title:
            results.append("\nSocial Media Security Guidelines:")
            results.append("- Limit information shared on public profiles")
            results.append("- Verify connection requests before accepting")
            results.append("- Use strong, unique passwords for each platform")
            results.append("- Enable two-factor authentication")
            results.append("- Be cautious of third-party applications")
            
    elif script.category.name == 'Password Cracking':
        results.append("\nPassword Security Recommendations:")
        results.append("- Use long, complex, unique passwords")
        results.append("- Implement multi-factor authentication")
        results.append("- Use secure password hashing algorithms")
        results.append("- Apply proper account lockout policies")
        results.append("- Regularly audit password policies and strength")
        
        # Add specific content for certain password cracking tools
        if "Dictionary" in script.title:
            results.append("\nProtecting Against Dictionary Attacks:")
            results.append("- Avoid common words and phrases in passwords")
            results.append("- Implement rate limiting on authentication attempts")
            results.append("- Use salted password hashing")
            results.append("- Consider password complexity requirements")
            results.append("- Implement account lockout after failed attempts")
        elif "Rainbow" in script.title:
            results.append("\nRainbow Table Attack Prevention:")
            results.append("- Use unique salts for each password hash")
            results.append("- Implement key stretching algorithms")
            results.append("- Use modern hashing algorithms (bcrypt, Argon2)")
            results.append("- Increase computational cost of password verification")
            results.append("- Regularly update password hashing mechanisms")
            
    elif script.category.name == 'Cloud & Container Security':
        results.append("\nCloud Security Best Practices:")
        results.append("- Implement the principle of least privilege")
        results.append("- Use multi-factor authentication")
        results.append("- Encrypt sensitive data at rest and in transit")
        results.append("- Maintain proper configuration management")
        results.append("- Regularly audit access and permissions")
        
        # Add specific content for certain cloud security tools
        if "AWS" in script.title or "S3" in script.title:
            results.append("\nAWS Security Recommendations:")
            results.append("- Use AWS CloudTrail for comprehensive logging")
            results.append("- Implement proper IAM policies and roles")
            results.append("- Secure S3 buckets with appropriate permissions")
            results.append("- Use VPC security groups and NACLs effectively")
            results.append("- Enable AWS GuardDuty for threat detection")
        elif "Docker" in script.title or "Container" in script.title:
            results.append("\nContainer Security Guidelines:")
            results.append("- Use minimal base images")
            results.append("- Scan containers for vulnerabilities")
            results.append("- Never run containers as root")
            results.append("- Implement proper network segmentation")
            results.append("- Use read-only file systems when possible")
            
    elif script.category.name == 'Hardware & Firmware Hacking':
        results.append("\nHardware Security Recommendations:")
        results.append("- Implement secure boot mechanisms")
        results.append("- Use hardware security modules for cryptographic operations")
        results.append("- Apply physical security controls")
        results.append("- Protect debug and test interfaces")
        results.append("- Implement anti-tampering mechanisms")
        
        # Add specific content for certain hardware security tools
        if "Firmware" in script.title:
            results.append("\nFirmware Security Best Practices:")
            results.append("- Implement secure update mechanisms")
            results.append("- Sign firmware with strong cryptographic signatures")
            results.append("- Use secure boot to verify firmware integrity")
            results.append("- Implement proper key management for firmware signing")
            results.append("- Remove debug capabilities in production")
        elif "JTAG" in script.title or "Serial" in script.title:
            results.append("\nDebug Interface Security Guidelines:")
            results.append("- Disable or physically remove debug interfaces in production")
            results.append("- Implement authentication for debug access")
            results.append("- Use fuse bits to permanently disable debug features")
            results.append("- Monitor for unexpected debug activity")
            results.append("- Implement side-channel attack protections")
            
    elif script.category.name == 'Industrial Control Systems (ICS/SCADA)':
        results.append("\nICS/SCADA Security Best Practices:")
        results.append("- Implement network segmentation and air-gapping")
        results.append("- Use unidirectional security gateways when possible")
        results.append("- Apply defense in depth strategies")
        results.append("- Develop and test incident response procedures")
        results.append("- Regularly assess and patch systems")
        
        # Add specific content for certain ICS security tools
        if "Modbus" in script.title or "Protocol" in script.title:
            results.append("\nIndustrial Protocol Security Recommendations:")
            results.append("- Implement protocol-aware monitoring")
            results.append("- Use authenticated and encrypted protocols when available")
            results.append("- Monitor for unusual command sequences")
            results.append("- Implement proper access controls")
            results.append("- Validate protocol inputs and commands")
        elif "PLC" in script.title or "SCADA" in script.title:
            results.append("\nPLC and SCADA Security Guidelines:")
            results.append("- Change default credentials")
            results.append("- Implement access control lists")
            results.append("- Regularly backup configurations")
            results.append("- Monitor for unauthorized changes")
            results.append("- Use secure remote access methods")
            
    elif script.category.name == 'Bluetooth & RF Hacking':
        results.append("\nWireless Security Best Practices:")
        results.append("- Implement proper encryption")
        results.append("- Use strong authentication mechanisms")
        results.append("- Regularly update firmware")
        results.append("- Monitor for unauthorized devices")
        results.append("- Implement proper pairing procedures")
        
        # Add specific content for certain wireless security tools
        if "BLE" in script.title:
            results.append("\nBluetooth Low Energy Security Recommendations:")
            results.append("- Use LE Secure Connections pairing")
            results.append("- Implement proper key management")
            results.append("- Consider privacy features like address randomization")
            results.append("- Validate GATT client authentication")
            results.append("- Minimize sensitive information in advertising packets")
        elif "RF" in script.title or "Radio" in script.title:
            results.append("\nRF Security Guidelines:")
            results.append("- Use frequency hopping when available")
            results.append("- Implement proper encryption of the radio channel")
            results.append("- Minimize transmission power to reduce range")
            results.append("- Use directional antennas when appropriate")
            results.append("- Consider jamming detection and resilience")
    else:
        results.append("\nSecurity Fundamentals:")
        results.append("- Apply defense in depth")
        results.append("- Follow the principle of least privilege")
        results.append("- Regularly update and patch systems")
        results.append("- Educate users on security practices")
        results.append("- Perform regular security assessments")
    
    # Add a demo section to show what the tool would do
    results.append("\n[DEMO OUTPUT]")
    results.append(f"Running {script.title} simulation...")
    results.append(f"Target: demo-system.example.com")
    results.append(f"Parameters: Default educational settings")
    results.append(f"Scan time: {random.randint(5, 60)} seconds")
    results.append(f"Results: Educational demonstration complete")
    
    return "\n".join(results)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html', error=str(e)), 500

# Initialize the database with script categories and scripts
# Flask 2.0+ removed before_first_request, using with_appcontext instead
def initialize_database():
    """Populate the database with categories and scripts if empty."""
    if Category.query.count() == 0:
        logger.info("Initializing database with categories and scripts")
        
        # Create categories
        categories = {
            'web_application': Category(
                name='Web Application Security',
                description='Scripts for testing web applications for vulnerabilities',
                icon='globe'
            ),
            'network': Category(
                name='Network Security',
                description='Tools for network reconnaissance and security testing',
                icon='wifi'
            ),
            'iot': Category(
                name='IoT Security',
                description='Internet of Things security testing tools',
                icon='cpu'
            ),
            'crypto': Category(
                name='Cryptography',
                description='Tools for cryptographic analysis and attacks',
                icon='lock'
            ),
            'mobile': Category(
                name='Mobile Security',
                description='Tools for testing and analyzing mobile applications',
                icon='mobile-alt'
            ),
            'cloud': Category(
                name='Cloud & Container Security',
                description='Security tools for cloud services and container environments',
                icon='cloud'
            ),
            'blockchain': Category(
                name='Blockchain & Smart Contract Security',
                description='Tools for analyzing blockchain networks and smart contracts',
                icon='link'
            ),
            'ics': Category(
                name='Industrial Control Systems (ICS/SCADA)',
                description='Security testing tools for industrial systems and SCADA networks',
                icon='industry'
            ),
            'hardware': Category(
                name='Hardware & Firmware Hacking',
                description='Tools for analyzing and testing hardware devices and firmware',
                icon='microchip'
            ),
            'bluetooth': Category(
                name='Bluetooth & RF Hacking',
                description='Tools for analyzing and testing wireless communications',
                icon='bluetooth'
            ),
            'malware': Category(
                name='Malware Analysis & Forensics',
                description='Tools for analyzing malicious software and digital forensics',
                icon='bug'
            ),
            'redteam': Category(
                name='Red Team Toolkit',
                description='Tools for offensive security testing and red team exercises',
                icon='user-secret'
            ),
            'blueteam': Category(
                name='Blue Team Toolkit',
                description='Tools for defensive security monitoring and incident response',
                icon='shield-alt'
            ),
            'social': Category(
                name='Social Engineering',
                description='Tools for testing human-focused security vulnerabilities',
                icon='users'
            ),
            'password': Category(
                name='Password Cracking',
                description='Tools for testing password security and hash cracking',
                icon='key'
            )
        }
        
        # Add categories to the database
        for category in categories.values():
            db.session.add(category)
        
        db.session.commit()

        # Create scripts - IoT Security
        iot_scripts = [
            Script(
                title='IoT Device Scanner',
                description='A tool to discover and fingerprint IoT devices on a network',
                module_path='scripts.iot.iot_device_scanner',
                category_id=categories['iot'].id
            ),
            Script(
                title='IoT Device Fingerprinting',
                description='Tool to identify and classify IoT devices based on network traffic patterns',
                module_path='scripts.iot.iot_device_fingerprinting',
                category_id=categories['iot'].id
            ),
            Script(
                title='IoT Protocol Scanner',
                description='Scanner for detecting common IoT protocols like MQTT and CoAP',
                module_path='scripts.iot.iot_protocol_scanner',
                category_id=categories['iot'].id
            ),
            Script(
                title='Smart TV Traffic Analyzer',
                description='Tool to capture and analyze network traffic from Smart TVs',
                module_path='scripts.iot.smart_tv_analyzer',
                category_id=categories['iot'].id
            ),
            Script(
                title='Default Credentials Auditor',
                description='Tool to check IoT devices for default login credentials',
                module_path='scripts.iot.default_credentials_auditor',
                category_id=categories['iot'].id
            )
        ]
        
        # Web Application Security scripts
        web_scripts = [
            Script(
                title='SQL Injection Tester',
                description='A tool to test web applications for SQL injection vulnerabilities',
                module_path='scripts.web_application.sql_injection_tester',
                category_id=categories['web_application'].id
            ),
            Script(
                title='XSS Scanner',
                description='A scanner for Cross-Site Scripting vulnerabilities in web applications',
                module_path='scripts.web_application.xss_scanner',
                category_id=categories['web_application'].id
            ),
            Script(
                title='CSRF Exploit Simulator',
                description='Simulator for Cross-Site Request Forgery attacks',
                module_path='scripts.web_application.csrf_simulator',
                category_id=categories['web_application'].id
            ),
            Script(
                title='Directory Traversal Scanner',
                description='Tool to test for directory traversal vulnerabilities',
                module_path='scripts.web_application.directory_traversal_scanner',
                category_id=categories['web_application'].id
            ),
            Script(
                title='HTTP Header Security Checker',
                description='Analyzer for HTTP security headers',
                module_path='scripts.web_application.header_security_checker',
                category_id=categories['web_application'].id
            )
        ]
        
        # Network Security scripts
        network_scripts = [
            Script(
                title='Port Scanner',
                description='A tool to scan for open ports on network hosts',
                module_path='scripts.network.port_scanner',
                category_id=categories['network'].id
            ),
            Script(
                title='Packet Sniffer',
                description='A network packet capture and analysis tool',
                module_path='scripts.network.packet_sniffer',
                category_id=categories['network'].id
            ),
            Script(
                title='ARP Spoofing Tool',
                description='Tool for ARP spoofing attack simulation',
                module_path='scripts.network.arp_spoofer',
                category_id=categories['network'].id
            ),
            Script(
                title='DNS Spoofing Simulator',
                description='Simulator for DNS spoofing attacks',
                module_path='scripts.network.dns_spoofer',
                category_id=categories['network'].id
            ),
            Script(
                title='Network Vulnerability Scanner',
                description='Network-wide vulnerability scanning tool',
                module_path='scripts.network.network_vulnerability_scanner',
                category_id=categories['network'].id
            )
        ]
        
        # Cryptography scripts
        crypto_scripts = [
            Script(
                title='Hash Cracker',
                description='A tool to attempt cracking password hashes using various methods',
                module_path='scripts.cryptography.hash_cracker',
                category_id=categories['crypto'].id
            ),
            Script(
                title='Symmetric Encryption Tool',
                description='Tool for symmetric encryption and decryption',
                module_path='scripts.cryptography.symmetric_encryption',
                category_id=categories['crypto'].id
            ),
            Script(
                title='Asymmetric Encryption Tool',
                description='Tool for asymmetric encryption and decryption',
                module_path='scripts.cryptography.asymmetric_encryption',
                category_id=categories['crypto'].id
            ),
            Script(
                title='Digital Signature Verifier',
                description='Tool to verify digital signatures',
                module_path='scripts.cryptography.digital_signature_verifier',
                category_id=categories['crypto'].id
            ),
            Script(
                title='Cryptanalysis Tool',
                description='Tool for basic cryptanalysis techniques',
                module_path='scripts.cryptography.cryptanalysis_tool',
                category_id=categories['crypto'].id
            )
        ]
        
        # Mobile Security scripts
        mobile_scripts = [
            Script(
                title='Android APK Analyzer',
                description='Tool to analyze Android APK files for security issues',
                module_path='scripts.mobile.apk_analyzer',
                category_id=categories['mobile'].id
            ),
            Script(
                title='iOS App Bundle Inspector',
                description='Inspector for iOS application bundles',
                module_path='scripts.mobile.ios_app_inspector',
                category_id=categories['mobile'].id
            ),
            Script(
                title='Mobile App Static Analyzer',
                description='Static code analysis tool for mobile applications',
                module_path='scripts.mobile.static_analyzer',
                category_id=categories['mobile'].id
            ),
            Script(
                title='SSL Pinning Bypass Emulator',
                description='Tool to demonstrate SSL pinning bypass techniques',
                module_path='scripts.mobile.ssl_pinning_bypass',
                category_id=categories['mobile'].id
            ),
            Script(
                title='Mobile App Activity Logger',
                description='Tool for logging mobile application activities',
                module_path='scripts.mobile.app_activity_logger',
                category_id=categories['mobile'].id
            )
        ]
        
        # Cloud & Container Security scripts
        cloud_scripts = [
            Script(
                title='AWS Misconfiguration Scanner',
                description='Scanner for AWS security misconfigurations',
                module_path='scripts.cloud.aws_misconfig_scanner',
                category_id=categories['cloud'].id
            ),
            Script(
                title='S3 Bucket Enum & Access Tester',
                description='Tool to enumerate S3 buckets and test access permissions',
                module_path='scripts.cloud.s3_bucket_tester',
                category_id=categories['cloud'].id
            ),
            Script(
                title='Docker Image Malware Scanner',
                description='Scanner for malware in Docker container images',
                module_path='scripts.cloud.docker_malware_scanner',
                category_id=categories['cloud'].id
            ),
            Script(
                title='Kubernetes Pod Escalation Tester',
                description='Tool to test privilege escalation in Kubernetes pods',
                module_path='scripts.cloud.k8s_pod_escalation',
                category_id=categories['cloud'].id
            ),
            Script(
                title='IAM Policy Analyzer',
                description='Analyzer for IAM policies and permissions',
                module_path='scripts.cloud.iam_policy_analyzer',
                category_id=categories['cloud'].id
            )
        ]
        
        # Blockchain & Smart Contract Security scripts
        blockchain_scripts = [
            Script(
                title='Solidity Static Analyzer',
                description='Static analysis tool for Solidity smart contracts',
                module_path='scripts.blockchain.solidity_analyzer',
                category_id=categories['blockchain'].id
            ),
            Script(
                title='Smart Contract Fuzzer',
                description='Fuzzing tool for smart contract testing',
                module_path='scripts.blockchain.smart_contract_fuzzer',
                category_id=categories['blockchain'].id
            ),
            Script(
                title='Re-entrancy Attack Emulator',
                description='Tool to demonstrate re-entrancy attacks on smart contracts',
                module_path='scripts.blockchain.reentrancy_emulator',
                category_id=categories['blockchain'].id
            ),
            Script(
                title='Wallet Address Analyzer',
                description='Tool for analyzing cryptocurrency wallet addresses',
                module_path='scripts.blockchain.wallet_analyzer',
                category_id=categories['blockchain'].id
            ),
            Script(
                title='Token Approval Analyzer',
                description='Tool to analyze token approvals in Ethereum contracts',
                module_path='scripts.blockchain.token_approval_analyzer',
                category_id=categories['blockchain'].id
            )
        ]
        
        # ICS/SCADA scripts
        ics_scripts = [
            Script(
                title='Modbus Packet Injector',
                description='Tool for Modbus protocol packet injection',
                module_path='scripts.ics.modbus_injector',
                category_id=categories['ics'].id
            ),
            Script(
                title='SCADA Device Scanner',
                description='Scanner for SCADA devices on industrial networks',
                module_path='scripts.ics.scada_scanner',
                category_id=categories['ics'].id
            ),
            Script(
                title='DNP3 Protocol Inspector',
                description='Inspector for DNP3 protocol communications',
                module_path='scripts.ics.dnp3_inspector',
                category_id=categories['ics'].id
            ),
            Script(
                title='ICS Network Mapper',
                description='Tool for mapping industrial control system networks',
                module_path='scripts.ics.ics_network_mapper',
                category_id=categories['ics'].id
            ),
            Script(
                title='PLC Command Logger',
                description='Tool for logging PLC commands and operations',
                module_path='scripts.ics.plc_command_logger',
                category_id=categories['ics'].id
            )
        ]
        
        # Hardware & Firmware scripts
        hardware_scripts = [
            Script(
                title='Firmware Bin Extractor',
                description='Tool to extract contents from firmware binary files',
                module_path='scripts.hardware.firmware_extractor',
                category_id=categories['hardware'].id
            ),
            Script(
                title='Serial Port Sniffer',
                description='Sniffer for serial port communications',
                module_path='scripts.hardware.serial_port_sniffer',
                category_id=categories['hardware'].id
            ),
            Script(
                title='BIOS Firmware Scanner',
                description='Scanner for BIOS firmware vulnerabilities',
                module_path='scripts.hardware.bios_scanner',
                category_id=categories['hardware'].id
            ),
            Script(
                title='Bootloader Fingerprinter',
                description='Tool to fingerprint device bootloaders',
                module_path='scripts.hardware.bootloader_fingerprinter',
                category_id=categories['hardware'].id
            ),
            Script(
                title='EEPROM Data Decoder',
                description='Tool for decoding EEPROM data',
                module_path='scripts.hardware.eeprom_decoder',
                category_id=categories['hardware'].id
            )
        ]
        
        # Bluetooth & RF scripts
        bluetooth_scripts = [
            Script(
                title='BLE Packet Analyzer',
                description='Analyzer for Bluetooth Low Energy packets',
                module_path='scripts.bluetooth.ble_packet_analyzer',
                category_id=categories['bluetooth'].id
            ),
            Script(
                title='Bluetooth Device Tracker',
                description='Tool for tracking Bluetooth devices',
                module_path='scripts.bluetooth.bluetooth_tracker',
                category_id=categories['bluetooth'].id
            ),
            Script(
                title='BLE GATT Enumerator',
                description='Tool to enumerate BLE GATT services and characteristics',
                module_path='scripts.bluetooth.ble_gatt_enumerator',
                category_id=categories['bluetooth'].id
            ),
            Script(
                title='Bluetooth Profile Scanner',
                description='Scanner for Bluetooth device profiles',
                module_path='scripts.bluetooth.profile_scanner',
                category_id=categories['bluetooth'].id
            ),
            Script(
                title='BLE Advertising Sniffer',
                description='Sniffer for BLE advertising packets',
                module_path='scripts.bluetooth.ble_advertising_sniffer',
                category_id=categories['bluetooth'].id
            )
        ]
        
        # Malware Analysis scripts
        malware_scripts = [
            Script(
                title='Static Malware Classifier',
                description='Tool for classifying malware samples based on static features',
                module_path='scripts.malware.static_classifier',
                category_id=categories['malware'].id
            ),
            Script(
                title='Suspicious String Extractor',
                description='Tool to extract suspicious strings from binaries',
                module_path='scripts.malware.string_extractor',
                category_id=categories['malware'].id
            ),
            Script(
                title='YARA Rule Generator',
                description='Assistant for creating YARA rules for malware detection',
                module_path='scripts.malware.yara_generator',
                category_id=categories['malware'].id
            ),
            Script(
                title='PE File Structure Visualizer',
                description='Tool to visualize PE file structures',
                module_path='scripts.malware.pe_visualizer',
                category_id=categories['malware'].id
            ),
            Script(
                title='IOC Extractor Tool',
                description='Tool to extract Indicators of Compromise',
                module_path='scripts.malware.ioc_extractor',
                category_id=categories['malware'].id
            )
        ]
        
        # Red Team scripts
        redteam_scripts = [
            Script(
                title='Phishing Simulation Template',
                description='Templates for phishing simulation campaigns',
                module_path='scripts.redteam.phishing_template',
                category_id=categories['redteam'].id
            ),
            Script(
                title='Reverse Shell Generator',
                description='Generator for reverse shell payloads',
                module_path='scripts.redteam.reverse_shell_generator',
                category_id=categories['redteam'].id
            ),
            Script(
                title='Password Spraying Tool',
                description='Tool for password spraying attacks',
                module_path='scripts.redteam.password_spraying',
                category_id=categories['redteam'].id
            ),
            Script(
                title='Custom Wordlist Generator',
                description='Tool for generating custom wordlists for password attacks',
                module_path='scripts.redteam.wordlist_generator',
                category_id=categories['redteam'].id
            ),
            Script(
                title='Red Team Report Generator',
                description='Tool for generating red team exercise reports',
                module_path='scripts.redteam.report_generator',
                category_id=categories['redteam'].id
            )
        ]
        
        # Blue Team scripts
        blueteam_scripts = [
            Script(
                title='Log Collector & Analyzer',
                description='Tool for collecting and analyzing log data',
                module_path='scripts.blueteam.log_analyzer',
                category_id=categories['blueteam'].id
            ),
            Script(
                title='Honeypot Deployment Template',
                description='Template for setting up security honeypots',
                module_path='scripts.blueteam.honeypot_template',
                category_id=categories['blueteam'].id
            ),
            Script(
                title='Incident Report Auto-Generator',
                description='Tool for generating security incident reports',
                module_path='scripts.blueteam.incident_report_generator',
                category_id=categories['blueteam'].id
            ),
            Script(
                title='Endpoint Scanner',
                description='Security scanner for endpoint devices',
                module_path='scripts.blueteam.endpoint_scanner',
                category_id=categories['blueteam'].id
            ),
            Script(
                title='Log4Shell Detection Script',
                description='Tool for detecting Log4Shell vulnerability',
                module_path='scripts.blueteam.log4shell_detector',
                category_id=categories['blueteam'].id
            )
        ]
        
        # Social Engineering scripts
        social_scripts = [
            Script(
                title='Phishing Email Generator',
                description='Generator for educational phishing email templates',
                module_path='scripts.social.phishing_email_generator',
                category_id=categories['social'].id
            ),
            Script(
                title='Social Media Scraper',
                description='Tool for collecting public social media information',
                module_path='scripts.social.social_media_scraper',
                category_id=categories['social'].id
            ),
            Script(
                title='LinkedIn Recon Script',
                description='Tool for collecting public LinkedIn information',
                module_path='scripts.social.linkedin_recon',
                category_id=categories['social'].id
            ),
            Script(
                title='Email Header Analyzer',
                description='Tool for analyzing email headers',
                module_path='scripts.social.email_header_analyzer',
                category_id=categories['social'].id
            ),
            Script(
                title='Social Engineering Awareness Quiz',
                description='Quiz generator for social engineering awareness',
                module_path='scripts.social.awareness_quiz',
                category_id=categories['social'].id
            )
        ]
        
        # Password Cracking scripts
        password_scripts = [
            Script(
                title='Dictionary Attack Tool',
                description='Tool for performing dictionary attacks on password hashes',
                module_path='scripts.password.dictionary_attack',
                category_id=categories['password'].id
            ),
            Script(
                title='Rainbow Table Generator',
                description='Generator for password rainbow tables',
                module_path='scripts.password.rainbow_table_generator',
                category_id=categories['password'].id
            ),
            Script(
                title='Password Strength Analyzer',
                description='Tool for analyzing password strength',
                module_path='scripts.password.strength_analyzer',
                category_id=categories['password'].id
            ),
            Script(
                title='Password Policy Tester',
                description='Tool for testing password policy compliance',
                module_path='scripts.password.policy_tester',
                category_id=categories['password'].id
            ),
            Script(
                title='Hash Cracker',
                description='A tool to attempt cracking password hashes using various methods',
                module_path='scripts.cryptography.hash_cracker',
                category_id=categories['password'].id
            )
        ]
        
        # Combine all scripts
        all_scripts = (
            iot_scripts + web_scripts + network_scripts + crypto_scripts + 
            mobile_scripts + cloud_scripts + blockchain_scripts + ics_scripts + 
            hardware_scripts + bluetooth_scripts + malware_scripts + 
            redteam_scripts + blueteam_scripts + social_scripts + password_scripts
        )
        
        # Add scripts to the database
        for script in all_scripts:
            db.session.add(script)
        
        db.session.commit()
        logger.info("Database initialization completed")
