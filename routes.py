import os
import importlib
import inspect
import logging
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
