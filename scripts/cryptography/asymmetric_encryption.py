"""
Asymmetric Encryption Tool

This script provides tools for asymmetric (public-key) encryption and decryption, digital
signatures, key generation, and related cryptographic operations. It supports RSA and ECC
algorithms with various key sizes and demonstrates secure asymmetric cryptography practices.

This tool is intended for educational purposes and to demonstrate secure cryptographic
implementations.
"""

import os
import base64
import argparse
import json
import time
import logging
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, utils as crypto_utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AsymmetricEncryptionTool:
    """Tool for asymmetric encryption, decryption, and signature operations."""
    
    def __init__(self):
        """Initialize the asymmetric encryption tool."""
        pass
    
    def generate_rsa_key_pair(self, key_size=2048, password=None):
        """
        Generate an RSA key pair.
        
        Parameters:
        -----------
        key_size : int
            Size of the RSA key in bits
        password : str, optional
            Password to encrypt the private key
            
        Returns:
        --------
        tuple:
            (private_key, public_key) as PEM-encoded strings
        """
        # Validate key size
        if key_size < 2048:
            logger.warning("RSA key size less than 2048 bits is not recommended for security")
            
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
            
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        ).decode('utf-8')
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    def generate_ec_key_pair(self, curve=ec.SECP256R1(), password=None):
        """
        Generate an Elliptic Curve key pair.
        
        Parameters:
        -----------
        curve : ec.EllipticCurve
            The elliptic curve to use
        password : str, optional
            Password to encrypt the private key
            
        Returns:
        --------
        tuple:
            (private_key, public_key) as PEM-encoded strings
        """
        # Generate private key
        private_key = ec.generate_private_key(curve)
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
            
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        ).decode('utf-8')
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    def rsa_encrypt(self, public_key_pem, plaintext):
        """
        Encrypt data using RSA public key.
        
        Parameters:
        -----------
        public_key_pem : str
            PEM-encoded RSA public key
        plaintext : str
            Data to encrypt
            
        Returns:
        --------
        str:
            Base64-encoded encrypted data
        """
        # Load public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        # RSA can only encrypt limited data size based on key size
        # For larger data, hybrid encryption (symmetric + asymmetric) should be used
        # Here we demonstrate direct RSA encryption for small data
        
        # Encrypt data
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Encode to base64 for easy storage/transmission
        encoded = base64.b64encode(ciphertext).decode('utf-8')
        return encoded
    
    def rsa_decrypt(self, private_key_pem, ciphertext_b64, password=None):
        """
        Decrypt data using RSA private key.
        
        Parameters:
        -----------
        private_key_pem : str
            PEM-encoded RSA private key
        ciphertext_b64 : str
            Base64-encoded encrypted data
        password : str, optional
            Password to decrypt the private key
            
        Returns:
        --------
        str:
            Decrypted plaintext
        """
        # Decode base64
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Load private key
        if password:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=password.encode()
            )
        else:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
        
        # Decrypt data
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode('utf-8')
        
        return plaintext
    
    def rsa_sign(self, private_key_pem, message, password=None):
        """
        Sign a message using RSA private key.
        
        Parameters:
        -----------
        private_key_pem : str
            PEM-encoded RSA private key
        message : str
            Message to sign
        password : str, optional
            Password to decrypt the private key
            
        Returns:
        --------
        str:
            Base64-encoded signature
        """
        # Load private key
        if password:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=password.encode()
            )
        else:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
        
        # Sign the message
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Encode to base64
        encoded = base64.b64encode(signature).decode('utf-8')
        return encoded
    
    def rsa_verify(self, public_key_pem, message, signature_b64):
        """
        Verify a signature using RSA public key.
        
        Parameters:
        -----------
        public_key_pem : str
            PEM-encoded RSA public key
        message : str
            Original message
        signature_b64 : str
            Base64-encoded signature
            
        Returns:
        --------
        bool:
            True if signature is valid, False otherwise
        """
        # Load public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        # Decode signature
        signature = base64.b64decode(signature_b64)
        
        # Verify signature
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def ec_sign(self, private_key_pem, message, password=None):
        """
        Sign a message using EC private key.
        
        Parameters:
        -----------
        private_key_pem : str
            PEM-encoded EC private key
        message : str
            Message to sign
        password : str, optional
            Password to decrypt the private key
            
        Returns:
        --------
        str:
            Base64-encoded signature
        """
        # Load private key
        if password:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=password.encode()
            )
        else:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
        
        # Sign the message
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        
        # Encode to base64
        encoded = base64.b64encode(signature).decode('utf-8')
        return encoded
    
    def ec_verify(self, public_key_pem, message, signature_b64):
        """
        Verify a signature using EC public key.
        
        Parameters:
        -----------
        public_key_pem : str
            PEM-encoded EC public key
        message : str
            Original message
        signature_b64 : str
            Base64-encoded signature
            
        Returns:
        --------
        bool:
            True if signature is valid, False otherwise
        """
        # Load public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        # Decode signature
        signature = base64.b64decode(signature_b64)
        
        # Verify signature
        try:
            public_key.verify(
                signature,
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
    
    def save_keys_to_file(self, private_key, public_key, private_key_path, public_key_path):
        """
        Save key pair to files.
        
        Parameters:
        -----------
        private_key : str
            PEM-encoded private key
        public_key : str
            PEM-encoded public key
        private_key_path : str
            Path to save private key
        public_key_path : str
            Path to save public key
            
        Returns:
        --------
        tuple:
            (private_key_path, public_key_path)
        """
        # Save private key
        with open(private_key_path, 'w') as f:
            f.write(private_key)
        
        # Save public key
        with open(public_key_path, 'w') as f:
            f.write(public_key)
        
        return private_key_path, public_key_path
    
    def load_key_from_file(self, key_path):
        """
        Load key from file.
        
        Parameters:
        -----------
        key_path : str
            Path to key file
            
        Returns:
        --------
        str:
            PEM-encoded key
        """
        with open(key_path, 'r') as f:
            key = f.read()
        return key

def key_generation_demo():
    """
    Demonstrate key generation for RSA and ECC.
    
    Returns:
    --------
    str:
        Formatted output of the demo
    """
    tool = AsymmetricEncryptionTool()
    output = []
    
    output.append("===== Asymmetric Key Generation Demo =====")
    
    # RSA Key Generation
    output.append("\n----- RSA Key Generation -----")
    
    output.append("\nGenerating 2048-bit RSA key pair...")
    start_time = time.time()
    private_key, public_key = tool.generate_rsa_key_pair(key_size=2048)
    duration = time.time() - start_time
    
    output.append(f"Key generation completed in {duration:.2f} seconds")
    output.append("\nRSA Private Key (excerpt):")
    output.append("\n".join(private_key.split("\n")[:4]) + "\n...")
    output.append("\nRSA Public Key (excerpt):")
    output.append("\n".join(public_key.split("\n")[:4]) + "\n...")
    
    # ECC Key Generation
    output.append("\n----- Elliptic Curve Key Generation -----")
    
    output.append("\nGenerating SECP256R1 (P-256) EC key pair...")
    start_time = time.time()
    ec_private_key, ec_public_key = tool.generate_ec_key_pair()
    duration = time.time() - start_time
    
    output.append(f"Key generation completed in {duration:.2f} seconds")
    output.append("\nEC Private Key (excerpt):")
    output.append("\n".join(ec_private_key.split("\n")[:4]) + "\n...")
    output.append("\nEC Public Key (excerpt):")
    output.append("\n".join(ec_public_key.split("\n")[:4]) + "\n...")
    
    output.append("\nKey Size Comparison:")
    output.append(f"RSA 2048-bit private key: ~{len(private_key)} bytes")
    output.append(f"ECC P-256 private key: ~{len(ec_private_key)} bytes")
    output.append(f"Size advantage: ECC is ~{len(private_key) / len(ec_private_key):.1f}x smaller")
    
    return "\n".join(output)

def encryption_demo():
    """
    Demonstrate RSA encryption and decryption.
    
    Returns:
    --------
    str:
        Formatted output of the demo
    """
    tool = AsymmetricEncryptionTool()
    output = []
    
    output.append("===== RSA Encryption and Decryption Demo =====")
    
    # Generate keys
    output.append("\nGenerating RSA key pair...")
    private_key, public_key = tool.generate_rsa_key_pair()
    output.append("Key generation complete")
    
    # Sample message
    message = "This is a secret message for asymmetric encryption demonstration"
    output.append(f"\nOriginal message: {message}")
    
    # Encrypt
    output.append("\nEncrypting message with public key...")
    encrypted = tool.rsa_encrypt(public_key, message)
    output.append(f"Encrypted (base64): {encrypted[:64]}...")
    
    # Decrypt
    output.append("\nDecrypting message with private key...")
    decrypted = tool.rsa_decrypt(private_key, encrypted)
    output.append(f"Decrypted: {decrypted}")
    
    # Verification
    output.append(f"\nVerification: {'Successful' if message == decrypted else 'Failed'}")
    
    return "\n".join(output)

def signature_demo():
    """
    Demonstrate digital signatures with RSA and ECC.
    
    Returns:
    --------
    str:
        Formatted output of the demo
    """
    tool = AsymmetricEncryptionTool()
    output = []
    
    output.append("===== Digital Signature Demo =====")
    
    # Generate RSA keys
    output.append("\n----- RSA Digital Signatures -----")
    output.append("\nGenerating RSA key pair...")
    rsa_private_key, rsa_public_key = tool.generate_rsa_key_pair()
    
    # Sample message
    message = "This is a message that needs to be signed for authenticity"
    output.append(f"\nOriginal message: {message}")
    
    # Sign with RSA
    output.append("\nSigning message with RSA private key...")
    rsa_signature = tool.rsa_sign(rsa_private_key, message)
    output.append(f"RSA signature (base64): {rsa_signature[:64]}...")
    
    # Verify with RSA
    output.append("\nVerifying RSA signature with public key...")
    rsa_valid = tool.rsa_verify(rsa_public_key, message, rsa_signature)
    output.append(f"RSA signature verification: {'Valid' if rsa_valid else 'Invalid'}")
    
    # Try with tampered message
    tampered_message = message + " (tampered)"
    output.append(f"\nTrying to verify with tampered message: {tampered_message}")
    rsa_tampered_valid = tool.rsa_verify(rsa_public_key, tampered_message, rsa_signature)
    output.append(f"Tampered message verification: {'Valid' if rsa_tampered_valid else 'Invalid'}")
    
    # Generate EC keys
    output.append("\n----- Elliptic Curve Digital Signatures -----")
    output.append("\nGenerating EC key pair...")
    ec_private_key, ec_public_key = tool.generate_ec_key_pair()
    
    # Sign with EC
    output.append("\nSigning message with EC private key...")
    ec_signature = tool.ec_sign(ec_private_key, message)
    output.append(f"EC signature (base64): {ec_signature[:64]}...")
    
    # Verify with EC
    output.append("\nVerifying EC signature with public key...")
    ec_valid = tool.ec_verify(ec_public_key, message, ec_signature)
    output.append(f"EC signature verification: {'Valid' if ec_valid else 'Invalid'}")
    
    # Compare signature sizes
    output.append("\nSignature Size Comparison:")
    output.append(f"RSA signature size: {len(base64.b64decode(rsa_signature))} bytes")
    output.append(f"EC signature size: {len(base64.b64decode(ec_signature))} bytes")
    output.append(f"Size advantage: EC is ~{len(base64.b64decode(rsa_signature)) / len(base64.b64decode(ec_signature)):.1f}x smaller")
    
    return "\n".join(output)

def security_recommendations():
    """
    Provide security recommendations for asymmetric cryptography.
    
    Returns:
    --------
    str:
        Formatted security recommendations
    """
    recommendations = [
        "===== Asymmetric Cryptography Security Recommendations =====",
        "",
        "1. Key Lengths",
        "   - RSA: Use at least 2048 bits, preferably 3072 or 4096 bits for long-term security",
        "   - ECC: Use at least P-256 (SECP256R1) curve, preferably P-384 for sensitive applications",
        "",
        "2. Key Management",
        "   - Protect private keys with strong passwords",
        "   - Store private keys securely (HSMs for high-security applications)",
        "   - Implement proper key rotation policies",
        "   - Never share private keys or embed them in source code",
        "",
        "3. Algorithm Selection",
        "   - ECC provides equivalent security to RSA with shorter keys",
        "   - ECC operations are faster than equivalent-security RSA operations",
        "   - RSA is more widely supported in legacy systems",
        "   - For new systems, prefer ECC for better performance",
        "",
        "4. Encryption Practices",
        "   - Only encrypt small amounts of data directly with asymmetric encryption",
        "   - For larger data, use hybrid encryption (symmetric + asymmetric)",
        "   - Use proper padding schemes like OAEP for RSA encryption",
        "   - Never use the same key pair for both encryption and signing",
        "",
        "5. Signature Practices",
        "   - Always use cryptographic hash functions (SHA-256 or better) when signing",
        "   - For RSA, use PSS padding instead of PKCS#1 v1.5 padding when possible",
        "   - Verify signatures before trusting signed data",
        "   - Consider timestamping for long-term signature validity",
        "",
        "6. Protocol Considerations",
        "   - Implement secure key exchange protocols (like ECDHE)",
        "   - Use TLS 1.3 or later for secure communications",
        "   - Consider post-quantum cryptography for future-proofing",
        "   - Keep cryptographic libraries up-to-date",
        "",
        "7. Operational Security",
        "   - Implement certificate pinning for mobile/client applications",
        "   - Use certificate transparency logs for public certificates",
        "   - Monitor for certificate expiration",
        "   - Have a plan for cryptographic agility (ability to change algorithms)"
    ]
    
    return "\n".join(recommendations)

def run_complete_demo():
    """
    Run all demos and generate a comprehensive report.
    
    Returns:
    --------
    str:
        Complete demonstration output
    """
    sections = [
        "===== ASYMMETRIC ENCRYPTION TOOL DEMONSTRATION =====",
        "This is an educational demonstration of asymmetric cryptography",
        "including key generation, encryption/decryption, and digital signatures.",
        "",
        key_generation_demo(),
        "",
        encryption_demo(),
        "",
        signature_demo(),
        "",
        security_recommendations(),
        "",
        "===== End of Demonstration ====="
    ]
    
    return "\n".join(sections)

def main():
    """Main function to run the asymmetric encryption tool."""
    parser = argparse.ArgumentParser(description='Asymmetric Encryption Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Generate key pair
    gen_parser = subparsers.add_parser('generate', help='Generate key pair')
    gen_parser.add_argument('--type', choices=['rsa', 'ec'], default='rsa', 
                           help='Key type (default: rsa)')
    gen_parser.add_argument('--size', type=int, default=2048,
                           help='Key size for RSA (default: 2048)')
    gen_parser.add_argument('--curve', default='P-256',
                           help='Curve for EC (default: P-256)')
    gen_parser.add_argument('--password', help='Password to encrypt private key')
    gen_parser.add_argument('--private', required=True, help='Private key output file')
    gen_parser.add_argument('--public', required=True, help='Public key output file')
    
    # Encrypt
    enc_parser = subparsers.add_parser('encrypt', help='Encrypt message')
    enc_parser.add_argument('--key', required=True, help='Public key file')
    enc_parser.add_argument('--message', help='Message to encrypt')
    enc_parser.add_argument('--input', help='Input file to encrypt')
    enc_parser.add_argument('--output', help='Output file for encrypted data')
    
    # Decrypt
    dec_parser = subparsers.add_parser('decrypt', help='Decrypt message')
    dec_parser.add_argument('--key', required=True, help='Private key file')
    dec_parser.add_argument('--password', help='Password for private key')
    dec_parser.add_argument('--message', help='Encrypted message (base64)')
    dec_parser.add_argument('--input', help='Input file with encrypted data')
    dec_parser.add_argument('--output', help='Output file for decrypted data')
    
    # Sign
    sign_parser = subparsers.add_parser('sign', help='Sign message')
    sign_parser.add_argument('--key', required=True, help='Private key file')
    sign_parser.add_argument('--type', choices=['rsa', 'ec'], default='rsa',
                            help='Key type (default: rsa)')
    sign_parser.add_argument('--password', help='Password for private key')
    sign_parser.add_argument('--message', help='Message to sign')
    sign_parser.add_argument('--input', help='Input file to sign')
    sign_parser.add_argument('--output', help='Output file for signature')
    
    # Verify
    verify_parser = subparsers.add_parser('verify', help='Verify signature')
    verify_parser.add_argument('--key', required=True, help='Public key file')
    verify_parser.add_argument('--type', choices=['rsa', 'ec'], default='rsa',
                             help='Key type (default: rsa)')
    verify_parser.add_argument('--message', help='Original message')
    verify_parser.add_argument('--input', help='Input file with original message')
    verify_parser.add_argument('--signature', required=True, help='Signature (base64 or file)')
    
    # Demo
    demo_parser = subparsers.add_parser('demo', help='Run demonstrations')
    demo_parser.add_argument('--all', action='store_true', help='Run all demos')
    demo_parser.add_argument('--keys', action='store_true', help='Run key generation demo')
    demo_parser.add_argument('--encrypt', action='store_true', help='Run encryption demo')
    demo_parser.add_argument('--sign', action='store_true', help='Run signature demo')
    demo_parser.add_argument('--recommendations', action='store_true', 
                           help='Show security recommendations')
    demo_parser.add_argument('--output', help='Output file for demo results')
    
    args = parser.parse_args()
    
    # Create tool instance
    tool = AsymmetricEncryptionTool()
    
    if args.command == 'generate':
        # Generate key pair
        try:
            if args.type == 'rsa':
                print(f"Generating {args.size}-bit RSA key pair...")
                private_key, public_key = tool.generate_rsa_key_pair(
                    key_size=args.size, 
                    password=args.password
                )
            else:  # EC
                curve_map = {
                    'P-256': ec.SECP256R1(),
                    'P-384': ec.SECP384R1(),
                    'P-521': ec.SECP521R1(),
                    'secp256k1': ec.SECP256K1()
                }
                curve = curve_map.get(args.curve, ec.SECP256R1())
                print(f"Generating {args.curve} EC key pair...")
                private_key, public_key = tool.generate_ec_key_pair(
                    curve=curve,
                    password=args.password
                )
                
            # Save keys
            tool.save_keys_to_file(private_key, public_key, args.private, args.public)
            print(f"Private key saved to: {args.private}")
            print(f"Public key saved to: {args.public}")
            
            if args.password:
                print("Private key is encrypted with the provided password")
            else:
                print("Warning: Private key is not encrypted")
                
        except Exception as e:
            print(f"Error generating keys: {e}")
            
    elif args.command == 'encrypt':
        try:
            # Load public key
            public_key = tool.load_key_from_file(args.key)
            
            # Get message
            if args.message:
                message = args.message
            elif args.input:
                with open(args.input, 'r') as f:
                    message = f.read()
            else:
                message = input("Enter message to encrypt: ")
            
            # Encrypt
            encrypted = tool.rsa_encrypt(public_key, message)
            
            # Output
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(encrypted)
                print(f"Encrypted message saved to: {args.output}")
            else:
                print(f"Encrypted (base64): {encrypted}")
                
        except Exception as e:
            print(f"Error encrypting message: {e}")
            
    elif args.command == 'decrypt':
        try:
            # Load private key
            private_key = tool.load_key_from_file(args.key)
            
            # Get encrypted message
            if args.message:
                encrypted = args.message
            elif args.input:
                with open(args.input, 'r') as f:
                    encrypted = f.read()
            else:
                encrypted = input("Enter encrypted message (base64): ")
            
            # Decrypt
            decrypted = tool.rsa_decrypt(private_key, encrypted, args.password)
            
            # Output
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(decrypted)
                print(f"Decrypted message saved to: {args.output}")
            else:
                print(f"Decrypted: {decrypted}")
                
        except Exception as e:
            print(f"Error decrypting message: {e}")
            
    elif args.command == 'sign':
        try:
            # Load private key
            private_key = tool.load_key_from_file(args.key)
            
            # Get message
            if args.message:
                message = args.message
            elif args.input:
                with open(args.input, 'r') as f:
                    message = f.read()
            else:
                message = input("Enter message to sign: ")
            
            # Sign
            if args.type == 'rsa':
                signature = tool.rsa_sign(private_key, message, args.password)
            else:  # EC
                signature = tool.ec_sign(private_key, message, args.password)
            
            # Output
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(signature)
                print(f"Signature saved to: {args.output}")
            else:
                print(f"Signature (base64): {signature}")
                
        except Exception as e:
            print(f"Error signing message: {e}")
            
    elif args.command == 'verify':
        try:
            # Load public key
            public_key = tool.load_key_from_file(args.key)
            
            # Get message
            if args.message:
                message = args.message
            elif args.input:
                with open(args.input, 'r') as f:
                    message = f.read()
            else:
                message = input("Enter original message: ")
            
            # Get signature
            if os.path.isfile(args.signature):
                with open(args.signature, 'r') as f:
                    signature = f.read().strip()
            else:
                signature = args.signature
            
            # Verify
            if args.type == 'rsa':
                valid = tool.rsa_verify(public_key, message, signature)
            else:  # EC
                valid = tool.ec_verify(public_key, message, signature)
            
            # Output result
            if valid:
                print("Signature is VALID")
                print("The message was signed by the owner of the private key and has not been tampered with")
            else:
                print("Signature is INVALID")
                print("The message may have been tampered with or was not signed by the expected private key")
                
        except Exception as e:
            print(f"Error verifying signature: {e}")
            
    elif args.command == 'demo':
        results = []
        
        if args.all or not any([args.keys, args.encrypt, args.sign, args.recommendations]):
            print("Running full demonstration...")
            results.append(run_complete_demo())
        else:
            if args.keys:
                print("Running key generation demonstration...")
                results.append(key_generation_demo())
                
            if args.encrypt:
                print("Running encryption demonstration...")
                results.append(encryption_demo())
                
            if args.sign:
                print("Running signature demonstration...")
                results.append(signature_demo())
                
            if args.recommendations:
                print("Showing security recommendations...")
                results.append(security_recommendations())
        
        # Output demo results
        demo_output = "\n\n".join(results)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(demo_output)
            print(f"Demo results saved to: {args.output}")
        else:
            print("\n" + demo_output)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()