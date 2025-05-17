#!/usr/bin/env python3
"""
Hash Cracker

This script provides tools to attempt cracking password hashes using various methods
including dictionary attacks, brute force, and rainbow table lookups. It supports
multiple hash algorithms and includes educational information about hash security.

This tool is intended for educational purposes and authorized security testing only.
"""

import argparse
import hashlib
import sys
import time
import string
import itertools
import logging
import os
import requests
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from scripts.utils.disclaimer import print_disclaimer, require_confirmation, require_legal_confirmation

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Supported hash algorithms and their respective functions
HASH_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
    'sha3_224': hashlib.sha3_224,
    'sha3_256': hashlib.sha3_256,
    'sha3_384': hashlib.sha3_384,
    'sha3_512': hashlib.sha3_512
}

def identify_hash_type(hash_string):
    """
    Attempt to identify the type of hash based on its length and character set.
    
    Parameters:
    -----------
    hash_string : str
        The hash string to identify
        
    Returns:
    --------
    list:
        Possible hash types
    """
    hash_length = len(hash_string)
    possible_types = []
    
    # Check if the hash consists of hexadecimal characters
    if all(c in string.hexdigits for c in hash_string):
        # MD5
        if hash_length == 32:
            possible_types.append("md5")
        # SHA-1
        elif hash_length == 40:
            possible_types.append("sha1")
        # SHA-224, SHA3-224
        elif hash_length == 56:
            possible_types.extend(["sha224", "sha3_224"])
        # SHA-256, SHA3-256
        elif hash_length == 64:
            possible_types.extend(["sha256", "sha3_256"])
        # SHA-384, SHA3-384
        elif hash_length == 96:
            possible_types.extend(["sha384", "sha3_384"])
        # SHA-512, SHA3-512
        elif hash_length == 128:
            possible_types.extend(["sha512", "sha3_512"])
    
    # Check for common password hash formats
    if re.match(r'^\$2[aby]\$\d+\$[./A-Za-z0-9]{53}$', hash_string):
        possible_types.append("bcrypt")
    elif re.match(r'^\$6\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{86}$', hash_string):
        possible_types.append("sha512crypt")
    elif re.match(r'^\$5\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{43}$', hash_string):
        possible_types.append("sha256crypt")
    elif re.match(r'^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$', hash_string):
        possible_types.append("md5crypt")
    elif re.match(r'^[0-9a-f]{32}:[0-9a-f]+$', hash_string):
        possible_types.append("md5:salt")
    
    if not possible_types:
        possible_types.append("unknown")
    
    return possible_types

def download_wordlist(url, output_path):
    """
    Download a wordlist from a URL.
    
    Parameters:
    -----------
    url : str
        The URL to download from
    output_path : str
        Where to save the downloaded file
        
    Returns:
    --------
    bool:
        True if successful, False otherwise
    """
    try:
        logger.info(f"Downloading wordlist from {url}")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 8192
        downloaded = 0
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=block_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    
                    # Print progress
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\rDownloading: {percent:.1f}% ({downloaded}/{total_size} bytes)", end='')
        
        print()  # New line after progress
        logger.info(f"Downloaded wordlist to {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error downloading wordlist: {str(e)}")
        return False

def generate_hash(text, algorithm, salt=None):
    """
    Generate a hash from text using the specified algorithm.
    
    Parameters:
    -----------
    text : str
        The text to hash
    algorithm : str
        The algorithm to use
    salt : str, optional
        Salt to prepend or append to the text
        
    Returns:
    --------
    str:
        The generated hash
    """
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    hasher = HASH_ALGORITHMS[algorithm]()
    
    if salt:
        # For simple demonstration, just prepend the salt
        # Real password hashing would use more complex methods
        hasher.update((salt + text).encode('utf-8'))
    else:
        hasher.update(text.encode('utf-8'))
    
    return hasher.hexdigest()

def dictionary_attack(hash_to_crack, wordlist_path, algorithm, salt=None, max_words=None):
    """
    Perform a dictionary attack against a hash.
    
    Parameters:
    -----------
    hash_to_crack : str
        The hash to crack
    wordlist_path : str
        Path to the wordlist file
    algorithm : str
        Hash algorithm to use
    salt : str, optional
        Salt to apply to each word
    max_words : int, optional
        Maximum number of words to try
        
    Returns:
    --------
    tuple:
        (bool, str, int): Success, cracked password, attempts made
    """
    if not os.path.exists(wordlist_path):
        logger.error(f"Wordlist not found: {wordlist_path}")
        return False, None, 0
    
    hash_to_crack = hash_to_crack.lower()
    words_tried = 0
    start_time = time.time()
    
    logger.info(f"Starting dictionary attack using {wordlist_path}")
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
            for word in wordlist:
                word = word.strip()
                words_tried += 1
                
                if words_tried % 10000 == 0:
                    elapsed = time.time() - start_time
                    print(f"\rTried {words_tried} passwords ({words_tried/elapsed:.0f} p/s)...", end='')
                
                if max_words and words_tried >= max_words:
                    break
                
                try:
                    word_hash = generate_hash(word, algorithm, salt)
                    if word_hash.lower() == hash_to_crack:
                        elapsed = time.time() - start_time
                        print(f"\rSuccess! Tried {words_tried} passwords in {elapsed:.2f} seconds")
                        return True, word, words_tried
                except:
                    # Skip words that cause encoding errors
                    continue
        
        elapsed = time.time() - start_time
        print(f"\rCompleted. Tried {words_tried} passwords in {elapsed:.2f} seconds")
        return False, None, words_tried
    
    except Exception as e:
        logger.error(f"Error in dictionary attack: {str(e)}")
        return False, None, words_tried

def brute_force_attack(hash_to_crack, algorithm, charset=None, min_length=1, max_length=8, salt=None):
    """
    Perform a brute force attack against a hash.
    
    Parameters:
    -----------
    hash_to_crack : str
        The hash to crack
    algorithm : str
        Hash algorithm to use
    charset : str, optional
        Character set to use (default: lowercase letters and digits)
    min_length : int
        Minimum password length to try
    max_length : int
        Maximum password length to try
    salt : str, optional
        Salt to apply to each attempt
        
    Returns:
    --------
    tuple:
        (bool, str, int): Success, cracked password, attempts made
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits
    
    hash_to_crack = hash_to_crack.lower()
    attempts = 0
    start_time = time.time()
    
    logger.info(f"Starting brute force attack with charset: {charset}")
    print(f"Brute force attack using charset: {charset}")
    print(f"Testing password lengths from {min_length} to {max_length}")
    print("This may take a very long time depending on the parameters.")
    
    try:
        for length in range(min_length, max_length + 1):
            print(f"\nTrying length {length}...")
            
            for attempt in itertools.product(charset, repeat=length):
                password = ''.join(attempt)
                attempts += 1
                
                if attempts % 10000 == 0:
                    elapsed = time.time() - start_time
                    current = ''.join(attempt)
                    print(f"\rTried {attempts} passwords ({attempts/elapsed:.0f} p/s), Current: {current}", end='')
                
                try:
                    password_hash = generate_hash(password, algorithm, salt)
                    if password_hash.lower() == hash_to_crack:
                        elapsed = time.time() - start_time
                        print(f"\rSuccess! Tried {attempts} passwords in {elapsed:.2f} seconds")
                        return True, password, attempts
                except:
                    # Skip any encoding errors
                    continue
        
        elapsed = time.time() - start_time
        print(f"\rCompleted. Tried {attempts} passwords in {elapsed:.2f} seconds")
        return False, None, attempts
    
    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\nBrute force attack interrupted after {attempts} attempts ({elapsed:.2f} seconds)")
        return False, None, attempts
    
    except Exception as e:
        logger.error(f"Error in brute force attack: {str(e)}")
        return False, None, attempts

def online_hash_lookup(hash_to_crack):
    """
    Perform an online hash lookup (simulated for educational purposes).
    
    Parameters:
    -----------
    hash_to_crack : str
        The hash to look up
        
    Returns:
    --------
    tuple:
        (bool, str): Success and the result if found
    """
    print("Note: In a real scenario, this would query online hash databases.")
    print("For educational purposes, we're simulating this lookup.")
    
    # In a real implementation, this would query services like:
    # - https://crackstation.net/
    # - https://hashkiller.io/
    # - https://md5decrypt.net/
    
    # Common hash:plain mappings for demonstration
    DEMO_HASH_MAP = {
        "5f4dcc3b5aa765d61d8327deb882cf99": "password",
        "e10adc3949ba59abbe56e057f20f883e": "123456",
        "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
        "482c811da5d5b4bc6d497ffa98491e38": "password123",
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": "password",
        "7c4a8d09ca3762af61e59520943dc26494f8941b": "123456"
    }
    
    hash_to_crack = hash_to_crack.lower()
    
    print("Checking hash against known databases...")
    time.sleep(2)  # Simulate lookup time
    
    if hash_to_crack in DEMO_HASH_MAP:
        result = DEMO_HASH_MAP[hash_to_crack]
        print(f"Found match in database: {result}")
        return True, result
    
    print("Hash not found in online databases.")
    return False, None

def generate_rainbow_table(wordlist_path, algorithm, output_path, limit=1000):
    """
    Generate a simple rainbow table from a wordlist.
    
    Parameters:
    -----------
    wordlist_path : str
        Path to the wordlist file
    algorithm : str
        Hash algorithm to use
    output_path : str
        Where to save the rainbow table
    limit : int
        Maximum number of entries to generate
        
    Returns:
    --------
    bool:
        True if successful, False otherwise
    """
    if not os.path.exists(wordlist_path):
        logger.error(f"Wordlist not found: {wordlist_path}")
        return False
    
    try:
        entries = 0
        start_time = time.time()
        
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
            with open(output_path, 'w', encoding='utf-8') as output:
                for word in wordlist:
                    word = word.strip()
                    if not word:
                        continue
                    
                    try:
                        word_hash = generate_hash(word, algorithm)
                        output.write(f"{word_hash}:{word}\n")
                        entries += 1
                        
                        if entries % 1000 == 0:
                            elapsed = time.time() - start_time
                            print(f"\rGenerated {entries} entries ({entries/elapsed:.0f} e/s)...", end='')
                        
                        if entries >= limit:
                            break
                    except:
                        # Skip words that cause encoding errors
                        continue
        
        elapsed = time.time() - start_time
        print(f"\rCompleted. Generated {entries} entries in {elapsed:.2f} seconds")
        logger.info(f"Rainbow table generated: {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error generating rainbow table: {str(e)}")
        return False

def rainbow_table_attack(hash_to_crack, rainbow_table_path):
    """
    Look up a hash in a rainbow table.
    
    Parameters:
    -----------
    hash_to_crack : str
        The hash to look up
    rainbow_table_path : str
        Path to the rainbow table file
        
    Returns:
    --------
    tuple:
        (bool, str): Success and the result if found
    """
    if not os.path.exists(rainbow_table_path):
        logger.error(f"Rainbow table not found: {rainbow_table_path}")
        return False, None
    
    hash_to_crack = hash_to_crack.lower()
    
    try:
        logger.info(f"Searching hash in rainbow table: {rainbow_table_path}")
        print(f"Searching for hash in rainbow table...")
        
        with open(rainbow_table_path, 'r', encoding='utf-8', errors='ignore') as table:
            for line in table:
                if not line.strip():
                    continue
                
                parts = line.strip().split(':', 1)
                if len(parts) != 2:
                    continue
                
                stored_hash, plaintext = parts
                
                if stored_hash.lower() == hash_to_crack:
                    print(f"Found match in rainbow table: {plaintext}")
                    return True, plaintext
        
        print("Hash not found in rainbow table.")
        return False, None
    
    except Exception as e:
        logger.error(f"Error searching rainbow table: {str(e)}")
        return False, None

def check_password_strength(password):
    """
    Check the strength of a password.
    
    Parameters:
    -----------
    password : str
        The password to check
        
    Returns:
    --------
    dict:
        Password strength assessment
    """
    assessment = {
        'length': len(password),
        'has_lowercase': any(c.islower() for c in password),
        'has_uppercase': any(c.isupper() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_special': any(c in string.punctuation for c in password),
        'score': 0,
        'rating': '',
        'suggestions': []
    }
    
    # Calculate score
    score = 0
    
    # Length
    if len(password) >= 12:
        score += 30
    elif len(password) >= 10:
        score += 20
    elif len(password) >= 8:
        score += 10
    else:
        assessment['suggestions'].append("Increase password length to at least 12 characters")
    
    # Character types
    if assessment['has_lowercase']:
        score += 10
    else:
        assessment['suggestions'].append("Add lowercase letters")
    
    if assessment['has_uppercase']:
        score += 10
    else:
        assessment['suggestions'].append("Add uppercase letters")
    
    if assessment['has_digit']:
        score += 10
    else:
        assessment['suggestions'].append("Add numbers")
    
    if assessment['has_special']:
        score += 15
    else:
        assessment['suggestions'].append("Add special characters")
    
    # Check for common patterns
    if password.lower() in ['password', 'admin', '123456', 'qwerty', 'welcome']:
        score -= 30
        assessment['suggestions'].append("Avoid commonly used passwords")
    
    if all(c.isdigit() for c in password):
        score -= 20
        assessment['suggestions'].append("Avoid using only numbers")
    
    # Assign rating
    if score >= 60:
        rating = "Strong"
    elif score >= 40:
        rating = "Moderate"
    else:
        rating = "Weak"
    
    assessment['score'] = max(0, score)
    assessment['rating'] = rating
    
    return assessment

def print_hash_info(hash_string):
    """
    Print information about a hash string.
    
    Parameters:
    -----------
    hash_string : str
        The hash string to analyze
        
    Returns:
    --------
    None
    """
    possible_types = identify_hash_type(hash_string)
    
    print("\n" + "=" * 80)
    print("HASH ANALYSIS")
    print("=" * 80)
    print(f"Hash: {hash_string}")
    print(f"Length: {len(hash_string)} characters")
    print(f"Character set: {'Hexadecimal' if all(c in string.hexdigits for c in hash_string) else 'Mixed'}")
    
    if possible_types:
        print(f"Possible hash types: {', '.join(possible_types)}")
    else:
        print("Could not identify hash type.")
    
    print("=" * 80)

def print_password_strength_assessment(assessment):
    """
    Print a password strength assessment.
    
    Parameters:
    -----------
    assessment : dict
        The password strength assessment
        
    Returns:
    --------
    None
    """
    print("\n" + "=" * 80)
    print("PASSWORD STRENGTH ASSESSMENT")
    print("=" * 80)
    print(f"Length: {assessment['length']} characters")
    print(f"Contains lowercase letters: {'Yes' if assessment['has_lowercase'] else 'No'}")
    print(f"Contains uppercase letters: {'Yes' if assessment['has_uppercase'] else 'No'}")
    print(f"Contains digits: {'Yes' if assessment['has_digit'] else 'No'}")
    print(f"Contains special characters: {'Yes' if assessment['has_special'] else 'No'}")
    print(f"Overall strength: {assessment['rating']} ({assessment['score']}/75)")
    
    if assessment['suggestions']:
        print("\nSuggestions for improvement:")
        for suggestion in assessment['suggestions']:
            print(f"- {suggestion}")
    
    print("\nEstimated time to crack:")
    if assessment['score'] >= 60:
        print("- Dictionary attack: Very unlikely")
        print("- Brute force attack: Years to centuries")
    elif assessment['score'] >= 40:
        print("- Dictionary attack: Unlikely if not based on a dictionary word")
        print("- Brute force attack: Days to years")
    else:
        print("- Dictionary attack: Likely if based on common words")
        print("- Brute force attack: Seconds to hours")
    
    print("=" * 80)

def main():
    """Main function to run the hash cracker from the command line."""
    parser = argparse.ArgumentParser(
        description="Hash Cracker for Educational Purposes",
        epilog="This tool is for educational and authorized testing only."
    )
    
    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    # Crack mode
    crack_parser = subparsers.add_parser('crack', help='Crack a hash')
    crack_parser.add_argument(
        "--hash", 
        required=True,
        help="The hash to crack"
    )
    crack_parser.add_argument(
        "--algorithm",
        choices=list(HASH_ALGORITHMS.keys()),
        help="Hash algorithm (if not specified, will try to identify)"
    )
    crack_parser.add_argument(
        "--salt",
        help="Salt to use (for salted hashes)"
    )
    crack_parser.add_argument(
        "--wordlist",
        help="Path to wordlist file for dictionary attack"
    )
    crack_parser.add_argument(
        "--download-wordlist",
        help="URL to download a wordlist from"
    )
    crack_parser.add_argument(
        "--rainbow",
        help="Path to rainbow table for lookup"
    )
    crack_parser.add_argument(
        "--brute-force",
        action="store_true",
        help="Perform brute force attack"
    )
    crack_parser.add_argument(
        "--charset",
        default=string.ascii_lowercase + string.digits,
        help="Character set for brute force (default: lowercase + digits)"
    )
    crack_parser.add_argument(
        "--min-length",
        type=int,
        default=1,
        help="Minimum password length for brute force"
    )
    crack_parser.add_argument(
        "--max-length",
        type=int,
        default=8,
        help="Maximum password length for brute force"
    )
    crack_parser.add_argument(
        "--online",
        action="store_true",
        help="Perform online hash lookup (simulated)"
    )
    
    # Generate mode
    gen_parser = subparsers.add_parser('generate', help='Generate hash from text')
    gen_parser.add_argument(
        "--text", 
        required=True,
        help="Text to hash"
    )
    gen_parser.add_argument(
        "--algorithm",
        choices=list(HASH_ALGORITHMS.keys()),
        default="md5",
        help="Hash algorithm to use (default: md5)"
    )
    gen_parser.add_argument(
        "--salt",
        help="Salt to prepend to the text"
    )
    
    # Rainbow table mode
    rainbow_parser = subparsers.add_parser('rainbow', help='Generate rainbow table')
    rainbow_parser.add_argument(
        "--wordlist", 
        required=True,
        help="Path to wordlist file"
    )
    rainbow_parser.add_argument(
        "--algorithm",
        choices=list(HASH_ALGORITHMS.keys()),
        default="md5",
        help="Hash algorithm to use (default: md5)"
    )
    rainbow_parser.add_argument(
        "--output",
        required=True,
        help="Output file for the rainbow table"
    )
    rainbow_parser.add_argument(
        "--limit",
        type=int,
        default=10000,
        help="Maximum number of entries (default: 10000)"
    )
    
    # Analyze mode
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a hash or password')
    analyze_parser.add_argument(
        "--hash",
        help="Hash to analyze"
    )
    analyze_parser.add_argument(
        "--password",
        help="Password to analyze for strength"
    )
    
    args = parser.parse_args()
    
    # Display disclaimer and require confirmation
    print_disclaimer(
        script_name="Hash Cracker",
        description="Educational tool for understanding hash cracking techniques",
        additional_warning="Using this tool to crack passwords without authorization is illegal."
    )
    
    if not require_confirmation():
        return
    
    # Handle different modes
    if args.mode == 'crack':
        # Crack a hash
        hash_to_crack = args.hash
        
        # Try to identify the hash type if not specified
        if not args.algorithm:
            possible_types = identify_hash_type(hash_to_crack)
            if len(possible_types) == 1 and possible_types[0] != "unknown":
                algorithm = possible_types[0]
                print(f"Hash identified as: {algorithm}")
            else:
                print(f"Possible hash types: {', '.join(possible_types)}")
                print("Please specify the algorithm with --algorithm")
                return 1
        else:
            algorithm = args.algorithm
        
        # Process requests in order of complexity
        
        # 1. Online lookup (simulated)
        if args.online:
            if require_legal_confirmation("your jurisdiction"):
                print("\n--- Online Hash Lookup ---")
                success, result = online_hash_lookup(hash_to_crack)
                
                if success:
                    print(f"\nHash successfully cracked: {result}")
                    
                    # Show password strength if cracked
                    if result:
                        assessment = check_password_strength(result)
                        print_password_strength_assessment(assessment)
                    
                    return 0
        
        # 2. Rainbow table lookup
        if args.rainbow:
            print("\n--- Rainbow Table Attack ---")
            success, result = rainbow_table_attack(hash_to_crack, args.rainbow)
            
            if success:
                print(f"\nHash successfully cracked: {result}")
                
                # Show password strength if cracked
                if result:
                    assessment = check_password_strength(result)
                    print_password_strength_assessment(assessment)
                
                return 0
        
        # 3. Dictionary attack
        if args.wordlist or args.download_wordlist:
            # Download wordlist if specified
            if args.download_wordlist:
                wordlist_dir = os.path.expanduser("~/.hashcracker")
                os.makedirs(wordlist_dir, exist_ok=True)
                
                wordlist_filename = os.path.basename(args.download_wordlist) or "downloaded_wordlist.txt"
                wordlist_path = os.path.join(wordlist_dir, wordlist_filename)
                
                if download_wordlist(args.download_wordlist, wordlist_path):
                    print(f"Wordlist downloaded to {wordlist_path}")
                else:
                    print("Failed to download wordlist.")
                    return 1
            else:
                wordlist_path = args.wordlist
            
            print("\n--- Dictionary Attack ---")
            success, result, attempts = dictionary_attack(
                hash_to_crack, 
                wordlist_path, 
                algorithm, 
                args.salt
            )
            
            if success:
                print(f"\nHash successfully cracked: {result}")
                
                # Show password strength if cracked
                if result:
                    assessment = check_password_strength(result)
                    print_password_strength_assessment(assessment)
                
                return 0
        
        # 4. Brute force attack (last resort)
        if args.brute_force:
            if require_legal_confirmation("your jurisdiction"):
                print("\n--- Brute Force Attack ---")
                print("Warning: Brute force attacks can take a very long time!")
                print(f"Using character set: {args.charset}")
                print(f"Testing passwords from {args.min_length} to {args.max_length} characters")
                
                success, result, attempts = brute_force_attack(
                    hash_to_crack, 
                    algorithm, 
                    args.charset, 
                    args.min_length, 
                    args.max_length, 
                    args.salt
                )
                
                if success:
                    print(f"\nHash successfully cracked: {result}")
                    
                    # Show password strength if cracked
                    if result:
                        assessment = check_password_strength(result)
                        print_password_strength_assessment(assessment)
                    
                    return 0
        
        print("\nFailed to crack the hash with the specified methods.")
    
    elif args.mode == 'generate':
        # Generate a hash
        text = args.text
        algorithm = args.algorithm
        salt = args.salt
        
        print("\n--- Hash Generation ---")
        generated_hash = generate_hash(text, algorithm, salt)
        
        print(f"Algorithm: {algorithm}")
        if salt:
            print(f"Salt: {salt}")
        print(f"Original text: {text}")
        print(f"Generated hash: {generated_hash}")
    
    elif args.mode == 'rainbow':
        # Generate a rainbow table
        wordlist = args.wordlist
        algorithm = args.algorithm
        output = args.output
        limit = args.limit
        
        print("\n--- Rainbow Table Generation ---")
        print(f"Generating rainbow table using algorithm: {algorithm}")
        print(f"Wordlist: {wordlist}")
        print(f"Output: {output}")
        print(f"Entry limit: {limit}")
        
        if generate_rainbow_table(wordlist, algorithm, output, limit):
            print(f"\nRainbow table successfully generated: {output}")
        else:
            print("\nFailed to generate rainbow table.")
    
    elif args.mode == 'analyze':
        # Analyze hash or password
        if args.hash:
            print_hash_info(args.hash)
        
        if args.password:
            assessment = check_password_strength(args.password)
            print_password_strength_assessment(assessment)
    
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
