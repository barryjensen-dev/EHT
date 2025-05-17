"""
CSRF Exploit Simulator

This script provides tools to simulate and demonstrate Cross-Site Request Forgery (CSRF) attacks
for educational purposes. It helps understand how CSRF vulnerabilities work, how they can be
detected, and how to implement proper protection mechanisms in web applications.

This tool is intended for educational purposes and authorized security assessment only.
"""

import argparse
import os
import re
import html
import logging
import time
import json
import random
import string
from urllib.parse import urlparse, parse_qs

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CSRFVulnerabilityAnalyzer:
    """Class for analyzing web applications for CSRF vulnerabilities."""
    
    def __init__(self):
        """Initialize the CSRF vulnerability analyzer."""
        self.reports = []
    
    def analyze_form(self, form_html, page_url):
        """
        Analyze an HTML form for CSRF vulnerabilities.
        
        Parameters:
        -----------
        form_html : str
            The HTML code of the form to analyze
        page_url : str
            The URL of the page containing the form
            
        Returns:
        --------
        dict:
            Analysis results
        """
        result = {
            'form_action': None,
            'method': 'GET',  # Default
            'has_csrf_token': False,
            'csrf_token_name': None,
            'fields': [],
            'is_vulnerable': True,  # Assume vulnerable until proven otherwise
            'vulnerability_reasons': [],
            'protection_methods': []
        }
        
        # Extract form action and method
        action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        if action_match:
            result['form_action'] = action_match.group(1)
        else:
            result['form_action'] = page_url  # Default to current page
            
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        if method_match:
            result['method'] = method_match.group(1).upper()
        
        # Extract form fields
        field_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        fields = re.findall(field_pattern, form_html, re.IGNORECASE)
        
        for field_name in fields:
            field_info = {'name': field_name}
            
            # Check if it's a hidden field
            is_hidden_match = re.search(
                r'<input[^>]*name=["\']' + re.escape(field_name) + r'["\'][^>]*type=["\']hidden["\'][^>]*>',
                form_html, 
                re.IGNORECASE
            )
            field_info['is_hidden'] = bool(is_hidden_match)
            
            # Extract field value if present
            value_match = re.search(
                r'<input[^>]*name=["\']' + re.escape(field_name) + r'["\'][^>]*value=["\']([^"\']*)["\'][^>]*>',
                form_html, 
                re.IGNORECASE
            )
            field_info['has_value'] = bool(value_match)
            field_info['value'] = value_match.group(1) if value_match else None
            
            result['fields'].append(field_info)
            
            # Check if this field looks like a CSRF token
            if any(token_name in field_name.lower() for token_name in ['csrf', 'token', 'nonce', 'xsrf']):
                result['has_csrf_token'] = True
                result['csrf_token_name'] = field_name
        
        # Check for cookie-based CSRF protection (SameSite attributes)
        result['has_samesite_cookie'] = False  # Would need to check response headers
        
        # Check for custom headers that might prevent CSRF
        result['checks_custom_headers'] = False  # Would need to check server code
        
        # Determine if the form is vulnerable to CSRF
        if result['has_csrf_token']:
            result['is_vulnerable'] = False
            result['protection_methods'].append(f"Uses CSRF token: {result['csrf_token_name']}")
        
        # If it's a GET form, it should not modify state (and thus is less of a CSRF concern)
        if result['method'] == 'GET':
            result['vulnerability_reasons'].append(
                "Form uses GET method, which should not be used for state-changing operations"
            )
        
        # If no CSRF token, the form might be vulnerable
        if not result['has_csrf_token'] and result['method'] == 'POST':
            result['vulnerability_reasons'].append("No CSRF token found in the form")
            result['protection_methods'].append(
                "Add a CSRF token: <input type='hidden' name='csrf_token' value='random_token'>"
            )
        
        return result
    
    def analyze_website(self, url, html_content):
        """
        Analyze a website for CSRF vulnerabilities.
        
        Parameters:
        -----------
        url : str
            The URL of the website to analyze
        html_content : str
            The HTML content of the website
            
        Returns:
        --------
        dict:
            Analysis results
        """
        result = {
            'url': url,
            'forms': [],
            'has_vulnerabilities': False,
            'samesite_cookies_used': False,  # Would need to check response headers
            'overall_assessment': '',
            'recommendations': []
        }
        
        # Extract forms
        form_pattern = r'<form[^>]*>.*?</form>'
        forms = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        if not forms:
            result['overall_assessment'] = "No forms found on the page to analyze for CSRF vulnerabilities."
            return result
        
        # Analyze each form
        for form_html in forms:
            form_result = self.analyze_form(form_html, url)
            result['forms'].append(form_result)
            
            if form_result['is_vulnerable']:
                result['has_vulnerabilities'] = True
        
        # Generate overall assessment
        vulnerable_count = sum(1 for form in result['forms'] if form['is_vulnerable'])
        total_forms = len(result['forms'])
        
        if vulnerable_count == 0:
            result['overall_assessment'] = f"All {total_forms} forms appear to have CSRF protection."
        else:
            result['overall_assessment'] = (
                f"Found {vulnerable_count} out of {total_forms} forms potentially vulnerable to CSRF attacks."
            )
        
        # Generate recommendations
        if result['has_vulnerabilities']:
            result['recommendations'] = [
                "Implement CSRF tokens for all state-changing forms (especially POST requests)",
                "Set SameSite=Strict or SameSite=Lax for cookies",
                "Verify the Origin and Referer headers on the server side",
                "Consider implementing Custom Request Headers for AJAX requests",
                "For critical operations, consider requiring re-authentication"
            ]
        
        return result
    
    def generate_exploit_poc(self, form_data, target_url):
        """
        Generate a proof-of-concept HTML page for exploiting a CSRF vulnerability.
        
        Parameters:
        -----------
        form_data : dict
            Analysis results for a vulnerable form
        target_url : str
            The URL of the target website
            
        Returns:
        --------
        str:
            HTML code for a CSRF exploit
        """
        if not form_data['is_vulnerable']:
            return "This form does not appear to be vulnerable to CSRF attacks."
        
        # Determine the form action URL
        action_url = form_data['form_action']
        if not action_url.startswith('http'):
            # Relative URL, make it absolute
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            if action_url.startswith('/'):
                action_url = base_url + action_url
            else:
                action_url = target_url.rsplit('/', 1)[0] + '/' + action_url
        
        # Generate HTML for the PoC
        method = form_data['method']
        
        html_poc = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "    <title>CSRF Proof of Concept</title>",
            "    <meta charset='UTF-8'>",
            "</head>",
            "<body>",
            "    <h1>CSRF Proof of Concept (Educational Purposes Only)</h1>",
            "    <p>This page demonstrates a Cross-Site Request Forgery vulnerability.</p>",
            ""
        ]
        
        if method == 'GET':
            params = []
            for field in form_data['fields']:
                field_name = html.escape(field['name'])
                field_value = html.escape(field['value'] or 'default_value')
                params.append(f"{field_name}={field_value}")
            
            get_url = action_url
            if params:
                get_url += '?' + '&'.join(params)
            
            html_poc.extend([
                f"    <p>The link below will trigger a GET request to {html.escape(get_url)}</p>",
                f"    <a href='{html.escape(get_url)}' id='exploit_link'>Click me</a>",
                "    <script>",
                "        // Auto-trigger for demonstration",
                "        // document.getElementById('exploit_link').click();",
                "    </script>"
            ])
            
        else:  # POST
            html_poc.extend([
                f"    <p>The form below will be automatically submitted to {html.escape(action_url)}</p>",
                "    <form id='csrf_form' action='" + html.escape(action_url) + "' method='POST'>",
            ])
            
            for field in form_data['fields']:
                field_name = html.escape(field['name'])
                field_value = html.escape(field['value'] or 'default_value')
                html_poc.append(f"        <input type='hidden' name='{field_name}' value='{field_value}'>")
            
            html_poc.extend([
                "    </form>",
                "    <script>",
                "        // Auto-submit for demonstration",
                "        // Uncomment the next line in a real attack scenario",
                "        // document.getElementById('csrf_form').submit();",
                "    </script>"
            ])
        
        html_poc.extend([
            "    <h2>Educational Notes:</h2>",
            "    <ul>",
            "        <li>This PoC is for educational purposes to demonstrate CSRF vulnerabilities</li>",
            "        <li>In a real attack, this page would be hosted on an attacker's server</li>",
            "        <li>The victim would need to visit this page while authenticated on the target site</li>",
            "        <li>The request would include the victim's cookies and authentication</li>",
            "        <li>The JavaScript could be modified to auto-submit without user interaction</li>",
            "    </ul>",
            "    <h2>Protection Measures:</h2>",
            "    <ul>",
            "        <li>Implement anti-CSRF tokens in all forms</li>",
            "        <li>Use SameSite cookie attributes</li>",
            "        <li>Validate Origin and Referer headers</li>",
            "        <li>Require re-authentication for sensitive actions</li>",
            "    </ul>",
            "</body>",
            "</html>"
        ])
        
        return "\n".join(html_poc)
    
    def generate_csrf_token(self, length=32):
        """
        Generate a secure random token for CSRF protection.
        
        Parameters:
        -----------
        length : int
            Length of the token
            
        Returns:
        --------
        str:
            A random token
        """
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def generate_protection_example(self):
        """
        Generate example code for implementing CSRF protection.
        
        Returns:
        --------
        dict:
            Example code for different frameworks
        """
        examples = {
            'flask': {
                'description': 'Using Flask-WTF for CSRF protection',
                'code': """
# Setup (app.py)
from flask import Flask, render_template, request, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)

# In your HTML templates
<form method="post">
    {{ csrf_token() }}
    <!-- form fields -->
    <button type="submit">Submit</button>
</form>
                """
            },
            'django': {
                'description': 'Using Django built-in CSRF protection',
                'code': """
# In your HTML templates
<form method="post">
    {% csrf_token %}
    <!-- form fields -->
    <button type="submit">Submit</button>
</form>

# In settings.py
MIDDLEWARE = [
    # ...
    'django.middleware.csrf.CsrfViewMiddleware',
    # ...
]
                """
            },
            'php': {
                'description': 'Manual CSRF implementation in PHP',
                'code': """
<?php
// In your session initialization
session_start();
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// In your form
echo '<form method="post">';
echo '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';
// form fields
echo '<button type="submit">Submit</button>';
echo '</form>';

// Validating in your form handler
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }
    // Process form
}
?>
                """
            },
            'javascript': {
                'description': 'Using JavaScript to add CSRF tokens to AJAX requests',
                'code': """
// Get the CSRF token from a meta tag or cookie
const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

// Add it to all AJAX requests
fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify(data)
})
.then(response => response.json())
.then(data => console.log(data));
                """
            }
        }
        
        return examples


def simulate_csrf_assessment(target_url, html_content=None):
    """
    Simulate a CSRF vulnerability assessment on a target URL.
    
    Parameters:
    -----------
    target_url : str
        The URL to assess for CSRF vulnerabilities
    html_content : str, optional
        HTML content to analyze (for educational simulation)
        
    Returns:
    --------
    dict:
        Assessment results
    """
    analyzer = CSRFVulnerabilityAnalyzer()
    
    # For educational purposes, if no HTML content is provided,
    # we'll generate a simulated page with a form that may or may not have CSRF protection
    if not html_content:
        html_content = _generate_sample_html(include_csrf_token=random.choice([True, False]))
    
    # Analyze the website
    result = analyzer.analyze_website(target_url, html_content)
    
    # Generate PoC for any vulnerable forms
    for form in result['forms']:
        if form['is_vulnerable']:
            form['poc_html'] = analyzer.generate_exploit_poc(form, target_url)
    
    # Add protection examples
    result['protection_examples'] = analyzer.generate_protection_example()
    
    # Add timestamp
    result['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
    
    return result


def _generate_sample_html(include_csrf_token=True):
    """
    Generate sample HTML with a form for educational demonstration.
    
    Parameters:
    -----------
    include_csrf_token : bool
        Whether to include a CSRF token in the form
        
    Returns:
    --------
    str:
        Sample HTML content
    """
    csrf_token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
    
    html = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "    <title>Sample Form</title>",
        "</head>",
        "<body>",
        "    <h1>User Profile Update</h1>",
        "    <form action='/update_profile' method='POST'>",
    ]
    
    if include_csrf_token:
        html.append(f"        <input type='hidden' name='csrf_token' value='{csrf_token}'>")
    
    html.extend([
        "        <div>",
        "            <label for='name'>Name:</label>",
        "            <input type='text' id='name' name='name' value='John Doe'>",
        "        </div>",
        "        <div>",
        "            <label for='email'>Email:</label>",
        "            <input type='email' id='email' name='email' value='john@example.com'>",
        "        </div>",
        "        <div>",
        "            <button type='submit'>Update Profile</button>",
        "        </div>",
        "    </form>",
        "</body>",
        "</html>"
    ])
    
    return "\n".join(html)


def generate_assessment_report(assessment_result):
    """
    Generate a human-readable report from CSRF assessment results.
    
    Parameters:
    -----------
    assessment_result : dict
        Results from simulate_csrf_assessment
        
    Returns:
    --------
    str:
        Formatted report
    """
    report = [
        "CSRF Vulnerability Assessment Report",
        "=====================================",
        f"Target URL: {assessment_result['url']}",
        f"Date: {assessment_result['timestamp']}",
        "",
        "Summary",
        "-------",
        assessment_result['overall_assessment'],
        ""
    ]
    
    # Forms analysis
    report.append("Form Analysis")
    report.append("------------")
    
    for i, form in enumerate(assessment_result['forms'], 1):
        action = form['form_action'] or '[current page]'
        method = form['method']
        
        report.append(f"Form #{i} (Action: {action}, Method: {method})")
        
        if form['is_vulnerable']:
            report.append("Status: VULNERABLE TO CSRF")
            
            if form['vulnerability_reasons']:
                report.append("Vulnerability reasons:")
                for reason in form['vulnerability_reasons']:
                    report.append(f"- {reason}")
        else:
            report.append("Status: Protected against CSRF")
            
            if form['protection_methods']:
                report.append("Protection methods:")
                for method in form['protection_methods']:
                    report.append(f"- {method}")
        
        report.append("Form fields:")
        for field in form['fields']:
            field_type = "Hidden" if field['is_hidden'] else "Visible"
            report.append(f"- {field['name']} ({field_type})")
        
        report.append("")
    
    # Recommendations
    if assessment_result['recommendations']:
        report.append("Recommendations")
        report.append("--------------")
        for rec in assessment_result['recommendations']:
            report.append(f"- {rec}")
        report.append("")
    
    # Educational notes
    report.append("Educational Notes")
    report.append("----------------")
    report.append("Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to submit")
    report.append("unintended requests to a web application in which they're currently authenticated.")
    report.append("")
    report.append("Best practices for CSRF protection:")
    report.append("1. Use anti-CSRF tokens in all state-changing forms")
    report.append("2. Set SameSite cookie attributes (Strict or Lax)")
    report.append("3. Verify Origin and Referer headers")
    report.append("4. Use custom request headers for AJAX requests")
    report.append("5. Implement proper session management")
    report.append("")
    report.append("Remember: This tool is for educational purposes only and should only be used on")
    report.append("websites you own or have explicit permission to test.")
    
    return "\n".join(report)


def main():
    """Main function to run the CSRF simulator from the command line."""
    parser = argparse.ArgumentParser(description='CSRF Vulnerability Simulator (Educational)')
    parser.add_argument('url', help='Target URL to analyze')
    parser.add_argument('--output', help='Output file for assessment results')
    args = parser.parse_args()
    
    # Run the assessment
    print(f"Simulating CSRF assessment for {args.url} (educational purposes only)")
    results = simulate_csrf_assessment(args.url)
    
    # Generate and display report
    report = generate_assessment_report(results)
    print("\n" + report)
    
    # Save results if output file is specified
    if args.output:
        if args.output.endswith('.json'):
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nAssessment results saved to {args.output}")
        else:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\nAssessment report saved to {args.output}")


if __name__ == "__main__":
    main()