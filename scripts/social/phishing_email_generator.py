"""
Phishing Email Generator

This script provides a framework for generating educational phishing email templates
to demonstrate common phishing techniques and help users learn to identify potentially
malicious emails. It includes various templates and customization options.

This tool is intended for educational purposes and authorized security assessment only.
"""

import argparse
import json
import logging
import random
import time
import os
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of common company names for templates (for educational purposes only)
COMPANIES = [
    {"name": "Example Bank", "domain": "examplebank.com", "industry": "Banking"},
    {"name": "Demo Tech", "domain": "demotech.com", "industry": "Technology"},
    {"name": "Test Services", "domain": "testservices.com", "industry": "Services"},
    {"name": "Sample Healthcare", "domain": "samplehealth.org", "industry": "Healthcare"},
    {"name": "Educational University", "domain": "eduuniversity.edu", "industry": "Education"},
    {"name": "Mock Shop", "domain": "mockshop.com", "industry": "Retail"},
    {"name": "Fictional Cloud", "domain": "fictionalcloud.com", "industry": "Cloud Services"},
    {"name": "Test Delivery", "domain": "testdelivery.com", "industry": "Delivery"},
    {"name": "Example Streaming", "domain": "examplestreaming.com", "industry": "Entertainment"},
    {"name": "Demo Social", "domain": "demosocial.com", "industry": "Social Media"}
]

# Phishing techniques and their descriptions
PHISHING_TECHNIQUES = {
    "credential_harvesting": "Attempts to trick users into entering their credentials on a fake website",
    "malware_delivery": "Attempts to trick users into downloading and running malware",
    "spear_phishing": "Targeted phishing that uses personal information to increase credibility",
    "business_email_compromise": "Impersonates a business executive to request fraudulent transfers",
    "fake_invoice": "Sends a fake invoice requesting payment to an attacker-controlled account",
    "tech_support_scam": "Impersonates tech support to gain system access or payment",
    "account_verification": "Claims account verification is needed to prevent account closure",
    "tax_scam": "Impersonates tax authorities to steal personal and financial information",
    "prize_scam": "Claims the recipient has won a prize but needs to pay fees or provide information",
    "covid_scam": "Exploits the COVID-19 pandemic to create urgency or offer fake services"
}

# Common psychological triggers used in phishing emails
PSYCHOLOGICAL_TRIGGERS = {
    "urgency": "Creates a sense of urgency to force quick, unthinking action",
    "fear": "Instills fear to manipulate recipients into acting",
    "curiosity": "Exploits natural curiosity to entice recipients to click links or open attachments",
    "greed": "Appeals to desire for monetary gain or free items",
    "helpfulness": "Exploits people's natural tendency to be helpful",
    "authority": "Impersonates authority figures to increase compliance",
    "social_proof": "Uses the bandwagon effect and social influence",
    "scarcity": "Creates illusion of limited availability to force quick action",
    "reciprocity": "Offers something to create a feeling of obligation to reciprocate",
    "familiarity": "Creates a false sense of familiarity to build trust"
}

class PhishingEmailGenerator:
    """Class for generating educational phishing email templates."""
    
    def __init__(self):
        """Initialize the phishing email generator."""
        self.templates = self._load_templates()
        
    def _load_templates(self):
        """
        Load email templates from internal dictionary.
        
        Returns:
        --------
        dict:
            Dictionary of templates
        """
        # These templates are for educational purposes only
        templates = {
            "account_security_alert": {
                "subject": "{company} Security Alert: Unusual Sign-In Attempt",
                "body": """
Dear {name},

We detected an unusual sign-in attempt to your {company} account from {location} on {date_time}.

If this wasn't you, your account may be compromised. Please secure your account immediately by clicking the link below:

{link_text}: {link_url}

If you don't take action within 24 hours, your account may be temporarily suspended for security reasons.

Regards,
{company} Security Team
{sender_email}
                """,
                "techniques": ["credential_harvesting", "account_verification"],
                "triggers": ["urgency", "fear"]
            },
            "invoice_payment": {
                "subject": "Invoice #{invoice_number} Payment Required",
                "body": """
Dear {name},

This is a reminder that invoice #{invoice_number} for {amount} is due for payment.

Please review the attached invoice and process the payment as soon as possible to avoid late fees.

If you have questions about this invoice, please contact billing@{sender_domain}.

Payment options:
- Credit Card: Click here to pay online: {link_url}
- Bank Transfer: See account details in the attached invoice

Thank you for your prompt attention to this matter.

Regards,
Accounts Receivable
{company}
{sender_email}
                """,
                "techniques": ["fake_invoice", "malware_delivery"],
                "triggers": ["urgency", "authority"]
            },
            "package_delivery": {
                "subject": "Your Package Delivery #{tracking_number} Update",
                "body": """
Dear {name},

We attempted to deliver your package (Tracking: {tracking_number}) today, but were unable to complete the delivery.

To schedule a new delivery time, please click on the link below and confirm your address:

{link_text}: {link_url}

If we don't hear from you within 3 days, your package will be returned to the sender.

Thank you for your cooperation.

Delivery Management Team
{company}
{sender_email}
                """,
                "techniques": ["credential_harvesting"],
                "triggers": ["urgency", "curiosity"]
            },
            "tax_refund": {
                "subject": "TAX REFUND {tax_year}: {amount} Ready for Processing",
                "body": """
Dear Taxpayer {name},

Good news! After a review of your {tax_year} tax records, we have determined that you are eligible for a refund of {amount}.

To process your refund, we need you to verify your information by clicking on the secure link below:

{link_text}: {link_url}

Please note that refund processing takes 2-3 business days after verification is complete.

Regards,
Tax Refund Department
{sender_email}
                """,
                "techniques": ["tax_scam", "credential_harvesting"],
                "triggers": ["greed", "authority"]
            },
            "shared_document": {
                "subject": "{sender_name} shared a document with you: {document_name}",
                "body": """
Hi {name},

{sender_name} ({sender_email}) has shared a document with you: "{document_name}"

You can view this document by clicking the link below:

{link_text}: {link_url}

This link will expire in 24 hours.

Regards,
{company} Cloud Services
                """,
                "techniques": ["credential_harvesting", "malware_delivery"],
                "triggers": ["curiosity", "familiarity"]
            },
            "password_reset": {
                "subject": "{company} Account: Password Reset Request",
                "body": """
Hello {name},

We received a request to reset the password for your {company} account.

To set a new password, click on the link below:

{link_text}: {link_url}

If you didn't request a password reset, please ignore this email or contact support if you have concerns about your account security.

This password reset link is valid for 30 minutes.

Best regards,
{company} Support Team
{sender_email}
                """,
                "techniques": ["credential_harvesting"],
                "triggers": ["helpfulness", "authority"]
            },
            "subscription_expiring": {
                "subject": "Your {company} subscription is about to expire",
                "body": """
Dear {name},

Your {company} subscription will expire in 3 days.

To avoid interruption of service, please renew your subscription by clicking on the link below:

{link_text}: {link_url}

If your subscription expires, you may lose access to your data and premium features.

Thank you for being a valued customer.

Subscription Management
{company}
{sender_email}
                """,
                "techniques": ["credential_harvesting", "business_email_compromise"],
                "triggers": ["urgency", "fear", "scarcity"]
            },
            "prize_winner": {
                "subject": "CONGRATULATIONS! You've won a {prize_name}!",
                "body": """
CONGRATULATIONS {name}!

You have been selected as the winner of a {prize_name} in our recent prize draw!

To claim your prize, you need to:

1. Click on this link: {link_url}
2. Verify your identity
3. Pay a small processing fee of {amount}

Please claim your prize within 48 hours or it will be awarded to another participant.

Best regards,
Prize Management Team
{company}
{sender_email}
                """,
                "techniques": ["prize_scam", "credential_harvesting"],
                "triggers": ["greed", "urgency", "scarcity"]
            },
            "covid_assistance": {
                "subject": "COVID-19 Financial Assistance Program: You Qualify for {amount}",
                "body": """
Dear {name},

Due to the ongoing COVID-19 pandemic, you qualify for financial assistance of {amount} through the emergency relief program.

To receive your payment, please verify your information at:

{link_text}: {link_url}

Applications must be submitted within 7 days to guarantee processing.

Stay safe,
COVID-19 Relief Administration
{sender_email}
                """,
                "techniques": ["covid_scam", "credential_harvesting"],
                "triggers": ["urgency", "helpfulness", "authority"]
            },
            "it_support": {
                "subject": "URGENT: Your {company} Email Storage is Full",
                "body": """
Dear {name},

Our system has detected that your email account is at 99% capacity. If you don't take action, you may stop receiving emails and could lose data.

To increase your storage or archive old emails, please log in at:

{link_text}: {link_url}

This is an automated notification from the IT department. Please do not reply to this email.

IT Support
{company}
{sender_email}
                """,
                "techniques": ["tech_support_scam", "credential_harvesting"],
                "triggers": ["urgency", "fear", "authority"]
            }
        }
        
        return templates
    
    def generate_phishing_email(self, template_name=None, recipient_name=None, company=None, technique=None, custom_fields=None):
        """
        Generate a phishing email based on template and parameters.
        
        Parameters:
        -----------
        template_name : str
            Name of the template to use (random if None)
        recipient_name : str
            Name of the recipient (random if None)
        company : dict
            Company information (random if None)
        technique : str
            Phishing technique to use (compatible random if None)
        custom_fields : dict
            Custom fields to use in the template
            
        Returns:
        --------
        dict:
            Generated phishing email with metadata
        """
        # Choose a template if not specified
        if not template_name:
            template_name = random.choice(list(self.templates.keys()))
        elif template_name not in self.templates:
            raise ValueError(f"Template '{template_name}' not found")
        
        template = self.templates[template_name]
        
        # If technique is specified, ensure the template supports it
        if technique and technique not in template["techniques"]:
            logger.warning(f"Template '{template_name}' doesn't use technique '{technique}'. Using random supported technique.")
            technique = random.choice(template["techniques"])
        elif not technique:
            technique = random.choice(template["techniques"])
        
        # Generate or use provided company info
        if not company:
            company = random.choice(COMPANIES)
        
        # Generate or use recipient name
        if not recipient_name:
            first_names = ["John", "Jane", "Alex", "Sam", "Taylor", "Jordan", "Casey", "Morgan", "Jamie", "Riley"]
            last_names = ["Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor"]
            recipient_name = f"{random.choice(first_names)} {random.choice(last_names)}"
        
        # Prepare default fields
        fields = {
            "name": recipient_name,
            "company": company["name"],
            "sender_domain": company["domain"],
            "sender_email": f"{self._generate_sender_name(company)}@{company['domain']}",
            "sender_name": self._generate_sender_name(company, as_full_name=True),
            "date_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "location": f"{self._random_city()}, {self._random_country()}",
            "link_text": self._generate_link_text(technique),
            "link_url": self._generate_phishing_url(company, technique),
            "amount": f"${random.randint(100, 9999)}.{random.randint(0, 99):02d}",
            "invoice_number": f"INV-{random.randint(10000, 99999)}",
            "tracking_number": f"{random.choice(['TRK', 'PKG', 'SHP'])}{random.randint(1000000, 9999999)}",
            "document_name": f"{random.choice(['Report', 'Invoice', 'Contract', 'Agreement', 'Proposal'])}-{random.randint(1000, 9999)}.{random.choice(['pdf', 'docx', 'xlsx'])}",
            "tax_year": datetime.now().year - 1,
            "prize_name": random.choice(["iPhone", "MacBook Pro", "Amazon Gift Card", "$5,000 Cash Prize", "Dream Vacation"])
        }
        
        # Update with custom fields if provided
        if custom_fields:
            fields.update(custom_fields)
        
        # Format the template
        subject = template["subject"].format(**fields)
        body = template["body"].format(**fields)
        
        # Prepare the result with metadata
        result = {
            "template_name": template_name,
            "subject": subject,
            "body": body,
            "recipient": {
                "name": recipient_name,
                "email": self._generate_recipient_email(recipient_name)
            },
            "sender": {
                "name": fields["sender_name"] if "sender_name" in fields else None,
                "email": fields["sender_email"]
            },
            "company": company,
            "technique": {
                "name": technique,
                "description": PHISHING_TECHNIQUES.get(technique, "Unknown technique")
            },
            "psychological_triggers": [
                {
                    "name": trigger,
                    "description": PSYCHOLOGICAL_TRIGGERS.get(trigger, "Unknown trigger")
                }
                for trigger in template["triggers"]
            ],
            "indicators": self._generate_phishing_indicators(subject, body, fields),
            "metadata": {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "fields_used": list(fields.keys())
            }
        }
        
        return result
    
    def _generate_sender_name(self, company, as_full_name=False):
        """
        Generate a plausible sender name based on company and email type.
        
        Parameters:
        -----------
        company : dict
            Company information
        as_full_name : bool
            Whether to return a full name instead of an email username
            
        Returns:
        --------
        str:
            Generated sender name
        """
        department_emails = [
            "support", "helpdesk", "service", "billing", "account", "security", 
            "admin", "notifications", "alerts", "info", "team", "noreply"
        ]
        
        person_first_names = ["John", "Jane", "Michael", "Sarah", "David", "Jennifer", "Robert", "Lisa"]
        person_last_names = ["Smith", "Johnson", "Williams", "Jones", "Brown", "Miller", "Davis", "Wilson"]
        
        if as_full_name:
            return f"{random.choice(person_first_names)} {random.choice(person_last_names)}"
        
        # 60% chance of department email, 40% chance of person email
        if random.random() < 0.6:
            return random.choice(department_emails)
        else:
            first = random.choice(person_first_names).lower()
            last = random.choice(person_last_names).lower()
            
            # Different formats for email usernames
            formats = [
                f"{first}.{last}",
                f"{first[0]}{last}",
                f"{first}{last[0]}",
                f"{first}{random.randint(1, 99)}"
            ]
            
            return random.choice(formats)
    
    def _generate_recipient_email(self, name):
        """
        Generate a plausible recipient email based on their name.
        
        Parameters:
        -----------
        name : str
            Recipient's name
            
        Returns:
        --------
        str:
            Generated email address
        """
        domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com", "protonmail.com"]
        
        # Parse name into components
        name_parts = name.lower().split()
        if len(name_parts) >= 2:
            first = name_parts[0]
            last = name_parts[-1]
            
            # Different formats for email usernames
            formats = [
                f"{first}.{last}@{random.choice(domains)}",
                f"{first}{last}@{random.choice(domains)}",
                f"{first}{last[0]}@{random.choice(domains)}",
                f"{first[0]}{last}@{random.choice(domains)}",
                f"{first}{random.randint(1, 99)}@{random.choice(domains)}"
            ]
            
            return random.choice(formats)
        else:
            # If we can't parse the name properly
            return f"{name.lower().replace(' ', '')}{random.randint(1, 999)}@{random.choice(domains)}"
    
    def _random_city(self):
        """
        Return a random city name for location simulation.
        
        Returns:
        --------
        str:
            Random city name
        """
        cities = [
            "New York", "London", "Tokyo", "Paris", "Moscow", "Beijing", "Sydney", 
            "Berlin", "Mumbai", "Cairo", "Toronto", "Rio de Janeiro", "Singapore"
        ]
        return random.choice(cities)
    
    def _random_country(self):
        """
        Return a random country name for location simulation.
        
        Returns:
        --------
        str:
            Random country name
        """
        countries = [
            "United States", "United Kingdom", "Japan", "France", "Russia", "China", 
            "Australia", "Germany", "India", "Egypt", "Canada", "Brazil", "Singapore"
        ]
        return random.choice(countries)
    
    def _generate_link_text(self, technique):
        """
        Generate appropriate link text based on phishing technique.
        
        Parameters:
        -----------
        technique : str
            Phishing technique
            
        Returns:
        --------
        str:
            Generated link text
        """
        link_texts = {
            "credential_harvesting": [
                "Secure your account", "Verify your identity", "Sign in to continue", 
                "Reset your password", "Confirm your account"
            ],
            "malware_delivery": [
                "Download your file", "View document", "Open attachment", 
                "Download invoice", "View report"
            ],
            "fake_invoice": [
                "View invoice details", "Pay now", "Download invoice", 
                "Review payment", "Check invoice status"
            ],
            "prize_scam": [
                "Claim your prize", "Verify eligibility", "Confirm your win", 
                "Get your reward", "Accept prize"
            ],
            "covid_scam": [
                "Apply for assistance", "Check eligibility", "Submit application", 
                "Claim benefits", "Complete verification"
            ],
            "tax_scam": [
                "Claim your refund", "Verify tax information", "Process refund", 
                "Complete tax verification", "Submit refund request"
            ]
        }
        
        default_texts = [
            "Click here", "Visit link", "Continue", "Proceed", "Open"
        ]
        
        technique_texts = link_texts.get(technique, default_texts)
        return random.choice(technique_texts)
    
    def _generate_phishing_url(self, company, technique):
        """
        Generate a believable phishing URL for educational demonstration.
        
        Parameters:
        -----------
        company : dict
            Company information
        technique : str
            Phishing technique
            
        Returns:
        --------
        str:
            Generated phishing URL
        """
        # Generate URLs for educational purposes only
        company_domain = company["domain"]
        
        # Different phishing URL patterns
        patterns = [
            # Typosquatting examples
            f"https://{self._typosquat(company_domain)}/account/verify",
            f"https://{company_domain.replace('.', '-')}.suspicious-domain.com/login",
            
            # Subdomain abuse examples
            f"https://{company_domain}.{self._random_subdomain()}.phishing-demo.com/verification",
            
            # Path confusion examples
            f"https://secure-{self._random_chars(8)}.com/{company_domain}/security",
            
            # URL shortener simulation
            f"https://sh.rt/{self._random_chars(6)}",
            
            # Long/confusing URLs
            f"https://{self._random_subdomain()}.com/authentication?company={company_domain}&redirect={self._random_chars(32)}",
            
            # IDN homograph example (educational representation)
            f"https://{self._homograph_simulation(company_domain)}/account"
        ]
        
        # Choose appropriate URL pattern based on technique
        if technique == "credential_harvesting":
            return random.choice([patterns[0], patterns[1], patterns[2], patterns[6]])
        elif technique == "malware_delivery":
            return f"https://download-{self._random_chars(8)}.net/document?id={self._random_chars(16)}"
        else:
            return random.choice(patterns)
    
    def _typosquat(self, domain):
        """
        Generate a typosquatting domain for educational purposes.
        
        Parameters:
        -----------
        domain : str
            Original domain
            
        Returns:
        --------
        str:
            Typosquatted domain
        """
        # Various typosquatting techniques
        name, tld = domain.split('.', 1)
        
        techniques = [
            # Character omission
            name[1:] + '.' + tld if len(name) > 1 else name + '.' + tld,
            
            # Character duplication
            name + name[-1] + '.' + tld,
            
            # Adjacent character swap
            name[0] + name[2] + name[1] + name[3:] + '.' + tld if len(name) > 3 else name + '.' + tld,
            
            # Character replacement
            name.replace('e', '3').replace('i', '1').replace('a', '4') + '.' + tld,
            
            # TLD variation
            name + '.' + random.choice(['org', 'net', 'info', 'co']) if tld == 'com' else name + '.com',
            
            # Hyphenation
            name[:len(name)//2] + '-' + name[len(name)//2:] + '.' + tld if len(name) > 2 else name + '.' + tld
        ]
        
        return random.choice(techniques)
    
    def _random_subdomain(self):
        """
        Generate a random subdomain for educational phishing URLs.
        
        Returns:
        --------
        str:
            Random subdomain
        """
        prefixes = ['secure', 'login', 'account', 'signin', 'verify', 'auth', 'service']
        suffixes = ['portal', 'service', 'center', 'verify', 'secure', 'site']
        
        if random.random() < 0.5:
            return random.choice(prefixes) + '-' + self._random_chars(4)
        else:
            return random.choice(prefixes) + random.choice(suffixes)
    
    def _random_chars(self, length=8):
        """
        Generate a random string of characters.
        
        Parameters:
        -----------
        length : int
            Length of the string
            
        Returns:
        --------
        str:
            Random string
        """
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _homograph_simulation(self, domain):
        """
        Simulate IDN homograph attacks (for educational purposes).
        
        Parameters:
        -----------
        domain : str
            Original domain
            
        Returns:
        --------
        str:
            Simulated homograph domain
        """
        # Since actual Unicode homographs might be used maliciously,
        # we'll just simulate them for educational purposes
        name, tld = domain.split('.', 1)
        return f"{name}-homograph-example.{tld}"
    
    def _generate_phishing_indicators(self, subject, body, fields):
        """
        Generate a list of phishing indicators for educational purposes.
        
        Parameters:
        -----------
        subject : str
            Email subject
        body : str
            Email body
        fields : dict
            Template fields
            
        Returns:
        --------
        list:
            List of phishing indicators
        """
        indicators = []
        
        # Check for urgency language
        urgency_phrases = ["urgent", "immediate", "alert", "warning", "attention", "action required"]
        if any(phrase in subject.lower() for phrase in urgency_phrases):
            indicators.append({
                "type": "urgency_subject",
                "description": "Subject line creates a false sense of urgency",
                "example": subject
            })
        
        # Check for suspicious sender
        if "@" in fields.get("sender_email", ""):
            sender_domain = fields["sender_email"].split("@")[1]
            if sender_domain != fields["sender_domain"]:
                indicators.append({
                    "type": "mismatched_sender",
                    "description": "Email sender domain doesn't match claimed company",
                    "example": f"Email from {fields['sender_email']} claims to be from {fields['company']}"
                })
        
        # Check for suspicious URLs
        if "link_url" in fields:
            link_url = fields["link_url"]
            company_domain = fields["sender_domain"]
            
            if company_domain not in link_url or "-" in link_url or "suspicious" in link_url:
                indicators.append({
                    "type": "suspicious_url",
                    "description": "Link URL doesn't match the claimed company domain",
                    "example": link_url
                })
        
        # Check for generic greeting
        generic_greetings = ["dear customer", "dear valued customer", "dear user", "hello", "dear sir/madam"]
        if any(greeting in body.lower()[:30] for greeting in generic_greetings):
            indicators.append({
                "type": "generic_greeting",
                "description": "Email uses a generic greeting instead of personalizing",
                "example": body.split("\n")[0]
            })
        
        # Check for poor grammar or spelling
        # (simplified check for educational purposes)
        grammar_issues = ["kindly", "please to", "immediate action require", "verify you account"]
        if any(issue in body.lower() for issue in grammar_issues):
            indicators.append({
                "type": "grammar_issues",
                "description": "Email contains grammar or spelling errors",
                "example": "Contains phrases like 'kindly' that are common in phishing emails"
            })
        
        # Check for requests for personal information
        if "verify your information" in body.lower() or "confirm your details" in body.lower():
            indicators.append({
                "type": "information_request",
                "description": "Email requests personal or sensitive information",
                "example": "Asks recipient to verify or confirm personal details"
            })
        
        # Check for unexpected attachments or links
        if "attachment" in body.lower() or "download" in body.lower():
            indicators.append({
                "type": "unexpected_attachment",
                "description": "Email references unexpected attachments or downloads",
                "example": "Prompts recipient to download files or open attachments"
            })
        
        # Check for mismatched link text and URL
        if "link_text" in fields and "link_url" in fields:
            if "secure" in fields["link_text"].lower() and "suspicious" in fields["link_url"]:
                indicators.append({
                    "type": "mismatched_link",
                    "description": "Link text doesn't match the actual URL destination",
                    "example": f"Text says '{fields['link_text']}' but URL is '{fields['link_url']}'"
                })
        
        # Add one random general indicator for educational purposes
        general_indicators = [
            {
                "type": "unusual_sender",
                "description": "Email comes from an unusual or unexpected sender",
                "example": f"Email from {fields.get('sender_email', 'unknown')} when you weren't expecting it"
            },
            {
                "type": "unusual_timing",
                "description": "Email received at an unusual time",
                "example": "Email sent at 3:27 AM"
            },
            {
                "type": "unexpected_email",
                "description": "Email is unexpected and unsolicited",
                "example": "Receiving an email about an account or service you don't have"
            }
        ]
        
        indicators.append(random.choice(general_indicators))
        
        return indicators
    
    def get_available_templates(self):
        """
        Get a list of available templates with their details.
        
        Returns:
        --------
        list:
            List of template details
        """
        result = []
        for name, template in self.templates.items():
            result.append({
                "name": name,
                "subject_template": template["subject"],
                "techniques": template["techniques"],
                "triggers": template["triggers"]
            })
        
        return result
    
    def get_available_techniques(self):
        """
        Get a list of available phishing techniques with descriptions.
        
        Returns:
        --------
        dict:
            Dictionary of techniques and descriptions
        """
        return PHISHING_TECHNIQUES
    
    def get_psychological_triggers(self):
        """
        Get a list of psychological triggers used in phishing.
        
        Returns:
        --------
        dict:
            Dictionary of triggers and descriptions
        """
        return PSYCHOLOGICAL_TRIGGERS

def generate_phishing_email_example(template=None, recipient=None, company=None, technique=None, custom_fields=None):
    """
    Generate a phishing email example for educational purposes.
    
    Parameters:
    -----------
    template : str
        Template name to use (random if None)
    recipient : str
        Recipient name (random if None)
    company : str
        Company name to impersonate (random if None)
    technique : str
        Phishing technique to use (compatible random if None)
    custom_fields : dict
        Custom fields to use in the template
        
    Returns:
    --------
    dict:
        Generated phishing email with metadata
    """
    generator = PhishingEmailGenerator()
    
    # If company is a string, convert to dict format
    if company and isinstance(company, str):
        company_obj = None
        for comp in COMPANIES:
            if comp["name"].lower() == company.lower():
                company_obj = comp
                break
        
        if not company_obj:
            company_obj = {
                "name": company,
                "domain": company.lower().replace(" ", "") + ".com",
                "industry": "Unknown"
            }
        
        company = company_obj
    
    return generator.generate_phishing_email(
        template_name=template, 
        recipient_name=recipient, 
        company=company, 
        technique=technique, 
        custom_fields=custom_fields
    )

def analyze_email_for_phishing(subject, body, sender=None):
    """
    Analyze an email to identify potential phishing indicators.
    
    Parameters:
    -----------
    subject : str
        Email subject
    body : str
        Email body
    sender : str
        Email sender
        
    Returns:
    --------
    dict:
        Analysis results with phishing indicators
    """
    indicators = []
    risk_score = 0
    
    # Check for urgency language in subject
    urgency_phrases = ["urgent", "immediate", "alert", "warning", "attention", "action required"]
    if any(phrase in subject.lower() for phrase in urgency_phrases):
        indicators.append({
            "type": "urgency_subject",
            "description": "Subject creates a false sense of urgency",
            "severity": "medium"
        })
        risk_score += 2
    
    # Check for suspicious sender
    if sender:
        suspicious_domains = ["mail.com", "gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
        expected_business_domain = False
        
        for domain in suspicious_domains:
            if domain in sender:
                if any(business in sender.lower() for business in ["bank", "paypal", "amazon", "microsoft", "apple", "google"]):
                    indicators.append({
                        "type": "suspicious_sender",
                        "description": f"Business entity using a free email provider: {sender}",
                        "severity": "high"
                    })
                    risk_score += 3
                    expected_business_domain = True
        
        # If sender has unusual characters
        if any(char in sender for char in "!#$%^&*()+="):
            indicators.append({
                "type": "unusual_sender_chars",
                "description": "Sender email contains unusual characters",
                "severity": "high"
            })
            risk_score += 3
    
    # Check for suspicious URLs
    urls = []
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s]*)?'
    found_urls = re.findall(url_pattern, body)
    
    for url in found_urls:
        urls.append(url)
        
        # Check for suspicious domains in the URL
        suspicious_domains = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "tiny.cc"]
        if any(domain in url for domain in suspicious_domains):
            indicators.append({
                "type": "url_shortener",
                "description": f"Email contains shortened URL: {url}",
                "severity": "medium"
            })
            risk_score += 2
        
        # Check for mismatched URLs and link text
        link_text_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        link_matches = re.findall(link_text_pattern, body)
        
        for text, link in link_matches:
            if "secure" in text.lower() and not (link.startswith("https") or "secure" in link.lower()):
                indicators.append({
                    "type": "mismatched_link",
                    "description": f"Link text '{text}' doesn't match URL '{link}'",
                    "severity": "high"
                })
                risk_score += 3
    
    # Check for requests for sensitive information
    sensitive_phrases = [
        "verify your account", "confirm your details", "update your information",
        "credit card", "social security", "password", "login credentials", "banking details"
    ]
    
    for phrase in sensitive_phrases:
        if phrase in body.lower():
            indicators.append({
                "type": "information_request",
                "description": f"Email requests sensitive information: '{phrase}'",
                "severity": "high"
            })
            risk_score += 3
            break
    
    # Check for suspicious attachments
    attachment_patterns = [
        r'\.zip file', r'\.exe file', r'\.pdf attached', r'open the attachment',
        r'see attachment', r'attached file', r'attached invoice'
    ]
    
    for pattern in attachment_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            indicators.append({
                "type": "suspicious_attachment",
                "description": "Email references attachments",
                "severity": "medium"
            })
            risk_score += 2
            break
    
    # Check for poor grammar and spelling
    grammar_issues = [
        "kindly", "please to", "immediate action require", "verify you account",
        "dear costumer", "dear valued customer", "your account has been compromized"
    ]
    
    grammar_issue_count = sum(1 for issue in grammar_issues if issue in body.lower())
    if grammar_issue_count >= 2:
        indicators.append({
            "type": "grammar_issues",
            "description": f"Email contains {grammar_issue_count} grammar or spelling issues",
            "severity": "medium"
        })
        risk_score += grammar_issue_count
    
    # Calculate final risk score and classification
    if risk_score >= 8:
        classification = "High risk - Likely phishing"
    elif risk_score >= 4:
        classification = "Medium risk - Suspicious"
    elif risk_score >= 1:
        classification = "Low risk - Some concerns"
    else:
        classification = "Minimal risk - Likely legitimate"
    
    return {
        "indicators": indicators,
        "risk_score": risk_score,
        "classification": classification,
        "urls_found": urls,
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def generate_educational_report(email_data):
    """
    Generate an educational report about a phishing email.
    
    Parameters:
    -----------
    email_data : dict
        Phishing email data from generate_phishing_email_example
        
    Returns:
    --------
    str:
        Educational report
    """
    # Extract key information
    technique = email_data["technique"]["name"]
    technique_desc = email_data["technique"]["description"]
    triggers = email_data["psychological_triggers"]
    indicators = email_data["indicators"]
    
    # Build the report
    report = [
        "===== PHISHING EMAIL EDUCATIONAL REPORT =====",
        "",
        "This is an educational analysis of a simulated phishing email.",
        "",
        f"SUBJECT: {email_data['subject']}",
        f"FROM: {email_data['sender']['name']} <{email_data['sender']['email']}>",
        f"TO: {email_data['recipient']['name']} <{email_data['recipient']['email']}>",
        "",
        "--- EMAIL BODY ---",
        email_data['body'],
        "--- END EMAIL ---",
        "",
        "PHISHING TECHNIQUE:",
        f"* {technique}: {technique_desc}",
        "",
        "PSYCHOLOGICAL TRIGGERS USED:",
    ]
    
    for trigger in triggers:
        report.append(f"* {trigger['name']}: {trigger['description']}")
    
    report.append("")
    report.append("PHISHING INDICATORS:")
    
    for indicator in indicators:
        report.append(f"* {indicator['type']}: {indicator['description']}")
        if "example" in indicator:
            report.append(f"  Example: {indicator['example']}")
    
    report.append("")
    report.append("HOW TO IDENTIFY THIS PHISHING ATTEMPT:")
    
    # Add specific advice based on the template and technique
    if technique == "credential_harvesting":
        report.extend([
            "1. Check the sender's email address carefully - does it match the claimed organization?",
            "2. Hover over links (don't click) to see where they actually go",
            "3. Be suspicious of urgent requests for account verification",
            "4. Contact the company directly through official channels, not via reply"
        ])
    elif technique == "fake_invoice":
        report.extend([
            "1. Verify all invoices through your company's finance department",
            "2. Check if you've done business with this vendor before",
            "3. Be wary of unexpected invoices or payment requests",
            "4. Never open attachments from unknown or suspicious senders"
        ])
    else:
        report.extend([
            "1. Be suspicious of unexpected emails, especially those creating urgency",
            "2. Check sender email addresses carefully",
            "3. Do not click on links or download attachments unless you're certain of their legitimacy",
            "4. When in doubt, contact the purported sender through official channels"
        ])
    
    report.append("")
    report.append("GENERAL PHISHING PREVENTION TIPS:")
    report.extend([
        "1. Use multi-factor authentication when available",
        "2. Keep software and browsers updated",
        "3. Use anti-phishing tools and security software",
        "4. Be skeptical of emails requesting personal information",
        "5. Verify requests through official channels or phone numbers",
        "6. Report suspected phishing to your IT department and the impersonated organization"
    ])
    
    report.append("")
    report.append("This educational example was generated for cybersecurity awareness training.")
    report.append("===== END OF REPORT =====")
    
    return "\n".join(report)

def main():
    """Main function to run the phishing email generator from the command line."""
    parser = argparse.ArgumentParser(
        description='Phishing Email Generator for Educational Purposes',
        epilog='This tool is intended for cybersecurity education and authorized security assessments only.'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate a sample phishing email')
    generate_parser.add_argument('--template', help='Template name to use')
    generate_parser.add_argument('--recipient', help='Recipient name')
    generate_parser.add_argument('--company', help='Company name to impersonate')
    generate_parser.add_argument('--technique', help='Phishing technique to use')
    generate_parser.add_argument('--output', help='Output file for email data (JSON)')
    generate_parser.add_argument('--report', action='store_true', help='Generate educational report')
    
    # List templates command
    templates_parser = subparsers.add_parser('templates', help='List available templates')
    
    # List techniques command
    techniques_parser = subparsers.add_parser('techniques', help='List available phishing techniques')
    
    # List triggers command
    triggers_parser = subparsers.add_parser('triggers', help='List psychological triggers used in phishing')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze an email for phishing indicators')
    analyze_parser.add_argument('--subject', required=True, help='Email subject')
    analyze_parser.add_argument('--body', required=True, help='Email body')
    analyze_parser.add_argument('--sender', help='Email sender')
    analyze_parser.add_argument('--output', help='Output file for analysis (JSON)')
    
    args = parser.parse_args()
    
    # Create generator
    generator = PhishingEmailGenerator()
    
    if args.command == 'generate':
        email_data = generate_phishing_email_example(
            template=args.template,
            recipient=args.recipient,
            company=args.company,
            technique=args.technique
        )
        
        # Print the generated email
        print(f"\nSubject: {email_data['subject']}")
        print(f"From: {email_data['sender']['name']} <{email_data['sender']['email']}>")
        print(f"To: {email_data['recipient']['name']} <{email_data['recipient']['email']}>")
        print("\n" + email_data['body'])
        
        # Generate report if requested
        if args.report:
            report = generate_educational_report(email_data)
            print("\n\n" + report)
        
        # Save to file if output specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(email_data, f, indent=2)
            print(f"\nEmail data saved to: {args.output}")
    
    elif args.command == 'templates':
        templates = generator.get_available_templates()
        
        print("\nAvailable Templates:")
        for i, template in enumerate(templates, 1):
            print(f"\n{i}. {template['name']}")
            print(f"   Subject: {template['subject_template']}")
            print(f"   Techniques: {', '.join(template['techniques'])}")
            print(f"   Triggers: {', '.join(template['triggers'])}")
    
    elif args.command == 'techniques':
        techniques = generator.get_available_techniques()
        
        print("\nPhishing Techniques:")
        for technique, description in techniques.items():
            print(f"\n- {technique.replace('_', ' ').title()}")
            print(f"  {description}")
    
    elif args.command == 'triggers':
        triggers = generator.get_psychological_triggers()
        
        print("\nPsychological Triggers in Phishing:")
        for trigger, description in triggers.items():
            print(f"\n- {trigger.title()}")
            print(f"  {description}")
    
    elif args.command == 'analyze':
        analysis = analyze_email_for_phishing(args.subject, args.body, args.sender)
        
        print("\nEmail Phishing Analysis:")
        print(f"Classification: {analysis['classification']}")
        print(f"Risk Score: {analysis['risk_score']}/10")
        
        if analysis['indicators']:
            print("\nPhishing Indicators Detected:")
            for indicator in analysis['indicators']:
                print(f"- {indicator['type']} ({indicator['severity']})")
                print(f"  {indicator['description']}")
        else:
            print("\nNo phishing indicators detected.")
        
        if analysis['urls_found']:
            print("\nURLs Found:")
            for url in analysis['urls_found']:
                print(f"- {url}")
        
        # Save analysis to file if output specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(analysis, f, indent=2)
            print(f"\nAnalysis saved to: {args.output}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()