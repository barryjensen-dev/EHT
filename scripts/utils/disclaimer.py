"""
Disclaimer utility for the Ethical Hacking Toolkit.

This module provides functions to display ethical usage disclaimers
and warnings for the toolkit scripts.
"""

import sys
from datetime import datetime

def print_disclaimer(script_name, description=None, additional_warning=None):
    """
    Prints a standardized ethical usage disclaimer for toolkit scripts.
    
    Parameters:
    -----------
    script_name : str
        The name of the script being run
    description : str, optional
        A brief description of what the script does
    additional_warning : str, optional
        Any additional warning specific to this script
        
    Returns:
    --------
    None
    """
    border = "=" * 80
    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(border)
    print(f"{script_name.upper()} - ETHICAL USAGE DISCLAIMER".center(80))
    print(border)
    print()
    
    if description:
        print(f"DESCRIPTION: {description}")
        print()
    
    print("WARNING: This script is provided for EDUCATIONAL AND AUTHORIZED SECURITY")
    print("ASSESSMENT PURPOSES ONLY. Using this tool without proper authorization")
    print("may violate laws and regulations in your jurisdiction.")
    print()
    
    if additional_warning:
        print(f"ADDITIONAL WARNING: {additional_warning}")
        print()
    
    print("GUIDELINES FOR ETHICAL USE:")
    print("1. Only use this tool on systems you own or have explicit permission to test")
    print("2. Document all security testing activities")
    print("3. Report vulnerabilities responsibly to the system owners")
    print("4. Follow all applicable laws and regulations")
    print("5. Never use this tool for malicious purposes or unauthorized access")
    print()
    
    print(f"Date and Time: {current_date}")
    print(border)
    print()

def require_confirmation():
    """
    Requires user confirmation before proceeding with script execution.
    
    This function asks the user to explicitly confirm that they will use
    the script ethically and have proper authorization.
    
    Returns:
    --------
    bool:
        True if user confirms, False otherwise
    """
    print("\nConfirmation required:")
    print("By proceeding, you confirm that you:")
    print("1. Have read and understood the disclaimer")
    print("2. Have proper authorization to use this tool")
    print("3. Will use this tool ethically and responsibly")
    print("4. Accept all responsibility for your actions")
    
    while True:
        response = input("\nDo you confirm? (yes/no): ").strip().lower()
        if response in ('yes', 'y'):
            return True
        elif response in ('no', 'n'):
            print("Confirmation denied. Exiting script.")
            return False
        else:
            print("Please enter 'yes' or 'no'.")

def require_legal_confirmation(country=None):
    """
    Requires specific confirmation about legal compliance in the user's jurisdiction.
    
    Parameters:
    -----------
    country : str, optional
        The country or jurisdiction to specifically mention
        
    Returns:
    --------
    bool:
        True if user confirms, False otherwise
    """
    print("\nLegal confirmation required:")
    
    if country:
        print(f"This type of security testing may be regulated in {country}.")
    else:
        print("This type of security testing may be regulated in your jurisdiction.")
    
    print("You must ensure you have the legal right to perform these actions.")
    print("Legal consequences for unauthorized testing can be severe.")
    
    while True:
        response = input("\nDo you confirm you have the legal authority to proceed? (yes/no): ").strip().lower()
        if response in ('yes', 'y'):
            return True
        elif response in ('no', 'n'):
            print("Confirmation denied. Exiting script.")
            return False
        else:
            print("Please enter 'yes' or 'no'.")
