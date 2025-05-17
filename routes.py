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
        web_app_category = Category(
            name='Web Application Security',
            description='Scripts for testing web applications for vulnerabilities',
            icon='globe'
        )
        
        network_category = Category(
            name='Network Security',
            description='Tools for network reconnaissance and security testing',
            icon='wifi'
        )
        
        iot_category = Category(
            name='IoT Security',
            description='Internet of Things security testing tools',
            icon='cpu'
        )
        
        crypto_category = Category(
            name='Cryptography',
            description='Tools for cryptographic analysis and attacks',
            icon='lock'
        )
        
        # Add categories to the database
        db.session.add(web_app_category)
        db.session.add(network_category)
        db.session.add(iot_category)
        db.session.add(crypto_category)
        
        db.session.commit()
        
        # Create scripts
        scripts = [
            Script(
                title='SQL Injection Tester',
                description='A tool to test web applications for SQL injection vulnerabilities',
                module_path='scripts.web_application.sql_injection_tester',
                category_id=web_app_category.id
            ),
            Script(
                title='XSS Scanner',
                description='A scanner for Cross-Site Scripting vulnerabilities in web applications',
                module_path='scripts.web_application.xss_scanner',
                category_id=web_app_category.id
            ),
            Script(
                title='Port Scanner',
                description='A tool to scan for open ports on network hosts',
                module_path='scripts.network.port_scanner',
                category_id=network_category.id
            ),
            Script(
                title='Packet Sniffer',
                description='A network packet capture and analysis tool',
                module_path='scripts.network.packet_sniffer',
                category_id=network_category.id
            ),
            Script(
                title='IoT Device Scanner',
                description='A tool to discover and fingerprint IoT devices on a network',
                module_path='scripts.iot.iot_device_scanner',
                category_id=iot_category.id
            ),
            Script(
                title='Hash Cracker',
                description='A tool to attempt cracking password hashes using various methods',
                module_path='scripts.cryptography.hash_cracker',
                category_id=crypto_category.id
            )
        ]
        
        # Add scripts to the database
        for script in scripts:
            db.session.add(script)
        
        db.session.commit()
        logger.info("Database initialization completed")
