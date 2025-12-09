#!/usr/bin/env python3
"""
SplitSmart Web Application
Flask-based web UI for the SplitSmart secure expense splitting system.
"""

import json
import os
from flask import Flask, render_template, request, jsonify, session, g
from flask_cors import CORS
from datetime import datetime, timedelta
import threading
import bcrypt
import time
import hashlib
import hmac as hmac_lib
from functools import wraps
from collections import defaultdict
from typing import Optional

from server.server import SplitSmartServer
from client.client import SplitSmartClient

app = Flask(__name__)
# Use environment variable for secret key in production
app.secret_key = os.environ.get('SECRET_KEY', 'split-smart-secure-key-change-in-production')
CORS(app)

# Global server instance (shared across requests)
_server_instance = None
_server_lock = threading.Lock()

# Rate limiting storage
_rate_limit_store = defaultdict(list)
_rate_limit_lock = threading.Lock()

# API security configuration
RATE_LIMIT_REQUESTS = 100  # requests per window
RATE_LIMIT_WINDOW = 60  # seconds
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB
MIN_PASSWORD_LENGTH = 6
MAX_USERNAME_LENGTH = 50
MAX_DESCRIPTION_LENGTH = 500
MAX_AMOUNT = 1000000  # $1,000,000

def get_server():
    """Get or create server instance (thread-safe)."""
    global _server_instance
    with _server_lock:
        if _server_instance is None:
            _server_instance = SplitSmartServer()
    return _server_instance

# Security decorators and utilities
def rate_limit(max_requests: int = RATE_LIMIT_REQUESTS, window: int = RATE_LIMIT_WINDOW):
    """Rate limiting decorator."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier
            client_id = request.remote_addr
            if session.get('user_id'):
                client_id = f"{client_id}:{session.get('user_id')}"
            
            current_time = time.time()
            
            with _rate_limit_lock:
                # Clean old entries
                _rate_limit_store[client_id] = [
                    req_time for req_time in _rate_limit_store[client_id]
                    if current_time - req_time < window
                ]
                
                # Check rate limit
                if len(_rate_limit_store[client_id]) >= max_requests:
                    return jsonify({
                        'success': False,
                        'error': 'Rate limit exceeded. Please try again later.'
                    }), 429
                
                # Add current request
                _rate_limit_store[client_id].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_input(data: dict, rules: dict) -> tuple[bool, Optional[str]]:
    """
    Validate input data against rules.
    
    Args:
        data: Input data dictionary
        rules: Validation rules dictionary
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    for field, rule in rules.items():
        value = data.get(field)
        
        # Required check
        if rule.get('required', False) and (value is None or value == ''):
            return False, f"{field} is required"
        
        if value is None:
            continue
        
        # Type check
        if 'type' in rule:
            if rule['type'] == 'str' and not isinstance(value, str):
                return False, f"{field} must be a string"
            elif rule['type'] == 'float' and not isinstance(value, (int, float)):
                return False, f"{field} must be a number"
            elif rule['type'] == 'int' and not isinstance(value, int):
                return False, f"{field} must be an integer"
        
        # String validation
        if isinstance(value, str):
            if 'min_length' in rule and len(value) < rule['min_length']:
                return False, f"{field} must be at least {rule['min_length']} characters"
            if 'max_length' in rule and len(value) > rule['max_length']:
                return False, f"{field} must be at most {rule['max_length']} characters"
            if 'pattern' in rule:
                import re
                if not re.match(rule['pattern'], value):
                    return False, f"{field} format is invalid"
        
        # Number validation
        if isinstance(value, (int, float)):
            if 'min' in rule and value < rule['min']:
                return False, f"{field} must be at least {rule['min']}"
            if 'max' in rule and value > rule['max']:
                return False, f"{field} must be at most {rule['max']}"
    
    return True, None

def sanitize_string(value: str, max_length: int = 1000) -> str:
    """Sanitize string input."""
    if not isinstance(value, str):
        return ""
    # Remove null bytes and control characters
    sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\n\r\t')
    # Truncate to max length
    return sanitized[:max_length].strip()

@app.before_request
def security_checks():
    """Perform security checks before processing requests."""
    # Check request size
    if request.content_length and request.content_length > MAX_REQUEST_SIZE:
        return jsonify({
            'success': False,
            'error': 'Request too large'
        }), 413

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Store active clients per session
clients = {}

@app.route('/')
def index():
    """Main page."""
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
@rate_limit(max_requests=10, window=60)  # 10 registrations per minute
def api_register():
    """Register a new user with password."""
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400
        
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON'}), 400
        
        # Validate input
        validation_rules = {
            'username': {
                'required': True,
                'type': 'str',
                'min_length': 1,
                'max_length': MAX_USERNAME_LENGTH,
                'pattern': r'^[a-zA-Z0-9_-]+$'  # Alphanumeric, underscore, hyphen only
            },
            'password': {
                'required': True,
                'type': 'str',
                'min_length': MIN_PASSWORD_LENGTH,
                'max_length': 128
            }
        }
        
        is_valid, error_msg = validate_input(data, validation_rules)
        if not is_valid:
            return jsonify({'success': False, 'error': error_msg}), 400
        
        username = sanitize_string(data.get('username', '').strip(), MAX_USERNAME_LENGTH)
        password = data.get('password', '').strip()
        
        # Additional password strength check
        if len(password) < MIN_PASSWORD_LENGTH:
            return jsonify({'success': False, 'error': f'Password must be at least {MIN_PASSWORD_LENGTH} characters'}), 400
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        server = get_server()
        client = SplitSmartClient(username, server)
        
        # Generate keys if not exists
        if not client.crypto.load_keys():
            public_key_pem = client.crypto.generate_keys()
        else:
            public_key_pem = client.crypto.get_public_key_pem()
        
        # Register with server (including password hash)
        success = server.register_user(username, public_key_pem, password_hash)
        
        if success:
            # Store client in session
            session['user_id'] = username
            clients[username] = client
            
            return jsonify({
                'success': True,
                'message': f'User {username} registered successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'User {username} already exists'
            }), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
@rate_limit(max_requests=5, window=60)  # 5 login attempts per minute
def api_login():
    """Login with password and establish secure session."""
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400
        
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON'}), 400
        
        # Validate input
        validation_rules = {
            'username': {
                'required': True,
                'type': 'str',
                'min_length': 1,
                'max_length': MAX_USERNAME_LENGTH
            },
            'password': {
                'required': True,
                'type': 'str',
                'min_length': 1
            }
        }
        
        is_valid, error_msg = validate_input(data, validation_rules)
        if not is_valid:
            return jsonify({'success': False, 'error': error_msg}), 400
        
        username = sanitize_string(data.get('username', '').strip(), MAX_USERNAME_LENGTH)
        password = data.get('password', '').strip()
        
        server = get_server()
        
        # Verify password first
        if not server.verify_user_password(username, password):
            return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
        
        # Get or create client
        if username not in clients:
            client = SplitSmartClient(username, server)
            clients[username] = client
        else:
            client = clients[username]
        
        # Login (establish secure session)
        success = client.login()
        
        if success:
            session['user_id'] = username
            return jsonify({
                'success': True,
                'message': f'Logged in as {username}',
                'session_id': client.crypto.session_id
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to establish secure session'}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Logout current user."""
    username = session.pop('user_id', None)
    if username and username in clients:
        # Clear session but keep client for potential re-login
        pass
    return jsonify({'success': True, 'message': 'Logged out'})

@app.route('/api/add_expense', methods=['POST'])
@rate_limit(max_requests=50, window=60)  # 50 expenses per minute
def api_add_expense():
    """Add an expense."""
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        
        if username not in clients:
            return jsonify({'success': False, 'error': 'Session expired'}), 401
        
        client = clients[username]
        
        if not client.crypto.has_session():
            return jsonify({'success': False, 'error': 'Session expired. Please login again'}), 401
        
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400
        
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON'}), 400
        
        # Validate input
        validation_rules = {
            'payer': {
                'required': True,
                'type': 'str',
                'min_length': 1,
                'max_length': MAX_USERNAME_LENGTH,
                'pattern': r'^[a-zA-Z0-9_-]+$'
            },
            'amount': {
                'required': True,
                'type': 'float',
                'min': 0.01,
                'max': MAX_AMOUNT
            },
            'description': {
                'required': True,
                'type': 'str',
                'min_length': 1,
                'max_length': MAX_DESCRIPTION_LENGTH
            }
        }
        
        is_valid, error_msg = validate_input(data, validation_rules)
        if not is_valid:
            return jsonify({'success': False, 'error': error_msg}), 400
        
        payer = sanitize_string(data.get('payer', '').strip(), MAX_USERNAME_LENGTH)
        amount = float(data.get('amount', 0))
        description = sanitize_string(data.get('description', '').strip(), MAX_DESCRIPTION_LENGTH)
        
        # Additional validation
        if amount <= 0 or amount > MAX_AMOUNT:
            return jsonify({'success': False, 'error': f'Amount must be between $0.01 and ${MAX_AMOUNT:,.2f}'}), 400
        
        success = client.add_expense(payer, amount, description)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Expense added: {payer} paid ${amount:.2f} for {description}'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to add expense'}), 400
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid amount'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ledger', methods=['GET'])
def api_ledger():
    """Get ledger entries."""
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        
        if username not in clients:
            return jsonify({'success': False, 'error': 'Session expired'}), 401
        
        client = clients[username]
        
        if not client.crypto.has_session():
            return jsonify({'success': False, 'error': 'Session expired. Please login again'}), 401
        
        entries = client.view_ledger()
        
        if entries is None:
            # Try to get entries directly from server
            server = get_server()
            entries = server.ledger.get_all_entries()
            if not entries:
                return jsonify({'success': False, 'error': 'Failed to retrieve ledger'}), 500
        
        return jsonify({
            'success': True,
            'entries': entries
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/balances', methods=['GET'])
def api_balances():
    """Get balances."""
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        
        if username not in clients:
            return jsonify({'success': False, 'error': 'Session expired'}), 401
        
        client = clients[username]
        
        if not client.crypto.has_session():
            return jsonify({'success': False, 'error': 'Session expired. Please login again'}), 401
        
        balances = client.view_balances()
        
        if balances is None:
            return jsonify({'success': False, 'error': 'Failed to retrieve balances'}), 500
        
        # Format balances for display
        formatted_balances = balances.get('detailed', {})
        
        return jsonify({
            'success': True,
            'balances': formatted_balances
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/verify_tampering', methods=['GET'])
def api_verify_tampering():
    """Verify ledger integrity (tampering detection)."""
    try:
        server = get_server()
        is_valid, error = server.ledger.verify_chain_integrity()
        
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'error': error if not is_valid else None,
            'message': 'Ledger integrity verified' if is_valid else f'Tampering detected: {error}'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
def api_users():
    """Get list of registered users."""
    try:
        server = get_server()
        users = server.list_users()
        return jsonify({
            'success': True,
            'users': users
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def api_status():
    """Get current session status."""
    username = session.get('user_id')
    has_session = False
    if username and username in clients:
        has_session = clients[username].crypto.has_session()
    
    return jsonify({
        'success': True,
        'logged_in': username is not None,
        'username': username,
        'has_session': has_session
    })

@app.route('/api/blockchain', methods=['GET'])
def api_blockchain():
    """Get blockchain information."""
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        
        server = get_server()
        blockchain_info = server.ledger.get_blockchain_info()
        entries = server.ledger.get_all_entries()
        
        return jsonify({
            'success': True,
            'blockchain': blockchain_info,
            'blocks': entries[-10:] if len(entries) > 10 else entries  # Last 10 blocks
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analytics', methods=['GET'])
def api_analytics():
    """Get comprehensive analytics data."""
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        
        server = get_server()
        entries = server.ledger.get_all_entries()
        
        if not entries:
            return jsonify({
                'success': True,
                'analytics': {
                    'total_expenses': 0,
                    'total_amount': 0,
                    'entry_count': 0,
                    'by_payer': {},
                    'by_user': {},
                    'recent_entries': [],
                    'daily_spending': {},
                    'average_expense': 0,
                    'largest_expense': None,
                    'smallest_expense': None,
                    'most_active_payer': None,
                    'expense_trends': []
                }
            })
        
        # Calculate analytics
        total_amount = sum(float(entry['amount']) for entry in entries)
        entry_count = len(entries)
        average_expense = total_amount / entry_count if entry_count > 0 else 0
        
        # Expenses by payer
        by_payer = {}
        for entry in entries:
            payer = entry['payer']
            amount = float(entry['amount'])
            by_payer[payer] = by_payer.get(payer, 0) + amount
        
        # Expenses by user (who created the entry)
        by_user = {}
        for entry in entries:
            user = entry['user_id']
            amount = float(entry['amount'])
            by_user[user] = by_user.get(user, 0) + amount
        
        # Recent entries (last 10)
        recent_entries = sorted(entries, key=lambda x: x['timestamp'], reverse=True)[:10]
        
        # Daily spending
        daily_spending = {}
        for entry in entries:
            try:
                date = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00')).date()
                date_str = date.isoformat()
                daily_spending[date_str] = daily_spending.get(date_str, 0) + float(entry['amount'])
            except:
                pass
        
        # Largest and smallest expenses
        largest_expense = max(entries, key=lambda x: float(x['amount']))
        smallest_expense = min(entries, key=lambda x: float(x['amount']))
        
        # Most active payer
        most_active_payer = max(by_payer.items(), key=lambda x: x[1])[0] if by_payer else None
        
        # Expense trends (last 7 days)
        expense_trends = []
        from datetime import timedelta
        today = datetime.now().date()
        for i in range(6, -1, -1):
            date = today - timedelta(days=i)
            date_str = date.isoformat()
            amount = daily_spending.get(date_str, 0)
            expense_trends.append({
                'date': date_str,
                'amount': amount,
                'count': sum(1 for e in entries if e['timestamp'].startswith(date_str))
            })
        
        analytics = {
            'total_expenses': entry_count,
            'total_amount': round(total_amount, 2),
            'entry_count': entry_count,
            'by_payer': {k: round(v, 2) for k, v in by_payer.items()},
            'by_user': {k: round(v, 2) for k, v in by_user.items()},
            'recent_entries': recent_entries,
            'daily_spending': {k: round(v, 2) for k, v in daily_spending.items()},
            'average_expense': round(average_expense, 2),
            'largest_expense': {
                'id': largest_expense['id'],
                'payer': largest_expense['payer'],
                'amount': round(float(largest_expense['amount']), 2),
                'description': largest_expense['description'],
                'timestamp': largest_expense['timestamp']
            },
            'smallest_expense': {
                'id': smallest_expense['id'],
                'payer': smallest_expense['payer'],
                'amount': round(float(smallest_expense['amount']), 2),
                'description': smallest_expense['description'],
                'timestamp': smallest_expense['timestamp']
            },
            'most_active_payer': most_active_payer,
            'expense_trends': expense_trends
        }
        
        return jsonify({
            'success': True,
            'analytics': analytics
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    print("=" * 80)
    print("SplitSmart Web Application".center(80))
    print("=" * 80)
    print("\nStarting Flask server...")
    print("Open your browser to: http://localhost:5000")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 80)
    
    # Get port from environment variable (for cloud platforms)
    port = int(os.environ.get('PORT', 5000))
    # Disable debug mode in production
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=port, threaded=True)

