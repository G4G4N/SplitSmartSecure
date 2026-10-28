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
from shared.constants import ERROR_SECURITY_POLICY
from ai_security import config as ai_cfg

app = Flask(__name__)
# Use environment variable for secret key in production
app.secret_key = os.environ.get('SECRET_KEY', 'split-smart-secure-key-change-in-production')

# Configure session cookies for production
# In production (HTTPS), use secure cookies
is_production = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('RAILWAY_ENVIRONMENT') or os.environ.get('RENDER')
app.config['SESSION_COOKIE_SECURE'] = is_production  # Only send cookies over HTTPS in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # 24 hour sessions

# Configure CORS to allow credentials (for session cookies)
# In production, allow credentials from any origin (Railway/Render provide HTTPS)
# For better security, you can restrict to specific domains
CORS(app, supports_credentials=True)

# Global server instance (shared across requests)
_server_instance = None
_server_lock = threading.Lock()

# Rate limiting storage
_rate_limit_store = defaultdict(list)
_rate_limit_lock = threading.Lock()

# Replay protection storage (request hash -> timestamp)
_replay_protection_store = {}
_replay_protection_lock = threading.Lock()
REPLAY_PROTECTION_WINDOW = 300  # 5 minutes in seconds

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

def get_ai_security():
    """Get the AI security engine attached to the server."""
    return get_server().ai_security

def client_fingerprint() -> str:
    """
    Identify the calling client for intrusion scoring.
    Behind the hosting platform's proxy (production) the real address is in
    X-Forwarded-For; locally the header is untrusted and remote_addr is used.
    """
    if is_production:
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
    return request.remote_addr or 'unknown'

# Endpoints that a blocked client may not call (reads stay available so the UI
# can still show the user why they are blocked).
AI_PROTECTED_ENDPOINTS = {'api_login', 'api_register', 'api_add_expense', 'api_ai_security_analyze'}

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
                limited = len(_rate_limit_store[client_id]) >= max_requests
                if not limited:
                    # Add current request
                    _rate_limit_store[client_id].append(current_time)
            
            if limited:
                # Feed the AI intrusion detector so persistent abusers escalate
                try:
                    get_ai_security().record_event('rate_limited', client_id=client_fingerprint(),
                                                   user_id=session.get('user_id'),
                                                   details={'endpoint': request.endpoint})
                except Exception:
                    pass
                return jsonify({
                    'success': False,
                    'error': 'Rate limit exceeded. Please try again later.'
                }), 429
            
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
    
    # AI SECURITY: adaptive intrusion response. Clients whose decaying risk
    # score crossed the block threshold (brute force, credential stuffing,
    # repeated tampering / injection attempts) are refused state-changing calls.
    if request.endpoint in AI_PROTECTED_ENDPOINTS:
        verdict = get_ai_security().evaluate_client(client_fingerprint())
        g.ai_client_verdict = verdict
        if verdict.blocked:
            app.logger.warning(f"AI security blocked client {verdict.client_id}: {verdict.reasons}")
            response = jsonify({
                'success': False,
                'error': 'AI Security: this client is temporarily blocked after repeated suspicious activity',
                'client_action': verdict.action,
                'retry_after': verdict.retry_after
            })
            response.headers['Retry-After'] = str(verdict.retry_after)
            return response, 403

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
        engine = server.ai_security
        
        # AI SECURITY: tarpit clients the intrusion detector wants throttled,
        # which makes password guessing slow without locking out real users.
        verdict = getattr(g, 'ai_client_verdict', None)
        if verdict is not None and verdict.throttled and ai_cfg.THROTTLE_DELAY_SECONDS > 0:
            time.sleep(ai_cfg.THROTTLE_DELAY_SECONDS)
        
        # Verify password first
        if not server.verify_user_password(username, password):
            event = engine.record_event('login_failed', client_id=client_fingerprint(), user_id=username)
            payload = {'success': False, 'error': 'Invalid username or password'}
            if event['client_action'] != ai_cfg.CLIENT_ACTION_ALLOW:
                payload['security_notice'] = (f"AI Security: repeated failed logins detected "
                                              f"(response: {event['client_action']})")
            return jsonify(payload), 401
        
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
            engine.record_event('login_success', client_id=client_fingerprint(), user_id=username)
            # Generate request integrity key for modification protection
            # This key is used to compute HMAC of request body
            integrity_key = os.urandom(32).hex()  # 256-bit key
            session['integrity_key'] = integrity_key
            
            return jsonify({
                'success': True,
                'message': f'Logged in as {username}',
                'session_id': client.crypto.session_id,
                'integrity_key': integrity_key  # Send to client for HMAC computation
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
        
        # Get raw request body BEFORE parsing JSON (for HMAC verification)
        # This must be done before request.json to get the exact bytes sent by client
        raw_request_body = request.get_data()
        
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
        
        # MODIFICATION PROTECTION: Verify request integrity using HMAC
        integrity_key = session.get('integrity_key')
        if integrity_key:
            # Get HMAC from request header
            request_hmac = request.headers.get('X-Request-HMAC')
            if not request_hmac:
                app.logger.error(f"Missing HMAC header for user {username}")
                return jsonify({
                    'success': False,
                    'error': 'Request integrity check failed: Missing HMAC header'
                }), 400
            
            # Compute expected HMAC of request body
            # Use the raw request body we captured before JSON parsing
            if not raw_request_body:
                app.logger.error(f"Raw request body is empty for user {username}")
                return jsonify({
                    'success': False,
                    'error': 'Request integrity check failed: Empty request body'
                }), 400
            
            expected_hmac = hmac_lib.new(
                integrity_key.encode('utf-8'),
                raw_request_body,
                hashlib.sha256
            ).hexdigest()
            
            # Verify HMAC matches (constant-time comparison)
            if not hmac_lib.compare_digest(request_hmac, expected_hmac):
                # Log for debugging
                app.logger.warning(f"HMAC mismatch for user {username}")
                get_ai_security().record_event('hmac_mismatch', client_id=client_fingerprint(), user_id=username,
                                               details={'payer': payer, 'amount': amount, 'description': description})
                app.logger.debug(f"Expected HMAC: {expected_hmac}")
                app.logger.debug(f"Received HMAC: {request_hmac}")
                app.logger.debug(f"Request body: {raw_request_body.decode('utf-8', errors='ignore')}")
                return jsonify({
                    'success': False,
                    'error': 'Modification attack detected: Request integrity check failed'
                }), 400  # 400 Bad Request - modified request
            else:
                app.logger.debug(f"HMAC verified for user {username}")
        else:
            app.logger.warning(f"No integrity key in session for user {username}")
        
        # REPLAY PROTECTION: Create hash of request content
        # Hash includes: username, payer, amount, description
        # This prevents the exact same request from being processed multiple times
        request_content = f"{username}:{payer}:{amount:.2f}:{description}"
        request_hash = hashlib.sha256(request_content.encode('utf-8')).hexdigest()
        
        current_time = time.time()
        
        # Check for replay attack
        with _replay_protection_lock:
            # Clean old entries (older than REPLAY_PROTECTION_WINDOW)
            expired_keys = [
                key for key, timestamp in _replay_protection_store.items()
                if current_time - timestamp > REPLAY_PROTECTION_WINDOW
            ]
            for key in expired_keys:
                del _replay_protection_store[key]
            
            # Check if this request was already processed successfully
            replayed = request_hash in _replay_protection_store
        
        if replayed:
            # Request was seen recently - this is a replay attack
            get_ai_security().record_event('replay_detected', client_id=client_fingerprint(), user_id=username,
                                           details={'payer': payer, 'amount': amount, 'description': description,
                                                    'layer': 'web_api'})
            return jsonify({
                'success': False,
                'error': 'Replay attack detected: This exact request was already processed recently'
            }), 409  # 409 Conflict
        
        try:
            # Check if client has valid crypto session
            if not client.crypto.has_session():
                app.logger.error(f"Client {username} has no crypto session")
                return jsonify({'success': False, 'error': 'Crypto session expired. Please login again'}), 401
            
            app.logger.info(f"Attempting to add expense for {username}: {payer} paid ${amount:.2f} for {description}")
            app.logger.info(f"Session ID: {client.crypto.session_id}")
            
            # AI SECURITY: score the submission (injection classifier + behavioural
            # anomaly detection) before it is signed and sent through the protocol.
            engine = get_ai_security()
            assessment = engine.assess_expense(username, payer, amount, description)
            if assessment.blocked:
                engine.commit_expense(assessment, client_id=client_fingerprint(), accepted=False)
                app.logger.warning(f"AI security rejected expense from {username}: {assessment.block_reason}")
                status = 400 if assessment.threat.malicious else 403
                return jsonify({
                    'success': False,
                    'error': assessment.block_reason,
                    'security': assessment.to_dict()
                }), status
            
            success = client.add_expense(payer, amount, description)
            
            if success:
                # Only store hash if request succeeded (prevents replay of successful requests)
                with _replay_protection_lock:
                    _replay_protection_store[request_hash] = current_time
                
                # The protocol server performed (and recorded) the authoritative assessment
                security = (client.last_response or {}).get('security') or assessment.to_dict()
                payload = {
                    'success': True,
                    'message': f'Expense added: {payer} paid ${amount:.2f} for {description}',
                    'security': security
                }
                if security.get('action') == 'flag':
                    payload['warning'] = (f"AI Security flagged this expense as {security.get('risk_level')} risk "
                                          f"(score {security.get('risk_score', 0):.0f}/100)")
                app.logger.info(f"Expense added successfully for {username} "
                                f"(AI risk {security.get('risk_level')}, score {security.get('risk_score')})")
                return jsonify(payload)
            else:
                last_error = client.last_error or {}
                if last_error.get('error_code') == ERROR_SECURITY_POLICY:
                    app.logger.warning(f"Protocol-level AI security rejection for {username}: {last_error.get('message')}")
                    return jsonify({
                        'success': False,
                        'error': last_error.get('message', 'Rejected by AI security'),
                        'security': assessment.to_dict()
                    }), 403
                app.logger.error(f"client.add_expense() returned False for user {username}")
                app.logger.error(f"Session ID: {client.crypto.session_id}")
                app.logger.error(f"Has session: {client.crypto.has_session()}")
                return jsonify({'success': False, 'error': 'Failed to add expense. Check server logs for details.'}), 400
        except Exception as e:
            app.logger.exception(f"Exception adding expense for user {username}: {str(e)}")
            return jsonify({'success': False, 'error': f'Failed to add expense: {str(e)}'}), 500
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
        
        # Format balances for display - include both detailed and simplified
        detailed_balances = balances.get('detailed', {})
        simplified_balances = balances.get('simplified', [])
        
        return jsonify({
            'success': True,
            'balances': {
                'detailed': detailed_balances,
                'simplified': simplified_balances
            }
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
    session_id = None
    if username and username in clients:
        has_session = clients[username].crypto.has_session()
        session_id = clients[username].crypto.session_id if has_session else None
    
    # Return integrity key if user is logged in (for modification protection)
    integrity_key = session.get('integrity_key') if username else None
    
    return jsonify({
        'success': True,
        'logged_in': username is not None,
        'username': username,
        'has_session': has_session,
        'session_id': session_id,
        'integrity_key': integrity_key  # Include integrity key for HMAC computation
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

# ---------------------------------------------------------------------------
# AI security endpoints
# ---------------------------------------------------------------------------
@app.route('/api/ai_security/status', methods=['GET'])
def api_ai_security_status():
    """AI security dashboard: threat level, counters, model info, recent events."""
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        engine = get_ai_security()
        dashboard = engine.get_dashboard()
        dashboard['client'] = engine.evaluate_client(client_fingerprint()).to_dict()
        return jsonify({'success': True, 'dashboard': dashboard})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai_security/events', methods=['GET'])
def api_ai_security_events():
    """List recorded security events (newest first)."""
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        try:
            limit = max(1, min(int(request.args.get('limit', 50)), 200))
        except ValueError:
            limit = 50
        severity = request.args.get('min_severity')
        events = get_ai_security().get_events(limit=limit, min_severity=severity)
        return jsonify({'success': True, 'events': events, 'count': len(events)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai_security/analyze', methods=['POST'])
@rate_limit(max_requests=30, window=60)
def api_ai_security_analyze():
    """
    Dry-run analysis: score an expense (or classify a raw string) without
    touching the ledger, baselines or event log counters other than dry_runs.
    """
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400
        data = request.json or {}
        engine = get_ai_security()
        
        if 'text' in data and 'description' not in data:
            text = sanitize_string(str(data.get('text', '')), MAX_DESCRIPTION_LENGTH)
            return jsonify({'success': True, 'analysis': {'threat': engine.analyze_text(text)}})
        
        description = sanitize_string(str(data.get('description', '')), MAX_DESCRIPTION_LENGTH)
        payer = sanitize_string(str(data.get('payer') or username), MAX_USERNAME_LENGTH)
        try:
            amount = float(data.get('amount', 0) or 0)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'Invalid amount'}), 400
        if not description:
            return jsonify({'success': False, 'error': 'description is required'}), 400
        analysis = engine.analyze_expense(username, payer, amount, description)
        return jsonify({'success': True, 'analysis': analysis})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai_security/explain/<int:event_id>', methods=['GET'])
@rate_limit(max_requests=10, window=60)
def api_ai_security_explain(event_id):
    """Explain a security event (Claude-backed when configured, rule-based otherwise)."""
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({'success': False, 'error': 'Not logged in'}), 401
        result = get_ai_security().explain_event(event_id)
        if not result.get('found'):
            return jsonify({'success': False, 'error': f'Event {event_id} not found'}), 404
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analytics', methods=['GET'])
def api_analytics():
    """Get comprehensive analytics data."""
    try:
        username = session.get('user_id')
        if not username:
            return jsonify({
                'success': False, 
                'error': 'Not logged in',
                'debug': 'Session expired or not authenticated'
            }), 401
        
        server = get_server()
        entries = server.ledger.get_all_entries()
        
        # Log for debugging (remove in production if needed)
        if os.environ.get('FLASK_DEBUG', 'False').lower() == 'true':
            print(f"[Analytics] User: {username}, Entries: {len(entries) if entries else 0}")
        
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
        # Log error for debugging
        import traceback
        error_trace = traceback.format_exc()
        if os.environ.get('FLASK_DEBUG', 'False').lower() == 'true':
            print(f"[Analytics Error] {str(e)}")
            print(error_trace)
        return jsonify({
            'success': False, 
            'error': str(e),
            'message': 'Failed to load analytics data'
        }), 500

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

