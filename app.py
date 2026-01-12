"""
===========================================
⚠️  WARNING: INTENTIONALLY VULNERABLE APPLICATION ⚠️
===========================================

This application is DESIGNED to be vulnerable for educational purposes only.
DO NOT deploy this application to any public server or production environment.

FOR LOCALHOST USE ONLY - NEVER EXPOSE TO THE INTERNET

Purpose: Educational cybersecurity training and ethical hacking practice
Tech Stack: Flask + MongoDB
Security Level: INTENTIONALLY VULNERABLE (No protections enabled)
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import json
from datetime import datetime, timedelta
import re

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'weak_secret_key_12345'  # ⚠️ VULNERABILITY: Weak secret key

# MongoDB Configuration
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
DATABASE_NAME = 'vulnerable_app'

# Connect to MongoDB
try:
    client = MongoClient(MONGODB_URI)
    db = client[DATABASE_NAME]
    client.server_info()
    print(f"[+] Connected to MongoDB: {DATABASE_NAME}")
except Exception as e:
    print(f"[!] MongoDB connection error: {e}")
    db = None

# Initialize collections
users_collection = db.users if db is not None else None
progress_collection = db.progress if db is not None else None
attempts_collection = db.attempts if db is not None else None
comments_collection = db.comments if db is not None else None
defender_attempts_collection = db.defender_attempts if db is not None else None
defense_logs_collection = db.defense_logs if db is not None else None
security_config_collection = db.security_config if db is not None else None

# Security Levels
SECURITY_LEVELS = ['low', 'medium', 'high', 'impossible']
LEVELS = ['easy', 'medium', 'hard', 'impossible']

# ===========================================
# HELPER FUNCTIONS
# ===========================================

def get_security_level():
    """Get current security level from session, default to 'low'"""
    return session.get('security_level', 'low')

def set_security_level(level):
    """Set security level in session"""
    if level in SECURITY_LEVELS:
        session['security_level'] = level

def get_user_mode():
    """Get current user mode from session, default to 'attack'"""
    return session.get('user_mode', 'attack')

def set_user_mode(mode):
    """Set user mode in session and MongoDB"""
    if mode in ['attack', 'defend']:
        session['user_mode'] = mode
        user_id = get_user_id()
        if user_id and users_collection is not None:
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'mode': mode}}
            )

def require_auth():
    """Check if user is authenticated"""
    if 'username' not in session:
        return False
    return True

def get_user_id():
    """Get current user ID from session"""
    return session.get('user_id', None)

def sanitize_input(text, level='low', defender_mode=False):
    """
    REAL-WORLD Input Sanitization
    
    This function applies REAL sanitization based on mode:
    
    🔴 ATTACK MODE:
    - Low security: NO sanitization (XSS executes)
    - Medium/High: Partial sanitization (some XSS works)
    - Impossible: Full sanitization (XSS blocked)
    
    🛡️ DEFENDER MODE:
    - Always applies stronger sanitization
    - Security level controls strength
    - Low: Minimal filtering
    - Medium: Script tag removal
    - High: HTML encoding + script removal
    - Impossible: Full encoding + all patterns removed
    
    This is REAL protection - sanitized content is stored in database.
    """
    # Defender mode applies stronger protections based on security level
    if defender_mode:
        if level == 'impossible':
            # Full sanitization
            text = text.replace('<', '&lt;').replace('>', '&gt;')
            text = text.replace('"', '&quot;').replace("'", '&#x27;')
            text = text.replace('/', '&#x2F;')
            # Remove all script tags and event handlers
            text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
            text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
            text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
        elif level == 'high':
            # Strong sanitization
            text = text.replace('<', '&lt;').replace('>', '&gt;')
            text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
            text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
            text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
        elif level == 'medium':
            # Medium sanitization
            text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
            text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
        elif level == 'low':
            # Minimal sanitization
            text = text.replace('<script>', '').replace('</script>', '')
    else:
        # Attack mode - use original logic
        if level == 'impossible':
            # Full sanitization
            text = text.replace('<', '&lt;').replace('>', '&gt;')
            text = text.replace('"', '&quot;').replace("'", '&#x27;')
            text = text.replace('/', '&#x2F;')
        elif level == 'high':
            # Partial sanitization
            text = text.replace('<script', '').replace('</script>', '')
            text = text.replace('javascript:', '')
        elif level == 'medium':
            # Basic filtering
            text = text.replace('<script>', '').replace('</script>', '')
        # 'low' level: no sanitization
    return text

def check_nosql_injection_defense(username, password, level='easy'):
    """
    Check if NoSQL injection should be blocked in Defender Mode
    Returns (blocked, reason, defense_explanation)
    """
    user_mode = get_user_mode()
    if user_mode != 'defend':
        return (False, None, None)
    
    security = get_security_level()
    
    # Check for JSON parsing attempts (NoSQL injection vector)
    parsed_username = username
    parsed_password = password
    is_json_username = False
    is_json_password = False
    
    try:
        if isinstance(username, str) and username.startswith('{'):
            parsed_username = json.loads(username)
            is_json_username = True
        if isinstance(password, str) and password.startswith('{'):
            parsed_password = json.loads(password)
            is_json_password = True
    except:
        pass
    
    # Check for MongoDB operators
    dangerous_operators = ['$ne', '$gt', '$lt', '$gte', '$lte', '$regex', '$where', 
                          '$function', '$expr', '$in', '$nin', '$exists', '$type']
    
    found_operators = []
    if isinstance(parsed_username, dict):
        found_operators.extend([op for op in parsed_username.keys() if op in dangerous_operators])
    if isinstance(parsed_password, dict):
        found_operators.extend([op for op in parsed_password.keys() if op in dangerous_operators])
    
    # Apply defense based on security level
    if security == 'impossible':
        # Block all JSON parsing and operators
        if is_json_username or is_json_password or found_operators:
            defense_explanation = (
                "Defender Mode (Impossible): All NoSQL injection attempts are blocked. "
                "The application uses parameterized queries with strict type checking. "
                "User input is never parsed as JSON for database queries, and all MongoDB operators are blocked."
            )
            return (True, "NoSQL injection blocked - parameterized queries enforced", defense_explanation)
    elif security == 'high':
        # Block dangerous operators but allow some basic ones
        dangerous_ops = ['$where', '$function', '$expr']
        if any(op in found_operators for op in dangerous_ops):
            defense_explanation = (
                "Defender Mode (High): Dangerous MongoDB operators ($where, $function, $expr) are blocked. "
                "These operators can execute arbitrary code. The application filters these operators "
                "and uses input validation to prevent code injection."
            )
            return (True, f"NoSQL injection blocked - dangerous operators detected: {', '.join([op for op in found_operators if op in dangerous_ops])}", defense_explanation)
    elif security == 'medium':
        # Block code execution operators
        code_exec_ops = ['$where', '$function']
        if any(op in found_operators for op in code_exec_ops):
            defense_explanation = (
                "Defender Mode (Medium): Code execution operators ($where, $function) are blocked. "
                "These operators allow JavaScript execution in MongoDB queries, which is a critical security risk. "
                "The application filters these specific operators while allowing basic comparison operators."
            )
            return (True, f"NoSQL injection blocked - code execution operators detected: {', '.join([op for op in found_operators if op in code_exec_ops])}", defense_explanation)
    elif security == 'low':
        # Minimal defense - only block code execution
        code_exec_ops = ['$where', '$function']
        if any(op in found_operators for op in code_exec_ops):
            defense_explanation = (
                "Defender Mode (Low): Only code execution operators are blocked. "
                "This is minimal protection - most NoSQL injection techniques will still work. "
                "In production, you should implement stronger defenses like parameterized queries."
            )
            return (True, f"NoSQL injection blocked - code execution operators detected", defense_explanation)
    
    return (False, None, None)

def check_xss_defense(payload, level='easy'):
    """
    Check if XSS should be blocked in Defender Mode
    Returns (blocked, reason, defense_explanation)
    """
    user_mode = get_user_mode()
    if user_mode != 'defend':
        return (False, None, None)
    
    security = get_security_level()
    
    # Check for XSS patterns
    xss_patterns = {
        'script_tags': r'<script[^>]*>.*?</script>',
        'javascript_protocol': r'javascript:',
        'event_handlers': r'on\w+\s*=',
        'img_onerror': r'<img[^>]*onerror',
        'svg_onload': r'<svg[^>]*onload',
        'iframe': r'<iframe[^>]*>',
        'body_onload': r'<body[^>]*onload',
    }
    
    found_patterns = []
    for pattern_name, pattern in xss_patterns.items():
        if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
            found_patterns.append(pattern_name)
    
    if not found_patterns:
        return (False, None, None)
    
    # Apply defense based on security level
    if security == 'impossible':
        # Block all XSS patterns
        defense_explanation = (
            "Defender Mode (Impossible): All XSS attempts are blocked. "
            "The application uses comprehensive input sanitization and output encoding. "
            "All HTML tags are encoded, script tags are stripped, and event handlers are removed. "
            "Content Security Policy (CSP) headers prevent inline script execution."
        )
        return (True, f"XSS blocked - detected patterns: {', '.join(found_patterns)}", defense_explanation)
    elif security == 'high':
        # Block script tags and most event handlers
        if 'script_tags' in found_patterns or 'javascript_protocol' in found_patterns:
            defense_explanation = (
                "Defender Mode (High): Script tags and javascript: protocol are blocked. "
                "The application uses HTML entity encoding and filters dangerous tags. "
                "Some event handlers may still work, but script execution is prevented."
            )
            return (True, f"XSS blocked - script tags/javascript protocol detected", defense_explanation)
    elif security == 'medium':
        # Block basic script tags
        if 'script_tags' in found_patterns:
            defense_explanation = (
                "Defender Mode (Medium): Basic script tags are blocked. "
                "The application filters <script> tags, but event handlers and other techniques may still work. "
                "For stronger protection, implement output encoding and CSP headers."
            )
            return (True, "XSS blocked - script tags detected", defense_explanation)
    elif security == 'low':
        # Minimal defense - only block obvious script tags
        if 'script_tags' in found_patterns and '<script>' in payload.lower():
            defense_explanation = (
                "Defender Mode (Low): Only basic <script> tags are blocked. "
                "This is minimal protection - most XSS techniques will still work. "
                "In production, implement comprehensive input validation and output encoding."
            )
            return (True, "XSS blocked - basic script tags detected", defense_explanation)
    
    return (False, None, None)

def log_defender_block(user_id, module, level, payload, reason, defense_explanation):
    """Log a blocked attack attempt in defender mode"""
    if defender_attempts_collection is None:
        return
    
    defender_attempts_collection.insert_one({
        'user_id': user_id,
        'module': module,
        'level': level,
        'payload': str(payload)[:1000],
        'reason': reason,
        'defense_explanation': defense_explanation,
        'timestamp': datetime.now(),
        'security_level': get_security_level()
    })

def mark_defender_progress(user_id, module, level):
    """Mark a defender level as completed"""
    if progress_collection is None:
        return
    
    progress_key = f"defender_{module}_{level}"
    
    progress_collection.update_one(
        {'user_id': user_id},
        {
            '$set': {
                progress_key: True,
                'last_updated': datetime.now()
            },
            '$setOnInsert': {
                'user_id': user_id,
                'created_at': datetime.now()
            }
        },
        upsert=True
    )

def attempt_nosql_injection(username, password, level='easy'):
    """
    REAL-WORLD NoSQL Injection Handler
    
    This function demonstrates REAL attacks and REAL defenses:
    
    🔴 ATTACK MODE (Real Vulnerability):
    - JSON input is ACTUALLY parsed: {"$ne": null} becomes a dict
    - MongoDB operators ACTUALLY work in queries
    - Injection ACTUALLY bypasses authentication
    - Same database, same endpoints, real exploitation
    
    🛡️ DEFENDER MODE (Real Protection):
    - JSON parsing is DISABLED at backend level
    - Input is ALWAYS treated as strings
    - MongoDB operators are NEVER used in queries
    - Strict type enforcement prevents injection
    - Same database, same endpoints, real protection
    
    This is NOT simulation - the backend logic actually changes.
    Returns (success, message, explanation, found_user, blocked_by_defender, defense_info)
    """
    user_mode = get_user_mode()
    security = get_security_level()
    
    # Create test user for demonstration if it doesn't exist
    test_username = 'admin'
    test_password = 'password123'
    if users_collection is not None:
        test_user = users_collection.find_one({'username': test_username})
        if test_user is None:
            users_collection.insert_one({
                'username': test_username,
                'password': test_password,
                'email': 'admin@test.com',
                'created_at': datetime.now()
            })
    
    # Store original values
    orig_username = str(username) if username is not None else ''
    orig_password = str(password) if password is not None else ''
    
    # ============================================
    # DEFENDER MODE: REAL PROTECTION ENFORCED
    # ============================================
    if user_mode == 'defend':
        # In Defender Mode, NEVER parse JSON - always use strict string comparison
        # This is REAL protection - the backend actually enforces it
        
        # Check if user tried to inject JSON/MongoDB operators
        attempted_injection = False
        injection_details = []
        
        # Check for JSON-like input
        if (isinstance(username, str) and username.strip().startswith('{')) or \
           (isinstance(password, str) and password.strip().startswith('{')):
            attempted_injection = True
            injection_details.append("JSON-like input detected")
        
        # Try to parse to detect operators (for logging only, not for query)
        parsed_username_check = username
        parsed_password_check = password
        found_operators = []
        try:
            if isinstance(username, str) and username.strip().startswith('{'):
                parsed_username_check = json.loads(username)
                if isinstance(parsed_username_check, dict):
                    dangerous_ops = ['$ne', '$gt', '$lt', '$gte', '$lte', '$regex', '$where', 
                                    '$function', '$expr', '$in', '$nin', '$exists', '$type']
                    found_ops = [op for op in parsed_username_check.keys() if op in dangerous_ops]
                    if found_ops:
                        found_operators.extend(found_ops)
                        injection_details.append(f"MongoDB operators in username: {', '.join(found_ops)}")
            if isinstance(password, str) and password.strip().startswith('{'):
                parsed_password_check = json.loads(password)
                if isinstance(parsed_password_check, dict):
                    dangerous_ops = ['$ne', '$gt', '$lt', '$gte', '$lte', '$regex', '$where', 
                                    '$function', '$expr', '$in', '$nin', '$exists', '$type']
                    found_ops = [op for op in parsed_password_check.keys() if op in dangerous_ops]
                    if found_ops:
                        found_operators.extend(found_ops)
                        injection_details.append(f"MongoDB operators in password: {', '.join(found_ops)}")
        except:
            pass
        
        # Apply defense based on security level
        should_block = False
        defense_explanation = ""
        
        if security == 'impossible':
            # Block ALL injection attempts
            if attempted_injection or found_operators:
                should_block = True
                defense_explanation = (
                    "Defender Mode (Impossible): All NoSQL injection attempts are blocked. "
                    "The application uses parameterized queries with strict type checking. "
                    "User input is NEVER parsed as JSON for database queries, and all MongoDB operators are blocked. "
                    "Only exact string matches are allowed."
                )
        elif security == 'high':
            # Block dangerous operators
            dangerous_ops = ['$where', '$function', '$expr']
            if any(op in found_operators for op in dangerous_ops):
                should_block = True
                defense_explanation = (
                    f"Defender Mode (High): Dangerous MongoDB operators ({', '.join([op for op in found_operators if op in dangerous_ops])}) are blocked. "
                    "These operators can execute arbitrary code. The application filters these operators "
                    "and enforces strict input validation."
                )
        elif security == 'medium':
            # Block code execution operators
            code_exec_ops = ['$where', '$function']
            if any(op in found_operators for op in code_exec_ops):
                should_block = True
                defense_explanation = (
                    f"Defender Mode (Medium): Code execution operators ({', '.join([op for op in found_operators if op in code_exec_ops])}) are blocked. "
                    "These operators allow JavaScript execution in MongoDB queries. "
                    "The application filters these specific operators."
                )
        elif security == 'low':
            # Minimal defense
            code_exec_ops = ['$where', '$function']
            if any(op in found_operators for op in code_exec_ops):
                should_block = True
                defense_explanation = (
                    "Defender Mode (Low): Code execution operators are blocked. "
                    "This is minimal protection - most NoSQL injection techniques will still work. "
                    "In production, implement stronger defenses like parameterized queries."
                )
        
        if should_block:
            # Log the blocked attempt
            user_id = get_user_id()
            if user_id:
                log_defender_block(user_id, 'nosql_injection', level, 
                                 {'username': username, 'password': password}, 
                                 f"Blocked: {', '.join(injection_details)}", defense_explanation)
                mark_defender_progress(user_id, 'nosql_injection', level)
            
            return (False, f"❌ Attack blocked by Defender Mode", 
                   f"NoSQL injection attempt detected and blocked. {defense_explanation}", 
                   None, True, defense_explanation)
        
        # If not blocked, enforce strict string comparison (REAL protection)
        # NEVER use parsed JSON in query - always use string comparison
        if users_collection is not None:
            user = users_collection.find_one({
                'username': orig_username,  # Always string, never dict
                'password': orig_password   # Always string, never dict
            })
            if user is not None:
                return (False, "❌ Login failed", 
                       "Defender Mode: Only exact credentials work. NoSQL injection is blocked by strict type enforcement.", 
                       None, False, None)
            else:
                return (False, "❌ Invalid credentials", 
                       "Defender Mode: Authentication failed. NoSQL injection attempts are blocked.", 
                       None, False, None)
    
    # ============================================
    # ATTACK MODE: REAL VULNERABILITY (JSON parsing enabled)
    # ============================================
    # Parse JSON if provided (for NoSQL injection) - THIS IS THE VULNERABILITY
    parsed_username = username
    parsed_password = password
    try:
        if isinstance(username, str) and username.startswith('{'):
            parsed_username = json.loads(username)  # REAL VULNERABILITY: JSON parsing
        if isinstance(password, str) and password.startswith('{'):
            parsed_password = json.loads(password)  # REAL VULNERABILITY: JSON parsing
    except:
        pass
    
    # Check security level - this controls vulnerability
    if security == 'impossible':
        # Secure - no injection possible, always use string comparison
        if users_collection is not None:
            user = users_collection.find_one({
                'username': str(orig_username),
                'password': str(orig_password)
            })
            if user is not None:
                return (True, "✅ Login successful with correct credentials", 
                       "Impossible level: Only exact credentials work (secure)", user, False, None)
            else:
                return (False, "❌ Invalid credentials", 
                       "Impossible level: NoSQL injection blocked by parameterized queries", None, False, None)
    
    # For low/medium/high security levels - vulnerable to injection
    # Build query based on security level
    query = {}
    
    if security == 'low':
        # Low security: Direct injection, accepts dicts directly
        query['username'] = parsed_username if isinstance(parsed_username, dict) else orig_username
        query['password'] = parsed_password if isinstance(parsed_password, dict) else orig_password
    elif security == 'medium':
        # Medium security: Some filtering, but still vulnerable
        if isinstance(parsed_username, dict):
            # Check for dangerous operators and filter some
            if '$where' in parsed_username or '$function' in parsed_username:
                query['username'] = orig_username  # Block $where and $function
            else:
                query['username'] = parsed_username
        else:
            query['username'] = orig_username
            
        if isinstance(parsed_password, dict):
            if '$where' in parsed_password or '$function' in parsed_password:
                query['password'] = orig_password
            else:
                query['password'] = parsed_password
        else:
            query['password'] = orig_password
    elif security == 'high':
        # High security: More filtering, but still some vulnerabilities
        if isinstance(parsed_username, dict):
            # Only allow certain operators
            allowed_ops = ['$ne', '$gt', '$lt', '$regex']
            filtered = {k: v for k, v in parsed_username.items() if k in allowed_ops}
            if filtered:
                query['username'] = filtered
            else:
                query['username'] = orig_username
        else:
            query['username'] = orig_username
            
        if isinstance(parsed_password, dict):
            allowed_ops = ['$ne', '$gt', '$lt', '$regex']
            filtered = {k: v for k, v in parsed_password.items() if k in allowed_ops}
            if filtered:
                query['password'] = filtered
            else:
                query['password'] = orig_password
        else:
            query['password'] = orig_password
    
    # Execute query
    found_user = None
    if users_collection is not None:
        try:
            found_user = users_collection.find_one(query)
        except Exception as e:
            # Query error - might be malformed
            return (False, "❌ Query error. Check your payload syntax.", 
                   f"Error: {str(e)[:100]}", None, False, None)
    
    # Validate based on difficulty level
    if found_user is not None:
        # Injection worked - now check if it meets difficulty requirements
        if level == 'easy':
            # Easy: Any successful injection
            return (True, "✅ Correct! You successfully exploited this level", 
                   f"Easy level: Basic NoSQL injection worked! Found user: {found_user.get('username', 'unknown')}", found_user, False, None)
        elif level == 'medium':
            # Medium: Requires operators, not just correct password
            if isinstance(parsed_username, dict) or isinstance(parsed_password, dict):
                return (True, "✅ Correct! You successfully exploited this level",
                       f"Medium level: Used MongoDB operators to bypass authentication. Found user: {found_user.get('username', 'unknown')}", found_user, False, None)
            else:
                return (False, "❌ Found user but no injection detected",
                       "Medium level requires using MongoDB operators, not just correct credentials", found_user, False, None)
        elif level == 'hard':
            # Hard: Requires sophisticated operators
            if isinstance(parsed_username, dict) and isinstance(parsed_password, dict):
                ops_found = set()
                if isinstance(parsed_username, dict):
                    ops_found.update(parsed_username.keys())
                if isinstance(parsed_password, dict):
                    ops_found.update(parsed_password.keys())
                if len(ops_found) >= 2:
                    return (True, "✅ Correct! You successfully exploited this level",
                           f"Hard level: Used multiple operators to bypass. Found user: {found_user.get('username', 'unknown')}", found_user, False, None)
            return (False, "❌ Injection worked but level requires more sophisticated payload",
                   "Hard level requires using multiple operators in both fields", found_user, False, None)
        elif level == 'impossible':
            # Impossible: Should never work
            return (False, "❌ This level is secure. No injection possible.",
                   "Impossible level uses proper parameterized queries", None, False, None)
    else:
        # No user found
        return (False, "❌ No user found. Try different payload or check syntax.", 
               f"Hint: Use operators like {{\"$ne\": null}} or {{\"$regex\": \".*\"}} for {security} security level", None, False, None)

def validate_xss_payload(payload, level='easy'):
    """
    Validate XSS payload based on security level and difficulty level
    Returns (success, message, explanation, blocked_by_defender, defense_info)
    """
    # Check defender mode first
    blocked, block_reason, defense_explanation = check_xss_defense(payload, level)
    if blocked:
        user_id = get_user_id()
        if user_id:
            log_defender_block(user_id, 'xss', level, payload, block_reason, defense_explanation)
            mark_defender_progress(user_id, 'xss', level)
        return (False, f"❌ XSS blocked by Defender Mode", 
               f"{block_reason}. {defense_explanation}", True, defense_explanation)
    
    security = get_security_level()
    
    # Check for XSS patterns
    xss_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<img[^>]*onerror',
        r'<svg[^>]*onload',
        r'<iframe[^>]*>',
        r'<body[^>]*onload',
    ]
    
    found_patterns = []
    for pattern in xss_patterns:
        if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
            found_patterns.append(pattern)
    
    # Check security level first
    if security == 'impossible':
        return (False, "❌ XSS blocked by security level (Impossible)",
               "Impossible security level: Full input sanitization and output encoding prevent XSS", False, None)
    
    # For low/medium/high security - check if payload would execute
    payload_lower = payload.lower()
    
    # Apply security-based filtering
    if security == 'high':
        # High security: Filter script tags and some event handlers
        if '<script' in payload_lower:
            return (False, "❌ Script tags filtered by security level (High)",
                   "High security level filters <script> tags. Try event handlers or other techniques.")
        # Check if event handlers work
        if any('on' in pattern for pattern in found_patterns):
            # Event handlers might work
            pass
    elif security == 'medium':
        # Medium security: Basic filtering
        if '<script>' in payload_lower and '</script>' in payload_lower:
            return (False, "❌ Basic script tags filtered (Medium)",
                   "Medium security filters basic <script> tags. Try variations or event handlers.")
    
    # Now validate based on difficulty level
    if level == 'easy':
        # Easy: Any XSS pattern works
        if '<script' in payload_lower or len(found_patterns) > 0:
            return (True, "✅ Correct! You successfully exploited this level",
                   "Easy level: XSS payload detected and will execute", False, None)
    elif level == 'medium':
        # Medium: Need event handlers or javascript: URLs
        if any('on' in pattern for pattern in found_patterns) or 'javascript:' in payload_lower:
            return (True, "✅ Correct! You successfully exploited this level",
                   "Medium level: Used event handlers or javascript: protocol", False, None)
        elif '<script' in payload_lower:
            return (False, "❌ Script tags don't work at medium level",
                   "Medium level: Script tags are filtered. Try event handlers like onerror or onload", False, None)
    elif level == 'hard':
        # Hard: Need sophisticated payloads (SVG, iframe, encoding)
        if 'svg' in payload_lower or 'iframe' in payload_lower or len(found_patterns) >= 2:
            return (True, "✅ Correct! You successfully exploited this level",
                   "Hard level: Used advanced XSS techniques (SVG, iframe, etc.)", False, None)
        else:
            return (False, "❌ Need more sophisticated XSS payload",
                   "Hard level: Requires advanced techniques like SVG, iframe, or encoding", False, None)
    elif level == 'impossible':
        return (False, "❌ This difficulty level is secure. No XSS possible.",
               "Impossible level: Full input sanitization and output encoding", False, None)
    
    if not found_patterns:
        return (False, "❌ No XSS payload detected. Try using <script> tags or event handlers.",
               "Hint: Use <script>alert('XSS')</script> or event handlers like onerror", False, None)
    
    return (False, "❌ Payload detected but doesn't meet level requirements.",
           "Try using different XSS techniques for this level", False, None)

def mark_level_complete(user_id, module, level):
    """Mark a level as completed for a user"""
    if progress_collection is None:
        return
    
    progress_key = f"{module}_{level}"
    
    # Update or insert progress
    progress_collection.update_one(
        {'user_id': user_id},
        {
            '$set': {
                progress_key: True,
                'last_updated': datetime.now()
            },
            '$setOnInsert': {
                'user_id': user_id,
                'created_at': datetime.now()
            }
        },
        upsert=True
    )

def update_streak(user_id):
    """Update user's daily streak"""
    if progress_collection is None:
        return
    
    progress = progress_collection.find_one({'user_id': user_id})
    today = datetime.now().date()
    
    if progress is not None and 'last_completed' in progress:
        last_date = progress['last_completed'].date()
        if last_date == today:
            # Already completed today
            return
        elif last_date == today - timedelta(days=1):
            # Continue streak
            new_streak = progress.get('streak', 0) + 1
        else:
            # Reset streak
            new_streak = 1
    else:
        # First completion
        new_streak = 1
    
    progress_collection.update_one(
        {'user_id': user_id},
        {
            '$set': {
                'streak': new_streak,
                'last_completed': datetime.now()
            },
            '$setOnInsert': {
                'user_id': user_id,
                'created_at': datetime.now()
            }
        },
        upsert=True
    )

def get_user_progress(user_id):
    """Get user's progress data"""
    if progress_collection is None:
        return {}
    
    progress = progress_collection.find_one({'user_id': user_id})
    if progress is None:
        return {'streak': 0, 'completed_levels': [], 'defender_completed_levels': []}
    
    # Count completed levels (attack mode)
    completed = []
    defender_completed = []
    modules = ['nosql_injection', 'xss']
    for module in modules:
        for level in LEVELS:
            key = f"{module}_{level}"
            if progress.get(key, False):
                completed.append(f"{module}_{level}")
            defender_key = f"defender_{module}_{level}"
            if progress.get(defender_key, False):
                defender_completed.append(f"{module}_{level}")
    
    return {
        'streak': progress.get('streak', 0),
        'completed_levels': completed,
        'defender_completed_levels': defender_completed,
        'last_completed': progress.get('last_completed', None)
    }

def is_level_unlocked(user_id, module, level):
    """Check if a level is unlocked for a user"""
    if level == 'easy':
        return True
    
    progress = get_user_progress(user_id)
    level_index = LEVELS.index(level)
    prev_level = LEVELS[level_index - 1]
    prev_key = f"{module}_{prev_level}"
    
    return prev_key in progress.get('completed_levels', [])

def log_attempt(user_id, module, level, payload, success):
    """Log an attack attempt"""
    if attempts_collection is None:
        return
    
    attempts_collection.insert_one({
        'user_id': user_id,
        'module': module,
        'level': level,
        'payload': str(payload)[:1000],  # Limit length
        'success': success,
        'timestamp': datetime.now(),
        'security_level': get_security_level()
    })

# ===========================================
# AUTHENTICATION ROUTES
# ===========================================

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """⚠️ VULNERABLE: User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        email = request.form.get('email', '')
        
        # ⚠️ VULNERABILITY: No input validation, plain text password storage
        if users_collection is not None:
            # Check if user exists
            existing = users_collection.find_one({'username': username})
            if existing is not None:
                return render_template('register.html', error='Username already exists')
            
            user_data = {
                'username': username,
                'password': password,  # ⚠️ PLAIN TEXT
                'email': email,
                'mode': 'attack',  # Default mode
                'created_at': datetime.now()
            }
            users_collection.insert_one(user_data)
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """⚠️ VULNERABLE: Login with NoSQL injection vulnerability"""
    if request.method == 'POST':
        # ⚠️ VULNERABILITY: Accept both form and JSON (makes NoSQL injection easier)
        if request.is_json:
            data = request.get_json()
            username = data.get('username', '') if data else ''
            password = data.get('password', '') if data else ''
        else:
            username = request.form.get('username', '')
            password = request.form.get('password', '')
        
        # ⚠️ CRITICAL: Try to parse as JSON for NoSQL injection
        try:
            if isinstance(username, str) and username.startswith('{'):
                username = json.loads(username)
            if isinstance(password, str) and password.startswith('{'):
                password = json.loads(password)
        except:
            pass
        
        # ⚠️ VULNERABILITY: Direct query without sanitization
        if users_collection is not None:
            # Build query - vulnerable to NoSQL injection
            query = {}
            if username is not None:
                query['username'] = username
            if password is not None:
                query['password'] = password
            
            user = users_collection.find_one(query)
            
            if user is not None:
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                session['security_level'] = 'low'  # Default security level
                # Set mode from user document or default to 'attack'
                user_mode = user.get('mode', 'attack')
                session['user_mode'] = user_mode
                return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect(url_for('index'))

# ===========================================
# DASHBOARD
# ===========================================

@app.route('/dashboard')
def dashboard():
    """User dashboard with progress"""
    if not require_auth():
        return redirect(url_for('login'))
    
    user_id = get_user_id()
    progress = get_user_progress(user_id)
    
    # Calculate overall progress
    total_levels = len(LEVELS) * 2  # 2 modules × 4 levels
    completed_count = len(progress.get('completed_levels', []))
    progress_percent = int((completed_count / total_levels) * 100) if total_levels > 0 else 0
    
    user_mode = get_user_mode()
    
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         progress=progress,
                         progress_percent=progress_percent,
                         security_level=get_security_level().upper(),
                         user_mode=user_mode)

@app.route('/set_security', methods=['POST'])
def set_security():
    """Set security level"""
    if not require_auth():
        return redirect(url_for('login'))
    
    level = request.form.get('level', 'low').lower()
    set_security_level(level)
    return redirect(url_for('dashboard'))

@app.route('/set_mode', methods=['POST'])
def set_mode():
    """Set user mode (attack/defend) and redirect to dedicated mode page"""
    if not require_auth():
        return redirect(url_for('login'))
    
    mode = request.form.get('mode', 'attack').lower()
    set_user_mode(mode)
    
    # Redirect to dedicated mode pages
    if mode == 'defend':
        return redirect(url_for('defender_mode'))
    else:
        return redirect(url_for('attack_mode'))

# ===========================================
# NOSQL INJECTION MODULE
# ===========================================

@app.route('/nosql/<level>', methods=['GET', 'POST'])
def nosql_level(level):
    """NoSQL Injection module - different levels"""
    if not require_auth():
        return redirect(url_for('login'))
    
    if level not in LEVELS:
        return redirect(url_for('dashboard'))
    
    user_id = get_user_id()
    
    # Check if level is unlocked
    if not is_level_unlocked(user_id, 'nosql_injection', level):
        return render_template('locked.html', module='NoSQL Injection', level=level.capitalize())
    
    success_msg = None
    error_msg = None
    explanation = None
    blocked_by_defender = False
    defense_info = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Try JSON parsing for NoSQL injection
        parsed_username = username
        parsed_password = password
        try:
            if username.startswith('{'):
                parsed_username = json.loads(username)
            if password.startswith('{'):
                parsed_password = json.loads(password)
        except:
            pass
        
        # Attempt actual NoSQL injection attack
        result = attempt_nosql_injection(parsed_username, parsed_password, level)
        success, msg, exp, found_user, blocked_by_defender, defense_info = result
        
        if success:
            success_msg = msg
            explanation = exp
            if found_user is not None:
                mark_level_complete(user_id, 'nosql_injection', level)
                update_streak(user_id)
            log_attempt(user_id, 'nosql_injection', level, {'username': username, 'password': password}, True)
        else:
            error_msg = msg
            explanation = exp
            if blocked_by_defender:
                # This is a defender mode block - don't log as failed attack
                pass
            else:
                log_attempt(user_id, 'nosql_injection', level, {'username': username, 'password': password}, False)
    
    # Get completion status
    progress = get_user_progress(user_id)
    is_completed = f"nosql_injection_{level}" in progress.get('completed_levels', [])
    user_mode = get_user_mode()
    
    return render_template('nosql_level.html',
                         level=level,
                         level_name=level.capitalize(),
                         success_msg=success_msg,
                         error_msg=error_msg,
                         explanation=explanation,
                         is_completed=is_completed,
                         security_level=get_security_level(),
                         user_mode=user_mode,
                         blocked_by_defender=blocked_by_defender,
                         defense_info=defense_info)

@app.route('/nosql')
def nosql_index():
    """NoSQL Injection module index"""
    if not require_auth():
        return redirect(url_for('login'))
    
    user_id = get_user_id()
    progress = get_user_progress(user_id)
    
    levels_status = []
    for level in LEVELS:
        key = f"nosql_injection_{level}"
        is_unlocked = is_level_unlocked(user_id, 'nosql_injection', level)
        is_completed = key in progress.get('completed_levels', [])
        levels_status.append({
            'level': level,
            'name': level.capitalize(),
            'unlocked': is_unlocked,
            'completed': is_completed
        })
    
    return render_template('nosql_index.html', levels=levels_status)

# ===========================================
# XSS MODULE
# ===========================================

@app.route('/xss/<level>', methods=['GET', 'POST'])
def xss_level(level):
    """XSS module - different levels"""
    if not require_auth():
        return redirect(url_for('login'))
    
    if level not in LEVELS:
        return redirect(url_for('dashboard'))
    
    user_id = get_user_id()
    
    # Check if level is unlocked
    if not is_level_unlocked(user_id, 'xss', level):
        return render_template('locked.html', module='XSS', level=level.capitalize())
    
    success_msg = None
    error_msg = None
    explanation = None
    stored_comments = []
    blocked_by_defender = False
    defense_info = None
    
    if request.method == 'POST':
        content = request.form.get('content', '')
        author = session.get('username', 'Anonymous')
        
        security = get_security_level()
        user_mode = get_user_mode()
        
        # ============================================
        # REAL XSS PROTECTION/EXECUTION
        # ============================================
        # In Defender Mode: Sanitize BEFORE validation and storage
        # In Attack Mode: Keep original for real XSS execution
        if user_mode == 'defend':
            # REAL PROTECTION: Sanitize input in Defender Mode
            sanitized_content = sanitize_input(content, security, defender_mode=True)
        else:
            # Attack Mode: Apply only security-level based sanitization (may be minimal)
            sanitized_content = sanitize_input(content, security, defender_mode=False)
        
        # Validate payload (check original content before sanitization)
        result = validate_xss_payload(content, level)
        success, msg, exp, blocked_by_defender, defense_info = result
        
        if success:
            success_msg = msg
            explanation = exp
            mark_level_complete(user_id, 'xss', level)
            update_streak(user_id)
            log_attempt(user_id, 'xss', level, content, True)
        else:
            error_msg = msg
            explanation = exp
            if blocked_by_defender:
                # This is a defender mode block - don't log as failed attack
                pass
            else:
                log_attempt(user_id, 'xss', level, content, False)
        
        # Store comment - REAL PROTECTION/EXECUTION:
        # Defender Mode: Store sanitized content (XSS blocked)
        # Attack Mode: Store original content (XSS executes)
        if comments_collection is not None:
            stored_content = sanitized_content if user_mode == 'defend' else content
            comments_collection.insert_one({
                'author': author,
                'content': stored_content,  # REAL: Defender=sanitized, Attack=raw
                'level': level,
                'module': 'xss',
                'security_level': security,
                'user_mode': user_mode,  # Store mode for rendering decision
                'created_at': datetime.now()
            })
    
    # Get stored comments for this level
    if comments_collection is not None:
        stored_comments = list(comments_collection.find({
            'module': 'xss',
            'level': level
        }).sort('created_at', -1).limit(20))
    
    # Get completion status
    progress = get_user_progress(user_id)
    is_completed = f"xss_{level}" in progress.get('completed_levels', [])
    user_mode = get_user_mode()
    
    return render_template('xss_level.html',
                         level=level,
                         level_name=level.capitalize(),
                         success_msg=success_msg,
                         error_msg=error_msg,
                         explanation=explanation,
                         comments=stored_comments,
                         is_completed=is_completed,
                         security_level=get_security_level(),
                         user_mode=user_mode,
                         blocked_by_defender=blocked_by_defender,
                         defense_info=defense_info)

@app.route('/xss')
def xss_index():
    """XSS module index"""
    if not require_auth():
        return redirect(url_for('login'))
    
    user_id = get_user_id()
    progress = get_user_progress(user_id)
    
    levels_status = []
    for level in LEVELS:
        key = f"xss_{level}"
        is_unlocked = is_level_unlocked(user_id, 'xss', level)
        is_completed = key in progress.get('completed_levels', [])
        levels_status.append({
            'level': level,
            'name': level.capitalize(),
            'unlocked': is_unlocked,
            'completed': is_completed
        })
    
    return render_template('xss_index.html', levels=levels_status)

# ===========================================
# DEFENSE LOGS (Defender Mode Only)
# ===========================================

@app.route('/defense_logs')
def defense_logs():
    """View defense logs - Defender Mode only"""
    if not require_auth():
        return redirect(url_for('login'))
    
    user_mode = get_user_mode()
    if user_mode != 'defend':
        return redirect(url_for('dashboard'))
    
    user_id = get_user_id()
    
    # Get blocked attack attempts
    logs = []
    if defender_attempts_collection is not None:
        logs = list(defender_attempts_collection.find({
            'user_id': user_id
        }).sort('timestamp', -1).limit(100))
    
    return render_template('defense_logs.html', 
                         logs=logs,
                         user_mode=user_mode)

# ===========================================
# DEDICATED MODE PAGES
# ===========================================

def get_security_config(user_id):
    """Get current security configuration"""
    if security_config_collection is None:
        # Return default structure if collection doesn't exist
        return {
            'input_validation': {'enabled': False, 'type': 'none', 'cost': 0},
            'authentication': {'lockout_enabled': False, 'captcha_enabled': False, 'mfa_enabled': False, 'cost': 0},
            'file_upload': {'restrictions_enabled': False, 'sandbox_enabled': False, 'cost': 0},
            'csrf_protection': {'enabled': False, 'implementation': 'none', 'cost': 0},
            'security_headers': {'enabled': False, 'headers': [], 'cost': 0}
        }
    
    config = security_config_collection.find_one({'user_id': user_id})
    if config is None:
        # Initialize default config
        default_config = {
            'user_id': user_id,
            'input_validation': {'enabled': False, 'type': 'none', 'cost': 0},
            'authentication': {'lockout_enabled': False, 'captcha_enabled': False, 'mfa_enabled': False, 'cost': 0},
            'file_upload': {'restrictions_enabled': False, 'sandbox_enabled': False, 'cost': 0},
            'csrf_protection': {'enabled': False, 'implementation': 'none', 'cost': 0},
            'security_headers': {'enabled': False, 'headers': [], 'cost': 0},
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        security_config_collection.insert_one(default_config)
        return default_config
    
    # Ensure all fields exist
    if 'input_validation' not in config:
        config['input_validation'] = {'enabled': False, 'type': 'none', 'cost': 0}
    if 'authentication' not in config:
        config['authentication'] = {'lockout_enabled': False, 'captcha_enabled': False, 'mfa_enabled': False, 'cost': 0}
    if 'file_upload' not in config:
        config['file_upload'] = {'restrictions_enabled': False, 'sandbox_enabled': False, 'cost': 0}
    if 'csrf_protection' not in config:
        config['csrf_protection'] = {'enabled': False, 'implementation': 'none', 'cost': 0}
    if 'security_headers' not in config:
        config['security_headers'] = {'enabled': False, 'headers': [], 'cost': 0}
    
    return config

def calculate_budget_used(config):
    """Calculate total security budget used"""
    total = 0
    total += config.get('input_validation', {}).get('cost', 0)
    total += config.get('authentication', {}).get('cost', 0)
    total += config.get('file_upload', {}).get('cost', 0)
    total += config.get('csrf_protection', {}).get('cost', 0)
    total += config.get('security_headers', {}).get('cost', 0)
    return total

def calculate_current_risk(config):
    """Calculate current risk level"""
    # Lower risk if more protections enabled, but misconfigurations increase risk
    risk = 100
    if config.get('input_validation', {}).get('enabled'):
        risk -= 15
    if config.get('authentication', {}).get('lockout_enabled'):
        risk -= 10
    if config.get('csrf_protection', {}).get('enabled'):
        risk -= 10
    if config.get('security_headers', {}).get('enabled'):
        risk -= 5
    
    # Check for misconfigurations (increase risk)
    csrf_impl = config.get('csrf_protection', {}).get('implementation', 'none')
    if csrf_impl == 'weak':
        risk += 20  # Weak implementation is dangerous
    
    return max(0, min(100, risk))

def calculate_exposure_level(config):
    """Calculate exposure level"""
    exposure = 100
    if config.get('input_validation', {}).get('enabled'):
        exposure -= 20
    if config.get('authentication', {}).get('mfa_enabled'):
        exposure -= 15
    if config.get('file_upload', {}).get('sandbox_enabled'):
        exposure -= 15
    if config.get('security_headers', {}).get('enabled'):
        exposure -= 10
    
    return max(0, min(100, exposure))

def get_security_logs(user_id, limit=50):
    """Get security logs with simulated delays and noise"""
    if defense_logs_collection is None:
        return []
    
    # Get logs, but simulate delays (older logs appear first)
    logs = list(defense_logs_collection.find({
        'user_id': user_id
    }).sort('timestamp', -1).limit(limit))
    
    # Add noise to some logs (mark as false positives)
    import random
    for log in logs:
        if random.random() < 0.1:  # 10% false positive rate
            log['is_noise'] = True
        else:
            log['is_noise'] = False
    
    return logs

def update_noise_level(user_id, action_type, stealth_level):
    """Update noise level based on attack action"""
    current_noise = session.get('noise_level', 0)
    
    # Different actions generate different noise
    noise_map = {
        'reconnaissance': 2,
        'sql_injection': 15,
        'xss': 10,
        'file_upload': 20,
        'csrf': 5,
        'auth_bruteforce': 25,
        'idor': 8
    }
    
    base_noise = noise_map.get(action_type, 10)
    # Stealth level reduces noise (0-100, higher = more stealthy)
    noise_increase = base_noise * (1 - stealth_level / 100)
    
    new_noise = min(100, current_noise + noise_increase)
    session['noise_level'] = new_noise
    
    # Update risk and exposure scores
    session['risk_score'] = min(100, session.get('risk_score', 0) + base_noise * 0.5)
    session['exposure_score'] = min(100, session.get('exposure_score', 0) + base_noise * 0.3)
    
    return new_noise

@app.route('/attack_mode')
def attack_mode():
    """Dedicated Attack Mode page - Red Team perspective"""
    if not require_auth():
        return redirect(url_for('login'))
    
    user_mode = get_user_mode()
    if user_mode != 'attack':
        set_user_mode('attack')
        user_mode = 'attack'
    
    user_id = get_user_id()
    
    # Get attack metrics
    noise_level = session.get('noise_level', 0)
    stealth_rating = max(0, 100 - noise_level)
    risk_score = session.get('risk_score', 0)
    exposure_score = session.get('exposure_score', 0)
    
    # Get attack chain progress
    attack_chains = session.get('attack_chains', {})
    
    # Get recent reconnaissance data
    recon_data = session.get('recon_data', {})
    
    return render_template('attack_mode.html',
                         user_mode=user_mode,
                         noise_level=noise_level,
                         stealth_rating=stealth_rating,
                         risk_score=risk_score,
                         exposure_score=exposure_score,
                         attack_chains=attack_chains,
                         recon_data=recon_data)

@app.route('/defender_mode')
def defender_mode():
    """Dedicated Defender Mode page - Blue Team perspective"""
    if not require_auth():
        return redirect(url_for('login'))
    
    user_mode = get_user_mode()
    if user_mode != 'defend':
        set_user_mode('defend')
        user_mode = 'defend'
    
    user_id = get_user_id()
    
    # Get security configuration
    security_config = get_security_config(user_id)
    
    # Get security budget
    security_budget = session.get('security_budget', 100)
    budget_used = calculate_budget_used(security_config)
    budget_remaining = security_budget - budget_used
    
    # Get recent security logs (with delays/noise)
    security_logs = get_security_logs(user_id, limit=50)
    
    # Get risk metrics
    current_risk = calculate_current_risk(security_config)
    exposure_level = calculate_exposure_level(security_config)
    
    return render_template('defender_mode.html',
                         user_mode=user_mode,
                         security_config=security_config,
                         security_budget=security_budget,
                         budget_used=budget_used,
                         budget_remaining=budget_remaining,
                         security_logs=security_logs,
                         current_risk=current_risk,
                         exposure_level=exposure_level)

# ===========================================
# API ROUTES FOR ATTACK/DEFENSE MODES
# ===========================================

@app.route('/api/recon', methods=['POST'])
def api_recon():
    """Perform reconnaissance - adds noise"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = get_user_id()
    data = request.get_json()
    recon_type = data.get('type', 'endpoints')
    
    # Update noise level
    update_noise_level(user_id, 'reconnaissance', 50)  # Medium stealth
    
    # Generate reconnaissance data (no hints, realistic)
    recon_results = {}
    if recon_type == 'endpoints':
        recon_results = {
            'endpoints': ['/api/login', '/api/register', '/nosql/easy', '/xss/easy'],
            'methods': ['GET', 'POST'],
            'note': 'Some endpoints may require authentication'
        }
    elif recon_type == 'technologies':
        recon_results = {
            'server': 'Flask/2.0.0',
            'database': 'MongoDB',
            'framework': 'Python',
            'note': 'Technology stack identified'
        }
    elif recon_type == 'vulnerabilities':
        recon_results = {
            'potential_issues': ['Input validation', 'Authentication mechanisms'],
            'note': 'Further investigation required - no obvious vulnerabilities'
        }
    elif recon_type == 'users':
        recon_results = {
            'user_count': 'Unknown',
            'note': 'User enumeration may be possible through error messages'
        }
    
    # Store in session
    recon_data = session.get('recon_data', {})
    recon_data[recon_type] = recon_results
    session['recon_data'] = recon_data
    
    # Log reconnaissance
    if defense_logs_collection is not None:
        defense_logs_collection.insert_one({
            'user_id': user_id,
            'attack_type': 'reconnaissance',
            'action': f'Reconnaissance: {recon_type}',
            'source_ip': request.remote_addr,
            'severity': 'low',
            'timestamp': datetime.now()
        })
    
    return jsonify(recon_results)

@app.route('/api/http_request', methods=['POST'])
def api_http_request():
    """Handle HTTP request manipulation"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    method = data.get('method', 'GET')
    path = data.get('path', '/')
    headers = data.get('headers', '')
    body = data.get('body', '')
    
    # Simulate request processing
    response = {
        'status': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': {'message': 'Request processed', 'path': path}
    }
    
    # Update noise based on request type
    if method == 'POST' and body:
        update_noise_level(get_user_id(), 'http_manipulation', 30)
    
    return jsonify(response)

@app.route('/api/start_attack_chain', methods=['POST'])
def api_start_attack_chain():
    """Start a multi-step attack chain"""
    if not require_auth():
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = get_user_id()
    data = request.get_json()
    chain_type = data.get('chain_type', 'nosql')
    
    # Initialize attack chain
    attack_chains = session.get('attack_chains', {})
    attack_chains[chain_type] = {
        'status': 'in_progress',
        'steps_completed': 0,
        'total_steps': 3,
        'started_at': datetime.now().isoformat()
    }
    session['attack_chains'] = attack_chains
    
    return jsonify({'status': 'started', 'chain_type': chain_type})

@app.route('/update_security_config', methods=['POST'])
def update_security_config():
    """Update security configuration with budget constraints"""
    if not require_auth():
        return redirect(url_for('login'))
    
    user_mode = get_user_mode()
    if user_mode != 'defend':
        return redirect(url_for('defender_mode'))
    
    user_id = get_user_id()
    security_budget = session.get('security_budget', 100)
    
    # Calculate costs
    total_cost = 0
    
    # Input validation
    input_val_enabled = request.form.get('input_validation_enabled') == 'on'
    input_val_type = request.form.get('input_validation_type', 'none')
    if input_val_enabled:
        if input_val_type == 'blacklist':
            total_cost += 10
        elif input_val_type == 'whitelist':
            total_cost += 15
        elif input_val_type == 'prepared':
            total_cost += 20
    
    # Authentication
    if request.form.get('auth_lockout') == 'on':
        total_cost += 10
    if request.form.get('auth_captcha') == 'on':
        total_cost += 5
    if request.form.get('auth_mfa') == 'on':
        total_cost += 25
    
    # File upload
    if request.form.get('file_restrictions') == 'on':
        total_cost += 10
    if request.form.get('file_sandbox') == 'on':
        total_cost += 20
    
    # CSRF
    csrf_enabled = request.form.get('csrf_enabled') == 'on'
    csrf_impl = request.form.get('csrf_implementation', 'none')
    if csrf_enabled:
        if csrf_impl == 'weak':
            total_cost += 10
        elif csrf_impl == 'strong':
            total_cost += 15
    
    # Security headers
    headers_enabled = request.form.get('headers_enabled') == 'on'
    header_count = sum([
        1 if request.form.get('header_csp') else 0,
        1 if request.form.get('header_hsts') else 0,
        1 if request.form.get('header_xframe') else 0,
        1 if request.form.get('header_xss') else 0
    ])
    if headers_enabled:
        total_cost += header_count * 5
    
    # Check budget
    if total_cost > security_budget:
        return redirect(url_for('defender_mode') + '?error=budget_exceeded')
    
    # Update configuration
    if security_config_collection is not None:
        security_config_collection.update_one(
            {'user_id': user_id},
            {
                '$set': {
                    'input_validation': {
                        'enabled': input_val_enabled,
                        'type': input_val_type if input_val_enabled else 'none',
                        'cost': total_cost if input_val_enabled else 0
                    },
                    'authentication': {
                        'lockout_enabled': request.form.get('auth_lockout') == 'on',
                        'captcha_enabled': request.form.get('auth_captcha') == 'on',
                        'mfa_enabled': request.form.get('auth_mfa') == 'on',
                        'cost': sum([
                            10 if request.form.get('auth_lockout') == 'on' else 0,
                            5 if request.form.get('auth_captcha') == 'on' else 0,
                            25 if request.form.get('auth_mfa') == 'on' else 0
                        ])
                    },
                    'file_upload': {
                        'restrictions_enabled': request.form.get('file_restrictions') == 'on',
                        'sandbox_enabled': request.form.get('file_sandbox') == 'on',
                        'cost': sum([
                            10 if request.form.get('file_restrictions') == 'on' else 0,
                            20 if request.form.get('file_sandbox') == 'on' else 0
                        ])
                    },
                    'csrf_protection': {
                        'enabled': csrf_enabled,
                        'implementation': csrf_impl if csrf_enabled else 'none',
                        'cost': (10 if csrf_impl == 'weak' else 15) if csrf_enabled else 0
                    },
                    'security_headers': {
                        'enabled': headers_enabled,
                        'headers': [
                            'CSP' if request.form.get('header_csp') else None,
                            'HSTS' if request.form.get('header_hsts') else None,
                            'X-Frame-Options' if request.form.get('header_xframe') else None,
                            'X-XSS-Protection' if request.form.get('header_xss') else None
                        ],
                        'cost': header_count * 5 if headers_enabled else 0
                    },
                    'updated_at': datetime.now()
                }
            },
            upsert=True
        )
    
    return redirect(url_for('defender_mode'))

# ===========================================
# CONFIGURATION
# ===========================================

if __name__ == '__main__':
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True
    )
