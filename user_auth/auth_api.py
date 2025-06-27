# user_auth/auth_api.py - COMPLETE FIXED VERSION
import sys
import os
import time
import logging
from datetime import datetime, timedelta
import secrets
import re
import pymongo
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
from bson import ObjectId

# ============================================================================
# CONFIGURATION
# ============================================================================

class AuthConfig:
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'fraudshield-secret-key-change-in-production')
    API_KEY_PREFIX = 'fsk_'
    PASSWORD_MIN_LENGTH = 8
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30

# ============================================================================
# FLASK APP SETUP
# ============================================================================

app = Flask(__name__)
CORS(app, origins=["http://127.0.0.1:5500", "http://localhost:5500", "http://127.0.0.1:3000", "http://localhost:3000"])

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth_api.log'),
        logging.StreamHandler()
    ]
)

# Initialize MongoDB connection - FIXED: Synchronous connection
def get_db():
    """Get MongoDB database connection"""
    try:
        client = pymongo.MongoClient('mongodb://localhost:27017', serverSelectionTimeoutMS=3000)
        # Test connection
        client.server_info()
        return client.fraudshield
    except Exception as e:
        app.logger.error(f"MongoDB connection failed: {e}")
        return None

# Test MongoDB connection on startup
db = get_db()
if db is not None:
    app.logger.info("MongoDB connection established for authentication")
else:
    app.logger.error("Failed to connect to MongoDB")

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def generate_api_key() -> str:
    """Generate a secure API key"""
    return f"{AuthConfig.API_KEY_PREFIX}{secrets.token_urlsafe(32)}"

def validate_email(email: str) -> bool:
    """Simple email validation"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_strength(password: str) -> tuple:
    """Validate password meets security requirements"""
    if len(password) < AuthConfig.PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {AuthConfig.PASSWORD_MIN_LENGTH} characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;\':".,<>?]', password):
        return False, "Password must contain at least one special character"
    
    # Check for common weak patterns
    weak_patterns = [
        r'(.)\1{2,}',  # Repeated characters
        r'123456|234567|345678|456789|567890',  # Sequential numbers
        r'qwerty|asdfgh|zxcvbn',  # Keyboard patterns
        r'password|admin|user|test|guest'  # Common words
    ]
    
    for pattern in weak_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return False, "Password contains common patterns. Please choose a more secure password."
    
    return True, "Password is strong"

def create_error_response(message: str, status_code: int = 400, details: Optional[dict] = None) -> tuple:
    """Create standardized error response"""
    response = {
        "success": False,
        "error": message,
        "timestamp": datetime.now().isoformat()
    }
    if details:
        response["details"] = details
    
    return jsonify(response), status_code

def create_success_response(data: Optional[dict] = None, message: str = "Success") -> tuple:
    """Create standardized success response"""
    response = {
        "success": True,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }
    if data:
        response["data"] = data
    
    return jsonify(response), 200

def log_auth_attempt(email: str, success: bool, ip_address: str, user_agent: Optional[str] = None):
    """Log authentication attempts - FIXED: Synchronous version"""
    try:
        if db is not None:
            log_entry = {
                "email": email,
                "success": success,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "timestamp": datetime.now(),
                "type": "auth_attempt"
            }
            db.logs.insert_one(log_entry)
        
        app.logger.info(f"Auth attempt - Email: {email}, Success: {success}, IP: {ip_address}")
        
    except Exception as e:
        app.logger.error(f"Failed to log auth attempt: {e}")

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route("/auth/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db_status = "connected" if db is not None else "disconnected"
        if db is not None:
            # Try a simple operation
            try:
                db.users.count_documents({}, limit=1)
                db_status = "connected"
            except:
                db_status = "error"
        
        status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "database": db_status,
            "version": "1.0.0"
        }
        return jsonify(status)
    except Exception as e:
        app.logger.error(f"Health check failed: {e}")
        return create_error_response("Health check failed", 503)

@app.route("/auth/register", methods=["POST"])
def register():
    """User registration endpoint - FIXED VERSION"""
    if db is None:
        return create_error_response("Database unavailable", 503)
    
    try:
        data = request.get_json()
        if not data:
            return create_error_response("No data provided", 400)
        
        # FIXED: Add null checks for all fields
        name = (data.get('name') or '').strip()
        email = (data.get('email') or '').strip().lower()
        company = (data.get('company') or '').strip()
        password = data.get('password') or ''
        confirm_password = data.get('confirmPassword') or ''
        terms_accepted = data.get('terms', False)
        
        # Validation
        if not name:
            return create_error_response("Full name is required")
        
        if len(name) < 2:
            return create_error_response("Name must be at least 2 characters")
        
        if len(name.split()) < 2:
            return create_error_response("Please enter your full name (first and last)")
        
        if not email:
            return create_error_response("Email address is required")
        
        # Validate email format
        if not validate_email(email):
            return create_error_response("Please enter a valid email address")
        
        # Check for disposable email domains
        disposable_domains = ['tempmail.org', '10minutemail.com', 'guerrillamail.com', 'mailinator.com']
        domain = email.split('@')[1] if '@' in email else ''
        if domain in disposable_domains:
            return create_error_response("Temporary email addresses are not allowed")
        
        if not password:
            return create_error_response("Password is required")
        
        if password != confirm_password:
            return create_error_response("Passwords do not match")
        
        if not terms_accepted:
            return create_error_response("You must agree to the Terms of Service and Privacy Policy")
        
        # Validate password strength
        is_strong, password_message = validate_password_strength(password)
        if not is_strong:
            return create_error_response(password_message)
        
        # Check if user already exists
        existing_user = db.users.find_one({"email": email})
        if existing_user:
            return create_error_response("An account with this email already exists")
        
        # Hash password
        password_hash = hash_password(password)
        
        # Generate API key
        api_key = generate_api_key()
        
        # Create user document
        user_doc = {
            "name": name,
            "email": email,
            "company": company if company else None,
            "password_hash": password_hash,
            "api_key": api_key,
            "role": "user",
            "created_at": datetime.now(),
            "last_login": None,
            "is_verified": False,
            "login_attempts": 0,
            "locked_until": None,
            "terms_accepted_at": datetime.now()
        }
        
        # Insert user
        result = db.users.insert_one(user_doc)
        
        # Create site entry
        site_doc = {
            "user_id": str(result.inserted_id),
            "api_key": api_key,
            "site_name": f"{name}'s Site",
            "domain": email.split('@')[1],
            "created_at": datetime.now(),
            "status": "active"
        }
        db.sites.insert_one(site_doc)
        
        # Log successful registration
        log_auth_attempt(email, True, request.remote_addr or "", request.headers.get('User-Agent'))
        
        app.logger.info(f"User registered successfully: {email}")
        
        return create_success_response({
            "user": {
                "id": str(result.inserted_id),
                "name": name,
                "email": email,
                "company": company,
                "role": "user"
            },
            "api_key": api_key
        }, "Account created successfully")
        
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return create_error_response("Registration failed. Please try again.", 500)

@app.route("/auth/login", methods=["POST"])
def login():
    """User login endpoint - FIXED VERSION"""
    if db is None:
        return create_error_response("Database unavailable", 503)
    
    try:
        data = request.get_json()
        if not data:
            return create_error_response("No data provided", 400)
        
        # FIXED: Add null checks
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''
        remember = data.get('remember', False)
        
        if not email or not password:
            return create_error_response("Email and password are required")
        
        # Find user
        user = db.users.find_one({"email": email})
        
        if not user:
            log_auth_attempt(email, False, request.remote_addr or "", request.headers.get('User-Agent'))
            return create_error_response("Invalid email or password")
        
        # Check if account is locked
        if user.get('locked_until') and user['locked_until'] > datetime.now():
            minutes_left = int((user['locked_until'] - datetime.now()).total_seconds() / 60)
            return create_error_response(f"Account locked. Try again in {minutes_left} minutes.")
        
        # Verify password
        if not verify_password(password, user['password_hash']):
            # Increment login attempts
            attempts = user.get('login_attempts', 0) + 1
            update_data = {"login_attempts": attempts}
            
            # Lock account if too many attempts
            if attempts >= AuthConfig.MAX_LOGIN_ATTEMPTS:
                update_data["locked_until"] = datetime.now() + timedelta(minutes=AuthConfig.LOCKOUT_DURATION_MINUTES)
                app.logger.warning(f"Account locked for {email} due to too many failed attempts")
            
            db.users.update_one({"_id": user["_id"]}, {"$set": update_data})
            
            log_auth_attempt(email, False, request.remote_addr or "", request.headers.get('User-Agent'))
            return create_error_response("Invalid email or password")
        
        # Successful login - reset attempts and update last login
        db.users.update_one(
            {"_id": user["_id"]}, 
            {
                "$set": {
                    "last_login": datetime.now(),
                    "login_attempts": 0
                },
                "$unset": {"locked_until": ""}
            }
        )
        
        log_auth_attempt(email, True, request.remote_addr or "", request.headers.get('User-Agent'))
        
        app.logger.info(f"User logged in successfully: {email}")
        
        response_data = {
            "user": {
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "company": user.get("company"),
                "role": user.get("role", "user")
            },
            "api_key": user.get("api_key")
        }
        
        if remember:
            response_data["remember"] = True
        
        return create_success_response(response_data, "Login successful")
        
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return create_error_response("Login failed. Please try again.", 500)

@app.route("/auth/user-stats", methods=["GET"])
def get_user_stats():
    """Get user statistics"""
    try:
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Get basic stats
        total_users = db.users.count_documents({})
        verified_users = db.users.count_documents({"is_verified": True})
        active_today = db.users.count_documents({
            "last_login": {"$gte": datetime.now() - timedelta(days=1)}
        })
        
        # Get recent registrations
        recent_registrations = db.users.count_documents({
            "created_at": {"$gte": datetime.now() - timedelta(days=7)}
        })
        
        stats = {
            "total_users": total_users,
            "verified_users": verified_users,
            "active_today": active_today,
            "recent_registrations": recent_registrations,
            "verification_rate": round((verified_users / total_users * 100) if total_users > 0 else 0, 1)
        }
        
        return create_success_response(stats, "User statistics retrieved")
        
    except Exception as e:
        app.logger.error(f"Get user stats error: {e}")
        return create_error_response("Failed to get user statistics", 500)

@app.route("/auth/validate-api-key", methods=["POST"])
def validate_api_key():
    """Validate API key"""
    try:
        data = request.get_json()
        api_key = data.get('api_key', '') if data else ''
        
        if not api_key:
            return create_error_response("API key is required")
        
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        user = db.users.find_one({"api_key": api_key})
        
        if not user:
            return create_error_response("Invalid API key", 401)
        
        return create_success_response({
            "valid": True,
            "user": {
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "role": user.get("role", "user")
            }
        }, "API key is valid")
        
    except Exception as e:
        app.logger.error(f"API key validation error: {e}")
        return create_error_response("API key validation failed", 500)

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return create_error_response("Endpoint not found", 404)

@app.errorhandler(405)
def method_not_allowed(error):
    return create_error_response("Method not allowed", 405)

@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error(f"Internal server error: {error}")
    return create_error_response("Internal server error", 500)

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    app.logger.info("Starting FraudShield Authentication API...")
    app.logger.info(f"Max login attempts: {AuthConfig.MAX_LOGIN_ATTEMPTS}")
    app.logger.info(f"Lockout duration: {AuthConfig.LOCKOUT_DURATION_MINUTES} minutes")
    
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5001,
        threaded=True
    )