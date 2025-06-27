"""
FraudShield Authentication API - Pylance Standard Format
Author: FraudShield Team
Location: user_auth/auth_api.py
About: Complete authentication system with proper type hints and error handling
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import bcrypt
import pymongo
from pymongo import database
from bson import ObjectId
from flask import Flask, jsonify, request
from flask_cors import CORS

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# ============================================================================
# TYPE DEFINITIONS
# ============================================================================

UserDict = Dict[str, Any]
ResponseTuple = Tuple[Any, int]
SessionDict = Dict[str, Any]
DatabaseResponse = Optional[Dict[str, Any]]

# ============================================================================
# CONFIGURATION CLASS
# ============================================================================

class AuthConfig:
    """Configuration settings for the authentication API."""
    
    # Security Settings
    JWT_SECRET_KEY: str = os.getenv('JWT_SECRET_KEY', 'fraudshield-secret-key-change-in-production')
    API_KEY_PREFIX: str = 'fsk_'
    PASSWORD_MIN_LENGTH: int = 8
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 30
    
    # MongoDB Configuration
    MONGODB_URI: str = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
    DATABASE_NAME: str = os.getenv('DATABASE_NAME', 'fraudshield')
    
    # Session Configuration
    SESSION_DURATION_HOURS: int = 24
    REMEMBER_DURATION_DAYS: int = 30
    
    # API Configuration
    CORS_ORIGINS: List[str] = [
        "http://127.0.0.1:5500", 
        "http://localhost:5500",
        "http://127.0.0.1:3000", 
        "http://localhost:3000",
        "http://127.0.0.1:8080", 
        "http://localhost:8080"
    ]

# ============================================================================
# FLASK APP SETUP
# ============================================================================

app: Flask = Flask(__name__)
CORS(app, origins=AuthConfig.CORS_ORIGINS, supports_credentials=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth_api.log'),
        logging.StreamHandler()
    ]
)

logger: logging.Logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE MANAGER CLASS
# ============================================================================

class DatabaseManager:
    """Handles MongoDB connection with retry logic and health monitoring."""
    
    def __init__(self) -> None:
        """Initialize the database manager."""
        self.client: Optional[pymongo.MongoClient] = None
        self.db: Optional[database.Database] = None
        self.connected: bool = False
        self.connect()
    
    def connect(self, max_retries: int = 3, retry_delay: int = 2) -> bool:
        """
        Connect to MongoDB with retry logic.
        
        Args:
            max_retries: Maximum number of connection attempts
            retry_delay: Delay between retry attempts in seconds
            
        Returns:
            True if connection successful, False otherwise
        """
        for attempt in range(max_retries):
            try:
                logger.info(f"Attempting MongoDB connection (attempt {attempt + 1}/{max_retries})...")
                
                self.client = pymongo.MongoClient(
                    AuthConfig.MONGODB_URI, 
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=5000
                )
                
                # Test connection
                self.client.server_info()
                self.db = self.client[AuthConfig.DATABASE_NAME]
                
                # Test database access
                self.db.users.count_documents({}, limit=1)
                
                self.connected = True
                logger.info("✅ MongoDB connection established successfully")
                
                # Initialize collections if needed
                self._init_collections()
                return True
                
            except Exception as e:
                logger.error(f"❌ MongoDB connection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    logger.info(f"⏳ Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error("❌ All MongoDB connection attempts failed")
                    self.connected = False
                    return False
        
        return False
    
    def _init_collections(self) -> None:
        """Initialize database collections with indexes."""
        try:
            if self.db is None:
                return
                
            # Create indexes for better performance
            self.db.users.create_index("email", unique=True)
            self.db.users.create_index("api_key", unique=True)
            self.db.sessions.create_index("session_id", unique=True)
            self.db.sessions.create_index("expires_at", expireAfterSeconds=0)
            
            logger.info("✅ Database indexes created/verified")
            
            # Create default admin user if doesn't exist
            self._create_default_admin()
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize collections: {e}")
    
    def _create_default_admin(self) -> None:
        """Create default admin user if none exists."""
        try:
            if self.db is None:
                return
                
            admin_count = self.db.users.count_documents({"role": "admin"})
            if admin_count == 0:
                admin_user: UserDict = {
                    "name": "Administrator",
                    "email": "admin@fraudshield.com",
                    "password_hash": hash_password("Admin@123!"),
                    "api_key": generate_api_key(),
                    "role": "admin",
                    "created_at": datetime.now(),
                    "last_login": None,
                    "is_verified": True,
                    "login_attempts": 0,
                    "locked_until": None,
                    "terms_accepted_at": datetime.now()
                }
                
                self.db.users.insert_one(admin_user)
                logger.info("✅ Default admin user created: admin@fraudshield.com / Admin@123!")
                
        except Exception as e:
            logger.error(f"❌ Failed to create default admin: {e}")
    
    def is_connected(self) -> bool:
        """
        Check if database is connected.
        
        Returns:
            True if connected, False otherwise
        """
        if not self.connected or not self.client:
            return False
        
        try:
            self.client.server_info()
            return True
        except Exception:
            self.connected = False
            return False
    
    def reconnect(self) -> bool:
        """
        Attempt to reconnect to database.
        
        Returns:
            True if reconnection successful, False otherwise
        """
        if self.client:
            self.client.close()
        return self.connect()
    def get_database(self) -> Optional[database.Database]:
        """
        Get database connection with automatic reconnection.
        
        Returns:
            Database instance if connected, None otherwise
        """
        if not self.is_connected():
            logger.warning("🔄 Database disconnected, attempting reconnection...")
            if not self.reconnect():
                return None
        return self.db

# Initialize database manager
db_manager: DatabaseManager = DatabaseManager()

# ============================================================================
# SESSION MANAGEMENT FUNCTIONS
# ============================================================================

def create_session(user_id: Union[str, ObjectId], remember: bool = False) -> Optional[str]:
    """
    Create a new session for the user.
    
    Args:
        user_id: User's ObjectId or string ID
        remember: Whether this is a "remember me" session
        
    Returns:
        Session ID if successful, None otherwise
    """
    try:
        db = db_manager.get_database()
        if db is None:
            return None
        
        session_id = secrets.token_urlsafe(32)
        duration = (
            timedelta(days=AuthConfig.REMEMBER_DURATION_DAYS) 
            if remember 
            else timedelta(hours=AuthConfig.SESSION_DURATION_HOURS)
        )
        expires_at = datetime.now() + duration
        
        session_doc: SessionDict = {
            "session_id": session_id,
            "user_id": str(user_id),
            "created_at": datetime.now(),
            "expires_at": expires_at,
            "remember_me": remember,
            "ip_address": request.remote_addr or "unknown",
            "user_agent": request.headers.get('User-Agent', '')
        }
        
        db.sessions.insert_one(session_doc)
        return session_id
        
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        return None

def validate_session(session_id: str) -> DatabaseResponse:
    """
    Validate a session and return user info.
    
    Args:
        session_id: Session ID to validate
        
    Returns:
        User document if valid, None otherwise
    """
    try:
        db = db_manager.get_database()
        if db is None:
            return None
        
        session = db.sessions.find_one({
            "session_id": session_id,
            "expires_at": {"$gt": datetime.now()}
        })
        
        if not session:
            return None
        
        # Get user info
        user = db.users.find_one({"_id": ObjectId(session["user_id"])})
        if not user:
            # Clean up orphaned session
            db.sessions.delete_one({"session_id": session_id})
            return None
        
        return user
        
    except Exception as e:
        logger.error(f"Failed to validate session: {e}")
        return None

def cleanup_sessions() -> None:
    """Clean up expired sessions."""
    try:
        db = db_manager.get_database()
        if db is None:
            return
        
        result = db.sessions.delete_many({"expires_at": {"$lt": datetime.now()}})
        if result.deleted_count > 0:
            logger.info(f"Cleaned up {result.deleted_count} expired sessions")
            
    except Exception as e:
        logger.error(f"Failed to cleanup sessions: {e}")

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def hash_password(password: str) -> str:
    """
    Hash password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password string
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """
    Verify password against hash.
    
    Args:
        password: Plain text password
        hashed: Hashed password to verify against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def generate_api_key() -> str:
    """
    Generate a secure API key.
    
    Returns:
        Unique API key string with prefix
    """
    return f"{AuthConfig.API_KEY_PREFIX}{secrets.token_urlsafe(32)}"

def validate_email(email: str) -> bool:
    """
    Simple email validation.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid email format, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password meets security requirements.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
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

def create_error_response(message: str, status_code: int = 400, details: Optional[Dict[str, Any]] = None) -> ResponseTuple:
    """
    Create standardized error response.
    
    Args:
        message: Error message
        status_code: HTTP status code
        details: Optional additional details
        
    Returns:
        Tuple of (JSON response, status code)
    """
    response: Dict[str, Any] = {
        "success": False,
        "error": message,
        "timestamp": datetime.now().isoformat()
    }
    if details:
        response["details"] = details
    
    return jsonify(response), status_code

def create_success_response(data: Optional[Dict[str, Any]] = None, message: str = "Success") -> ResponseTuple:
    """
    Create standardized success response.
    
    Args:
        data: Optional response data
        message: Success message
        
    Returns:
        Tuple of (JSON response, status code)
    """
    response: Dict[str, Any] = {
        "success": True,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }
    if data:
        response["data"] = data
    
    return jsonify(response), 200

def log_auth_attempt(email: str, success: bool, ip_address: str, user_agent: Optional[str] = None) -> None:
    """
    Log authentication attempts.
    
    Args:
        email: User's email address
        success: Whether the attempt was successful
        ip_address: Client's IP address
        user_agent: Client's user agent string
    """
    try:
        db = db_manager.get_database()
        if db is not None:
            log_entry: Dict[str, Any] = {
                "email": email,
                "success": success,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "timestamp": datetime.now(),
                "type": "auth_attempt"
            }
            db.logs.insert_one(log_entry)
        
        logger.info(f"Auth attempt - Email: {email}, Success: {success}, IP: {ip_address}")
        
    except Exception as e:
        logger.error(f"Failed to log auth attempt: {e}")

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route("/auth/health", methods=["GET"])
def health_check() -> ResponseTuple:
    """
    Health check endpoint.
    
    Returns:
        JSON response with system health status
    """
    try:
        # Test database connection
        db_status = "disconnected"
        db_info: Dict[str, int] = {}
        
        db = db_manager.get_database()
        if db is not None:
            try:
                # Test database operations
                user_count = db.users.count_documents({})
                session_count = db.sessions.count_documents({})
                
                db_status = "connected"
                db_info = {
                    "users": user_count,
                    "active_sessions": session_count
                }
            except Exception as e:
                db_status = f"error: {str(e)}"
        
        status: Dict[str, Any] = {
            "status": "healthy" if db_status == "connected" else "degraded",
            "timestamp": datetime.now().isoformat(),
            "database": db_status,
            "database_info": db_info,
            "version": "1.0.0",
            "uptime": time.time() - start_time if 'start_time' in globals() else 0
        }
        return jsonify(status), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return create_error_response("Health check failed", 503)

@app.route("/auth/register", methods=["POST"])
def register() -> ResponseTuple:
    """
    User registration endpoint.
    
    Returns:
        JSON response with user data and API key if successful
    """
    db = db_manager.get_database()
    if db is None:
        return create_error_response("Database unavailable", 503)
    
    try:
        data = request.get_json()
        if not data:
            return create_error_response("No data provided", 400)
        
        # Extract and validate data
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
        user_doc: UserDict = {
            "name": name,
            "email": email,
            "company": company if company else None,
            "password_hash": password_hash,
            "api_key": api_key,
            "role": "user",
            "created_at": datetime.now(),
            "last_login": None,
            "is_verified": True,  # Auto-verify for demo
            "login_attempts": 0,
            "locked_until": None,
            "terms_accepted_at": datetime.now()
        }
        
        # Insert user
        result = db.users.insert_one(user_doc)
        
        # Create site entry
        site_doc: Dict[str, Any] = {
            "user_id": str(result.inserted_id),
            "api_key": api_key,
            "site_name": f"{name}'s Site",
            "domain": email.split('@')[1],
            "created_at": datetime.now(),
            "status": "active"
        }
        db.sites.insert_one(site_doc)
        
        # Create session
        session_id = create_session(result.inserted_id, remember=False)
        
        # Log successful registration
        log_auth_attempt(email, True, request.remote_addr or "", request.headers.get('User-Agent'))
        
        logger.info(f"User registered successfully: {email}")
        
        response_data: Dict[str, Any] = {
            "user": {
                "id": str(result.inserted_id),
                "name": name,
                "email": email,
                "company": company,
                "role": "user"
            },
            "api_key": api_key,
            "session_id": session_id
        }
        
        return create_success_response(response_data, "Account created successfully")
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return create_error_response("Registration failed. Please try again.", 500)

@app.route("/auth/login", methods=["POST"])
def login() -> ResponseTuple:
    """
    User login endpoint.
    
    Returns:
        JSON response with user data and session info if successful
    """
    db = db_manager.get_database()
    if db is None:
        return create_error_response("Database unavailable", 503)
    
    try:
        data = request.get_json()
        if not data:
            return create_error_response("No data provided", 400)
        
        # Extract and validate data
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
            update_data: Dict[str, Any] = {"login_attempts": attempts}
            
            # Lock account if too many attempts
            if attempts >= AuthConfig.MAX_LOGIN_ATTEMPTS:
                update_data["locked_until"] = datetime.now() + timedelta(minutes=AuthConfig.LOCKOUT_DURATION_MINUTES)
                logger.warning(f"Account locked for {email} due to too many failed attempts")
            
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
        
        # Create session
        session_id = create_session(user["_id"], remember)
        
        # Cleanup old sessions
        cleanup_sessions()
        
        log_auth_attempt(email, True, request.remote_addr or "", request.headers.get('User-Agent'))
        
        logger.info(f"User logged in successfully: {email}")
        
        response_data: Dict[str, Any] = {
            "user": {
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "company": user.get("company"),
                "role": user.get("role", "user")
            },
            "api_key": user.get("api_key"),
            "session_id": session_id
        }
        
        if remember:
            response_data["remember"] = True
        
        return create_success_response(response_data, "Login successful")
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return create_error_response("Login failed. Please try again.", 500)

@app.route("/auth/logout", methods=["POST"])
def logout() -> ResponseTuple:
    """
    User logout endpoint.
    
    Returns:
        JSON response confirming logout
    """
    try:
        data = request.get_json() or {}
        session_id = data.get('session_id')
        
        if session_id:
            db = db_manager.get_database()
            if db is not None:
                db.sessions.delete_one({"session_id": session_id})
        
        return create_success_response(None, "Logged out successfully")
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return create_error_response("Logout failed", 500)

@app.route("/auth/validate-session", methods=["POST"])
def validate_session_endpoint() -> ResponseTuple:
    """
    Validate session endpoint.
    
    Returns:
        JSON response with session validation result
    """
    try:
        data = request.get_json()
        session_id = data.get('session_id', '') if data else ''
        
        if not session_id:
            return create_error_response("Session ID is required")
        
        user = validate_session(session_id)
        
        if not user:
            return create_error_response("Invalid or expired session", 401)
        
        return create_success_response({
            "valid": True,
            "user": {
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "role": user.get("role", "user")
            }
        }, "Session is valid")
        
    except Exception as e:
        logger.error(f"Session validation error: {e}")
        return create_error_response("Session validation failed", 500)

@app.route("/auth/user-stats", methods=["GET"])
def get_user_stats() -> ResponseTuple:
    """
    Get user statistics endpoint.
    
    Returns:
        JSON response with user statistics
    """
    try:
        db = db_manager.get_database()
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
        
        stats: Dict[str, Union[int, float]] = {
            "total_users": total_users,
            "verified_users": verified_users,
            "active_today": active_today,
            "recent_registrations": recent_registrations,
            "verification_rate": round((verified_users / total_users * 100) if total_users > 0 else 0, 1)
        }
        
        return create_success_response(stats, "User statistics retrieved")
        
    except Exception as e:
        logger.error(f"Get user stats error: {e}")
        return create_error_response("Failed to get user statistics", 500)

@app.route("/auth/validate-api-key", methods=["POST"])
def validate_api_key() -> ResponseTuple:
    """
    Validate API key endpoint.
    
    Returns:
        JSON response with API key validation result
    """
    try:
        data = request.get_json()
        api_key = data.get('api_key', '') if data else ''
        
        if not api_key:
            return create_error_response("API key is required")
        
        db = db_manager.get_database()
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
        logger.error(f"API key validation error: {e}")
        return create_error_response("API key validation failed", 500)

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error: Any) -> ResponseTuple:
    """Handle 404 errors."""
    return create_error_response("Endpoint not found", 404)

@app.errorhandler(405)
def method_not_allowed(error: Any) -> ResponseTuple:
    """Handle 405 errors."""
    return create_error_response("Method not allowed", 405)

@app.errorhandler(500)
def internal_server_error(error: Any) -> ResponseTuple:
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return create_error_response("Internal server error", 500)

# ============================================================================
# MAINTENANCE TASKS
# ============================================================================

def run_maintenance() -> None:
    """Run periodic maintenance tasks."""
    try:
        cleanup_sessions()
        logger.info("✅ Maintenance tasks completed")
    except Exception as e:
        logger.error(f"❌ Maintenance tasks failed: {e}")

def maintenance_worker() -> None:
    """Background worker for maintenance tasks."""
    while True:
        time.sleep(3600)  # Run every hour
        run_maintenance()

# ============================================================================
# MAIN APPLICATION
# ============================================================================

if __name__ == "__main__":
    start_time: float = time.time()
    
    logger.info("🚀 Starting FraudShield Authentication API...")
    logger.info(f"Max login attempts: {AuthConfig.MAX_LOGIN_ATTEMPTS}")
    logger.info(f"Lockout duration: {AuthConfig.LOCKOUT_DURATION_MINUTES} minutes")
    logger.info(f"Database: {AuthConfig.MONGODB_URI}/{AuthConfig.DATABASE_NAME}")
    
    if db_manager.connected:
        logger.info("✅ Authentication API is ready!")
        logger.info("📡 Default admin: admin@fraudshield.com / Admin@123!")
    else:
        logger.warning("⚠️ Authentication API starting with limited functionality (no database)")
    
    # Start maintenance worker in background
    maintenance_thread = threading.Thread(target=maintenance_worker, daemon=True)
    maintenance_thread.start()
    
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5001,
        threaded=True
    )