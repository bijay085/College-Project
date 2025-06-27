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
from flask import Flask, jsonify, request, g, make_response
from flask_cors import CORS
from collections import defaultdict

app: Flask = Flask(__name__)

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# ============================================================================
# TYPE DEFINITIONS
# ============================================================================

UserDict = Dict[str, Any]
ResponseTuple = Tuple[Any, int]
SessionDict = Dict[str, Any]
DatabaseResponse = Optional[Dict[str, Any]]

# Simple in-memory rate limiter for admin stats endpoint
admin_stats_last_access = defaultdict(float)
ADMIN_STATS_RATE_LIMIT_SECONDS = 60

# ============================================================================
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
    # FIXED: Enhanced CORS Configuration
    CORS_ORIGINS: List[str] = [
        "http://127.0.0.1:5500", 
        "http://localhost:5500",
        "http://127.0.0.1:3000", 
        "http://localhost:3000",
        "http://127.0.0.1:8080", 
        "http://localhost:8080",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "null"  # file:// protocol for local dev
    ]

# ============================================================================
# FLASK APP SETUP
# ============================================================================

app: Flask = Flask(__name__)

# FIXED: Enhanced CORS configuration
CORS(app, 
     origins=AuthConfig.CORS_ORIGINS,
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     expose_headers=['Content-Type', 'Authorization'])

# ============================================================================
# FLASK APP SETUP
# ============================================================================

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

def log_warning(message, extra=None):
    """Log a warning with extra context."""
    logger.warning(f"[WARN] {message} | Extra: {extra}")

def log_error(message, extra=None):
    """Log an error with extra context."""
    logger.error(f"[ERROR] {message} | Extra: {extra}")

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
                logger.info("MongoDB connection established successfully")
                
                # Initialize collections if needed
                self._init_collections()
                return True
                
            except Exception as e:
                logger.error(f"MongoDB connection attempt {attempt + 1} failed: {e}")
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
            # Specify sparse=True to match existing index and avoid conflict
            self.db.users.create_index("api_key", unique=True, sparse=True)
            self.db.sessions.create_index("session_id", unique=True)
            self.db.sessions.create_index("expires_at", expireAfterSeconds=0)
            
            logger.info("Database indexes created/verified")
            
            # Create default admin user if doesn't exist
            self._create_default_admin()
            
        except Exception as e:
            logger.error(f"Failed to initialize collections: {e}")
    
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
                logger.info("Default admin user created: admin@fraudshield.com / Admin@123!")
                
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
            logger.warning("Database disconnected, attempting reconnection...")
            if not self.reconnect():
                return None
        return self.db

# Initialize database manager
db_manager: DatabaseManager = DatabaseManager()

# ============================================================================
# SESSION MANAGEMENT FUNCTIONS
# ============================================================================S

def create_session(user_id: Union[str, ObjectId ], remember: bool = False) -> Optional[str]:
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
        log_error(f"Failed to create session: {e}")
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
        log_error(f"Failed to validate session: {e}")
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
        log_error(f"Failed to cleanup sessions: {e}")

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
# USER MANAGEMENT ENDPOINTS (ADMIN ONLY)
# ============================================================================

from functools import wraps

def require_admin_auth():
    """Decorator to require admin authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get authorization header
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return create_error_response("Authentication required", 401)
                
                # Extract API key
                api_key = auth_header.replace('Bearer ', '')
                
                # Validate API key and check admin role
                db = db_manager.get_database()
                if db is None:
                    return create_error_response("Database unavailable", 503)
                
                user = db.users.find_one({"api_key": api_key})
                if not user:
                    return create_error_response("Invalid API key", 401)
                
                if user.get('role') != 'admin':
                    return create_error_response("Admin access required", 403)
                
                # Store user info for use in endpoint
                g.current_user = user
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Admin auth check failed: {e}")
                return create_error_response("Authentication failed", 401)
        
        return decorated_function
    return decorator

@app.route("/auth/users", methods=["GET"])
@require_admin_auth()
def get_all_users() -> ResponseTuple:
    """Get all users (admin only)"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Get query parameters
        search = request.args.get('search', '').strip()
        role_filter = request.args.get('role', '').strip()
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 100))
        
        # Build query
        query = {}
        if search:
            query['$or'] = [
                {'name': {'$regex': search, '$options': 'i'}},
                {'email': {'$regex': search, '$options': 'i'}},
                {'company': {'$regex': search, '$options': 'i'}}
            ]
        
        if role_filter:
            query['role'] = role_filter
        
        # Get total count
        total_count = db.users.count_documents(query)
        
        # Get users with pagination
        skip = (page - 1) * limit
        cursor = db.users.find(query, {
            'password_hash': 0  # Exclude password hash
        }).sort('created_at', -1).skip(skip).limit(limit)
        
        users = []
        for user in cursor:
            user_data = {
                'id': str(user['_id']),
                'name': user.get('name', ''),
                'email': user.get('email', ''),
                'company': user.get('company', ''),
                'role': user.get('role', 'user'),
                'created_at': user.get('created_at').isoformat() if user.get('created_at') else None,
                'last_login': user.get('last_login').isoformat() if user.get('last_login') else None,
                'is_verified': user.get('is_verified', False),
                'login_attempts': user.get('login_attempts', 0),
                'locked_until': user.get('locked_until').isoformat() if user.get('locked_until') else None,
                'api_key': user.get('api_key', ''),
                'status': 'locked' if user.get('locked_until') and user.get('locked_until') > datetime.now() else 'active'
            }
            users.append(user_data)
        
        response_data = {
            'users': users,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_count,
                'pages': (total_count + limit - 1) // limit
            }
        }
        
        logger.info(f"Retrieved {len(users)} users (page {page}, total: {total_count})")
        return create_success_response(response_data, f"Retrieved {len(users)} users")
        
    except ValueError as e:
        return create_error_response(f"Invalid parameters: {str(e)}", 400)
    except Exception as e:
        logger.error(f"Get users error: {e}")
        return create_error_response("Failed to retrieve users", 500)

@app.route("/auth/users", methods=["POST"])
@require_admin_auth()
def create_user() -> ResponseTuple:
    """Create a new user (admin only)"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        data = request.get_json()
        if not data:
            return create_error_response("No data provided", 400)
        
        # Extract and validate data
        name = (data.get('name') or '').strip()
        email = (data.get('email') or '').strip().lower()
        company = (data.get('company') or '').strip()
        password = data.get('password') or ''
        role = data.get('role', 'user').strip()
        locked = data.get('locked', False)
        
        # Validation
        if not name or len(name) < 2:
            return create_error_response("Valid name is required")
        
        if not email or not validate_email(email):
            return create_error_response("Valid email is required")
        
        if not password or len(password) < 8:
            return create_error_response("Password must be at least 8 characters")
        
        if role not in ['user', 'admin']:
            return create_error_response("Role must be 'user' or 'admin'")
        
        # Check if user already exists
        existing_user = db.users.find_one({"email": email})
        if existing_user:
            return create_error_response("User with this email already exists")
        
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
            "role": role,
            "created_at": datetime.now(),
            "last_login": None,
            "is_verified": True,
            "login_attempts": 0,
            "locked_until": datetime.now() + timedelta(days=365) if locked else None,
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
        
        logger.info(f"User created by admin: {email}")
        
        response_data = {
            "id": str(result.inserted_id),
            "name": name,
            "email": email,
            "company": company,
            "role": role,
            "api_key": api_key,
            "status": "locked" if locked else "active"
        }
        
        return create_success_response(response_data, "User created successfully")
        
    except Exception as e:
        logger.error(f"Create user error: {e}")
        return create_error_response("Failed to create user", 500)

@app.route("/auth/users/<user_id>", methods=["PUT"])
@require_admin_auth()
def update_user(user_id: str) -> ResponseTuple:
    """Update a user (admin only)"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Validate user_id
        try:
            user_object_id = ObjectId(user_id)
        except:
            return create_error_response("Invalid user ID", 400)
        
        # Check if user exists
        existing_user = db.users.find_one({"_id": user_object_id})
        if not existing_user:
            return create_error_response("User not found", 404)
        
        data = request.get_json()
        if not data:
            return create_error_response("No data provided", 400)
        
        # Build update document
        update_doc = {}
        
        # Update name
        if 'name' in data:
            name = (data['name'] or '').strip()
            if name and len(name) >= 2:
                update_doc['name'] = name
            else:
                return create_error_response("Valid name is required")
        
        # Update email
        if 'email' in data:
            email = (data['email'] or '').strip().lower()
            if email and validate_email(email):
                # Check if email is already taken by another user
                email_check = db.users.find_one({"email": email, "_id": {"$ne": user_object_id}})
                if email_check:
                    return create_error_response("Email already in use by another user")
                update_doc['email'] = email
            else:
                return create_error_response("Valid email is required")
        
        # Update company
        if 'company' in data:
            company = (data['company'] or '').strip()
            update_doc['company'] = company if company else None
        
        # Update role
        if 'role' in data:
            role = (data['role'] or '').strip()
            if role in ['user', 'admin']:
                update_doc['role'] = role
            else:
                return create_error_response("Role must be 'user' or 'admin'")
        
        # Update password if provided
        if 'password' in data and data['password']:
            password = data['password']
            if len(password) >= 8:
                update_doc['password_hash'] = hash_password(password)
                update_doc['login_attempts'] = 0  # Reset login attempts
            else:
                return create_error_response("Password must be at least 8 characters")
        
        # Update locked status
        if 'locked' in data:
            locked = data['locked']
            if locked:
                update_doc['locked_until'] = datetime.now() + timedelta(days=365)
            else:
                update_doc['locked_until'] = None
                update_doc['login_attempts'] = 0
        
        # Regenerate API key if requested
        if data.get('regenerate_api_key'):
            new_api_key = generate_api_key()
            update_doc['api_key'] = new_api_key
        
        if not update_doc:
            return create_error_response("No valid updates provided", 400)
        
        # Perform update
        result = db.users.update_one(
            {"_id": user_object_id},
            {"$set": update_doc}
        )
        
        if result.modified_count == 0:
            return create_error_response("No changes made", 400)
        
        # Get updated user
        updated_user = db.users.find_one({"_id": user_object_id}, {'password_hash': 0})
        if not updated_user:
            return create_error_response("Failed to retrieve updated user", 500)
        
        response_data = {
            'id': str(updated_user['_id']),
            'name': updated_user.get('name', ''),
            'email': updated_user.get('email', ''),
            'company': updated_user.get('company', ''),
            'role': updated_user.get('role', 'user'),
            'api_key': updated_user.get('api_key', ''),
            'status': 'locked' if updated_user.get('locked_until') and updated_user.get('locked_until') > datetime.now() else 'active'
        }
        
        logger.info(f"User updated by admin: {updated_user.get('email')}")
        return create_success_response(response_data, "User updated successfully")
        
    except Exception as e:
        logger.error(f"Update user error: {e}")
        return create_error_response("Failed to update user", 500)

@app.route("/auth/users/<user_id>", methods=["DELETE"])
@require_admin_auth()
def delete_user(user_id: str) -> ResponseTuple:
    """Delete a user (admin only)"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Validate user_id
        try:
            user_object_id = ObjectId(user_id)
        except:
            return create_error_response("Invalid user ID", 400)
        
        # Check if user exists
        user_to_delete = db.users.find_one({"_id": user_object_id})
        if not user_to_delete:
            return create_error_response("User not found", 404)
        
        # Prevent admin from deleting themselves
        from flask import g
        current_user_id = str(g.current_user['_id'])
        if user_id == current_user_id:
            return create_error_response("Cannot delete your own account", 400)
        
        # Prevent deleting the last admin
        if user_to_delete.get('role') == 'admin':
            admin_count = db.users.count_documents({"role": "admin"})
            if admin_count <= 1:
                return create_error_response("Cannot delete the last admin account", 400)
        
        # Delete user
        result = db.users.delete_one({"_id": user_object_id})
        
        if result.deleted_count == 0:
            return create_error_response("Failed to delete user", 500)
        
        # Clean up related data
        db.sites.delete_many({"user_id": user_id})
        db.sessions.delete_many({"user_id": user_id})
        
        logger.info(f"User deleted by admin: {user_to_delete.get('email')}")
        return create_success_response(None, "User deleted successfully")
        
    except Exception as e:
        logger.error(f"Delete user error: {e}")
        return create_error_response("Failed to delete user", 500)

@app.route("/auth/admin/stats", methods=["GET"])
@require_admin_auth()
def get_admin_stats() -> ResponseTuple:
    """Get detailed admin statistics"""
    # Rate limit: one request per ADMIN_STATS_RATE_LIMIT_SECONDS per user
    api_key = request.headers.get('Authorization', '').replace('Bearer ', '')
    now = time.time()
    last_access = admin_stats_last_access.get(api_key, 0)
    if now - last_access < ADMIN_STATS_RATE_LIMIT_SECONDS:
        return jsonify({
            "success": False,
            "error": f"Too many requests. Please wait {ADMIN_STATS_RATE_LIMIT_SECONDS} seconds between requests.",
            "timestamp": datetime.now().isoformat()
        }), 429
    admin_stats_last_access[api_key] = now

    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Calculate various statistics
        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)
        month_start = today_start - timedelta(days=30)
        
        stats: Dict[str, Any] = {
            # User counts
            "total_users": db.users.count_documents({}),
            "admin_users": db.users.count_documents({"role": "admin"}),
            "regular_users": db.users.count_documents({"role": "user"}),
            "verified_users": db.users.count_documents({"is_verified": True}),
            
            # Activity stats
            "active_today": db.users.count_documents({
                "last_login": {"$gte": today_start}
            }),
            "active_this_week": db.users.count_documents({
                "last_login": {"$gte": week_start}
            }),
            "active_this_month": db.users.count_documents({
                "last_login": {"$gte": month_start}
            }),
            
            # Registration stats
            "new_today": db.users.count_documents({
                "created_at": {"$gte": today_start}
            }),
            "new_this_week": db.users.count_documents({
                "created_at": {"$gte": week_start}
            }),
            "new_this_month": db.users.count_documents({
                "created_at": {"$gte": month_start}
            }),
            
            # Security stats
            "locked_accounts": db.users.count_documents({
                "locked_until": {"$gt": now}
            }),
            "never_logged_in": db.users.count_documents({
                "last_login": None
            }),
            
            # System stats
            "total_sites": db.sites.count_documents({}),
            "active_sessions": db.sessions.count_documents({
                "expires_at": {"$gt": now}
            })
        }
        
        # Recent activity
        recent_users = list(db.users.find(
            {},
            {"name": 1, "email": 1, "created_at": 1, "last_login": 1, "role": 1}
        ).sort("created_at", -1).limit(10))
        
        for user in recent_users:
            user['id'] = str(user.pop('_id'))
            if user.get('created_at'):
                user['created_at'] = user['created_at'].isoformat()
            if user.get('last_login'):
                user['last_login'] = user['last_login'].isoformat()
        
        stats['recent_users'] = recent_users
        
        return create_success_response(stats, "Admin statistics retrieved")
        
    except Exception as e:
        logger.error(f"Get admin stats error: {e}")
        return create_error_response("Failed to get statistics", 500)

# ============================================================================
# SETTINGS MANAGEMENT ENDPOINTS
# ============================================================================

@app.route("/auth/profile/update", methods=["PUT"])
@require_admin_auth()
def update_profile() -> ResponseTuple:
    """Update user profile (admin or own profile)"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        data = request.get_json()
        if not data:
            return create_error_response("No data provided", 400)
        
        current_user = g.current_user
        user_id_to_update = data.get('user_id', str(current_user['_id']))
        
        # Check if user can update this profile
        if str(current_user['_id']) != user_id_to_update and current_user.get('role') != 'admin':
            return create_error_response("Permission denied", 403)
        
        # Build update document
        update_doc = {}
        
        if 'name' in data and data['name'].strip():
            update_doc['name'] = data['name'].strip()
        
        if 'company' in data:
            update_doc['company'] = data['company'].strip() if data['company'] else None
        
        if not update_doc:
            return create_error_response("No valid updates provided", 400)
        
        update_doc['updated_at'] = datetime.now()
        
        # Update user
        try:
            user_object_id = ObjectId(user_id_to_update)
        except:
            return create_error_response("Invalid user ID", 400)
        
        result = db.users.update_one(
            {"_id": user_object_id},
            {"$set": update_doc}
        )
        
        if result.modified_count == 0:
            return create_error_response("No changes made or user not found", 400)
        
        # Get updated user
        updated_user = db.users.find_one({"_id": user_object_id}, {'password_hash': 0})
        if not updated_user:
            return create_error_response("Failed to retrieve updated user", 500)
        
        response_data = {
            'id': str(updated_user['_id']),
            'name': updated_user.get('name', ''),
            'email': updated_user.get('email', ''),
            'company': updated_user.get('company', ''),
            'role': updated_user.get('role', 'user')
        }
        
        logger.info(f"Profile updated: {updated_user.get('email')}")
        return create_success_response(response_data, "Profile updated successfully")
        
    except Exception as e:
        logger.error(f"Update profile error: {e}")
        return create_error_response("Failed to update profile", 500)

@app.route("/auth/settings/thresholds", methods=["GET"])
@require_admin_auth()
def get_fraud_thresholds() -> ResponseTuple:
    """Get current fraud detection thresholds"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Get thresholds from system_settings collection
        settings = db.system_settings.find_one({"_id": "fraud_thresholds"})
        
        if not settings:
            # Create default settings
            default_settings = {
                "_id": "fraud_thresholds",
                "fraud_threshold": 0.7,
                "suspicious_threshold": 0.4,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            }
            db.system_settings.insert_one(default_settings)
            settings = default_settings
        
        response_data = {
            "fraud_threshold": settings.get("fraud_threshold", 0.7) if settings else 0.7,
            "suspicious_threshold": settings.get("suspicious_threshold", 0.4) if settings else 0.4,
            "updated_at": settings.get("updated_at") if settings else None
        }
        
        return create_success_response(response_data, "Thresholds retrieved successfully")
        
    except Exception as e:
        logger.error(f"Get thresholds error: {e}")
        return create_error_response("Failed to get thresholds", 500)

@app.route("/auth/settings/thresholds", methods=["PUT"])
@require_admin_auth()
def update_fraud_thresholds() -> ResponseTuple:
    """Update fraud detection thresholds"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        data = request.get_json()
        if not data:
            return create_error_response("No data provided", 400)
        
        # Validate threshold values
        fraud_threshold = data.get('fraud_threshold')
        suspicious_threshold = data.get('suspicious_threshold')
        
        if fraud_threshold is not None:
            try:
                fraud_threshold = float(fraud_threshold)
                if not 0.1 <= fraud_threshold <= 1.0:
                    return create_error_response("Fraud threshold must be between 0.1 and 1.0", 400)
            except (ValueError, TypeError):
                return create_error_response("Invalid fraud threshold value", 400)
        
        if suspicious_threshold is not None:
            try:
                suspicious_threshold = float(suspicious_threshold)
                if not 0.1 <= suspicious_threshold <= 1.0:
                    return create_error_response("Suspicious threshold must be between 0.1 and 1.0", 400)
            except (ValueError, TypeError):
                return create_error_response("Invalid suspicious threshold value", 400)
        
        # Ensure fraud threshold is higher than suspicious threshold
        if fraud_threshold and suspicious_threshold and fraud_threshold <= suspicious_threshold:
            return create_error_response("Fraud threshold must be higher than suspicious threshold", 400)
        
        # Build update document
        update_doc: Dict[str, Any] = {"updated_at": datetime.now()}
        
        if fraud_threshold is not None:
            update_doc["fraud_threshold"] = fraud_threshold
        
        if suspicious_threshold is not None:
            update_doc["suspicious_threshold"] = suspicious_threshold
        
        # Update or create settings
        result = db.system_settings.update_one(
            {"_id": "fraud_thresholds"},
            {"$set": update_doc},
            upsert=True
        )
        
        # Get updated settings
        settings = db.system_settings.find_one({"_id": "fraud_thresholds"})
        
        response_data = {
            "fraud_threshold": settings["fraud_threshold"] if settings and "fraud_threshold" in settings else 0.7,
            "suspicious_threshold": settings["suspicious_threshold"] if settings and "suspicious_threshold" in settings else 0.4,
            "updated_at": settings["updated_at"] if settings and "updated_at" in settings else None
        }
        
        logger.info(f"Thresholds updated by admin: {g.current_user.get('email')}")
        return create_success_response(response_data, "Thresholds updated successfully")
        
    except Exception as e:
        logger.error(f"Update thresholds error: {e}")
        return create_error_response("Failed to update thresholds", 500)

@app.route("/auth/settings/system-health", methods=["GET"])
@require_admin_auth()
def get_system_health() -> ResponseTuple:
    """Get system health status"""
    try:
        health_status: Dict[str, Any] = {
            "api_status": "online",
            "database_status": "checking",
            "rule_engine_status": "active",
            "last_check": datetime.now().isoformat()
        }
        
        # Check database connection
        try:
            db = db_manager.get_database()
            if db is not None:
                # Test database operation
                test_result = db.users.count_documents({}, limit=1)
                health_status["database_status"] = "online"
                health_status["database_info"] = {
                    "collections": len(db.list_collection_names()),
                    "users_count": db.users.count_documents({})
                }
            else:
                health_status["database_status"] = "offline"
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            health_status["database_status"] = "offline"
            health_status["database_error"] = str(e)
        
        # Check bulk API (fraud checking API)
        try:
            import requests
            bulk_response = requests.get('http://127.0.0.1:5000/health', timeout=5)
            if bulk_response.status_code == 200:
                health_status["fraud_api_status"] = "online"
            else:
                health_status["fraud_api_status"] = "degraded"
        except Exception as e:
            health_status["fraud_api_status"] = "offline"
            health_status["fraud_api_error"] = str(e)
        
        return create_success_response(health_status, "System health retrieved")
        
    except Exception as e:
        logger.error(f"System health check error: {e}")
        return create_error_response("Failed to get system health", 500)

@app.route("/auth/user/regenerate-api-key", methods=["POST"])
@require_admin_auth()
def regenerate_user_api_key() -> ResponseTuple:
    """Regenerate API key for current user"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        current_user = g.current_user
        
        # Generate new API key
        new_api_key = generate_api_key()
        
        # Update user with new API key
        result = db.users.update_one(
            {"_id": current_user["_id"]},
            {
                "$set": {
                    "api_key": new_api_key,
                    "api_key_updated_at": datetime.now()
                }
            }
        )
        
        if result.modified_count == 0:
            return create_error_response("Failed to update API key", 500)
        
        # Update sites collection as well
        db.sites.update_many(
            {"user_id": str(current_user["_id"])},
            {"$set": {"api_key": new_api_key}}
        )
        
        response_data = {
            "api_key": new_api_key,
            "regenerated_at": datetime.now().isoformat()
        }
        
        logger.info(f"API key regenerated for user: {current_user.get('email')}")
        return create_success_response(response_data, "API key regenerated successfully")
        
    except Exception as e:
        logger.error(f"Regenerate API key error: {e}")
        return create_error_response("Failed to regenerate API key", 500)

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
        logger.info("Maintenance tasks completed")
    except Exception as e:
        logger.error(f"Maintenance tasks failed: {e}")

def maintenance_worker() -> None:
    """Background worker for maintenance tasks."""
    while True:
        time.sleep(3600)  # Run every hour
        run_maintenance()

# ============================================================================
# CORS PREFLIGHT HANDLER
@app.before_request
def handle_preflight():
    """Handle CORS preflight requests."""
    if request.method == "OPTIONS":
        response = jsonify({'status': 'OK'})
        response.headers.add("Access-Control-Allow-Origin", request.headers.get('Origin', '*'))
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept,Origin,X-Requested-With")
        response.headers.add('Access-Control-Allow-Methods', "GET,PUT,POST,DELETE,OPTIONS")
        response.headers.add('Access-Control-Allow-Credentials', "true")
        return response

# ============================================================================
# MAIN APPLICATION
# ============================================================================

if __name__ == "__main__":
    start_time: float = time.time()
    
    logger.info("Starting FraudShield Authentication API...")
    logger.info(f"Max login attempts: {AuthConfig.MAX_LOGIN_ATTEMPTS}")
    logger.info(f"Lockout duration: {AuthConfig.LOCKOUT_DURATION_MINUTES} minutes")
    logger.info(f"Database: {AuthConfig.MONGODB_URI}/{AuthConfig.DATABASE_NAME}")
    
    if db_manager.connected:
        logger.info("Authentication API is ready!")
        logger.info("Default admin: admin@fraudshield.com / Admin@123!")
    else:
        logger.warning("Authentication API starting with limited functionality (no database)")
    
    # Start maintenance worker in background
    maintenance_thread = threading.Thread(target=maintenance_worker, daemon=True)
    maintenance_thread.start()
    
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5001,
        threaded=True
    )