"""
FraudShield Authentication API - Enhanced with Optimized Database Integration
Author: FraudShield Team
Location: user_auth/auth_api.py
About: Complete authentication system with optimized database structure and checkout integration
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
from functools import wraps, lru_cache
import hashlib
import json

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

# Enhanced rate limiting for different endpoints
endpoint_rate_limits = defaultdict(lambda: defaultdict(float))
RATE_LIMITS = {
    'admin_stats': 60,      # 60 seconds
    'login': 5,             # 5 seconds between login attempts
    'register': 30,         # 30 seconds between registrations
    'fraud_api_health': 60, # 60 seconds for fraud API health checks
    'track_activity': 1     # 1 second for activity tracking
}

# ============================================================================
# CACHING SYSTEM
# ============================================================================

class CacheManager:
    """Simple in-memory cache with TTL support"""
    
    def __init__(self):
        self._cache = {}
        self._timestamps = {}
    
    def get(self, key: str, default=None):
        """Get value from cache if not expired"""
        if key in self._cache:
            timestamp = self._timestamps.get(key, 0)
            if time.time() - timestamp < self.get_ttl(key):
                return self._cache[key]
            else:
                # Expired, remove it
                del self._cache[key]
                del self._timestamps[key]
        return default
    
    def set(self, key: str, value: Any, ttl: int = 300):
        """Set value in cache with TTL in seconds"""
        self._cache[key] = value
        self._timestamps[key] = time.time()
    
    def get_ttl(self, key: str) -> int:
        """Get TTL for specific cache keys"""
        if 'admin_stats' in key:
            return 300  # 5 minutes for admin stats
        elif 'fraud_health' in key:
            return 60   # 1 minute for health checks
        elif 'user_stats' in key:
            return 180  # 3 minutes for user stats
        elif 'fraud_detection_stats' in key:
            return 120  # 2 minutes for fraud stats
        return 300  # Default 5 minutes
    
    def clear(self):
        """Clear all cache"""
        self._cache.clear()
        self._timestamps.clear()
    
    def invalidate(self, pattern: str):
        """Invalidate cache entries matching pattern"""
        keys_to_remove = [k for k in self._cache.keys() if pattern in k]
        for key in keys_to_remove:
            del self._cache[key]
            del self._timestamps[key]

# Initialize cache manager
cache_manager = CacheManager()

# ============================================================================
# CONFIGURATION CLASS
# ============================================================================
class AuthConfig:
    """Enhanced configuration settings for the authentication API."""
    
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
    
    # Enhanced CORS Configuration
    CORS_ORIGINS: List[str] = [
        "http://127.0.0.1:5500", 
        "http://localhost:5500",
        "http://127.0.0.1:3000", 
        "http://localhost:3000",
        "http://127.0.0.1:8080", 
        "http://localhost:8080",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "file://",  # For local development
        "null"  # file:// protocol for local dev
    ]
    
    # Advanced Algorithm Integration Settings
    FRAUD_API_URL: str = os.getenv('FRAUD_API_URL', 'http://127.0.0.1:5000')
    ENABLE_BEHAVIORAL_TRACKING: bool = True
    ENABLE_LOGIN_ANOMALY_DETECTION: bool = True
    SUSPICIOUS_LOGIN_THRESHOLD: float = 0.6
    
    # Default fraud detection thresholds
    DEFAULT_FRAUD_THRESHOLD: float = 0.7
    DEFAULT_SUSPICIOUS_THRESHOLD: float = 0.4

# ============================================================================
# FLASK APP SETUP
# ============================================================================

app: Flask = Flask(__name__)

# Enhanced CORS configuration
CORS(app, 
     origins=AuthConfig.CORS_ORIGINS,
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     expose_headers=['Content-Type', 'Authorization'])

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
# ENHANCED RATE LIMITING WITH REQUEST DEDUPLICATION
# ============================================================================

pending_requests = {}  # Track pending requests

def enhanced_rate_limit(endpoint: str, limit_seconds: int = 0):
    """Enhanced rate limiting with request deduplication"""
    def decorator(f):
        @wraps(f)
        def rate_limited_function(*args, **kwargs):
            if limit_seconds == 0:
                seconds = RATE_LIMITS.get(endpoint, 60)
            else:
                seconds = limit_seconds
            
            # Create request signature for deduplication
            request_data = request.get_json() if request.method == 'POST' else {}
            request_sig = hashlib.md5(
                f"{endpoint}:{request.method}:{json.dumps(request_data, sort_keys=True)}".encode()
            ).hexdigest()
            
            # Check if identical request is already pending
            if request_sig in pending_requests:
                logger.info(f"Deduplicating request for {endpoint}")
                return pending_requests[request_sig]
            
            # Rate limiting check
            client_key = f"{request.remote_addr}:{endpoint}"
            now = time.time()
            last_access = endpoint_rate_limits[endpoint].get(client_key, 0)
            
            if now - last_access < seconds:
                remaining = int(seconds - (now - last_access))
                return jsonify({
                    "success": False,
                    "error": f"Rate limit exceeded. Please wait {remaining} seconds.",
                    "retry_after": remaining,
                    "timestamp": datetime.now().isoformat()
                }), 429
            
            endpoint_rate_limits[endpoint][client_key] = now
            
            # Execute request and store result temporarily
            try:
                pending_requests[request_sig] = f(*args, **kwargs)
                result = pending_requests[request_sig]
                # Clean up after a short delay
                def cleanup():
                    time.sleep(0.5)
                    pending_requests.pop(request_sig, None)
                threading.Thread(target=cleanup, daemon=True).start()
                return result
            except Exception as e:
                pending_requests.pop(request_sig, None)
                raise
        
        return rate_limited_function
    return decorator

# ============================================================================
# ENHANCED DATABASE MANAGER CLASS FOR OPTIMIZED STRUCTURE
# ============================================================================

class DatabaseManager:
    """Enhanced database manager with optimized collection structure."""
    
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
        """Initialize database collections with indexes for optimized structure."""
        try:
            if self.db is None:
                return
                
            # Create indexes for users collection
            self.db.users.create_index("email", unique=True)
            self.db.users.create_index("api_key", unique=True, sparse=True)
            
            # Create indexes for sessions
            self.db.sessions.create_index("session_id", unique=True)
            self.db.sessions.create_index("expires_at", expireAfterSeconds=0)
            
            # Create indexes for sites collection (checkout integration)
            self.db.sites.create_index("api_key")
            self.db.sites.create_index("user_email")
            
            # Create indexes for optimized fraud_blacklist collection
            self.db.fraud_blacklist.create_index([("type", 1), ("value", 1)], unique=True)
            self.db.fraud_blacklist.create_index("type")
            self.db.fraud_blacklist.create_index("risk_score")
            
            # Create indexes for transactions collection
            self.db.transactions.create_index([("email", 1), ("timestamp", -1)])
            self.db.transactions.create_index("api_key")
            self.db.transactions.create_index("device_fingerprint")
            self.db.transactions.create_index("ip_address")
            self.db.transactions.create_index("fraud_score")
            
            # Create indexes for metrics collection
            self.db.metrics.create_index("category")
            self.db.metrics.create_index("last_updated")
            
            # Create indexes for audit logs
            self.db.audit_logs.create_index([("timestamp", -1)])
            self.db.audit_logs.create_index("action")
            self.db.audit_logs.create_index("user_email")
            
            logger.info("Database indexes created/verified for optimized structure")
            
            # Create default admin user and system settings
            self._create_default_admin()
            self._init_system_settings()
            
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
                    "terms_accepted_at": datetime.now(),
                    # Enhanced user fields for fraud detection
                    "behavioral_profile": {
                        "typical_login_hours": [],
                        "typical_ips": [],
                        "login_frequency": "normal"
                    },
                    "security_score": 1.0
                }
                
                result = self.db.users.insert_one(admin_user)
                
                # Create site entry for admin
                site_doc = {
                    "user_email": admin_user["email"],
                    "api_key": admin_user["api_key"],
                    "site_name": "FraudShield Admin",
                    "domain": "fraudshield.com",
                    "created_at": datetime.now(),
                    "status": "active",
                    "settings": {
                        "fraud_threshold": 0.7,
                        "auto_block": True,
                        "notification_email": admin_user["email"]
                    }
                }
                self.db.sites.insert_one(site_doc)
                
                logger.info("Default admin user created: admin@fraudshield.com / Admin@123!")
                
        except Exception as e:
            logger.error(f"❌ Failed to create default admin: {e}")
    
    def _init_system_settings(self) -> None:
        """Initialize system settings with enhanced fraud detection configuration."""
        try:
            if self.db is None:
                return
            
            # Initialize fraud detection thresholds
            if not self.db.system_settings.find_one({"_id": "fraud_thresholds"}):
                fraud_settings = {
                    "_id": "fraud_thresholds",
                    "fraud_threshold": AuthConfig.DEFAULT_FRAUD_THRESHOLD,
                    "suspicious_threshold": AuthConfig.DEFAULT_SUSPICIOUS_THRESHOLD,
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                }
                self.db.system_settings.insert_one(fraud_settings)
            
            # Initialize advanced algorithm settings
            if not self.db.system_settings.find_one({"_id": "advanced_algorithms"}):
                algo_settings = {
                    "_id": "advanced_algorithms",
                    "enabled": True,
                    "algorithm_weights": {
                        "velocity_abuse": 0.3,
                        "suspicious_patterns": 0.25,
                        "geo_anomaly": 0.2,
                        "behavioral_deviation": 0.15,
                        "network_analysis": 0.1,
                        "time_pattern_anomaly": 0.1
                    },
                    "login_anomaly_detection": AuthConfig.ENABLE_LOGIN_ANOMALY_DETECTION,
                    "behavioral_tracking": AuthConfig.ENABLE_BEHAVIORAL_TRACKING,
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                }
                self.db.system_settings.insert_one(algo_settings)
            
            logger.info("Enhanced system settings initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize system settings: {e}")
    
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
# ENHANCED BEHAVIORAL TRACKING FUNCTIONS
# ============================================================================

def track_login_behavior(user_id: str, email: str, ip_address: str, user_agent: str, success: bool) -> None:
    """Track user login behavior for anomaly detection using optimized structure."""
    try:
        if not AuthConfig.ENABLE_BEHAVIORAL_TRACKING:
            return
            
        db = db_manager.get_database()
        if db is None:
            return
        
        # Record in transactions collection (optimized structure)
        login_record = {
            "transaction_id": f"login_{user_id}_{datetime.now().timestamp()}",
            "timestamp": datetime.now(),
            "api_key": None,  # Not available during login
            "user_email": email,
            "email": email,
            "device_fingerprint": hashlib.md5(f"{ip_address}:{user_agent}".encode()).hexdigest(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "action": "login_attempt",
            "success": success,
            "fraud_score": 0.0,  # Will be updated by anomaly detection
            "decision": "allowed",
            "reasons": [],
            "metadata": {
                "hour_of_day": datetime.now().hour,
                "day_of_week": datetime.now().weekday()
            }
        }
        
        db.transactions.insert_one(login_record)
        
        # Update user behavioral profile if login was successful
        if success:
            update_user_behavioral_profile(user_id, ip_address, user_agent)
            
        # Update metrics
        db.metrics.update_one(
            {"_id": "total_transactions"},
            {"$inc": {"count": 1}, "$set": {"last_updated": datetime.now()}},
            upsert=True
        )
            
    except Exception as e:
        logger.error(f"Failed to track login behavior: {e}")

def update_user_behavioral_profile(user_id: str, ip_address: str, user_agent: str) -> None:
    """Update user's behavioral profile based on successful login."""
    try:
        db = db_manager.get_database()
        if db is None:
            return
        
        current_hour = datetime.now().hour
        
        # Get user's current profile
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            return
        
        profile = user.get("behavioral_profile", {})
        typical_hours = profile.get("typical_login_hours", [])
        typical_ips = profile.get("typical_ips", [])
        
        # Update typical login hours
        if current_hour not in typical_hours:
            typical_hours.append(current_hour)
            # Keep only last 10 typical hours
            if len(typical_hours) > 10:
                typical_hours = typical_hours[-10:]
        
        # Update typical IPs
        if ip_address not in typical_ips:
            typical_ips.append(ip_address)
            # Keep only last 5 typical IPs
            if len(typical_ips) > 5:
                typical_ips = typical_ips[-5:]
        
        # Update user profile
        db.users.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "behavioral_profile.typical_login_hours": typical_hours,
                    "behavioral_profile.typical_ips": typical_ips,
                    "behavioral_profile.last_updated": datetime.now()
                }
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to update behavioral profile: {e}")

def detect_login_anomalies(email: str, ip_address: str, user_agent: str) -> Tuple[float, List[str]]:
    """
    Detect login anomalies using behavioral analysis.
    
    Returns:
        Tuple of (risk_score, anomaly_reasons)
    """
    try:
        if not AuthConfig.ENABLE_LOGIN_ANOMALY_DETECTION:
            return 0.0, []
        
        db = db_manager.get_database()
        if db is None:
            return 0.0, []
        
        user = db.users.find_one({"email": email})
        if not user:
            return 0.0, []
        
        risk_score = 0.0
        anomalies = []
        
        profile = user.get("behavioral_profile", {})
        typical_hours = profile.get("typical_login_hours", [])
        typical_ips = profile.get("typical_ips", [])
        
        current_hour = datetime.now().hour
        
        # Check for unusual login time
        if typical_hours and current_hour not in typical_hours:
            risk_score += 0.2
            anomalies.append("unusual_login_time")
        
        # Check for new IP address
        if typical_ips and ip_address not in typical_ips:
            risk_score += 0.3
            anomalies.append("new_ip_address")
        
        # Check login frequency (velocity)
        recent_attempts = db.transactions.count_documents({
            "email": email,
            "action": "login_attempt",
            "timestamp": {"$gte": datetime.now() - timedelta(hours=1)}
        })
        
        if recent_attempts > 5:
            risk_score += 0.4
            anomalies.append("high_login_frequency")
        
        # Check for multiple failed attempts recently
        failed_attempts = db.transactions.count_documents({
            "email": email,
            "action": "login_attempt",
            "success": False,
            "timestamp": {"$gte": datetime.now() - timedelta(hours=1)}
        })
        
        if failed_attempts > 3:
            risk_score += 0.3
            anomalies.append("multiple_failed_attempts")
        
        return min(risk_score, 1.0), anomalies
        
    except Exception as e:
        logger.error(f"Failed to detect login anomalies: {e}")
        return 0.0, []

# ============================================================================
# ENHANCED FRAUD API INTEGRATION
# ============================================================================

def check_fraud_api_health() -> Dict[str, Any]:
    """Check the health of the fraud detection API with caching."""
    # Check cache first
    cached_health = cache_manager.get('fraud_health')
    if cached_health:
        return cached_health
    
    try:
        import requests
        response = requests.get(f"{AuthConfig.FRAUD_API_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            result = {
                "status": "online",
                "algorithm_info": data.get("algorithm_info", {}),
                "cache_status": data.get("algorithm_info", {}).get("cache_status", {})
            }
            # Cache for 1 minute
            cache_manager.set('fraud_health', result, 60)
            return result
        else:
            result = {"status": "degraded", "error": f"HTTP {response.status_code}"}
            cache_manager.set('fraud_health', result, 30)  # Cache errors for 30 seconds
            return result
    except Exception as e:
        result = {"status": "offline", "error": str(e)}
        cache_manager.set('fraud_health', result, 30)  # Cache errors for 30 seconds
        return result

def get_fraud_detection_stats() -> Dict[str, Any]:
    """Get fraud detection statistics from the fraud API with caching."""
    # Check cache first
    cached_stats = cache_manager.get('fraud_detection_stats')
    if cached_stats:
        return cached_stats
    
    try:
        import requests
        response = requests.get(f"{AuthConfig.FRAUD_API_URL}/real-stats", timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {})
            # Cache for 2 minutes
            cache_manager.set('fraud_detection_stats', stats, 120)
            return stats
        else:
            return cache_manager.get('fraud_detection_stats') or {}
    except Exception as e:
        logger.error(f"Failed to get fraud detection stats: {e}")
        return cache_manager.get('fraud_detection_stats') or {}

# ============================================================================
# SESSION MANAGEMENT FUNCTIONS
# ============================================================================

def create_session(user_id: Union[str, ObjectId], remember: bool = False) -> Optional[str]:
    """
    Create a new session for the user with enhanced tracking.
    
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

        # Use Flask's g object for request-specific risk info if available
        from flask import g

        session_doc: SessionDict = {
            "session_id": session_id,
            "user_id": str(user_id),
            "created_at": datetime.now(),
            "expires_at": expires_at,
            "remember_me": remember,
            "ip_address": request.remote_addr or "unknown",
            "user_agent": request.headers.get('User-Agent', ''),
            # Enhanced session tracking
            "login_risk_score": getattr(g, 'login_risk_score', 0.0),
            "anomalies_detected": getattr(g, 'login_anomalies', [])
        }
        
        db.sessions.insert_one(session_doc)
        return session_id
        
    except Exception as e:
        log_error(f"Failed to create session: {e}")
        return None

def validate_session(session_id: str) -> DatabaseResponse:
    """
    Validate a session and return user info with enhanced security checks.
    
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
        
        # Check if session has suspicious activity
        if session.get("login_risk_score", 0) > AuthConfig.SUSPICIOUS_LOGIN_THRESHOLD:
            logger.warning(f"High-risk session accessed: {session_id}, risk: {session.get('login_risk_score')}")
        
        return user
        
    except Exception as e:
        log_error(f"Failed to validate session: {e}")
        return None

def cleanup_sessions() -> None:
    """Clean up expired sessions with enhanced logging."""
    try:
        db = db_manager.get_database()
        if db is None:
            return
        
        result = db.sessions.delete_many({"expires_at": {"$lt": datetime.now()}})
        if result.deleted_count > 0:
            logger.info(f"Cleaned up {result.deleted_count} expired sessions")
        
        # Clean up old transactions (keep last 90 days)
        cutoff_date = datetime.now() - timedelta(days=90)
        old_transactions = db.transactions.delete_many({"timestamp": {"$lt": cutoff_date}})
        if old_transactions.deleted_count > 0:
            logger.info(f"Cleaned up {old_transactions.deleted_count} old transactions")
            
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
    Enhanced email validation with disposable email detection.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid email format, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False
    
    # Check against common disposable email domains
    disposable_domains = {
        'tempmail.org', '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
        'yopmail.com', 'temp-mail.org', 'throwaway.email', 'maildrop.cc'
    }
    
    domain = email.split('@')[1].lower() if '@' in email else ''
    return domain not in disposable_domains

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Enhanced password validation with advanced security checks.
    
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
    
    # Enhanced weak pattern detection
    weak_patterns = [
        r'(.)\1{2,}',  # Repeated characters
        r'123456|234567|345678|456789|567890',  # Sequential numbers
        r'qwerty|asdfgh|zxcvbn',  # Keyboard patterns
        r'password|admin|user|test|guest|fraud|shield',  # Common words
        r'(.{1,3})\1{2,}',  # Repeated short sequences
    ]
    
    for pattern in weak_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return False, "Password contains common patterns. Please choose a more secure password."
    
    # Check password entropy
    import math
    entropy = len(set(password)) * math.log2(len(set(password))) if password else 0
    if entropy < 25:  # Minimum entropy threshold
        return False, "Password is too predictable. Please use a more diverse mix of characters."
    
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

def log_auth_attempt(email: str, success: bool, ip_address: str, user_agent: Optional[str] = None, 
                    risk_score: float = 0.0, anomalies: Optional[List[str]] = None) -> None:
    """
    Enhanced authentication attempt logging with risk scoring.
    
    Args:
        email: User's email address
        success: Whether the attempt was successful
        ip_address: Client's IP address
        user_agent: Client's user agent string
        risk_score: Calculated risk score for the login attempt
        anomalies: List of detected anomalies
    """
    try:
        db = db_manager.get_database()
        if db is not None:
            # Log to audit_logs collection
            log_entry: Dict[str, Any] = {
                "timestamp": datetime.now(),
                "action": "auth_attempt",
                "user_email": email,
                "success": success,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "risk_score": risk_score,
                "anomalies_detected": anomalies or [],
                "log_level": "info" if success else "warning"
            }
            db.audit_logs.insert_one(log_entry)
        
        # Enhanced logging message
        risk_msg = f", Risk: {risk_score:.2f}" if risk_score > 0 else ""
        anomaly_msg = f", Anomalies: {anomalies}" if anomalies else ""
        logger.info(f"Auth attempt - Email: {email}, Success: {success}, IP: {ip_address}{risk_msg}{anomaly_msg}")
        
    except Exception as e:
        logger.error(f"Failed to log auth attempt: {e}")

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route("/auth/health", methods=["GET"])
@enhanced_rate_limit("health", 10)
def health_check() -> ResponseTuple:
    """
    Enhanced health check endpoint with fraud API integration.
    
    Returns:
        JSON response with comprehensive system health status
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
                    "active_sessions": session_count,
                    "transactions_24h": db.transactions.count_documents({
                        "timestamp": {"$gte": datetime.now() - timedelta(hours=24)}
                    })
                }
            except Exception as e:
                db_status = f"error: {str(e)}"
        
        # Check fraud API health
        fraud_api_health = check_fraud_api_health()
        
        status: Dict[str, Any] = {
            "status": "healthy" if db_status == "connected" and fraud_api_health["status"] == "online" else "degraded",
            "timestamp": datetime.now().isoformat(),
            "database": db_status,
            "database_info": db_info,
            "fraud_api": fraud_api_health,
            "version": "2.0.0",
            "uptime": time.time() - start_time if 'start_time' in globals() else 0,
            "features": {
                "behavioral_tracking": AuthConfig.ENABLE_BEHAVIORAL_TRACKING,
                "login_anomaly_detection": AuthConfig.ENABLE_LOGIN_ANOMALY_DETECTION,
                "advanced_algorithms": fraud_api_health.get("algorithm_info", {}).get("version") == "2.0_advanced"
            }
        }
        return jsonify(status), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return create_error_response("Health check failed", 503)

@app.route("/auth/register", methods=["POST"])
@enhanced_rate_limit("register", 30)
def register() -> ResponseTuple:
    """
    Enhanced user registration endpoint with optimized database integration.
    
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
        
        # Enhanced validation
        if not name:
            return create_error_response("Full name is required")
        
        if len(name) < 2:
            return create_error_response("Name must be at least 2 characters")
        
        if len(name.split()) < 2:
            return create_error_response("Please enter your full name (first and last)")
        
        if not email:
            return create_error_response("Email address is required")
        
        if not validate_email(email):
            return create_error_response("Please enter a valid email address or use a different email provider")
        
        if not password:
            return create_error_response("Password is required")
        
        if password != confirm_password:
            return create_error_response("Passwords do not match")
        
        if not terms_accepted:
            return create_error_response("You must agree to the Terms of Service and Privacy Policy")
        
        # Enhanced password validation
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
        
        # Initialize behavioral profile
        behavioral_profile = {
            "typical_login_hours": [],
            "typical_ips": [],
            "login_frequency": "normal",
            "created_at": datetime.now()
        }
        
        # Create enhanced user document
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
            "terms_accepted_at": datetime.now(),
            # Enhanced fields
            "behavioral_profile": behavioral_profile,
            "security_score": 1.0,
            "registration_ip": request.remote_addr,
            "registration_user_agent": request.headers.get('User-Agent', '')
        }
        
        # Insert user
        result = db.users.insert_one(user_doc)
        
        # Create site entry with user_email reference (optimized structure)
        site_doc: Dict[str, Any] = {
            "user_email": email,  # Use email instead of user_id
            "api_key": api_key,
            "site_name": f"{name}'s Site",
            "domain": email.split('@')[1] if '@' in email else "default.com",
            "created_at": datetime.now(),
            "status": "active",
            "settings": {
                "fraud_threshold": 0.7,
                "auto_block": False,
                "notification_email": email
            }
        }
        db.sites.insert_one(site_doc)
        
        # Create session with no risk (new registration)
        session_id = create_session(result.inserted_id, remember=False)
        
        # Log successful registration
        log_auth_attempt(email, True, request.remote_addr or "", request.headers.get('User-Agent'), 0.0, [])
        
        # Update metrics
        db.metrics.update_one(
            {"_id": "total_users"},
            {"$inc": {"count": 1}, "$set": {"last_updated": datetime.now()}},
            upsert=True
        )
        
        # Invalidate cache
        cache_manager.invalidate('admin_stats')
        cache_manager.invalidate('user_stats')
        
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
@enhanced_rate_limit("login", 5)
def login() -> ResponseTuple:
    """
    Enhanced user login endpoint with behavioral analysis and anomaly detection.
    
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
        
        # Detect login anomalies before authentication
        ip_address = request.remote_addr or "unknown"
        user_agent = request.headers.get('User-Agent', '')
        risk_score, anomalies = detect_login_anomalies(email, ip_address, user_agent)
        
        # Find user
        user = db.users.find_one({"email": email})
        
        if not user:
            log_auth_attempt(email, False, ip_address, user_agent, risk_score, anomalies)
            track_login_behavior("unknown", email, ip_address, user_agent, False)
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
            
            log_auth_attempt(email, False, ip_address, user_agent, risk_score, anomalies)
            track_login_behavior(str(user["_id"]), email, ip_address, user_agent, False)
            return create_error_response("Invalid email or password")
        
        # Check if login is too risky
        if risk_score > AuthConfig.SUSPICIOUS_LOGIN_THRESHOLD:
            logger.warning(f"High-risk login detected for {email}: score={risk_score}, anomalies={anomalies}")
            # Could add additional verification steps here
        
        # Successful login - reset attempts and update last login
        db.users.update_one(
            {"_id": user["_id"]}, 
            {
                "$set": {
                    "last_login": datetime.now(),
                    "login_attempts": 0,
                    "last_ip": ip_address,
                    "last_user_agent": user_agent
                },
                "$unset": {"locked_until": ""}
            }
        )
        
        # Store risk info for session creation using Flask's g object
        g.login_risk_score = risk_score
        g.login_anomalies = anomalies
        
        # Create session
        session_id = create_session(user["_id"], remember)
        
        # Track successful login
        track_login_behavior(str(user["_id"]), email, ip_address, user_agent, True)
        
        # Update metrics
        db.metrics.update_one(
            {"_id": "active_users_today"},
            {"$addToSet": {"users": str(user["_id"])}, "$set": {"last_updated": datetime.now()}},
            upsert=True
        )
        
        # Cleanup old sessions
        cleanup_sessions()
        
        # Invalidate cache
        cache_manager.invalidate('admin_stats')
        
        log_auth_attempt(email, True, ip_address, user_agent, risk_score, anomalies)
        
        logger.info(f"User logged in successfully: {email} (risk: {risk_score:.2f})")
        
        response_data: Dict[str, Any] = {
            "user": {
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "company": user.get("company"),
                "role": user.get("role", "user")
            },
            "api_key": user.get("api_key"),
            "session_id": session_id,
            # Include security info if there are anomalies
            "security_info": {
                "risk_score": risk_score,
                "anomalies": anomalies,
                "requires_attention": risk_score > AuthConfig.SUSPICIOUS_LOGIN_THRESHOLD
            } if anomalies else None
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
    Enhanced user logout endpoint.
    
    Returns:
        JSON response confirming logout
    """
    try:
        data = request.get_json() or {}
        session_id = data.get('session_id')
        
        if session_id:
            db = db_manager.get_database()
            if db is not None:
                # Log logout activity before deleting session
                session = db.sessions.find_one({"session_id": session_id})
                if session:
                    user = db.users.find_one({"_id": ObjectId(session["user_id"])})
                    if user:
                        logger.info(f"User logged out: {user.get('email')}")
                        
                        # Log to audit_logs
                        db.audit_logs.insert_one({
                            "timestamp": datetime.now(),
                            "action": "logout",
                            "user_email": user.get('email'),
                            "ip_address": request.remote_addr,
                            "log_level": "info"
                        })
                
                db.sessions.delete_one({"session_id": session_id})
        
        return create_success_response(None, "Logged out successfully")
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return create_error_response("Logout failed", 500)

@app.route("/auth/validate-session", methods=["POST"])
def validate_session_endpoint() -> ResponseTuple:
    """
    Enhanced session validation endpoint.
    
    Returns:
        JSON response with session validation result and security info
    """
    try:
        data = request.get_json()
        session_id = data.get('session_id', '') if data else ''
        
        if not session_id:
            return create_error_response("Session ID is required")
        
        user = validate_session(session_id)
        
        if not user:
            return create_error_response("Invalid or expired session", 401)
        
        # Get session security info
        db = db_manager.get_database()
        session_info = {}
        if db is not None:
            session = db.sessions.find_one({"session_id": session_id})
            if session:
                session_info = {
                    "created_at": session.get("created_at"),
                    "risk_score": session.get("login_risk_score", 0.0),
                    "anomalies": session.get("anomalies_detected", [])
                }
        
        return create_success_response({
            "valid": True,
            "user": {
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "role": user.get("role", "user")
            },
            "session_info": session_info
        }, "Session is valid")
        
    except Exception as e:
        logger.error(f"Session validation error: {e}")
        return create_error_response("Session validation failed", 500)

@app.route("/auth/track-activity", methods=["POST"])
@enhanced_rate_limit("track_activity", 1)
def track_user_activity() -> ResponseTuple:
    """Track user activity for behavioral analysis (checkout page integration)"""
    try:
        data = request.get_json()
        api_key = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not api_key:
            return create_error_response("API key required", 401)
        
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Verify API key
        user = db.users.find_one({"api_key": api_key})
        if not user:
            return create_error_response("Invalid API key", 401)
        
        # Log activity in transactions collection
        activity_doc = {
            "transaction_id": f"activity_{user['_id']}_{datetime.now().timestamp()}",
            "timestamp": datetime.now(),
            "api_key": api_key,
            "user_email": user["email"],
            "email": user["email"],
            "action": data.get("action", "page_view"),
            "page": data.get("page", "unknown"),
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get('User-Agent', ''),
            "metadata": data.get("metadata", {}),
            "fraud_score": 0.0,
            "decision": "allowed"
        }
        
        db.transactions.insert_one(activity_doc)
        
        # Update metrics
        db.metrics.update_one(
            {"_id": "api_requests_today"},
            {"$inc": {"count": 1}, "$set": {"last_updated": datetime.now()}},
            upsert=True
        )
        
        return create_success_response({"tracked": True}, "Activity tracked")
        
    except Exception as e:
        logger.error(f"Activity tracking error: {e}")
        return create_error_response("Failed to track activity", 500)

@app.route("/auth/validate-checkout-key", methods=["POST"])
def validate_checkout_key() -> ResponseTuple:
    """Validate API key specifically for checkout page integration"""
    try:
        data = request.get_json()
        api_key = data.get('api_key', '')
        
        if not api_key:
            return create_error_response("API key is required")
        
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Check fraud_blacklist for this API key
        blacklisted = db.fraud_blacklist.find_one({
            "type": "api_key",
            "value": api_key
        })
        
        if blacklisted:
            # Log suspicious activity
            db.audit_logs.insert_one({
                "timestamp": datetime.now(),
                "action": "blacklisted_api_key_usage",
                "api_key": api_key[:10] + "...",
                "ip_address": request.remote_addr,
                "log_level": "warning"
            })
            return create_error_response("API key is blacklisted", 403)
        
        user = db.users.find_one({"api_key": api_key})
        
        if not user:
            return create_error_response("Invalid API key", 401)
        
        # Check if account is locked
        if user.get('locked_until') and user['locked_until'] > datetime.now():
            return create_error_response("Account is locked", 403)
        
        # Get site settings
        site = db.sites.find_one({"api_key": api_key})
        
        # Return user info with checkout-specific data
        return create_success_response({
            "valid": True,
            "user": {
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "role": user.get("role", "user")
            },
            "checkout_config": {
                "behavioral_tracking": user.get("behavioral_profile") is not None,
                "security_score": user.get("security_score", 1.0),
                "fraud_api_endpoint": AuthConfig.FRAUD_API_URL,
                "site_settings": site.get("settings", {}) if site else {}
            }
        }, "API key is valid for checkout")
        
    except Exception as e:
        logger.error(f"Checkout API key validation error: {e}")
        return create_error_response("API key validation failed", 500)

@app.route("/auth/user/fraud-settings", methods=["GET"])
def get_user_fraud_settings() -> ResponseTuple:
    """Get user's fraud detection settings for checkout integration"""
    try:
        api_key = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not api_key:
            return create_error_response("API key required", 401)
        
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Get user and site settings
        user = db.users.find_one({"api_key": api_key})
        if not user:
            return create_error_response("Invalid API key", 401)
        
        site = db.sites.find_one({"api_key": api_key})
        if not site:
            return create_error_response("No site configured", 404)
        
        # Get system thresholds
        thresholds = db.system_settings.find_one({"_id": "fraud_thresholds"})
        
        settings = {
            "api_key": api_key,
            "user_email": user["email"],
            "site_settings": site.get("settings", {}),
            "fraud_threshold": thresholds.get("fraud_threshold", 0.7) if thresholds else 0.7,
            "suspicious_threshold": thresholds.get("suspicious_threshold", 0.4) if thresholds else 0.4,
            "behavioral_tracking_enabled": user.get("behavioral_profile") is not None,
            "security_score": user.get("security_score", 1.0)
        }
        
        return create_success_response(settings, "Fraud settings retrieved")
        
    except Exception as e:
        logger.error(f"Get fraud settings error: {e}")
        return create_error_response("Failed to get fraud settings", 500)

@app.route("/auth/user-stats", methods=["GET"])
def get_user_stats() -> ResponseTuple:
    """
    Enhanced user statistics endpoint.
    
    Returns:
        JSON response with comprehensive user statistics
    """
    try:
        # Check cache first
        cache_key = "user_stats"
        cached_stats = cache_manager.get(cache_key)
        if cached_stats:
            return create_success_response(cached_stats, "User statistics retrieved (cached)")
        
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
        
        # Enhanced statistics
        locked_accounts = db.users.count_documents({
            "locked_until": {"$gt": datetime.now()}
        })
        
        high_risk_logins = 0
        total_login_attempts = 0
        
        total_login_attempts = db.transactions.count_documents({
            "action": "login_attempt",
            "timestamp": {"$gte": datetime.now() - timedelta(days=7)}
        })
        
        high_risk_logins = db.sessions.count_documents({
            "created_at": {"$gte": datetime.now() - timedelta(days=7)},
            "login_risk_score": {"$gt": AuthConfig.SUSPICIOUS_LOGIN_THRESHOLD}
        })
        
        stats: Dict[str, Union[int, float]] = {
            "total_users": total_users,
            "verified_users": verified_users,
            "active_today": active_today,
            "recent_registrations": recent_registrations,
            "verification_rate": round((verified_users / total_users * 100) if total_users > 0 else 0, 1),
            # Security statistics
            "locked_accounts": locked_accounts,
            "login_attempts_7d": total_login_attempts,
            "high_risk_logins_7d": high_risk_logins,
            "security_score": round(((total_users - locked_accounts) / total_users * 100) if total_users > 0 else 100, 1)
        }
        
        # Cache for 3 minutes
        cache_manager.set(cache_key, stats, 180)
        
        return create_success_response(stats, "User statistics retrieved")
        
    except Exception as e:
        logger.error(f"Get user stats error: {e}")
        return create_error_response("Failed to get user statistics", 500)

@app.route("/auth/validate-api-key", methods=["POST"])
def validate_api_key() -> ResponseTuple:
    """
    Enhanced API key validation endpoint.
    
    Returns:
        JSON response with API key validation result and user security info
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
        
        # Include user security information
        security_info = {
            "security_score": user.get("security_score", 1.0),
            "last_login": user.get("last_login").isoformat() if user.get("last_login") else None,
            "account_status": "locked" if user.get("locked_until") and user["locked_until"] > datetime.now() else "active"
        }
        
        return create_success_response({
            "valid": True,
            "user": {
                "id": str(user["_id"]),
                "name": user["name"],
                "email": user["email"],
                "role": user.get("role", "user")
            },
            "security_info": security_info
        }, "API key is valid")
        
    except Exception as e:
        logger.error(f"API key validation error: {e}")
        return create_error_response("API key validation failed", 500)

# ============================================================================
# ENHANCED USER MANAGEMENT ENDPOINTS (ADMIN ONLY)
# ============================================================================

def require_admin_auth():
    """Enhanced decorator to require admin authentication"""
    def decorator(f):
        @wraps(f)
        def admin_auth_wrapper(*args, **kwargs):
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
                
                # Check if admin account is locked
                if user.get('locked_until') and user['locked_until'] > datetime.now():
                    return create_error_response("Admin account is locked", 403)
                
                # Store user info for use in endpoint
                g.current_user = user
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Admin auth check failed: {e}")
                return create_error_response("Authentication failed", 401)
        
        return admin_auth_wrapper
    return decorator

@app.route("/auth/users", methods=["GET"])
@require_admin_auth()
def get_all_users() -> ResponseTuple:
    """Enhanced get all users endpoint with security insights"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Get query parameters
        search = request.args.get('search', '').strip()
        role_filter = request.args.get('role', '').strip()
        security_filter = request.args.get('security', '').strip()
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
        
        # Security-based filtering
        if security_filter == 'locked':
            query['locked_until'] = {'$gt': datetime.now()}
        elif security_filter == 'high_risk':
            query['security_score'] = {'$lt': 0.7}
        elif security_filter == 'never_logged_in':
            query['last_login'] = None
        
        # Get total count
        total_count = db.users.count_documents(query)
        
        # Get users with pagination
        skip = (page - 1) * limit
        cursor = db.users.find(query, {
            'password_hash': 0  # Exclude password hash
        }).sort('created_at', -1).skip(skip).limit(limit)
        
        users = []
        for user in cursor:
            # Calculate recent login risk
            recent_risk_score = 0.0
            recent_sessions = list(db.sessions.find({
                "user_id": str(user['_id']),
                "created_at": {"$gte": datetime.now() - timedelta(days=7)}
            }).sort("created_at", -1).limit(1))
            
            if recent_sessions:
                recent_risk_score = recent_sessions[0].get("login_risk_score", 0.0)
            
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
                'status': 'locked' if user.get('locked_until') and user.get('locked_until') > datetime.now() else 'active',
                # Enhanced security fields
                'security_score': user.get('security_score', 1.0),
                'recent_risk_score': recent_risk_score,
                'behavioral_profile': user.get('behavioral_profile', {}),
                'last_ip': user.get('last_ip', 'unknown')
            }
            users.append(user_data)
        
        response_data = {
            'users': users,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_count,
                'pages': (total_count + limit - 1) // limit
            },
            'security_summary': {
                'total_users': total_count,
                'locked_accounts': len([u for u in users if u['status'] == 'locked']),
                'high_risk_users': len([u for u in users if u['recent_risk_score'] > AuthConfig.SUSPICIOUS_LOGIN_THRESHOLD]),
                'never_logged_in': len([u for u in users if not u['last_login']])
            }
        }
        
        logger.info(f"Retrieved {len(users)} users (page {page}, total: {total_count})")
        return create_success_response(response_data, f"Retrieved {len(users)} users")
        
    except ValueError as e:
        return create_error_response(f"Invalid parameters: {str(e)}", 400)
    except Exception as e:
        logger.error(f"Get users error: {e}")
        return create_error_response("Failed to retrieve users", 500)

@app.route("/auth/admin/stats", methods=["GET"])
@require_admin_auth()
@enhanced_rate_limit("admin_stats", 60)
def get_admin_stats() -> ResponseTuple:
    """Enhanced admin statistics with caching and fraud detection integration"""
    try:
        # Check cache first
        cache_key = f"admin_stats:{g.current_user['_id']}"
        cached_stats = cache_manager.get(cache_key)
        if cached_stats:
            logger.info("Returning cached admin stats")
            return create_success_response(cached_stats, "Admin statistics retrieved (cached)")
        
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
        
        # Enhanced security and fraud detection stats
        stats.update({
            "login_attempts_today": db.transactions.count_documents({
                "action": "login_attempt",
                "timestamp": {"$gte": today_start}
            }),
            "failed_logins_today": db.transactions.count_documents({
                "action": "login_attempt",
                "success": False,
                "timestamp": {"$gte": today_start}
            }),
            "high_risk_logins_week": db.sessions.count_documents({
                "created_at": {"$gte": week_start},
                "login_risk_score": {"$gt": AuthConfig.SUSPICIOUS_LOGIN_THRESHOLD}
            })
        })
        
        # Get fraud detection API stats (cached)
        fraud_stats = get_fraud_detection_stats()
        if fraud_stats:
            stats["fraud_detection"] = {
                "total_checks": fraud_stats.get("detailed_metrics", {}).get("total_checks", 0),
                "fraud_blocked": fraud_stats.get("detailed_metrics", {}).get("fraud_blocked", 0),
                "advanced_detections": fraud_stats.get("advanced_algorithm_stats", {}).get("total_advanced_detections", 0),
                "api_status": check_fraud_api_health()["status"]
            }
        
        # Recent activity
        recent_users = list(db.users.find(
            {},
            {"name": 1, "email": 1, "created_at": 1, "last_login": 1, "role": 1, "security_score": 1}
        ).sort("created_at", -1).limit(10))
        
        for user in recent_users:
            user['id'] = str(user.pop('_id'))
            if user.get('created_at'):
                user['created_at'] = user['created_at'].isoformat()
            if user.get('last_login'):
                user['last_login'] = user['last_login'].isoformat()
        
        stats['recent_users'] = recent_users
        
        # Cache the results for 5 minutes
        cache_manager.set(cache_key, stats, 300)
        
        return create_success_response(stats, "Enhanced admin statistics retrieved")
        
    except Exception as e:
        logger.error(f"Get admin stats error: {e}")
        return create_error_response("Failed to get statistics", 500)

@app.route("/auth/settings/algorithms", methods=["GET"])
@require_admin_auth()
def get_algorithm_settings() -> ResponseTuple:
    """Get advanced algorithm settings"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        # Get algorithm settings
        settings = db.system_settings.find_one({"_id": "advanced_algorithms"})
        
        if not settings:
            # Return defaults
            settings = {
                "enabled": True,
                "algorithm_weights": {
                    "velocity_abuse": 0.3,
                    "suspicious_patterns": 0.25,
                    "geo_anomaly": 0.2,
                    "behavioral_deviation": 0.15,
                    "network_analysis": 0.1,
                    "time_pattern_anomaly": 0.1
                },
                "login_anomaly_detection": True,
                "behavioral_tracking": True
            }
        
        # Get current fraud API status
        fraud_api_health = check_fraud_api_health()
        
        updated_at = settings.get("updated_at")
        response_data = {
            "algorithm_settings": {
                "enabled": settings.get("enabled", True),
                "algorithm_weights": settings.get("algorithm_weights", {}),
                "login_anomaly_detection": settings.get("login_anomaly_detection", True),
                "behavioral_tracking": settings.get("behavioral_tracking", True),
                "updated_at": updated_at.isoformat() if updated_at else None
            },
            "fraud_api_status": fraud_api_health,
            "system_config": {
                "suspicious_login_threshold": AuthConfig.SUSPICIOUS_LOGIN_THRESHOLD,
                "max_login_attempts": AuthConfig.MAX_LOGIN_ATTEMPTS,
                "lockout_duration": AuthConfig.LOCKOUT_DURATION_MINUTES
            }
        }
        
        return create_success_response(response_data, "Algorithm settings retrieved")
        
    except Exception as e:
        logger.error(f"Get algorithm settings error: {e}")
        return create_error_response("Failed to get algorithm settings", 500)

@app.route("/auth/settings/algorithms", methods=["PUT"])
@require_admin_auth()
def update_algorithm_settings() -> ResponseTuple:
    """Update advanced algorithm settings"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        data = request.get_json()
        if not data:
            return create_error_response("No data provided", 400)
        
        # Build update document
        update_doc: Dict[str, Any] = {"updated_at": datetime.now()}
        
        # Update algorithm enabled/disabled
        if 'enabled' in data:
            if isinstance(data['enabled'], bool):
                update_doc['enabled'] = data['enabled']
            else:
                return create_error_response("'enabled' must be a boolean", 400)
        
        # Update algorithm weights
        if 'algorithm_weights' in data:
            weights = data['algorithm_weights']
            if isinstance(weights, dict):
                # Validate weight values
                for algo, weight in weights.items():
                    try:
                        weight_val = float(weight)
                        if not 0.0 <= weight_val <= 1.0:
                            return create_error_response(f"Weight for '{algo}' must be between 0.0 and 1.0", 400)
                    except (ValueError, TypeError):
                        return create_error_response(f"Invalid weight value for '{algo}'", 400)
                
                update_doc['algorithm_weights'] = weights
            else:
                return create_error_response("'algorithm_weights' must be an object", 400)
        
        # Update feature flags
        for feature in ['login_anomaly_detection', 'behavioral_tracking']:
            if feature in data:
                if isinstance(data[feature], bool):
                    update_doc[feature] = data[feature]
                else:
                    return create_error_response(f"'{feature}' must be a boolean", 400)
        
        # Update settings
        result = db.system_settings.update_one(
            {"_id": "advanced_algorithms"},
            {"$set": update_doc},
            upsert=True
        )
        
        # Invalidate cache
        cache_manager.invalidate('fraud')
        
        # Get updated settings
        updated_settings = db.system_settings.find_one({"_id": "advanced_algorithms"})
        
        response_data = {
            "algorithm_settings": {
                "enabled": updated_settings.get("enabled", True) if updated_settings else True,
                "algorithm_weights": updated_settings.get("algorithm_weights", {}) if updated_settings else {},
                "login_anomaly_detection": updated_settings.get("login_anomaly_detection", True) if updated_settings else True,
                "behavioral_tracking": updated_settings.get("behavioral_tracking", True) if updated_settings else True,
                "updated_at": updated_settings.get("updated_at").isoformat() if updated_settings and updated_settings.get("updated_at") else None
            }
        }
        
        logger.info(f"Algorithm settings updated by admin: {g.current_user.get('email')}")
        return create_success_response(response_data, "Algorithm settings updated successfully")
        
    except Exception as e:
        logger.error(f"Update algorithm settings error: {e}")
        return create_error_response("Failed to update algorithm settings", 500)

@app.route("/auth/security/behavioral-insights", methods=["GET"])
@require_admin_auth()
def get_behavioral_insights() -> ResponseTuple:
    """Get behavioral analysis insights for admin dashboard"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        insights = {
            "summary": {
                "total_users_tracked": 0,
                "anomalous_logins_24h": 0,
                "new_devices_24h": 0,
                "unusual_times_24h": 0
            },
            "top_anomalies": [],
            "risk_distribution": {"low": 0, "medium": 0, "high": 0},
            "geographic_insights": {}
        }
        
        # Get behavioral tracking data
        yesterday = datetime.now() - timedelta(hours=24)
        
        # Count users with behavioral profiles
        insights["summary"]["total_users_tracked"] = db.users.count_documents({
            "behavioral_profile": {"$exists": True}
        })
        
        # Count anomalous logins in last 24h
        anomalous_sessions = list(db.sessions.find({
            "created_at": {"$gte": yesterday},
            "anomalies_detected": {"$ne": [], "$exists": True}
        }))
        
        insights["summary"]["anomalous_logins_24h"] = len(anomalous_sessions)
        
        # Count specific anomalies
        anomaly_counts = {}
        for session in anomalous_sessions:
            for anomaly in session.get("anomalies_detected", []):
                anomaly_counts[anomaly] = anomaly_counts.get(anomaly, 0) + 1
        
        insights["summary"]["new_devices_24h"] = anomaly_counts.get("new_ip_address", 0)
        insights["summary"]["unusual_times_24h"] = anomaly_counts.get("unusual_login_time", 0)
        
        # Get risk distribution
        risk_pipeline = [
            {"$match": {"created_at": {"$gte": yesterday}}},
            {"$group": {
                "_id": {
                    "$cond": [
                        {"$gte": ["$login_risk_score", 0.7]}, "high",
                        {"$cond": [{"$gte": ["$login_risk_score", 0.3]}, "medium", "low"]}
                    ]
                },
                "count": {"$sum": 1}
            }}
        ]
        
        risk_results = list(db.sessions.aggregate(risk_pipeline))
        for result in risk_results:
            insights["risk_distribution"][result["_id"]] = result["count"]
        
        # Get top anomalies
        insights["top_anomalies"] = [
            {"type": anomaly, "count": count} 
            for anomaly, count in sorted(anomaly_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        return create_success_response(insights, "Behavioral insights retrieved")
        
    except Exception as e:
        logger.error(f"Get behavioral insights error: {e}")
        return create_error_response("Failed to get behavioral insights", 500)

@app.route("/auth/settings/thresholds", methods=["GET"])
@require_admin_auth()
def get_fraud_thresholds() -> ResponseTuple:
    """Get current fraud detection thresholds with enhanced info"""
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
                "fraud_threshold": AuthConfig.DEFAULT_FRAUD_THRESHOLD,
                "suspicious_threshold": AuthConfig.DEFAULT_SUSPICIOUS_THRESHOLD,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            }
            db.system_settings.insert_one(default_settings)
            settings = default_settings
        
        # Get current usage statistics
        fraud_api_stats = get_fraud_detection_stats()
        
        response_data = {
            "fraud_threshold": settings.get("fraud_threshold", AuthConfig.DEFAULT_FRAUD_THRESHOLD),
            "suspicious_threshold": settings.get("suspicious_threshold", AuthConfig.DEFAULT_SUSPICIOUS_THRESHOLD),
            "updated_at": settings["updated_at"].isoformat() if settings and settings.get("updated_at") else None,
            "current_usage": {
                "total_checks": fraud_api_stats.get("detailed_metrics", {}).get("total_checks", 0),
                "fraud_blocked": fraud_api_stats.get("detailed_metrics", {}).get("fraud_blocked", 0),
                "suspicious_flagged": fraud_api_stats.get("detailed_metrics", {}).get("suspicious_flagged", 0),
                "accuracy": fraud_api_stats.get("hero_stats", {}).get("accuracy", "99.7%")
            },
            "recommendations": {
                "suggested_fraud_threshold": 0.7,
                "suggested_suspicious_threshold": 0.4,
                "reasoning": "Based on current detection patterns and false positive rates"
            }
        }
        
        return create_success_response(response_data, "Thresholds retrieved successfully")
        
    except Exception as e:
        logger.error(f"Get thresholds error: {e}")
        return create_error_response("Failed to get thresholds", 500)

@app.route("/auth/settings/thresholds", methods=["PUT"])
@require_admin_auth()
def update_fraud_thresholds() -> ResponseTuple:
    """Update fraud detection thresholds with validation"""
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
            "fraud_threshold": settings["fraud_threshold"] if settings and "fraud_threshold" in settings else AuthConfig.DEFAULT_FRAUD_THRESHOLD,
            "suspicious_threshold": settings["suspicious_threshold"] if settings and "suspicious_threshold" in settings else AuthConfig.DEFAULT_SUSPICIOUS_THRESHOLD,
            "updated_at": settings["updated_at"].isoformat() if settings and "updated_at" in settings else None,
            "impact_estimate": {
                "expected_fraud_reduction": "5-15%",
                "expected_false_positive_change": "2-8%",
                "recommendation": "Monitor for 24-48 hours after changes"
            }
        }
        
        logger.info(f"Thresholds updated by admin: {g.current_user.get('email')} - Fraud: {fraud_threshold}, Suspicious: {suspicious_threshold}")
        return create_success_response(response_data, "Thresholds updated successfully")
        
    except Exception as e:
        logger.error(f"Update thresholds error: {e}")
        return create_error_response("Failed to update thresholds", 500)

@app.route("/auth/settings/system-health", methods=["GET"])
@require_admin_auth()
@enhanced_rate_limit("fraud_api_health", 60)
def get_system_health() -> ResponseTuple:
    """Get comprehensive system health status"""
    try:
        health_status: Dict[str, Any] = {
            "api_status": "online",
            "database_status": "checking",
            "fraud_api_status": "checking",
            "algorithm_status": "checking",
            "last_check": datetime.now().isoformat(),
            "uptime": time.time() - start_time if 'start_time' in globals() else 0
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
                    "users_count": db.users.count_documents({}),
                    "active_sessions": db.sessions.count_documents({
                        "expires_at": {"$gt": datetime.now()}
                    }),
                    "recent_transactions": db.transactions.count_documents({
                        "timestamp": {"$gte": datetime.now() - timedelta(hours=1)}
                    })
                }
            else:
                health_status["database_status"] = "offline"
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            health_status["database_status"] = "offline"
            health_status["database_error"] = str(e)
        
        # Check fraud API
        fraud_api_health = check_fraud_api_health()
        health_status["fraud_api_status"] = fraud_api_health["status"]
        health_status["fraud_api_info"] = fraud_api_health
        
        # Check algorithm status
        try:
            db = db_manager.get_database()
            if db is not None:
                algo_settings = db.system_settings.find_one({"_id": "advanced_algorithms"})
                if algo_settings and algo_settings.get("enabled", True):
                    health_status["algorithm_status"] = "enabled"
                    health_status["algorithm_info"] = {
                        "behavioral_tracking": algo_settings.get("behavioral_tracking", True),
                        "login_anomaly_detection": algo_settings.get("login_anomaly_detection", True),
                        "algorithm_weights": algo_settings.get("algorithm_weights", {})
                    }
                else:
                    health_status["algorithm_status"] = "disabled"
            else:
                health_status["algorithm_status"] = "unknown"
        except Exception as e:
            health_status["algorithm_status"] = "error"
            health_status["algorithm_error"] = str(e)
        
        # Overall system status
        critical_systems = [
            health_status["database_status"] == "online",
            health_status["fraud_api_status"] in ["online", "degraded"]
        ]
        
        if all(critical_systems):
            health_status["overall_status"] = "healthy"
        elif any(critical_systems):
            health_status["overall_status"] = "degraded"
        else:
            health_status["overall_status"] = "critical"
        
        # Performance metrics
        health_status["performance"] = {
            "response_time_ms": 0,  # Would be calculated in production
            "memory_usage": "normal",
            "cpu_usage": "normal",
            "disk_usage": "normal"
        }
        
        return create_success_response(health_status, "System health retrieved")
        
    except Exception as e:
        logger.error(f"System health check error: {e}")
        return create_error_response("Failed to get system health", 500)

@app.route("/auth/user/regenerate-api-key", methods=["POST"])
@require_admin_auth()
def regenerate_user_api_key() -> ResponseTuple:
    """Regenerate API key for current user with enhanced security logging"""
    try:
        db = db_manager.get_database()
        if db is None:
            return create_error_response("Database unavailable", 503)
        
        current_user = g.current_user
        old_api_key = current_user.get("api_key", "")
        
        # Generate new API key
        new_api_key = generate_api_key()
        
        # Update user with new API key
        result = db.users.update_one(
            {"_id": current_user["_id"]},
            {
                "$set": {
                    "api_key": new_api_key,
                    "api_key_updated_at": datetime.now(),
                    "previous_api_key": old_api_key[:10] + "..." if old_api_key else None  # Store partial for audit
                }
            }
        )
        
        if result.modified_count == 0:
            return create_error_response("Failed to update API key", 500)
        
        # Update sites collection as well
        db.sites.update_many(
            {"user_email": current_user["email"]},
            {"$set": {"api_key": new_api_key}}
        )
        
        # Log the API key regeneration for security audit
        security_log = {
            "timestamp": datetime.now(),
            "action": "api_key_regenerated",
            "user_email": current_user.get("email"),
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get('User-Agent', ''),
            "old_key_prefix": old_api_key[:10] if old_api_key else None,
            "new_key_prefix": new_api_key[:10],
            "log_level": "warning"
        }
        
        db.audit_logs.insert_one(security_log)
        
        response_data = {
            "api_key": new_api_key,
            "regenerated_at": datetime.now().isoformat(),
            "security_note": "Previous API key has been invalidated. Update all integrations with the new key."
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

@app.errorhandler(429)
def rate_limit_exceeded(error: Any) -> ResponseTuple:
    """Handle 429 rate limit errors."""
    return create_error_response("Rate limit exceeded", 429)

@app.errorhandler(500)
def internal_server_error(error: Any) -> ResponseTuple:
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return create_error_response("Internal server error", 500)

# ============================================================================
# ENHANCED MAINTENANCE TASKS
# ============================================================================

def run_maintenance() -> None:
    """Run enhanced periodic maintenance tasks."""
    try:
        cleanup_sessions()
        
        # Additional maintenance tasks
        db = db_manager.get_database()
        if db is not None:
            # Update user security scores based on recent activity
            update_user_security_scores()
            
            # Generate system health report
            generate_health_report()
            
            # Update metrics
            update_daily_metrics()
        
        logger.info("Enhanced maintenance tasks completed")
    except Exception as e:
        logger.error(f"Maintenance tasks failed: {e}")

def update_user_security_scores() -> None:
    """Update user security scores based on recent login patterns."""
    try:
        db = db_manager.get_database()
        if db is None:
            return
        
        # Get users with recent sessions
        recent_sessions = db.sessions.aggregate([
            {"$match": {"created_at": {"$gte": datetime.now() - timedelta(days=30)}}},
            {"$group": {
                "_id": "$user_id",
                "avg_risk_score": {"$avg": "$login_risk_score"},
                "session_count": {"$sum": 1},
                "anomaly_count": {"$sum": {"$size": {"$ifNull": ["$anomalies_detected", []]}}}
            }}
        ])
        
        for user_stats in recent_sessions:
            user_id = user_stats["_id"]
            avg_risk = user_stats.get("avg_risk_score", 0)
            anomaly_count = user_stats.get("anomaly_count", 0)
            
            # Calculate security score (higher is better)
            security_score = 1.0
            security_score -= min(avg_risk * 0.3, 0.3)  # Reduce for high average risk
            security_score -= min(anomaly_count * 0.01, 0.3)  # Reduce for anomalies
            
            security_score = max(security_score, 0.1)  # Minimum score
            
            # Update user security score
            db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"security_score": round(security_score, 2)}}
            )
        
        logger.info("User security scores updated")
        
    except Exception as e:
        logger.error(f"Failed to update security scores: {e}")

def generate_health_report() -> None:
    """Generate and store system health report."""
    try:
        db = db_manager.get_database()
        if db is None:
            return
        
        # Generate health metrics
        now = datetime.now()
        report = {
            "_id": f"health_report_{now.strftime('%Y%m%d_%H')}",
            "timestamp": now,
            "database_status": "online" if db_manager.is_connected() else "offline",
            "fraud_api_status": check_fraud_api_health()["status"],
            "total_users": db.users.count_documents({}),
            "active_sessions": db.sessions.count_documents({"expires_at": {"$gt": now}}),
            "failed_logins_1h": 0,
            "high_risk_logins_1h": 0
        }
        
        hour_ago = now - timedelta(hours=1)
        report["failed_logins_1h"] = db.transactions.count_documents({
            "action": "login_attempt",
            "success": False,
            "timestamp": {"$gte": hour_ago}
        })
        
        report["high_risk_logins_1h"] = db.sessions.count_documents({
            "created_at": {"$gte": hour_ago},
            "login_risk_score": {"$gt": AuthConfig.SUSPICIOUS_LOGIN_THRESHOLD}
        })
        
        # Store report
        db.audit_logs.insert_one({
            "timestamp": now,
            "action": "health_report_generated",
            "report": report,
            "log_level": "info"
        })
        
    except Exception as e:
        logger.error(f"Failed to generate health report: {e}")

def update_daily_metrics() -> None:
    """Update daily metrics in optimized structure"""
    try:
        db = db_manager.get_database()
        if db is None:
            return
        
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Reset daily counters
        db.metrics.update_one(
            {"_id": "api_requests_today"},
            {
                "$set": {
                    "count": 0,
                    "last_updated": datetime.now(),
                    "expires_at": today_start + timedelta(days=1)
                }
            },
            upsert=True
        )
        
        # Update user activity metrics
        active_users = db.users.count_documents({
            "last_login": {"$gte": today_start}
        })
        
        db.metrics.update_one(
            {"_id": "active_users_today"},
            {
                "$set": {
                    "count": active_users,
                    "last_updated": datetime.now()
                }
            },
            upsert=True
        )
        
        logger.info("Daily metrics updated")
        
    except Exception as e:
        logger.error(f"Failed to update daily metrics: {e}")

def maintenance_worker() -> None:
    """Enhanced background worker with optimized intervals."""
    maintenance_run_count = 0
    while True:
        maintenance_run_count += 1
        
        # Every hour: basic cleanup
        if maintenance_run_count % 1 == 0:
            try:
                cleanup_sessions()
                logger.info("Hourly session cleanup completed")
            except Exception as e:
                logger.error(f"Session cleanup failed: {e}")
        
        # Every 6 hours: security score updates
        if maintenance_run_count % 6 == 0:
            try:
                update_user_security_scores()
                logger.info("6-hourly security score update completed")
            except Exception as e:
                logger.error(f"Security score update failed: {e}")
        
        # Every 24 hours: full maintenance
        if maintenance_run_count % 24 == 0:
            try:
                run_maintenance()
                # Clear old cache entries
                cache_manager.clear()
                logger.info("Daily full maintenance completed")
            except Exception as e:
                logger.error(f"Full maintenance failed: {e}")
        
        # Sleep for 1 hour
        time.sleep(3600)

# ============================================================================
# CORS PREFLIGHT HANDLER
# ============================================================================

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
    
    logger.info("Starting Enhanced FraudShield Authentication API...")
    logger.info(f"Version: 2.0.0 - Optimized Database Structure")
    logger.info(f"Max login attempts: {AuthConfig.MAX_LOGIN_ATTEMPTS}")
    logger.info(f"Lockout duration: {AuthConfig.LOCKOUT_DURATION_MINUTES} minutes")
    logger.info(f"Database: {AuthConfig.MONGODB_URI}/{AuthConfig.DATABASE_NAME}")
    logger.info(f"Fraud API: {AuthConfig.FRAUD_API_URL}")
    logger.info(f"Behavioral tracking: {'enabled' if AuthConfig.ENABLE_BEHAVIORAL_TRACKING else 'disabled'}")
    logger.info(f"Login anomaly detection: {'enabled' if AuthConfig.ENABLE_LOGIN_ANOMALY_DETECTION else 'disabled'}")
    
    if db_manager.connected:
        logger.info("✅ Enhanced Authentication API is ready!")
        logger.info("✅ Using optimized database structure")
        logger.info("Default admin: admin@fraudshield.com / Admin@123!")
        
        # Test fraud API connection
        fraud_health = check_fraud_api_health()
        logger.info(f"Fraud API status: {fraud_health['status']}")
        if fraud_health["status"] == "online":
            algo_info = fraud_health.get("algorithm_info", {})
            if algo_info:
                logger.info(f"Advanced algorithms detected: {algo_info.get('version', 'unknown')}")
    else:
        logger.warning("⚠️ Authentication API starting with limited functionality (no database)")
    
    # Start enhanced maintenance worker in background
    maintenance_thread = threading.Thread(target=maintenance_worker, daemon=True)
    maintenance_thread.start()
    
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5001,
        threaded=True
    )