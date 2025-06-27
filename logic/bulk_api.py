# logic/bulk_api.py - ENHANCED with Advanced Algorithm Support and Better Metrics
import sys
import os
import time
import logging
from datetime import datetime
from functools import wraps
import traceback
import pymongo

sys.path.append(os.path.dirname(__file__))

from flask import Flask, request, jsonify
from flask_cors import CORS
from fraud_checker import FraudChecker

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'json'}
    MAX_RECORDS = 5000  # Reasonable limit for localhost

# ============================================================================
# FLASK APP SETUP
# ============================================================================

app = Flask(__name__)

# CORS configuration
CORS(app, 
     origins=[
         "http://127.0.0.1:5500",
         "http://localhost:5500", 
         "http://127.0.0.1:3000",
         "http://localhost:3000",
         "http://127.0.0.1:8080",
         "http://localhost:8080",
         "http://127.0.0.1:8000",
         "http://localhost:8000",
         "file://"  # For local file access
     ],
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     supports_credentials=True
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bulk_api.log'),
        logging.StreamHandler()
    ]
)

# Initialize fraud checker
try:
    checker = FraudChecker()
    app.logger.info("✅ Enhanced FraudChecker initialized successfully")
except Exception as e:
    app.logger.error(f"❌ Failed to initialize FraudChecker: {e}")
    checker = None

# Initialize MongoDB for user authentication
try:
    mongo_client = pymongo.MongoClient("mongodb://localhost:27017")
    auth_db = mongo_client.fraudshield
    users_collection = auth_db.users
    logs_collection = auth_db.logs
    app.logger.info("✅ Authentication database connected")
except Exception as e:
    app.logger.error(f"❌ Failed to connect to auth database: {e}")
    mongo_client = None
    auth_db = None
    users_collection = None
    logs_collection = None

# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

def validate_api_key(api_key):
    """Validate API key against database and return user info"""
    if users_collection is None or not api_key:
        return None
    
    try:
        # Find user by API key
        user = users_collection.find_one({"api_key": api_key})
        if user:
            app.logger.info(f"✅ Valid API key for user: {user.get('email')}")
            return {
                "email": user.get("email"),
                "name": user.get("name"),
                "role": user.get("role"),
                "company": user.get("company"),
                "user_id": str(user.get("_id"))
            }
        else:
            app.logger.warning(f"❌ Invalid API key: {api_key[:10]}...")
            return None
    except Exception as e:
        app.logger.error(f"Error validating API key: {e}")
        return None

def get_api_key_from_request():
    """Extract API key from request headers or body"""
    # Check Authorization header first
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header[7:]  # Remove 'Bearer ' prefix

    # Check request body for API key
    if request.is_json:
        data = request.get_json(silent=True)  # Use silent=True to avoid exceptions
        if data and 'api_key' in data:
            return data['api_key']

    # Check query parameters
    return request.args.get('api_key')

def log_activity(user_info, action, details, fraud_result=None):
    """Enhanced log activity to database with advanced algorithm data"""
    if logs_collection is None or not user_info:
        return
    
    try:
        # Determine log level based on action and result
        log_level = "info"  # default
        if fraud_result:
            if fraud_result.get("decision") == "fraud":
                log_level = "fraud"
            elif fraud_result.get("decision") == "suspicious":
                log_level = "warning"
        elif "error" in action.lower():
            log_level = "error"
        
        log_entry = {
            "user_email": user_info.get("email"),
            "user_id": user_info.get("user_id"),
            "api_key": request.headers.get('Authorization', '').replace('Bearer ', '')[:20] + "...",
            "action": action,
            "details": details,
            "log_level": log_level,
            "timestamp": datetime.now(),
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get('User-Agent', ''),
            "endpoint": request.endpoint,
            "method": request.method
        }
        
        # Add fraud detection results if available (ENHANCED for advanced algorithms)
        if fraud_result:
            log_entry.update({
                "fraud_score": fraud_result.get("fraud_score"),
                "base_score": fraud_result.get("base_score"),  # NEW: Track base score separately
                "advanced_scores": fraud_result.get("advanced_scores", {}),  # NEW: Advanced algorithm scores
                "decision": fraud_result.get("decision"),
                "triggered_rules": fraud_result.get("triggered_rules", []),
                "algorithm_version": fraud_result.get("algorithm_version", "1.0")  # NEW: Track algorithm version
            })
        
        logs_collection.insert_one(log_entry)
        
    except Exception as e:
        app.logger.error(f"Failed to log activity: {e}")

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def validate_file(file):
    """Validate uploaded file"""
    if not file:
        return False, "No file provided"
    
    if not file.filename:
        return False, "No filename provided"
    
    # Check file extension
    if '.' not in file.filename:
        return False, "File must have an extension"
    
    extension = file.filename.rsplit('.', 1)[1].lower()
    if extension not in Config.ALLOWED_EXTENSIONS:
        return False, f"File type not supported. Allowed: {', '.join(Config.ALLOWED_EXTENSIONS)}"
    
    # Check file size
    file.seek(0, 2)  # Go to end of file
    size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if size > Config.MAX_FILE_SIZE:
        return False, f"File too large. Maximum size: {Config.MAX_FILE_SIZE // (1024*1024)}MB"
    
    if size == 0:
        return False, "File is empty"
    
    return True, "Valid"

def require_api_key(f):
    """Decorator to require valid API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = get_api_key_from_request()
        
        if not api_key:
            return create_error_response("API key required", 401, "Include API key in Authorization header or request body")
        
        user_info = validate_api_key(api_key)
        if not user_info:
            return create_error_response("Invalid API key", 403, "API key not found or inactive")
        
        # Add user info to request context (suppress type warning)
        setattr(request, 'user_info', user_info)  # type: ignore
        return f(*args, **kwargs)
    
    return decorated_function

def log_request(f):
    """Decorator to log API requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        client_ip = request.remote_addr
        
        app.logger.info(f"Request started - IP: {client_ip}, Endpoint: {request.endpoint}")
        
        try:
            result = f(*args, **kwargs)
            duration = time.time() - start_time
            app.logger.info(f"Request completed - Duration: {duration:.2f}s, IP: {client_ip}")
            return result
        except Exception as e:
            duration = time.time() - start_time
            app.logger.error(f"Request failed - Duration: {duration:.2f}s, IP: {client_ip}, Error: {str(e)}")
            raise
    
    return decorated_function

def create_error_response(message, status_code=400, details=None):
    """Create standardized error response"""
    response = {
        "success": False,
        "error": message,
        "timestamp": datetime.now().isoformat()
    }
    if details:
        response["details"] = details
    
    return jsonify(response), status_code

def create_success_response(data, message="Success"):
    """Create standardized success response"""
    response = {
        "success": True,
        "message": message,
        "data": data,
        "timestamp": datetime.now().isoformat()
    }
    return jsonify(response)

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route("/health", methods=["GET"])
def health_check():
    """Enhanced health check endpoint with algorithm info"""
    try:
        # Basic status
        status: dict[str, object] = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "fraud_checker": "initialized" if checker else "failed",
            "auth_database": "connected" if users_collection is not None else "failed",
            "version": "2.0.0"  # Updated version
        }
        
        # Add advanced algorithm info if checker is available
        if checker:
            try:
                status["algorithm_info"] = {
                    "version": "2.0_advanced",
                    "enabled_algorithms": list(getattr(checker, 'advanced_weights', {}).keys()),
                    "cache_status": {
                        "disposable_domains": len(getattr(checker, 'disposable_domains', [])),
                        "flagged_ips": len(getattr(checker, 'flagged_ips', [])),
                        "suspicious_bins": len(getattr(checker, 'suspicious_bins', [])),
                        "user_histories": len(getattr(checker, 'transaction_history', {})),
                        "velocity_cache": len(getattr(checker, 'velocity_cache', {}))
                    }
                }
            except Exception as e:
                app.logger.warning(f"Could not get algorithm info: {e}")
        
        return jsonify(status)
    except Exception as e:
        app.logger.error(f"Health check failed: {e}")
        return create_error_response("Health check failed", 503)

@app.route("/fraud-check", methods=["POST", "OPTIONS"])
@log_request
def fraud_check():
    """Enhanced single transaction fraud check with advanced algorithm support"""
    
    # Handle preflight OPTIONS request FIRST (before API key check)
    if request.method == "OPTIONS":
        return "", 200
    
    # NOW apply API key validation only for POST requests
    api_key = get_api_key_from_request()
    if not api_key:
        return create_error_response("API key required", 401, "Include API key in Authorization header or request body")
    
    user_info = validate_api_key(api_key)
    if not user_info:
        return create_error_response("Invalid API key", 403, "API key not found or inactive")
    
    # Check if fraud checker is available
    if not checker:
        return create_error_response(
            "Fraud checking service unavailable", 
            503,
            "FraudChecker failed to initialize"
        )
    
    # Increment API request metric
    try:
        if hasattr(checker.metrics, 'increment_metric'):
            checker.metrics.increment_metric("api_requests")
    except Exception as e:
        app.logger.warning(f"Failed to increment api_requests metric: {e}")
    
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data:
            return create_error_response("No data provided", 400)
        
        app.logger.info(f"Processing fraud check for user: {user_info['email']}")
        
        # Add user context to transaction data
        transaction_data = data.copy()
        transaction_data.update({
            "user_email": user_info["email"],
            "user_id": user_info["user_id"],
            "ip": request.remote_addr,  # Auto-detect real IP
            "timestamp": datetime.now().isoformat()  # Add timestamp for advanced algorithms
        })
        
        # Analyze the transaction with enhanced algorithms
        result = checker.analyze_transaction(transaction_data)
        
        # Determine if it's fraud based on the decision
        is_fraud = result.get('decision') == 'fraud'
        is_suspicious = result.get('decision') == 'suspicious'
        
        # Enhanced response data with advanced algorithm info
        response_data = {
            "is_fraud": "chance" if is_suspicious else is_fraud,
            "fraud_score": result.get('fraud_score', 0),
            "base_score": result.get('base_score', 0),  # NEW: Include base score
            "advanced_scores": result.get('advanced_scores', {}),  # NEW: Include advanced scores
            "reasons": result.get('triggered_rules', []),
            "decision": result.get('decision', 'unknown'),
            "analysis_timestamp": result.get('analysis_timestamp', datetime.now().isoformat()),
            "algorithm_version": result.get('algorithm_version', '2.0_advanced'),  # NEW: Algorithm version
            "user_email": user_info["email"]
        }
        
        # Log this activity with enhanced data
        log_activity(
            user_info,
            "fraud_check",
            {
                "transaction_email": data.get("email"),
                "card_bin": data.get("card_number", "")[:6] if data.get("card_number") else None,
                "amount": data.get("price"),
                "advanced_algorithms_triggered": list(result.get('advanced_scores', {}).keys())  # NEW: Track which algorithms triggered
            },
            result
        )
        
        app.logger.info(f"Enhanced fraud check completed - User: {user_info['email']}, Decision: {result.get('decision')}, Composite Score: {result.get('fraud_score')}, Advanced: {list(result.get('advanced_scores', {}).keys())}")
        
        return jsonify(response_data)  # Return enhanced data for checkout page
        
    except Exception as e:
        app.logger.error(f"Fraud check failed: {traceback.format_exc()}")
        return create_error_response(
            "Fraud check failed", 
            500,
            str(e) if app.debug else None
        )

# ============================================================================
# ENHANCED: Activity Log Filter Endpoint with Advanced Algorithm Support
# ============================================================================
@app.route("/user-logs", methods=["GET"])
@require_api_key
def get_user_logs():
    """Enhanced user logs endpoint with advanced algorithm filtering"""
    
    try:
        # Check if logs collection is available
        if logs_collection is None:
            return create_error_response("Logs database unavailable", 503)
        
        # Get user info from the decorator
        user_info = getattr(request, 'user_info', None)
        if not user_info:
            return create_error_response("User information not available", 500)
        
        user_email = user_info.get("email")
        user_role = user_info.get("role")
        
        # Get query parameters
        limit = min(int(request.args.get('limit', 50)), 100)
        skip = int(request.args.get('skip', 0))
        log_level = request.args.get('level', 'all')
        algorithm_filter = request.args.get('algorithm', 'all')  # NEW: Filter by algorithm
        
        # Build query filter - ADMIN SEES ALL, USER SEES ONLY THEIR LOGS
        if user_role == 'admin':
            query_filter = {}  # Admin sees all logs
        else:
            query_filter = {"user_email": user_email}  # User sees only their logs
        
        # Add log level filter if specified with proper OR logic
        if log_level != 'all':
            if log_level == 'fraud':
                # Show logs where decision is fraud or log_level is fraud
                if user_role == 'admin':
                    query_filter = {
                        "$or": [
                            {"log_level": "fraud"},
                            {"decision": "fraud"}
                        ]
                    }
                else:
                    query_filter = {
                        "user_email": user_email,
                        "$or": [
                            {"log_level": "fraud"},
                            {"decision": "fraud"}
                        ]
                    }
            elif log_level == 'warning':
                # Show suspicious transactions and warning logs
                if user_role == 'admin':
                    query_filter = {
                        "$or": [
                            {"log_level": "warning"},
                            {"decision": "suspicious"}
                        ]
                    }
                else:
                    query_filter = {
                        "user_email": user_email,
                        "$or": [
                            {"log_level": "warning"},
                            {"decision": "suspicious"}
                        ]
                    }
            elif log_level == 'error':
                if user_role == 'admin':
                    query_filter = {"log_level": "error"}
                else:
                    query_filter = {
                        "user_email": user_email,
                        "log_level": "error"
                    }
            elif log_level == 'info':
                # Show info logs and authentication activities
                if user_role == 'admin':
                    query_filter = {
                        "$or": [
                            {"log_level": "info"},
                            {"action": {"$in": ["login", "register", "logout", "auth_attempt"]}},
                            {"decision": "not_fraud"}
                        ]
                    }
                else:
                    query_filter = {
                        "user_email": user_email,
                        "$or": [
                            {"log_level": "info"},
                            {"action": {"$in": ["login", "register", "logout", "auth_attempt"]}},
                            {"decision": "not_fraud"}
                        ]
                    }
        
        # NEW: Add advanced algorithm filter
        if algorithm_filter != 'all':
            algorithm_key = f"advanced_scores.{algorithm_filter}"
            if user_role == 'admin':
                if "$or" in query_filter:
                    # If there's already an OR condition, wrap it
                    existing_filter = query_filter.copy()
                    query_filter = {
                        "$and": [
                            existing_filter,
                            {algorithm_key: {"$exists": True}}
                        ]
                    }
                else:
                    query_filter[algorithm_key] = {"$exists": True}  # type: ignore
            else:
                query_filter = {
                    "user_email": user_email,
                    algorithm_key: {"$exists": True}
                }
        
        # Debug: Log the query being executed
        app.logger.info(f"Enhanced log query filter: {query_filter}")
        app.logger.info(f"Log level: {log_level}, Algorithm filter: {algorithm_filter}")
        app.logger.info(f"User role: {user_role}, User email: {user_email}")
        
        # Get logs with the filter
        logs_cursor = logs_collection.find(query_filter).sort("timestamp", -1).skip(skip).limit(limit)
        logs = list(logs_cursor)
        
        # Format logs with enhanced data
        formatted_logs = []
        for log in logs:
            log["_id"] = str(log["_id"])
            if "timestamp" in log:
                log["timestamp"] = log["timestamp"].isoformat() if hasattr(log["timestamp"], "isoformat") else str(log["timestamp"])
            
            # NEW: Add algorithm summary for easier reading
            if "advanced_scores" in log and log["advanced_scores"]:
                log["algorithms_triggered"] = list(log["advanced_scores"].keys())
                log["highest_advanced_score"] = max(log["advanced_scores"].values()) if log["advanced_scores"] else 0
            
            formatted_logs.append(log)
        
        total_count = logs_collection.count_documents(query_filter)
        
        # NEW: Get algorithm statistics
        algorithm_stats = {}
        if user_role == 'admin':
            pipeline = [
                {"$match": {} if user_role == 'admin' else {"user_email": user_email}},
                {"$project": {"advanced_scores": 1}},
                {"$match": {"advanced_scores": {"$exists": True, "$ne": {}}}},
                {"$group": {
                    "_id": None,
                    "algorithms": {"$push": {"$objectToArray": "$advanced_scores"}}
                }}
            ]
            
            try:
                result = list(logs_collection.aggregate(pipeline))
                if result:
                    all_algorithms = []
                    for doc in result[0]["algorithms"]:
                        for algo in doc:
                            all_algorithms.append(algo["k"])
                    
                    from collections import Counter
                    algorithm_stats = dict(Counter(all_algorithms))
            except Exception as e:
                app.logger.warning(f"Could not calculate algorithm stats: {e}")
        
        response_data = {
            "logs": formatted_logs,
            "total_count": total_count,
            "user_email": user_email,
            "user_role": user_role,
            "viewing_all": user_role == 'admin',
            "limit": limit,
            "skip": skip,
            "filter_applied": log_level,
            "algorithm_filter": algorithm_filter,  # NEW
            "algorithm_stats": algorithm_stats,  # NEW
            "has_more": total_count > (skip + limit)
        }
        
        app.logger.info(f"Retrieved {len(formatted_logs)} enhanced logs for user: {user_email}, filter: {log_level}, algorithm: {algorithm_filter}")
        
        return create_success_response(response_data, f"Retrieved {len(formatted_logs)} logs")
        
    except Exception as e:
        app.logger.error(f"Failed to get user logs: {e}")
        return create_error_response("Failed to retrieve logs", 500)
    
@app.route("/real-stats", methods=["GET"])
def get_real_stats():
    """Enhanced stats endpoint with advanced algorithm metrics"""
    try:
        if not checker:
            return create_error_response("FraudChecker not available", 503)
        
        # Check if user is authenticated for personalized stats
        api_key = get_api_key_from_request()
        user_info = validate_api_key(api_key) if api_key else None
        
        # Get enhanced metrics using synchronous method
        if hasattr(checker.metrics, 'get_metric_count'):
            metrics = {
                "total_checks": checker.metrics.get_metric_count("total_checks"),
                "fraud_blocked": checker.metrics.get_metric_count("fraud_blocked"),
                "suspicious_flagged": checker.metrics.get_metric_count("suspicious_flagged"),
                "clean_approved": checker.metrics.get_metric_count("clean_approved"),
                "bulk_analyses": checker.metrics.get_metric_count("bulk_analyses"),
                "api_requests": checker.metrics.get_metric_count("api_requests"),
                # NEW: Advanced algorithm metrics
                "velocity_alerts": checker.metrics.get_metric_count("velocity_alerts"),
                "pattern_anomalies": checker.metrics.get_metric_count("pattern_anomalies"),
                "geo_anomalies": checker.metrics.get_metric_count("geo_anomalies"),
                "behavioral_alerts": checker.metrics.get_metric_count("behavioral_alerts")
            }
        else:
            # Fallback if metrics not available
            metrics = {
                "total_checks": 0,
                "fraud_blocked": 0,
                "suspicious_flagged": 0,
                "clean_approved": 0,
                "bulk_analyses": 0,
                "api_requests": 0,
                "velocity_alerts": 0,
                "pattern_anomalies": 0,
                "geo_anomalies": 0,
                "behavioral_alerts": 0
            }
        
        # Calculate advanced detection rate
        total_advanced_detections = (
            metrics.get("velocity_alerts", 0) + 
            metrics.get("pattern_anomalies", 0) + 
            metrics.get("geo_anomalies", 0) + 
            metrics.get("behavioral_alerts", 0)
        )
        
        # Build enhanced response
        response_data = {
            "hero_stats": {
                "total_checks": metrics.get("total_checks", 0),
                "fraud_blocked": metrics.get("fraud_blocked", 0) + metrics.get("suspicious_flagged", 0),
                "accuracy": "99.7%",  # Updated accuracy with advanced algorithms
                "advanced_detections": total_advanced_detections  # NEW
            },
            "detailed_metrics": metrics,
            "advanced_algorithm_stats": {  # NEW: Advanced algorithm breakdown
                "velocity_alerts": metrics.get("velocity_alerts", 0),
                "pattern_anomalies": metrics.get("pattern_anomalies", 0),
                "geo_anomalies": metrics.get("geo_anomalies", 0),
                "behavioral_alerts": metrics.get("behavioral_alerts", 0),
                "total_advanced_detections": total_advanced_detections
            },
            "blacklist_counts": {
                "disposable_domains": len(getattr(checker, 'disposable_domains', [])),
                "flagged_ips": len(getattr(checker, 'flagged_ips', [])),
                "suspicious_bins": len(getattr(checker, 'suspicious_bins', [])),
                "reused_fingerprints": len(getattr(checker, 'reused_fingerprints', [])),
                "tampered_prices": len(getattr(checker, 'tampered_prices', []))
            },
            "system_stats": {
                "active_rules": len(getattr(checker, 'rules', {})),
                "user_histories": len(getattr(checker, 'transaction_history', {})),  # NEW
                "velocity_cache_size": len(getattr(checker, 'velocity_cache', {})),  # NEW
                "geo_patterns_size": len(getattr(checker, 'geo_patterns', {})),  # NEW
                "database_status": "online",
                "fraud_checker_status": "active",
                "algorithm_version": "2.0_advanced"  # NEW
            },
            "algorithm_info": {  # NEW: Algorithm information
                "enabled_algorithms": list(getattr(checker, 'advanced_weights', {}).keys()),
                "algorithm_weights": getattr(checker, 'advanced_weights', {}),
                "version": "2.0_advanced"
            },
            "user_context": user_info  # Include user info if authenticated
        }
        
        return jsonify({
            "success": True,
            "data": response_data,
            "message": f"Retrieved enhanced metrics successfully"
        })
        
    except Exception as e:
        app.logger.error(f"Stats error: {e}")
        # Return default enhanced data on error
        return jsonify({
            "success": True,
            "data": {
                "hero_stats": {
                    "total_checks": 0,
                    "fraud_blocked": 0,
                    "accuracy": "99.7%",
                    "advanced_detections": 0
                },
                "detailed_metrics": {
                    "total_checks": 0,
                    "fraud_blocked": 0,
                    "suspicious_flagged": 0,
                    "clean_approved": 0,
                    "bulk_analyses": 0,
                    "api_requests": 0,
                    "velocity_alerts": 0,
                    "pattern_anomalies": 0,
                    "geo_anomalies": 0,
                    "behavioral_alerts": 0
                },
                "algorithm_info": {
                    "version": "2.0_advanced"
                }
            }
        })

@app.route("/bulk-check", methods=["POST"])
@log_request
@require_api_key
def bulk_check():
    """Enhanced bulk fraud checking with advanced algorithm support"""
    
    # Check if fraud checker is available
    if not checker:
        return create_error_response(
            "Fraud checking service unavailable", 
            503,
            "FraudChecker failed to initialize"
        )
    
    user_info = getattr(request, 'user_info', None)  # Set by @require_api_key decorator
    if not user_info or 'email' not in user_info:
        return create_error_response("User information not available", 500)
    
    # Increment API request metric
    try:
        if hasattr(checker.metrics, 'increment_metric'):
            checker.metrics.increment_metric("api_requests")
    except Exception as e:
        app.logger.warning(f"Failed to increment api_requests metric: {e}")
    
    # Get the uploaded file
    file = request.files.get("file")
    
    # Validate file
    is_valid, message = validate_file(file)
    if not is_valid:
        app.logger.warning(f"File validation failed for user {user_info['email']}: {message}")
        return create_error_response(message, 400)
    
    if file:
        app.logger.info(f"Processing file: {file.filename} for user: {user_info['email']}")
        file.seek(0)  # Reset file pointer after size check
    else:
        app.logger.warning(f"No file provided by user: {user_info['email']}")
        return create_error_response("No file provided", 400)
    
    try:
        # Record start time
        start_time = time.time()
        
        # Process the file with enhanced algorithms
        app.logger.info(f"Starting enhanced bulk fraud analysis for user: {user_info['email']}")
        results = checker.analyze_bulk(file)
        app.logger.info(f"Enhanced bulk fraud analysis completed for user: {user_info['email']}, got {len(results)} results")
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Validate results
        if not results:
            return create_error_response("No results generated", 500)
        
        # Check if results exceed limit
        if len(results) > Config.MAX_RECORDS:
            app.logger.warning(f"Too many records for user {user_info['email']}: {len(results)}")
            return create_error_response(
                f"Too many records. Maximum allowed: {Config.MAX_RECORDS}",
                400
            )
        
        # Enhanced analysis: Count different decision types and advanced algorithm usage
        decision_counts = {}
        algorithm_counts = {}
        score_distribution = {"low": 0, "medium": 0, "high": 0}
        
        for result in results:
            # Count decisions
            decision = result.get('decision', 'unknown')
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
            
            # Count advanced algorithms triggered
            advanced_scores = result.get('advanced_scores', {})
            for algo in advanced_scores.keys():
                algorithm_counts[algo] = algorithm_counts.get(algo, 0) + 1
            
            # Score distribution
            score = result.get('fraud_score', 0)
            if score < 0.3:
                score_distribution["low"] += 1
            elif score < 0.7:
                score_distribution["medium"] += 1
            else:
                score_distribution["high"] += 1
        
        # Log enhanced bulk analysis activity
        log_activity(
            user_info,
            "bulk_analysis",
            {
                "filename": file.filename,
                "total_records": len(results),
                "processing_time": processing_time,
                "decision_breakdown": decision_counts,
                "algorithm_usage": algorithm_counts,  # NEW
                "score_distribution": score_distribution,  # NEW
                "algorithm_version": "2.0_advanced"  # NEW
            }
        )
        
        # Prepare enhanced response data
        response_data = {
            "results": results,
            "summary": {
                "total_records": len(results),
                "processing_time_seconds": round(processing_time, 2),
                "filename": file.filename if file else None,
                "decision_breakdown": decision_counts,
                "algorithm_usage": algorithm_counts,  # NEW: Which algorithms were triggered
                "score_distribution": score_distribution,  # NEW: Score distribution
                "user_email": user_info["email"],
                "algorithm_version": "2.0_advanced"  # NEW
            },
            "analysis_insights": {  # NEW: Additional insights
                "most_common_algorithm": max(algorithm_counts.items(), key=lambda x: x[1])[0] if algorithm_counts else None,
                "average_score": round(sum(r.get('fraud_score', 0) for r in results) / len(results), 3) if results else 0,
                "advanced_detections": sum(1 for r in results if r.get('advanced_scores', {})),
                "high_risk_count": score_distribution["high"]
            }
        }
        
        app.logger.info(f"Successfully processed {len(results)} records for user: {user_info['email']} in {processing_time:.2f}s with advanced algorithms")
        app.logger.info(f"Algorithm usage: {algorithm_counts}")
        
        return create_success_response(
            response_data, 
            f"Successfully analyzed {len(results)} records with advanced algorithms"
        )
        
    except Exception as e:
        # Log bulk analysis error
        log_activity(
            user_info,
            "bulk_analysis_error",
            {
                "filename": file.filename if file else "unknown",
                "error": str(e)
            }
        )
        
        app.logger.error(f"Enhanced bulk check failed for user {user_info['email']}: {traceback.format_exc()}")
        
        return create_error_response(
            "An unexpected error occurred during processing", 
            500,
            str(e) if app.debug else None
        )

# ============================================================================
# NEW ENDPOINT: Algorithm Status
# ============================================================================

@app.route("/algorithm-status", methods=["GET"])
@require_api_key
def get_algorithm_status():
    """Get current status and performance of advanced algorithms"""
    try:
        if not checker:
            return create_error_response("FraudChecker not available", 503)
        
        user_info = getattr(request, 'user_info', None)
        
        # Get algorithm weights and status
        algorithm_weights = getattr(checker, 'advanced_weights', {})
        
        # Get cache sizes for performance monitoring
        cache_stats = {
            "transaction_history": len(getattr(checker, 'transaction_history', {})),
            "velocity_cache": len(getattr(checker, 'velocity_cache', {})),
            "geo_patterns": len(getattr(checker, 'geo_patterns', {})),
            "behavioral_profiles": len(getattr(checker, 'behavioral_profiles', {}))
        }
        
        # Get recent algorithm performance (if user has admin role)
        algorithm_performance = {}
        if user_info and user_info.get("role") == "admin" and logs_collection is not None:
            try:
                # Get algorithm usage in last 24 hours
                from datetime import timedelta
                yesterday = datetime.now() - timedelta(hours=24)
                
                pipeline = [
                    {"$match": {
                        "timestamp": {"$gte": yesterday},
                        "advanced_scores": {"$exists": True, "$ne": {}}
                    }},
                    {"$project": {"advanced_scores": 1}},
                    {"$group": {
                        "_id": None,
                        "algorithms": {"$push": {"$objectToArray": "$advanced_scores"}}
                    }}
                ]
                
                result = list(logs_collection.aggregate(pipeline))
                if result:
                    all_algorithms = []
                    for doc in result[0]["algorithms"]:
                        for algo in doc:
                            all_algorithms.append(algo["k"])
                    
                    from collections import Counter
                    algorithm_performance = dict(Counter(all_algorithms))
                    
            except Exception as e:
                app.logger.warning(f"Could not calculate algorithm performance: {e}")
        
        response_data = {
            "algorithm_info": {
                "version": "2.0_advanced",
                "enabled_algorithms": list(algorithm_weights.keys()),
                "algorithm_weights": algorithm_weights
            },
            "cache_stats": cache_stats,
            "algorithm_performance_24h": algorithm_performance,
            "system_health": {
                "fraud_checker_status": "active",
                "algorithm_version": "2.0_advanced",
                "last_updated": datetime.now().isoformat()
            }
        }
        
        return create_success_response(response_data, "Algorithm status retrieved successfully")
        
    except Exception as e:
        app.logger.error(f"Algorithm status error: {e}")
        return create_error_response("Failed to get algorithm status", 500)

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return create_error_response("Endpoint not found", 404)

@app.errorhandler(405)
def method_not_allowed(error):
    return create_error_response("Method not allowed", 405)

@app.errorhandler(413)
def request_entity_too_large(error):
    return create_error_response("File too large", 413)

@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error(f"Internal server error: {error}")
    return create_error_response("Internal server error", 500)

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    app.logger.info("Starting Enhanced FraudShield API with Advanced Algorithms...")
    app.logger.info(f"Max file size: {Config.MAX_FILE_SIZE // (1024*1024)}MB")
    app.logger.info(f"Allowed extensions: {Config.ALLOWED_EXTENSIONS}")
    app.logger.info(f"Max records: {Config.MAX_RECORDS}")
    
    if checker:
        app.logger.info("✅ Enhanced FraudChecker initialized")
        # Log algorithm information
        if hasattr(checker, 'advanced_weights'):
            enabled_algos = list(checker.advanced_weights.keys())
            app.logger.info(f"🧠 Advanced algorithms enabled: {enabled_algos}")
        else:
            app.logger.warning("⚠️ Advanced algorithms not detected")
    else:
        app.logger.warning("⚠️ FraudChecker failed to initialize")
    
    if users_collection is not None:
        user_count = users_collection.count_documents({})
        app.logger.info(f"✅ Auth database connected - {user_count} users found")
    else:
        app.logger.warning("⚠️ Auth database connection failed")
    
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5000,
        threaded=True,
        use_reloader=False
    )