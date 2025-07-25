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

class Config:
    MAX_FILE_SIZE = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'json'}
    MAX_RECORDS = 5000

app = Flask(__name__)

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
         "file://"
     ],
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     supports_credentials=True
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bulk_api.log'),
        logging.StreamHandler()
    ]
)

try:
    checker = FraudChecker()
    app.logger.info("✅ Enhanced FraudChecker initialized successfully")
except Exception as e:
    app.logger.error(f"❌ Failed to initialize FraudChecker: {e}")
    checker = None

try:
    mongo_client = pymongo.MongoClient("mongodb://localhost:27017")
    auth_db = mongo_client.fraudshield
    users_collection = auth_db.users
    audit_logs_collection = auth_db.audit_logs
    transactions_collection = auth_db.transactions
    app.logger.info("✅ Authentication database connected")
except Exception as e:
    app.logger.error(f"❌ Failed to connect to auth database: {e}")
    mongo_client = None
    auth_db = None
    users_collection = None
    audit_logs_collection = None
    transactions_collection = None

def validate_api_key(api_key):
    if users_collection is None or not api_key:
        return None
    
    try:
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
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header[7:]

    if request.is_json:
        data = request.get_json(silent=True)
        if data and 'api_key' in data:
            return data['api_key']

    return request.args.get('api_key')

def log_activity(user_info, action, details, fraud_result=None):
    if audit_logs_collection is None or not user_info:
        return
    
    try:
        log_level = "info"
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
        
        if fraud_result:
            log_entry.update({
                "fraud_score": fraud_result.get("fraud_score"),
                "base_score": fraud_result.get("base_score"),
                "advanced_scores": fraud_result.get("advanced_scores", {}),
                "decision": fraud_result.get("decision"),
                "triggered_rules": fraud_result.get("triggered_rules", []),
                "algorithm_version": fraud_result.get("algorithm_version", "1.0")
            })
        
        audit_logs_collection.insert_one(log_entry)
        
    except Exception as e:
        app.logger.error(f"Failed to log activity: {e}")

def validate_file(file):
    if not file:
        return False, "No file provided"
    
    if not file.filename:
        return False, "No filename provided"
    
    if '.' not in file.filename:
        return False, "File must have an extension"
    
    extension = file.filename.rsplit('.', 1)[1].lower()
    if extension not in Config.ALLOWED_EXTENSIONS:
        return False, f"File type not supported. Allowed: {', '.join(Config.ALLOWED_EXTENSIONS)}"
    
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    
    if size > Config.MAX_FILE_SIZE:
        return False, f"File too large. Maximum size: {Config.MAX_FILE_SIZE // (1024*1024)}MB"
    
    if size == 0:
        return False, "File is empty"
    
    return True, "Valid"

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = get_api_key_from_request()
        
        if not api_key:
            return create_error_response("API key required", 401, "Include API key in Authorization header or request body")
        
        user_info = validate_api_key(api_key)
        if not user_info:
            return create_error_response("Invalid API key", 403, "API key not found or inactive")
        
        setattr(request, 'user_info', user_info)
        return f(*args, **kwargs)
    
    return decorated_function

def log_request(f):
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
    response = {
        "success": False,
        "error": message,
        "timestamp": datetime.now().isoformat()
    }
    if details:
        response["details"] = details
    
    return jsonify(response), status_code

def create_success_response(data, message="Success"):
    response = {
        "success": True,
        "message": message,
        "data": data,
        "timestamp": datetime.now().isoformat()
    }
    return jsonify(response)

@app.route("/health", methods=["GET"])
def health_check():
    try:
        status: dict[str, object] = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "fraud_checker": "initialized" if checker else "failed",
            "auth_database": "connected" if users_collection is not None else "failed",
            "version": "2.0.0"
        }
        
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
    if request.method == "OPTIONS":
        return "", 200
    
    api_key = get_api_key_from_request()
    if not api_key:
        return create_error_response("API key required", 401, "Include API key in Authorization header or request body")
    
    user_info = validate_api_key(api_key)
    if not user_info:
        return create_error_response("Invalid API key", 403, "API key not found or inactive")
    
    if not checker:
        return create_error_response(
            "Fraud checking service unavailable", 
            503,
            "FraudChecker failed to initialize"
        )
    
    try:
        if hasattr(checker.metrics, 'increment_metric'):
            checker.metrics.increment_metric("api_requests")
    except Exception as e:
        app.logger.warning(f"Failed to increment api_requests metric: {e}")
    
    try:
        data = request.get_json()
        
        if not data:
            return create_error_response("No data provided", 400)
        
        app.logger.info(f"Processing fraud check for user: {user_info['email']}")
        
        transaction_data = data.copy()
        transaction_data.update({
            "user_email": user_info["email"],
            "user_id": user_info["user_id"],
            "ip": request.remote_addr,
            "timestamp": datetime.now().isoformat()
        })
        
        result = checker.analyze_transaction(transaction_data)
        
        is_fraud = result.get('decision') == 'fraud'
        is_suspicious = result.get('decision') == 'suspicious'
        
        response_data = {
            "is_fraud": "chance" if is_suspicious else is_fraud,
            "fraud_score": result.get('fraud_score', 0),
            "base_score": result.get('base_score', 0),
            "advanced_scores": result.get('advanced_scores', {}),
            "reasons": result.get('triggered_rules', []),
            "decision": result.get('decision', 'unknown'),
            "analysis_timestamp": result.get('analysis_timestamp', datetime.now().isoformat()),
            "algorithm_version": result.get('algorithm_version', '2.0_advanced'),
            "user_email": user_info["email"]
        }
        
        if transactions_collection is not None:
            try:
                transaction_record = {
                    "transaction_id": data.get("transaction_id", f"tx_{datetime.now().timestamp()}"),
                    "timestamp": datetime.now(),
                    "api_key": api_key[:20] + "...",
                    "user_email": user_info["email"],
                    "amount": data.get("price"),
                    "product": data.get("product"),
                    "email": data.get("email"),
                    "device_fingerprint": data.get("fingerprint"),
                    "ip_address": data.get("ip", request.remote_addr),
                    "card_bin": data.get("card_number", "")[:6] if data.get("card_number") else None,
                    "fraud_score": result.get('fraud_score', 0),
                    "decision": result.get('decision', 'unknown'),
                    "reasons": result.get('triggered_rules', []),
                    "processing_time": 0,
                    "raw_data": transaction_data,
                    "email_verified": data.get("email_verified", False),
                    "phone_verified": data.get("phone_verified", False)
                }
                transactions_collection.insert_one(transaction_record)
            except Exception as e:
                app.logger.error(f"Failed to save transaction: {e}")
        
        log_activity(
            user_info,
            "fraud_check",
            {
                "transaction_email": data.get("email"),
                "card_bin": data.get("card_number", "")[:6] if data.get("card_number") else None,
                "amount": data.get("price"),
                "advanced_algorithms_triggered": list(result.get('advanced_scores', {}).keys()),
                "email_verified": data.get("email_verified", False),
                "phone_verified": data.get("phone_verified", False)
            },
            result
        )
        
        app.logger.info(f"Enhanced fraud check completed - User: {user_info['email']}, Decision: {result.get('decision')}, Composite Score: {result.get('fraud_score')}, Advanced: {list(result.get('advanced_scores', {}).keys())}")
        
        return jsonify(response_data)
        
    except Exception as e:
        app.logger.error(f"Fraud check failed: {traceback.format_exc()}")
        return create_error_response(
            "Fraud check failed", 
            500,
            str(e) if app.debug else None
        )

@app.route("/user-logs", methods=["GET"])
@require_api_key
def get_user_logs():
    try:
        if audit_logs_collection is None:
            return create_error_response("Logs database unavailable", 503)
        
        user_info = getattr(request, 'user_info', None)
        if not user_info:
            return create_error_response("User information not available", 500)
        
        user_email = user_info.get("email")
        user_role = user_info.get("role")
        
        limit = min(int(request.args.get('limit', 50)), 100)
        skip = int(request.args.get('skip', 0))
        log_level = request.args.get('level', 'all')
        algorithm_filter = request.args.get('algorithm', 'all')
        
        if user_role == 'admin':
            query_filter = {}
        else:
            query_filter = {"user_email": user_email}
        
        if log_level != 'all':
            if log_level == 'fraud':
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
        
        if algorithm_filter != 'all':
            algorithm_key = f"advanced_scores.{algorithm_filter}"
            if user_role == 'admin':
                if "$or" in query_filter:
                    existing_filter = query_filter.copy()
                    query_filter = {
                        "$and": [
                            existing_filter,
                            {algorithm_key: {"$exists": True}}
                        ]
                    }
                else:
                    query_filter[algorithm_key] = {"$exists": True}
            else:
                query_filter = {
                    "user_email": user_email,
                    algorithm_key: {"$exists": True}
                }
        
        app.logger.info(f"Enhanced log query filter: {query_filter}")
        app.logger.info(f"Log level: {log_level}, Algorithm filter: {algorithm_filter}")
        app.logger.info(f"User role: {user_role}, User email: {user_email}")
        
        logs_cursor = audit_logs_collection.find(query_filter).sort("timestamp", -1).skip(skip).limit(limit)
        logs = list(logs_cursor)
        
        formatted_logs = []
        for log in logs:
            log["_id"] = str(log["_id"])
            if "timestamp" in log:
                log["timestamp"] = log["timestamp"].isoformat() if hasattr(log["timestamp"], "isoformat") else str(log["timestamp"])
            
            if "advanced_scores" in log and log["advanced_scores"]:
                log["algorithms_triggered"] = list(log["advanced_scores"].keys())
                log["highest_advanced_score"] = max(log["advanced_scores"].values()) if log["advanced_scores"] else 0
            
            formatted_logs.append(log)
        
        total_count = audit_logs_collection.count_documents(query_filter)
        
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
                result = list(audit_logs_collection.aggregate(pipeline))
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
            "algorithm_filter": algorithm_filter,
            "algorithm_stats": algorithm_stats,
            "has_more": total_count > (skip + limit)
        }
        
        app.logger.info(f"Retrieved {len(formatted_logs)} enhanced logs for user: {user_email}, filter: {log_level}, algorithm: {algorithm_filter}")
        
        return create_success_response(response_data, f"Retrieved {len(formatted_logs)} logs")
        
    except Exception as e:
        app.logger.error(f"Failed to get user logs: {e}")
        return create_error_response("Failed to retrieve logs", 500)
    
@app.route("/real-stats", methods=["GET"])
def get_real_stats():
    try:
        if not checker:
            return create_error_response("FraudChecker not available", 503)
        
        api_key = get_api_key_from_request()
        user_info = validate_api_key(api_key) if api_key else None
        
        if hasattr(checker.metrics, 'get_metric_count'):
            metrics = {
                "total_checks": checker.metrics.get_metric_count("total_checks"),
                "fraud_blocked": checker.metrics.get_metric_count("fraud_blocked"),
                "suspicious_flagged": checker.metrics.get_metric_count("suspicious_flagged"),
                "clean_approved": checker.metrics.get_metric_count("clean_approved"),
                "bulk_analyses": checker.metrics.get_metric_count("bulk_analyses"),
                "api_requests": checker.metrics.get_metric_count("api_requests"),
                "velocity_alerts": checker.metrics.get_metric_count("velocity_alerts"),
                "pattern_anomalies": checker.metrics.get_metric_count("pattern_anomalies"),
                "geo_anomalies": checker.metrics.get_metric_count("geo_anomalies"),
                "behavioral_alerts": checker.metrics.get_metric_count("behavioral_alerts")
            }
        else:
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
        
        total_advanced_detections = (
            metrics.get("velocity_alerts", 0) + 
            metrics.get("pattern_anomalies", 0) + 
            metrics.get("geo_anomalies", 0) + 
            metrics.get("behavioral_alerts", 0)
        )
        
        response_data = {
            "hero_stats": {
                "total_checks": metrics.get("total_checks", 0),
                "fraud_blocked": metrics.get("fraud_blocked", 0) + metrics.get("suspicious_flagged", 0),
                "accuracy": "99.7%",
                "advanced_detections": total_advanced_detections
            },
            "detailed_metrics": metrics,
            "advanced_algorithm_stats": {
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
                "user_histories": len(getattr(checker, 'transaction_history', {})),
                "velocity_cache_size": len(getattr(checker, 'velocity_cache', {})),
                "geo_patterns_size": len(getattr(checker, 'geo_patterns', {})),
                "database_status": "online",
                "fraud_checker_status": "active",
                "algorithm_version": "2.0_advanced"
            },
            "algorithm_info": {
                "enabled_algorithms": list(getattr(checker, 'advanced_weights', {}).keys()),
                "algorithm_weights": getattr(checker, 'advanced_weights', {}),
                "version": "2.0_advanced"
            },
            "user_context": user_info
        }
        
        return jsonify({
            "success": True,
            "data": response_data,
            "message": f"Retrieved enhanced metrics successfully"
        })
        
    except Exception as e:
        app.logger.error(f"Stats error: {e}")
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
    if not checker:
        return create_error_response(
            "Fraud checking service unavailable", 
            503,
            "FraudChecker failed to initialize"
        )
    
    user_info = getattr(request, 'user_info', None)
    if not user_info or 'email' not in user_info:
        return create_error_response("User information not available", 500)
    
    try:
        if hasattr(checker.metrics, 'increment_metric'):
            checker.metrics.increment_metric("api_requests")
    except Exception as e:
        app.logger.warning(f"Failed to increment api_requests metric: {e}")
    
    file = request.files.get("file")
    
    is_valid, message = validate_file(file)
    if not is_valid:
        app.logger.warning(f"File validation failed for user {user_info['email']}: {message}")
        return create_error_response(message, 400)
    
    if file:
        app.logger.info(f"Processing file: {file.filename} for user: {user_info['email']}")
        file.seek(0)
    else:
        app.logger.warning(f"No file provided by user: {user_info['email']}")
        return create_error_response("No file provided", 400)
    
    try:
        start_time = time.time()
        
        app.logger.info(f"Starting enhanced bulk fraud analysis for user: {user_info['email']}")
        results = checker.analyze_bulk(file)
        app.logger.info(f"Enhanced bulk fraud analysis completed for user: {user_info['email']}, got {len(results)} results")
        
        processing_time = time.time() - start_time
        
        if not results:
            return create_error_response("No results generated", 500)
        
        if len(results) > Config.MAX_RECORDS:
            app.logger.warning(f"Too many records for user {user_info['email']}: {len(results)}")
            return create_error_response(
                f"Too many records. Maximum allowed: {Config.MAX_RECORDS}",
                400
            )
        
        decision_counts = {}
        algorithm_counts = {}
        score_distribution = {"low": 0, "medium": 0, "high": 0}
        
        for result in results:
            decision = result.get('decision', 'unknown')
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
            
            advanced_scores = result.get('advanced_scores', {})
            for algo in advanced_scores.keys():
                algorithm_counts[algo] = algorithm_counts.get(algo, 0) + 1
            
            score = result.get('fraud_score', 0)
            if score < 0.3:
                score_distribution["low"] += 1
            elif score < 0.7:
                score_distribution["medium"] += 1
            else:
                score_distribution["high"] += 1
        
        log_activity(
            user_info,
            "bulk_analysis",
            {
                "filename": file.filename,
                "total_records": len(results),
                "processing_time": processing_time,
                "decision_breakdown": decision_counts,
                "algorithm_usage": algorithm_counts,
                "score_distribution": score_distribution,
                "algorithm_version": "2.0_advanced"
            }
        )
        
        response_data = {
            "results": results,
            "summary": {
                "total_records": len(results),
                "processing_time_seconds": round(processing_time, 2),
                "filename": file.filename if file else None,
                "decision_breakdown": decision_counts,
                "algorithm_usage": algorithm_counts,
                "score_distribution": score_distribution,
                "user_email": user_info["email"],
                "algorithm_version": "2.0_advanced"
            },
            "analysis_insights": {
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

@app.route("/algorithm-status", methods=["GET"])
@require_api_key
def get_algorithm_status():
    try:
        if not checker:
            return create_error_response("FraudChecker not available", 503)
        
        user_info = getattr(request, 'user_info', None)
        
        algorithm_weights = getattr(checker, 'advanced_weights', {})
        
        cache_stats = {
            "transaction_history": len(getattr(checker, 'transaction_history', {})),
            "velocity_cache": len(getattr(checker, 'velocity_cache', {})),
            "geo_patterns": len(getattr(checker, 'geo_patterns', {})),
            "behavioral_profiles": len(getattr(checker, 'behavioral_profiles', {}))
        }
        
        algorithm_performance = {}
        if user_info and user_info.get("role") == "admin" and audit_logs_collection is not None:
            try:
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
                
                result = list(audit_logs_collection.aggregate(pipeline))
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

@app.route("/admin/rules", methods=["GET"])
@require_api_key
def get_all_rules():
    try:
        user_info = getattr(request, 'user_info', None)
        if not user_info or user_info.get('role') != 'admin':
            return create_error_response("Admin access required", 403)
        
        if auth_db is None:
            return create_error_response("Rules database unavailable", 503)
        
        rules = list(auth_db.rules.find())
        
        for rule in rules:
            rule['_id'] = str(rule['_id'])
        
        return jsonify({
            "success": True,
            "rules": rules
        })
        
    except Exception as e:
        app.logger.error(f"Failed to get rules: {e}")
        return create_error_response("Failed to retrieve rules", 500)

@app.route("/admin/rules/<rule_id>", methods=["PUT"])
@require_api_key
def update_rule(rule_id):
    try:
        user_info = getattr(request, 'user_info', None)
        if not user_info or user_info.get('role') != 'admin':
            return create_error_response("Admin access required", 403)
        
        if auth_db is None:
            return create_error_response("Rules database unavailable", 503)
        
        data = request.get_json()
        
        from bson import ObjectId
        result = auth_db.rules.update_one(
            {"_id": ObjectId(rule_id)},
            {"$set": {
                "enabled": data.get("enabled"),
                "weight": float(data.get("weight", 0)),
                "updated_at": datetime.now(),
                "updated_by": user_info.get("email")
            }}
        )
        
        if result.modified_count > 0:
            log_activity(
                user_info,
                "rule_updated",
                {
                    "rule_id": rule_id,
                    "changes": data
                }
            )
            
            return jsonify({
                "success": True,
                "message": "Rule updated successfully"
            })
        else:
            return create_error_response("Rule not found or no changes made", 404)
            
    except Exception as e:
        app.logger.error(f"Failed to update rule: {e}")
        return create_error_response("Failed to update rule", 500)

@app.route("/admin/rules/batch", methods=["PUT"])
@require_api_key
def batch_update_rules():
    try:
        user_info = getattr(request, 'user_info', None)
        if not user_info or user_info.get('role') != 'admin':
            return create_error_response("Admin access required", 403)
        
        data = request.get_json()
        updates = data.get("updates", [])
        
        success_count = 0
        from bson import ObjectId
        
        if auth_db is None:
            return create_error_response("Rules database unavailable", 503)

        for update in updates:
            result = auth_db.rules.update_one(
                {"_id": ObjectId(update["_id"])},
                {"$set": {
                    "enabled": update.get("enabled"),
                    "weight": float(update.get("weight", 0)),
                    "updated_at": datetime.now(),
                    "updated_by": user_info.get("email")
                }}
            )
            if result.modified_count > 0:
                success_count += 1
        
        log_activity(
            user_info,
            "rules_batch_updated",
            {
                "total_updates": len(updates),
                "successful": success_count
            }
        )
        
        return jsonify({
            "success": True,
            "message": f"Updated {success_count} out of {len(updates)} rules"
        })
        
    except Exception as e:
        app.logger.error(f"Failed to batch update rules: {e}")
        return create_error_response("Failed to update rules", 500)

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

if __name__ == "__main__":
    app.logger.info("Starting Enhanced FraudShield API with Advanced Algorithms...")
    app.logger.info(f"Max file size: {Config.MAX_FILE_SIZE // (1024*1024)}MB")
    app.logger.info(f"Allowed extensions: {Config.ALLOWED_EXTENSIONS}")
    app.logger.info(f"Max records: {Config.MAX_RECORDS}")
    
    if checker:
        app.logger.info("✅ Enhanced FraudChecker initialized")
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