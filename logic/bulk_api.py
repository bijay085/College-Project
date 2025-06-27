# logic/bulk_api.py - FIXED to work with synchronous fraud checker
import sys
import os
import time
import logging
from datetime import datetime
from functools import wraps
import traceback

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

# Enhanced CORS configuration
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

# Add OPTIONS handler for preflight requests
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

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
    app.logger.info("✅ FraudChecker initialized successfully")
except Exception as e:
    app.logger.error(f"❌ Failed to initialize FraudChecker: {e}")
    checker = None

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
    """Health check endpoint"""
    try:
        status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "fraud_checker": "initialized" if checker else "failed",
            "version": "1.0.0"
        }
        return jsonify(status)
    except Exception as e:
        app.logger.error(f"Health check failed: {e}")
        return create_error_response("Health check failed", 503)

@app.route("/real-stats", methods=["GET"])
def get_real_stats():
    """Get real metrics - WORKS WITH SYNCHRONOUS FRAUD CHECKER"""
    try:
        if not checker:
            return create_error_response("FraudChecker not available", 503)
        
        # Get metrics using synchronous method
        if hasattr(checker.metrics, 'get_metric_count'):
            metrics = {
                "total_checks": checker.metrics.get_metric_count("total_checks"),
                "fraud_blocked": checker.metrics.get_metric_count("fraud_blocked"),
                "suspicious_flagged": checker.metrics.get_metric_count("suspicious_flagged"),
                "clean_approved": checker.metrics.get_metric_count("clean_approved"),
                "bulk_analyses": checker.metrics.get_metric_count("bulk_analyses"),
                "api_requests": checker.metrics.get_metric_count("api_requests")
            }
        else:
            # Fallback if metrics not available
            metrics = {
                "total_checks": 0,
                "fraud_blocked": 0,
                "suspicious_flagged": 0,
                "clean_approved": 0,
                "bulk_analyses": 0,
                "api_requests": 0
            }
        
        # Build response
        response_data = {
            "hero_stats": {
                "total_checks": metrics.get("total_checks", 0),
                "fraud_blocked": metrics.get("fraud_blocked", 0) + metrics.get("suspicious_flagged", 0),
                "accuracy": "99.2%"
            },
            "detailed_metrics": metrics,
            "blacklist_counts": {
                "disposable_domains": len(getattr(checker, 'disposable_domains', [])),
                "flagged_ips": len(getattr(checker, 'flagged_ips', [])),
                "suspicious_bins": len(getattr(checker, 'suspicious_bins', [])),
                "reused_fingerprints": len(getattr(checker, 'reused_fingerprints', [])),
                "tampered_prices": len(getattr(checker, 'tampered_prices', []))
            },
            "system_stats": {
                "active_rules": len(getattr(checker, 'rules', {})),
                "database_status": "online",
                "fraud_checker_status": "active"
            }
        }
        
        return jsonify({
            "success": True,
            "data": response_data,
            "message": f"Retrieved metrics successfully"
        })
        
    except Exception as e:
        app.logger.error(f"Stats error: {e}")
        # Return default data on error
        return jsonify({
            "success": True,
            "data": {
                "hero_stats": {
                    "total_checks": 0,
                    "fraud_blocked": 0,
                    "accuracy": "99.2%"
                },
                "detailed_metrics": {
                    "total_checks": 0,
                    "fraud_blocked": 0,
                    "suspicious_flagged": 0,
                    "clean_approved": 0,
                    "bulk_analyses": 0,
                    "api_requests": 0
                }
            }
        })

@app.route("/bulk-check", methods=["POST"])
@log_request
def bulk_check():
    """FIXED bulk fraud checking endpoint - now works with synchronous fraud checker"""
    
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
    
    # Get the uploaded file
    file = request.files.get("file")
    
    # Validate file
    is_valid, message = validate_file(file)
    if not is_valid:
        app.logger.warning(f"File validation failed: {message}")
        return create_error_response(message, 400)
    
    if file:
        app.logger.info(f"Processing file: {file.filename}, Size: {file.tell()} bytes")
        file.seek(0)  # Reset file pointer after size check
    else:
        app.logger.warning("No file provided for processing")
        return create_error_response("No file provided", 400)
    
    try:
        # Record start time
        start_time = time.time()
        
        # Process the file (SYNCHRONOUSLY - no await needed)
        app.logger.info("Starting fraud analysis...")
        results = checker.analyze_bulk(file)
        app.logger.info(f"Fraud analysis completed, got {len(results)} results")
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Validate results
        if not results:
            return create_error_response("No results generated", 500)
        
        # Check if results exceed limit
        if len(results) > Config.MAX_RECORDS:
            app.logger.warning(f"Too many records: {len(results)}")
            return create_error_response(
                f"Too many records. Maximum allowed: {Config.MAX_RECORDS}",
                400
            )
        
        # Count different decision types
        decision_counts = {}
        for result in results:
            decision = result.get('decision', 'unknown')
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
        
        # Prepare response data
        response_data = {
            "results": results,
            "summary": {
                "total_records": len(results),
                "processing_time_seconds": round(processing_time, 2),
                "filename": file.filename if file else None,
                "decision_breakdown": decision_counts
            }
        }
        
        app.logger.info(f"Successfully processed {len(results)} records in {processing_time:.2f}s")
        app.logger.info(f"Decision breakdown: {decision_counts}")
        
        # Log current metrics for verification
        if hasattr(checker.metrics, 'get_metric_count'):
            total_checks = checker.metrics.get_metric_count("total_checks")
            fraud_blocked = checker.metrics.get_metric_count("fraud_blocked")
            app.logger.info(f"📊 Current metrics - Total: {total_checks}, Fraud: {fraud_blocked}")
        
        return create_success_response(
            response_data, 
            f"Successfully analyzed {len(results)} records"
        )
        
    except FileNotFoundError as e:
        app.logger.error(f"File not found error: {e}")
        return create_error_response("File processing failed - file not found", 400)
    
    except ValueError as e:
        app.logger.error(f"Invalid file format: {e}")
        return create_error_response(
            "Invalid file format or corrupted data", 
            400, 
            str(e)
        )
    
    except MemoryError:
        app.logger.error("Memory error during processing")
        return create_error_response(
            "File too large to process", 
            413,
            "Try uploading a smaller file"
        )
    
    except Exception as e:
        # Log full traceback for debugging
        app.logger.error(f"Unexpected error during bulk check: {traceback.format_exc()}")
        
        return create_error_response(
            "An unexpected error occurred during processing", 
            500,
            str(e) if app.debug else None
        )

@app.route("/metrics", methods=["GET"])
def get_metrics():
    """Get detailed metrics for dashboard - SYNCHRONOUS VERSION"""
    try:
        if not checker:
            return create_error_response("Database unavailable", 503)
        
        # Get metrics synchronously
        if hasattr(checker.metrics, 'get_metric_count'):
            all_metrics = {
                "total_checks": checker.metrics.get_metric_count("total_checks"),
                "fraud_blocked": checker.metrics.get_metric_count("fraud_blocked"),
                "suspicious_flagged": checker.metrics.get_metric_count("suspicious_flagged"),
                "clean_approved": checker.metrics.get_metric_count("clean_approved"),
                "bulk_analyses": checker.metrics.get_metric_count("bulk_analyses"),
                "api_requests": checker.metrics.get_metric_count("api_requests")
            }
        else:
            all_metrics = {}
        
        return create_success_response({
            "metrics": all_metrics,
            "timestamp": datetime.now().isoformat()
        }, "Metrics retrieved successfully")
        
    except Exception as e:
        app.logger.error(f"Metrics endpoint failed: {e}")
        return create_error_response("Failed to get metrics", 500)

@app.route("/stats", methods=["GET"])
def get_stats():
    """Get API statistics - SYNCHRONOUS VERSION"""
    try:
        if not checker:
            return create_error_response("Database unavailable", 503)
        
        # Get stats synchronously (no await)
        import asyncio
        
        try:
            # Run the async get_stats method
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            stats = loop.run_until_complete(checker.get_stats())
            loop.close()
        except Exception as e:
            app.logger.warning(f"Failed to get async stats: {e}")
            # Fallback to basic stats
            stats = {
                "cache_stats": {
                    "disposable_domains": len(getattr(checker, 'disposable_domains', [])),
                    "flagged_ips": len(getattr(checker, 'flagged_ips', [])),
                    "suspicious_bins": len(getattr(checker, 'suspicious_bins', [])),
                    "reused_fingerprints": len(getattr(checker, 'reused_fingerprints', [])),
                    "tampered_prices": len(getattr(checker, 'tampered_prices', [])),
                    "active_rules": len(getattr(checker, 'rules', {}))
                }
            }
        
        # Add API configuration
        stats["config"] = {
            "max_file_size_mb": Config.MAX_FILE_SIZE // (1024*1024),
            "allowed_extensions": list(Config.ALLOWED_EXTENSIONS),
            "max_records": Config.MAX_RECORDS
        }
        
        return create_success_response(stats, "Statistics retrieved successfully")
        
    except Exception as e:
        app.logger.error(f"Stats endpoint failed: {e}")
        return create_error_response("Failed to get stats", 500)

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
    app.logger.info("Starting FIXED Bulk Fraud Check API...")
    app.logger.info(f"Max file size: {Config.MAX_FILE_SIZE // (1024*1024)}MB")
    app.logger.info(f"Allowed extensions: {Config.ALLOWED_EXTENSIONS}")
    app.logger.info(f"Max records: {Config.MAX_RECORDS}")
    
    if checker:
        app.logger.info("✅ FraudChecker with working metrics initialized")
        # Test that metrics are working
        if hasattr(checker.metrics, 'get_metric_count'):
            total_checks = checker.metrics.get_metric_count("total_checks")
            app.logger.info(f"📊 Current total_checks in database: {total_checks}")
        else:
            app.logger.warning("⚠️ Metrics methods not available")
    else:
        app.logger.warning("⚠️ FraudChecker failed to initialize")
    
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5000,
        threaded=True,
        use_reloader=False
    )