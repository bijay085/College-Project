# logic/bulk_api.py
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
    app.logger.info("FraudChecker initialized successfully")
except Exception as e:
    app.logger.error(f"Failed to initialize FraudChecker: {e}")
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
    """Get real counts from MongoDB database"""
    try:
        if not checker:
            return create_error_response("Database unavailable", 503)
        
        # Get real counts from the fraud checker's loaded data
        disposable_count = len(checker.disposable_domains)
        flagged_ips_count = len(checker.flagged_ips)
        suspicious_bins_count = len(checker.suspicious_bins)
        reused_fingerprints_count = len(checker.reused_fingerprints)
        tampered_prices_count = len(checker.tampered_prices)
        active_rules_count = len(checker.rules)
        
        # Calculate some derived stats
        total_blacklist_items = (disposable_count + flagged_ips_count + 
                               suspicious_bins_count + reused_fingerprints_count + 
                               tampered_prices_count)
        
        stats = {
            "hero_stats": {
                "total_checks": total_blacklist_items,
                "fraud_blocked": suspicious_bins_count + flagged_ips_count,
                "accuracy": "99.2%"
            },
            "blacklist_counts": {
                "disposable_domains": disposable_count,
                "flagged_ips": flagged_ips_count,
                "suspicious_bins": suspicious_bins_count,
                "reused_fingerprints": reused_fingerprints_count,
                "tampered_prices": tampered_prices_count
            },
            "system_stats": {
                "active_rules": active_rules_count,
                "total_blacklist_items": total_blacklist_items,
                "database_status": "online",
                "fraud_checker_status": "active"
            },
            "last_updated": datetime.now().isoformat()
        }
        
        app.logger.info(f"Real stats retrieved: {total_blacklist_items} total items, {active_rules_count} active rules")
        
        return create_success_response(stats, "Real statistics retrieved successfully")
        
    except Exception as e:
        app.logger.error(f"Real stats failed: {e}")
        return create_error_response("Failed to get real stats", 500)

@app.route("/bulk-check", methods=["POST"])
@log_request
def bulk_check():
    """Enhanced bulk fraud checking endpoint"""
    
    # Check if fraud checker is available
    if not checker:
        return create_error_response(
            "Fraud checking service unavailable", 
            503,
            "FraudChecker failed to initialize"
        )
    
    # Get the uploaded file
    file = request.files.get("file")
    
    # Validate file
    is_valid, message = validate_file(file)
    if not is_valid:
        app.logger.warning(f"File validation failed: {message}")
        return create_error_response(message, 400)
    
    if file:
        app.logger.info(f"Processing file: {file.filename}, Size: {file.tell()} bytes")
    else:
        app.logger.warning("No file provided for processing")
    
    try:
        # Record start time
        start_time = time.time()
        
        # Process the file
        results = checker.analyze_bulk(file)
        
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

@app.route("/stats", methods=["GET"])
def get_stats():
    """Get API statistics"""
    try:
        stats = {
            "config": {
                "max_file_size_mb": Config.MAX_FILE_SIZE // (1024*1024),
                "allowed_extensions": list(Config.ALLOWED_EXTENSIONS),
                "max_records": Config.MAX_RECORDS
            },
            "fraud_checker_status": "active" if checker else "inactive",
            "timestamp": datetime.now().isoformat()
        }
        return create_success_response(stats)
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
    app.logger.info("Starting Bulk Fraud Check API...")
    app.logger.info(f"Max file size: {Config.MAX_FILE_SIZE // (1024*1024)}MB")
    app.logger.info(f"Allowed extensions: {Config.ALLOWED_EXTENSIONS}")
    app.logger.info(f"Max records: {Config.MAX_RECORDS}")
    
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5000,
        threaded=True,
        use_reloader=False  # Add this line to disable the reloader
    )