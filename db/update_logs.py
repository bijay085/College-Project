# update_logs.py
import pymongo
from datetime import datetime

def update_existing_logs():
    client = pymongo.MongoClient("mongodb://localhost:27017")
    db = client.fraudshield
    logs_collection = db.logs
    
    # Update existing logs without log_level
    logs_without_level = logs_collection.find({"log_level": {"$exists": False}})
    
    for log in logs_without_level:
        log_level = "info"  # default
        
        # Determine log level based on existing data
        if log.get("decision") == "fraud":
            log_level = "fraud"
        elif log.get("decision") == "suspicious":
            log_level = "warning"
        elif "error" in log.get("action", "").lower():
            log_level = "error"
        elif log.get("action") in ["login", "register", "logout", "auth_attempt"]:
            log_level = "info"
        elif log.get("action") in ["fraud_check", "bulk_analysis"]:
            # For fraud checks, determine level by decision
            if log.get("decision") == "fraud":
                log_level = "fraud"
            elif log.get("decision") == "suspicious":
                log_level = "warning"
            else:
                log_level = "info"  # Clean transactions
        
        # Update the log
        logs_collection.update_one(
            {"_id": log["_id"]},
            {"$set": {"log_level": log_level}}
        )
        print(f"Updated log {log['_id']} - Action: {log.get('action')}, Decision: {log.get('decision')}, Level: {log_level}")
    
    print("✅ All existing logs updated with log_level field")

if __name__ == "__main__":
    update_existing_logs()