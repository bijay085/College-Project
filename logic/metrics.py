# Example usage of the metrics collection
import asyncio
from datetime import datetime
from mongo import MongoManager

async def initialize_metrics_collection():
    """Initialize the metrics collection with default counters"""
    mongo = MongoManager()
    metrics_collection = mongo.get_collection("metrics")
    
    # Initialize default counters if they don't exist
    default_metrics = [
        {
            "_id": "total_fraud_checks",
            "count": 0,
            "description": "Total number of fraud checks performed",
            "created_at": datetime.now(),
            "last_updated": datetime.now()
        },
        {
            "_id": "fraud_detected",
            "count": 0,
            "description": "Total number of fraud cases detected",
            "created_at": datetime.now(),
            "last_updated": datetime.now()
        },
        {
            "_id": "api_requests_today",
            "count": 0,
            "description": "API requests made today",
            "created_at": datetime.now(),
            "last_updated": datetime.now(),
            "reset_daily": True
        },
        {
            "_id": "active_users",
            "count": 0,
            "description": "Number of active users",
            "created_at": datetime.now(),
            "last_updated": datetime.now()
        },
        {
            "_id": "bulk_analyses",
            "count": 0,
            "description": "Total bulk analyses performed",
            "created_at": datetime.now(),
            "last_updated": datetime.now()
        }
    ]
    
    for metric in default_metrics:
        # Use upsert to avoid duplicates
        await metrics_collection.update_one(
            {"_id": metric["_id"]},
            {"$setOnInsert": metric},
            upsert=True
        )
    
    print("✅ Metrics collection initialized with default counters")

async def increment_metric(metric_id: str, increment: int = 1):
    """Increment a specific metric"""
    mongo = MongoManager()
    metrics_collection = mongo.get_collection("metrics")
    
    result = await metrics_collection.update_one(
        {"_id": metric_id},
        {
            "$inc": {"count": increment},
            "$set": {"last_updated": datetime.now()}
        },
        upsert=True
    )
    
    return result.modified_count > 0 or result.upserted_id is not None

async def get_metric(metric_id: str):
    """Get the current value of a metric"""
    mongo = MongoManager()
    metrics_collection = mongo.get_collection("metrics")
    
    metric = await metrics_collection.find_one({"_id": metric_id})
    return metric["count"] if metric else 0

async def get_all_metrics():
    """Get all metrics as a dictionary"""
    mongo = MongoManager()
    metrics_collection = mongo.get_collection("metrics")
    
    metrics = {}
    async for doc in metrics_collection.find():
        metrics[doc["_id"]] = {
            "count": doc["count"],
            "description": doc.get("description", ""),
            "last_updated": doc.get("last_updated")
        }
    
    return metrics

async def reset_daily_metrics():
    """Reset metrics marked for daily reset"""
    mongo = MongoManager()
    metrics_collection = mongo.get_collection("metrics")
    
    result = await metrics_collection.update_many(
        {"reset_daily": True},
        {
            "$set": {
                "count": 0,
                "last_updated": datetime.now()
            }
        }
    )
    
    print(f"✅ Reset {result.modified_count} daily metrics")

# Usage examples in your fraud detection code:

async def example_fraud_check_usage():
    """Example of how to use metrics in fraud detection"""
    
    # When performing a fraud check
    await increment_metric("total_fraud_checks")
    await increment_metric("api_requests_today")
    
    # If fraud is detected
    fraud_detected = True  # Your fraud detection logic here
    if fraud_detected:
        await increment_metric("fraud_detected")
    
    # Get current stats
    total_checks = await get_metric("total_fraud_checks")
    fraud_count = await get_metric("fraud_detected")
    
    print(f"Total fraud checks: {total_checks}")
    print(f"Fraud detected: {fraud_count}")
    
    # Calculate fraud rate
    fraud_rate = (fraud_count / total_checks * 100) if total_checks > 0 else 0
    print(f"Fraud detection rate: {fraud_rate:.2f}%")

# Integration with your existing fraud checker:

class EnhancedFraudChecker:
    def __init__(self):
        self.mongo = MongoManager()
        # ... existing initialization
    
    async def analyze_transaction(self, transaction_data):
        # Increment metric for each analysis
        await increment_metric("total_fraud_checks")
        
        # Your existing fraud analysis logic
        result = self.perform_fraud_analysis(transaction_data)
        
        # Track fraud detection
        if result.get("is_fraud"):
            await increment_metric("fraud_detected")
        
        return result

    def perform_fraud_analysis(self, transaction_data):
        """
        Dummy fraud analysis logic.
        Replace this with your actual fraud detection implementation.
        """
        # Example: Mark as fraud if amount > 1000
        is_fraud = transaction_data.get("amount", 0) > 1000
        return {"is_fraud": is_fraud}
    
    async def bulk_analyze(self, transactions):
        # Increment bulk analysis metric
        await increment_metric("bulk_analyses")
        
        # Your existing bulk analysis logic
        results = []
        for transaction in transactions:
            result = await self.analyze_transaction(transaction)
            results.append(result)
        
        return results

# API endpoint to get statistics:
async def get_fraud_stats():
    """Get fraud detection statistics for dashboard"""
    metrics = await get_all_metrics()
    
    stats = {
        "total_checks": metrics.get("total_fraud_checks", {}).get("count", 0),
        "fraud_detected": metrics.get("fraud_detected", {}).get("count", 0),
        "api_requests_today": metrics.get("api_requests_today", {}).get("count", 0),
        "active_users": metrics.get("active_users", {}).get("count", 0),
        "bulk_analyses": metrics.get("bulk_analyses", {}).get("count", 0)
    }
    
    # Calculate derived stats
    if stats["total_checks"] > 0:
        stats["fraud_rate"] = round(stats["fraud_detected"] / stats["total_checks"] * 100, 2)
    else:
        stats["fraud_rate"] = 0
    
    return stats

# Run initialization
if __name__ == "__main__":
    asyncio.run(initialize_metrics_collection())