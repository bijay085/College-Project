import asyncio
from datetime import datetime, timedelta
from mongo import MongoManager

async def initialize_metrics():
    """Initialize the metrics collection with optimized counters"""
    try:
        mongo = MongoManager()
        metrics_collection = mongo.get_collection("metrics")
        
        # Force collection creation if it doesn't exist
        await metrics_collection.insert_one({"_id": "__init__", "dummy": True})
        await metrics_collection.delete_one({"_id": "__init__"})
        
        # Optimized metrics structure (reduced and more meaningful)
        default_metrics = [
            # Core fraud metrics
            {
                "_id": "total_transactions",
                "count": 0,
                "description": "Total transactions processed",
                "category": "core",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "fraud_blocked",
                "count": 0,
                "description": "Transactions blocked as fraud",
                "category": "core",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "suspicious_flagged",
                "count": 0,
                "description": "Transactions flagged as suspicious",
                "category": "core",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "clean_approved",
                "count": 0,
                "description": "Clean transactions approved",
                "category": "core",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            
            # Performance metrics
            {
                "_id": "avg_processing_time",
                "value": 0.0,
                "description": "Average processing time (seconds)",
                "category": "performance",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "api_requests_today",
                "count": 0,
                "description": "API requests today",
                "category": "usage",
                "created_at": datetime.now(),
                "last_updated": datetime.now(),
                "expires_at": datetime.now() + timedelta(days=1)  # Auto-reset daily
            },
            
            # Detection accuracy
            {
                "_id": "detection_accuracy",
                "value": 0.0,
                "description": "Fraud detection accuracy percentage",
                "category": "accuracy",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "false_positives",
                "count": 0,
                "description": "False positive detections",
                "category": "accuracy",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            
            # System health
            {
                "_id": "system_errors",
                "count": 0,
                "description": "System errors in last 24h",
                "category": "health",
                "created_at": datetime.now(),
                "last_updated": datetime.now(),
                "expires_at": datetime.now() + timedelta(days=1)
            },
            
            # Business metrics
            {
                "_id": "total_amount_protected",
                "value": 0.0,
                "description": "Total transaction amount protected (USD)",
                "category": "business",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            }
        ]
        
        # Insert metrics using upsert to avoid duplicates
        for metric in default_metrics:
            await metrics_collection.update_one(
                {"_id": metric["_id"]},
                {"$setOnInsert": metric},
                upsert=True
            )
        
        # Create indexes for better performance
        await metrics_collection.create_index("category")
        await metrics_collection.create_index("last_updated")
        await metrics_collection.create_index("expires_at")  # For TTL
        
        print("✅ Metrics collection initialized with optimized counters")
        await show_metrics_summary()
        
    except Exception as e:
        print(f"❌ Failed to initialize metrics: {e}")

async def show_metrics():
    """Display current metrics in organized format"""
    try:
        mongo = MongoManager()
        metrics_collection = mongo.get_collection("metrics")
        
        print("\n📊 FraudShield Metrics Dashboard")
        print("=" * 70)
        
        # Group metrics by category
        categories = {}
        async for metric in metrics_collection.find():
            category = metric.get('category', 'other')
            if category not in categories:
                categories[category] = []
            categories[category].append(metric)
        
        # Display by category
        for category, metrics in categories.items():
            print(f"\n🔶 {category.upper()} METRICS")
            print("-" * 50)
            
            for metric in metrics:
                name = metric['_id'].replace('_', ' ').title()
                if 'count' in metric:
                    value = f"{metric['count']:,}"
                elif 'value' in metric:
                    value = f"{metric['value']:,.2f}"
                else:
                    value = "N/A"
                
                print(f"{name:30} | {value:>12}")
        
        print("=" * 70)
        
        # Calculate and show derived metrics
        await show_derived_metrics(metrics_collection)
        
    except Exception as e:
        print(f"❌ Failed to show metrics: {e}")

async def show_derived_metrics(collection):
    """Show calculated metrics like fraud rate, etc."""
    try:
        total = await get_metric_value(collection, "total_transactions")
        fraud = await get_metric_value(collection, "fraud_blocked")
        suspicious = await get_metric_value(collection, "suspicious_flagged")
        clean = await get_metric_value(collection, "clean_approved")
        
        if total > 0:
            print(f"\n📈 CALCULATED METRICS")
            print("-" * 50)
            print(f"{'Fraud Rate':30} | {(fraud/total*100):>8.1f}%")
            print(f"{'Suspicious Rate':30} | {(suspicious/total*100):>8.1f}%")
            print(f"{'Clean Rate':30} | {(clean/total*100):>8.1f}%")
            
            # Effectiveness score
            effectiveness = ((fraud + suspicious) / total) * 100 if total > 0 else 0
            print(f"{'Detection Effectiveness':30} | {effectiveness:>8.1f}%")
        
        print(f"\n🕒 Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except Exception as e:
        print(f"⚠️ Could not calculate derived metrics: {e}")

async def show_metrics_summary():
    """Quick summary of key metrics"""
    try:
        mongo = MongoManager()
        metrics_collection = mongo.get_collection("metrics")
        
        total = await get_metric_value(metrics_collection, "total_transactions")
        fraud = await get_metric_value(metrics_collection, "fraud_blocked")
        
        print(f"\n📊 Quick Summary:")
        print(f"   Total Transactions: {total:,}")
        print(f"   Fraud Blocked: {fraud:,}")
        if total > 0:
            print(f"   Fraud Rate: {(fraud/total*100):.1f}%")
        
    except Exception as e:
        print(f"⚠️ Could not show summary: {e}")

async def reset_metrics():
    """Reset metrics (with confirmation)"""
    try:
        mongo = MongoManager()
        metrics_collection = mongo.get_collection("metrics")
        
        # Reset counts but preserve structure
        result = await metrics_collection.update_many(
            {"count": {"$exists": True}},
            {
                "$set": {
                    "count": 0,
                    "last_updated": datetime.now()
                }
            }
        )
        
        # Reset values
        await metrics_collection.update_many(
            {"value": {"$exists": True}},
            {
                "$set": {
                    "value": 0.0,
                    "last_updated": datetime.now()
                }
            }
        )
        
        print(f"✅ Reset {result.modified_count} metrics")
        
    except Exception as e:
        print(f"❌ Failed to reset metrics: {e}")

async def get_metric_value(collection, metric_id):
    """Get the value of a specific metric"""
    try:
        doc = await collection.find_one({"_id": metric_id})
        if doc:
            return doc.get('count', doc.get('value', 0))
        return 0
    except:
        return 0

async def update_metric(metric_id, increment=1, value=None):
    """Update a specific metric"""
    try:
        mongo = MongoManager()
        metrics_collection = mongo.get_collection("metrics")
        
        if value is not None:
            # Set specific value
            await metrics_collection.update_one(
                {"_id": metric_id},
                {
                    "$set": {
                        "value": value,
                        "last_updated": datetime.now()
                    }
                }
            )
        else:
            # Increment count
            await metrics_collection.update_one(
                {"_id": metric_id},
                {
                    "$inc": {"count": increment},
                    "$set": {"last_updated": datetime.now()}
                }
            )
        
        print(f"✅ Updated metric: {metric_id}")
        
    except Exception as e:
        print(f"❌ Failed to update metric {metric_id}: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "init":
            asyncio.run(initialize_metrics())
        elif command == "reset":
            confirm = input("⚠️ Are you sure you want to reset ALL metrics to zero? (yes/no): ")
            if confirm.lower() == "yes":
                asyncio.run(reset_metrics())
            else:
                print("❌ Reset cancelled")
        elif command == "show":
            asyncio.run(show_metrics())
        else:
            print("❌ Unknown command. Use: init, reset, or show")
    else:
        print("📊 FraudShield Metrics Manager")
        print("Usage:")
        print("  python init_metrics.py init  - Initialize metrics collection")
        print("  python init_metrics.py show  - Show current metrics")
        print("  python init_metrics.py reset - Reset all metrics to zero")