# db/init_metrics.py
import asyncio
from datetime import datetime
from mongo import MongoManager

async def initialize_metrics():
    """Initialize the metrics collection with default counters"""
    try:
        mongo = MongoManager()
        metrics_collection = mongo.get_collection("metrics")
        # Force collection creation if it doesn't exist
        # --- DEBUG: Print database and collection info ---
        print("MongoManager DB:", getattr(mongo, "db", None))
        print("Collection object:", metrics_collection)
        print("Collection name:", getattr(metrics_collection, "name", None))
        # --- END DEBUG ---

        await metrics_collection.insert_one({"_id": "__init__", "dummy": True})
        await metrics_collection.delete_one({"_id": "__init__"})
        
        # Default metrics to track
        default_metrics = [
            {
                "_id": "total_checks",
                "count": 0,
                "description": "Total number of fraud checks performed",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "fraud_blocked",
                "count": 0,
                "description": "Number of transactions blocked as fraud",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "suspicious_flagged",
                "count": 0,
                "description": "Number of transactions flagged as suspicious",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "clean_approved",
                "count": 0,
                "description": "Number of transactions approved as clean",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "bulk_analyses",
                "count": 0,
                "description": "Number of bulk analysis operations performed",
                "created_at": datetime.now(),
                "last_updated": datetime.now()
            },
            {
                "_id": "api_requests",
                "count": 0,
                "description": "Total API requests processed",
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
        
        # Show current metrics
        print("✅ Metrics collection initialized with default counters")
        print("\n📊 Current Metrics:")
        
        async for doc in metrics_collection.find():
            print(f"  {doc['_id']}: {doc.get('count', 0)} - {doc.get('description', 'No description')}")
        
        print(f"\n🕒 Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except Exception as e:
        print(f"❌ Failed to initialize metrics: {e}")

async def reset_metrics():
    """Reset all metrics to zero (use with caution!)"""
    try:
        mongo = MongoManager()
        metrics_collection = mongo.get_collection("metrics")
        
        result = await metrics_collection.update_many(
            {},
            {
                "$set": {
                    "count": 0,
                    "last_updated": datetime.now()
                }
            }
        )
        
        print(f"✅ Reset {result.modified_count} metrics to zero")
        
    except Exception as e:
        print(f"❌ Failed to reset metrics: {e}")

async def show_metrics():
    """Display current metrics"""
    try:
        mongo = MongoManager()
        metrics_collection = mongo.get_collection("metrics")
        
        print("📊 Current Fraud Detection Metrics:")
        print("=" * 50)
        
        total_checks = 0
        
        async for doc in metrics_collection.find():
            count = doc.get('count', 0)
            description = doc.get('description', 'No description')
            last_updated = doc.get('last_updated', 'Never')
            
            print(f"{doc['_id']:20} | {count:>8,} | {description}")
            
            if doc['_id'] == 'total_checks':
                total_checks = count
        
        print("=" * 50)
        
        # Calculate derived stats
        fraud_blocked = await get_metric_value(metrics_collection, "fraud_blocked")
        suspicious = await get_metric_value(metrics_collection, "suspicious_flagged")
        clean = await get_metric_value(metrics_collection, "clean_approved")
        
        if total_checks > 0:
            fraud_rate = (fraud_blocked / total_checks) * 100
            suspicious_rate = (suspicious / total_checks) * 100
            clean_rate = (clean / total_checks) * 100
            
            print(f"\n📈 Analysis:")
            print(f"  Fraud Rate:      {fraud_rate:.1f}%")
            print(f"  Suspicious Rate: {suspicious_rate:.1f}%")
            print(f"  Clean Rate:      {clean_rate:.1f}%")
        
        print(f"\n🕒 Last checked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except Exception as e:
        print(f"❌ Failed to show metrics: {e}")

async def get_metric_value(collection, metric_id):
    """Get the value of a specific metric"""
    try:
        doc = await collection.find_one({"_id": metric_id})
        return doc.get('count', 0) if doc else 0
    except:
        return 0

async def main():
    """Main function to handle command line arguments"""
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "init":
            await initialize_metrics()
        elif command == "reset":
            confirm = input("⚠️  Are you sure you want to reset ALL metrics to zero? (yes/no): ")
            if confirm.lower() == "yes":
                await reset_metrics()
            else:
                print("❌ Reset cancelled")
        elif command == "show":
            await show_metrics()
        else:
            print("❌ Unknown command. Use: init, reset, or show")
    else:
        print("📊 FraudShield Metrics Manager")
        print("Usage:")
        print("  python init_metrics.py init  - Initialize metrics collection")
        print("  python init_metrics.py show  - Show current metrics")
        print("  python init_metrics.py reset - Reset all metrics to zero")

if __name__ == "__main__":
    import sys
    # Print sys.argv for debugging
    print("DEBUG: sys.argv =", sys.argv)
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "init":
            asyncio.run(initialize_metrics())
        elif command == "reset":
            confirm = input("⚠️  Are you sure you want to reset ALL metrics to zero? (yes/no): ")
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