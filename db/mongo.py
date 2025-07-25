from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import IndexModel, ASCENDING, DESCENDING, TEXT
from dotenv import load_dotenv
import os
from datetime import datetime

class MongoManager:
    def __init__(self):
        # Load .env file from same directory
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        load_dotenv(dotenv_path=env_path)
        
        self.mongo_uri = os.getenv("MONGO_URI")
        if not self.mongo_uri:
            raise ValueError("MONGO_URI is missing in .env")
            
        self.client = AsyncIOMotorClient(self.mongo_uri)
        self.db = self.client.fraudshield
        
        # Optimized collection structure - keeping your names but removing unnecessary ones
        self.collections = {
            # Core fraud detection (consolidated blacklists into one efficient collection)
            "fraud_blacklist": self.db.fraud_blacklist,  # Replaces disposable_emails, suspicious_bins, flagged_ips, etc.
            
            # Transaction analysis
            "transactions": self.db.transactions,  # Main transaction logs with fraud results
            
            # Rules engine
            "rules": self.db[os.getenv("RULES_COLLECTION", "rules")],
            
            # User management
            "users": self.db[os.getenv("USERS_COLLECTION", "users")],
            "sites": self.db[os.getenv("SITES_COLLECTION", "sites")],
            
            # Analytics and monitoring
            "metrics": self.db[os.getenv("METRICS_COLLECTION", "metrics")],
            "audit_logs": self.db.audit_logs,  # System events, errors, admin actions
        }
        
        # Remove these unnecessary collections from your original structure:
        # - disposable_emails (moved to fraud_blacklist)
        # - suspicious_bins (moved to fraud_blacklist) 
        # - flagged_ips (moved to fraud_blacklist)
        # - reused_fingerprints (moved to fraud_blacklist)
        # - tampered_prices (moved to fraud_blacklist)
        # - logs (replaced with transactions + audit_logs)
        # - api_logs (merged into transactions)

    def get_collection(self, name: str):
        if name not in self.collections:
            raise ValueError(f"Collection '{name}' is not defined in MongoManager.")
        return self.collections[name]
    
    async def setup_indexes(self):
        """Setup efficient indexes for better performance"""
        
        # Fraud blacklist indexes
        fraud_blacklist = self.collections["fraud_blacklist"]
        await fraud_blacklist.create_indexes([
            IndexModel([("type", ASCENDING), ("value", ASCENDING)], unique=True),
            IndexModel([("type", ASCENDING)]),
            IndexModel([("risk_score", DESCENDING)]),
            IndexModel([("created_at", DESCENDING)])
        ])
        
        # Transactions indexes
        transactions = self.collections["transactions"]
        await transactions.create_indexes([
            IndexModel([("email", ASCENDING)]),
            IndexModel([("device_fingerprint", ASCENDING)]),
            IndexModel([("card_bin", ASCENDING)]),
            IndexModel([("ip_address", ASCENDING)]),
            IndexModel([("timestamp", DESCENDING)]),
            IndexModel([("fraud_score", DESCENDING)]),
            IndexModel([("decision", ASCENDING)]),
            IndexModel([("api_key", ASCENDING), ("timestamp", DESCENDING)]),
            # Compound indexes for common queries
            IndexModel([("email", ASCENDING), ("timestamp", DESCENDING)]),
            IndexModel([("device_fingerprint", ASCENDING), ("timestamp", DESCENDING)])
        ])
        
        # Users indexes
        users = self.collections["users"]
        await users.create_indexes([
            IndexModel([("email", ASCENDING)], unique=True),
            IndexModel([("api_key", ASCENDING)], unique=True)
        ])
        
        # Rules indexes
        rules = self.collections["rules"]
        await rules.create_indexes([
            IndexModel([("rule_key", ASCENDING)], unique=True),
            IndexModel([("enabled", ASCENDING)]),
            IndexModel([("category", ASCENDING)]),
            IndexModel([("weight", DESCENDING)])
        ])
        
        print("✅ All indexes created successfully")

    async def cleanup_old_collections(self):
        """Remove old unnecessary collections"""
        old_collections = [
            "disposable_emails", "suspicious_bins", "flagged_ips", 
            "reused_fingerprints", "tampered_prices", "logs", "api_logs"
        ]
        
        for collection_name in old_collections:
            try:
                await self.db.drop_collection(collection_name)
                print(f"🗑️ Dropped old collection: {collection_name}")
            except Exception as e:
                print(f"⚠️ Could not drop {collection_name}: {e}")

    async def migrate_data(self):
        """Migrate data from old structure to new optimized structure"""
        await self._migrate_blacklist_data()
        await self._migrate_log_data()
        print("✅ Data migration completed")

    async def _migrate_blacklist_data(self):
        """Migrate all blacklist data into fraud_blacklist collection"""
        fraud_blacklist = self.collections["fraud_blacklist"]
        
        # Migration mappings
        migrations = [
            ("disposable_emails", "disposable_email", "domain"),
            ("suspicious_bins", "suspicious_bin", "bin"),
            ("flagged_ips", "flagged_ip", "ip"),
            ("reused_fingerprints", "reused_fingerprint", "fingerprint"),
            ("tampered_prices", "tampered_price", "price")
        ]
        
        for old_collection, fraud_type, field in migrations:
            if old_collection in await self.db.list_collection_names():
                old_col = self.db[old_collection]
                
                async for doc in old_col.find():
                    new_doc = {
                        "type": fraud_type,
                        "value": str(doc[field]),
                        "risk_score": 0.8,  # Default risk score
                        "created_at": doc.get("created_at", datetime.now()),
                        "source": "migration",
                        "metadata": {}
                    }
                    
                    # Upsert to avoid duplicates
                    await fraud_blacklist.update_one(
                        {"type": fraud_type, "value": str(doc[field])},
                        {"$setOnInsert": new_doc},
                        upsert=True
                    )
                
                print(f"✅ Migrated {old_collection} to fraud_blacklist")

    async def _migrate_log_data(self):
        """Migrate logs to optimized structure"""
        if "logs" in await self.db.list_collection_names():
            logs = self.db["logs"]
            transactions = self.collections["transactions"]
            audit_logs = self.collections["audit_logs"]
            
            async for log in logs.find():
                action = log.get("action", "")
                
                if action == "fraud_check":
                    # Move fraud checks to transactions
                    transaction_doc = {
                        "transaction_id": log.get("_id"),
                        "timestamp": log.get("timestamp", datetime.now()),
                        "api_key": log.get("api_key"),
                        "email": log.get("email"),
                        "amount": log.get("amount"),
                        "device_fingerprint": log.get("device_fingerprint"),
                        "ip_address": log.get("ip_address"),
                        "fraud_score": log.get("fraud_score", 0),
                        "decision": log.get("decision", "unknown"),
                        "reasons": log.get("reasons", []),
                        "raw_data": log.get("raw_data", {})
                    }
                    await transactions.insert_one(transaction_doc)
                else:
                    # Move other logs to audit_logs
                    audit_doc = {
                        "timestamp": log.get("timestamp", datetime.now()),
                        "action": action,
                        "user": log.get("user"),
                        "details": log.get("details", {}),
                        "ip_address": log.get("ip_address"),
                        "log_level": log.get("log_level", "info")
                    }
                    await audit_logs.insert_one(audit_doc)
            
            print("✅ Migrated logs to transactions and audit_logs")