import asyncio
from datetime import datetime
from mongo import MongoManager

class BlacklistSeeder:
    def __init__(self):
        self.mongo = MongoManager()
        
        # Optimized data structure - consolidate all blacklist data into one collection
        self.fraud_data = {
            # Consolidated fraud patterns (replaces 5 separate collections)
            "fraud_blacklist": [
                # Disposable emails
                {"type": "disposable_email", "value": "tempmail.com", "risk_score": 0.9, "source": "seed"},
                {"type": "disposable_email", "value": "mailinator.com", "risk_score": 0.9, "source": "seed"},
                {"type": "disposable_email", "value": "10minutemail.com", "risk_score": 0.9, "source": "seed"},
                {"type": "disposable_email", "value": "guerrillamail.com", "risk_score": 0.8, "source": "seed"},
                
                # Suspicious card BINs
                {"type": "suspicious_bin", "value": "123456", "risk_score": 0.95, "source": "seed"},
                {"type": "suspicious_bin", "value": "411111", "risk_score": 0.85, "source": "seed"},
                {"type": "suspicious_bin", "value": "999999", "risk_score": 0.95, "source": "seed"},
                {"type": "suspicious_bin", "value": "555555", "risk_score": 0.8, "source": "seed"},
                
                # Flagged IPs
                {"type": "flagged_ip", "value": "203.0.113.45", "risk_score": 0.9, "source": "seed"},
                {"type": "flagged_ip", "value": "198.51.100.22", "risk_score": 0.85, "source": "seed"},
                {"type": "flagged_ip", "value": "172.16.0.9", "risk_score": 0.7, "source": "seed"},
                {"type": "flagged_ip", "value": "10.0.0.1", "risk_score": 0.6, "source": "seed"},
                
                # Reused fingerprints
                {"type": "reused_fingerprint", "value": "fp_abc123", "risk_score": 0.8, "source": "seed"},
                {"type": "reused_fingerprint", "value": "fp_xyz789", "risk_score": 0.8, "source": "seed"},
                {"type": "reused_fingerprint", "value": "fp_repeat_777", "risk_score": 0.9, "source": "seed"},
                
                # Tampered prices
                {"type": "tampered_price", "value": "0.01", "risk_score": 0.95, "source": "seed"},
                {"type": "tampered_price", "value": "0.99", "risk_score": 0.7, "source": "seed"},
                {"type": "tampered_price", "value": "9999.99", "risk_score": 0.8, "source": "seed"},
                {"type": "tampered_price", "value": "1.00", "risk_score": 0.6, "source": "seed"},
            ],
            
            # User authentication data (keep existing structure but optimize)
            "users": [
                {
                    "email": "admin@fraudshield.com",
                    "name": "Admin",
                    "company": "FraudShield",
                    "password_hash": "$2b$12$hashed_admin_password",  # Use proper bcrypt
                    "role": "admin",
                    "api_key": "fsk_admin_test_key_123",
                    "created_at": datetime.now(),
                    "last_login": None,
                    "status": "active",
                    "permissions": ["read", "write", "admin"]
                },
                {
                    "email": "user@example.com", 
                    "name": "Test User",
                    "company": "Example Corp",
                    "password_hash": "$2b$12$hashed_user_password",  # Use proper bcrypt
                    "role": "user",
                    "api_key": "fsk_user_test_key_456",
                    "created_at": datetime.now(),
                    "last_login": None,
                    "status": "active",
                    "permissions": ["read", "write"]
                }
            ],
            
            "sites": [
                {
                    "user_email": "admin@fraudshield.com",  # Reference by email instead of user_id
                    "api_key": "fsk_admin_test_key_123",
                    "site_name": "FraudShield Admin",
                    "domain": "fraudshield.com",
                    "created_at": datetime.now(),
                    "status": "active",
                    "settings": {
                        "fraud_threshold": 0.7,
                        "auto_block": True,
                        "notification_email": "admin@fraudshield.com"
                    }
                },
                {
                    "user_email": "user@example.com",
                    "api_key": "fsk_user_test_key_456", 
                    "site_name": "Example Website",
                    "domain": "example.com",
                    "created_at": datetime.now(),
                    "status": "active",
                    "settings": {
                        "fraud_threshold": 0.8,
                        "auto_block": False,
                        "notification_email": "user@example.com"
                    }
                }
            ]
        }

    async def run(self):
        """Seed optimized database structure"""
        created = []
        inserted = []

        # Setup indexes first
        await self.mongo.setup_indexes()
        
        # Add created_at and metadata to fraud_blacklist items
        for item in self.fraud_data["fraud_blacklist"]:
            item["created_at"] = datetime.now()
            item["metadata"] = {"seeded": True}

        # Insert data into collections
        for collection_name, docs in self.fraud_data.items():
            col = self.mongo.get_collection(collection_name)
            count = await col.count_documents({})
            
            if count == 0:
                # Use upsert for fraud_blacklist to avoid duplicates
                if collection_name == "fraud_blacklist":
                    for doc in docs:
                        await col.update_one(
                            {"type": doc["type"], "value": doc["value"]},
                            {"$setOnInsert": doc},
                            upsert=True
                        )
                else:
                    await col.insert_many(docs)
                
                inserted.append(collection_name)
            
            created.append(collection_name)

        print(f"✅ Created optimized collections: {', '.join(created)}")
        if inserted:
            print(f"🟢 Inserted seed data into: {', '.join(inserted)}")
            print(f"📊 Fraud patterns seeded: {len(self.fraud_data['fraud_blacklist'])}")
        else:
            print("🟡 Data already exists, nothing inserted.")

        # Show collection statistics
        await self.show_stats()

    async def show_stats(self):
        """Show statistics for each collection"""
        print("\n📊 Collection Statistics:")
        print("-" * 50)
        
        # Fraud blacklist stats
        fraud_col = self.mongo.get_collection("fraud_blacklist")
        pipeline = [
            {"$group": {"_id": "$type", "count": {"$sum": 1}, "avg_risk": {"$avg": "$risk_score"}}},
            {"$sort": {"count": -1}}
        ]
        
        async for stat in fraud_col.aggregate(pipeline):
            print(f"{stat['_id']:20} | Count: {stat['count']:3} | Avg Risk: {stat['avg_risk']:.2f}")
        
        # Other collections
        for name in ["users", "sites"]:
            col = self.mongo.get_collection(name)
            count = await col.count_documents({})
            print(f"{name:20} | Count: {count:3}")
        print("-" * 50)

    async def migrate_from_old_structure(self):
        """Migrate data from old structure if it exists"""
        print("🔄 Checking for old data to migrate...")
        await self.mongo.migrate_data()
        
        # Clean up old collections after migration
        confirm = input("⚠️ Delete old collections after migration? (y/N): ")
        if confirm.lower() == 'y':
            await self.mongo.cleanup_old_collections()
            print("🧹 Old collections cleaned up")

if __name__ == "__main__":
    import sys
    
    seeder = BlacklistSeeder()
    
    if len(sys.argv) > 1 and sys.argv[1] == "migrate":
        # Run migration from old structure
        asyncio.run(seeder.migrate_from_old_structure())
    else:
        # Run normal seeding
        asyncio.run(seeder.run())