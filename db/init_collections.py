import asyncio
from datetime import datetime
from mongo import MongoManager

class BlacklistSeeder:
    def __init__(self):
        self.mongo = MongoManager()
        self.fake_data = {
            "disposable_emails": [
                {"domain": "tempmail.com"},
                {"domain": "mailinator.com"},
                {"domain": "10minutemail.com"},
            ],
            "suspicious_bins": [
                {"bin": "123456"},
                {"bin": "411111"},
                {"bin": "999999"},
            ],
            "flagged_ips": [
                {"ip": "203.0.113.45"},
                {"ip": "198.51.100.22"},
                {"ip": "172.16.0.9"},
            ],
            "reused_fingerprints": [
                {"fingerprint": "fp_abc123"},
                {"fingerprint": "fp_xyz789"},
                {"fingerprint": "fp_repeat_777"},
            ],
            "tampered_prices": [
                {"price": 0.01},
                {"price": 0.99},
                {"price": 9999.99},
            ],
            
            # NEW - User authentication collections
            "users": [
                {
                    "email": "admin@fraudshield.com",
                    "name": "Admin",
                    "company": "FraudShield",
                    "password_hash": "admin123",  # Will be hashed in real app
                    "role": "admin",
                    "api_key": "fsk_admin_test_key_123",
                    "created_at": datetime.now(),
                    "last_login": None
                },
                {
                    "email": "user@example.com", 
                    "name": "Test User",
                    "company": "Example Corp",
                    "password_hash": "user123",  # Will be hashed in real app
                    "role": "user",
                    "api_key": "fsk_user_test_key_456",
                    "created_at": datetime.now(),
                    "last_login": None
                }
            ],
            "sites": [
                {
                    "user_id": "admin",
                    "api_key": "fsk_admin_test_key_123",
                    "site_name": "FraudShield Admin",
                    "domain": "fraudshield.com",
                    "created_at": datetime.now(),
                    "status": "active"
                },
                {
                    "user_id": "user1",
                    "api_key": "fsk_user_test_key_456", 
                    "site_name": "Example Website",
                    "domain": "example.com",
                    "created_at": datetime.now(),
                    "status": "active"
                }
            ],
            "api_logs": [
                {
                    "api_key": "fsk_admin_test_key_123",
                    "endpoint": "/fraud-check",
                    "method": "POST",
                    "timestamp": datetime.now(),
                    "status": "success",
                    "fraud_score": 0.2,
                    "decision": "safe"
                }
            ]
        }

    async def run(self):
        created = []
        inserted = []

        for name, docs in self.fake_data.items():
            col = self.mongo.get_collection(name)
            count = await col.count_documents({})
            if count == 0:
                await col.insert_many(docs)
                inserted.append(name)
            created.append(name)

        print(f"✅ Created blacklist collections: {', '.join(created)}")
        if inserted:
            print(f"🟢 Inserted fake data into: {', '.join(inserted)}")
        else:
            print("🟡 Data already exists, nothing inserted.")

if __name__ == "__main__":
    asyncio.run(BlacklistSeeder().run())