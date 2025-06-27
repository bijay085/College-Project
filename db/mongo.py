from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

class MongoManager:
    def __init__(self):
        # Load .env file from same directory
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        load_dotenv(dotenv_path=env_path)
        
        self.mongo_uri = os.getenv("MONGO_URI")
        if not self.mongo_uri:
            raise ValueError("MONGO_URI is missing in .env")
            
        self.client = AsyncIOMotorClient(self.mongo_uri)
        self.db = self.client.fraudshield  # Optional: load DB name from env too
        
        # Collection names from .env (with fallback defaults)
        self.collections = {
            "disposable_emails": self.db[os.getenv("DISPOSABLE_EMAILS_COLLECTION", "disposable_emails")],
            "suspicious_bins": self.db[os.getenv("SUSPICIOUS_BINS_COLLECTION", "suspicious_bins")],
            "flagged_ips": self.db[os.getenv("FLAGGED_IPS_COLLECTION", "flagged_ips")],
            "reused_fingerprints": self.db[os.getenv("REUSED_FINGERPRINTS_COLLECTION", "reused_fingerprints")],
            "tampered_prices": self.db[os.getenv("TAMPERED_PRICES_COLLECTION", "tampered_prices")],
            "rules": self.db[os.getenv("RULES_COLLECTION", "rules")],
            "logs": self.db[os.getenv("LOGS_COLLECTION", "logs")],
            
            # User authentication collections
            "users": self.db[os.getenv("USERS_COLLECTION", "users")],
            "sites": self.db[os.getenv("SITES_COLLECTION", "sites")],
            "api_logs": self.db[os.getenv("API_LOGS_COLLECTION", "api_logs")]
        }
       
    def get_collection(self, name: str):
        if name not in self.collections:
            raise ValueError(f"Collection '{name}' is not defined in MongoManager.")
        return self.collections[name]