import asyncio
from mongo import MongoManager


class RulesSeeder:
    """
    Inserts default rule definitions into the `rules` collection.
    Includes planned rules as disabled.
    """

    def __init__(self):
        self.mongo = MongoManager()
        self.rules_data = [
            {
                "rule_key": "disposable_email",
                "enabled": True,
                "weight": 0.25,
                "description": "Email domain is disposable (e.g., tempmail.com)",
            },
            {
                "rule_key": "suspicious_bin",
                "enabled": True,
                "weight": 0.20,
                "description": "Card BIN is commonly used in fraud",
            },
            {
                "rule_key": "flagged_ip",
                "enabled": True,
                "weight": 0.25,
                "description": "IP address appears in flagged_ips list",
            },
            {
                "rule_key": "reused_fingerprint",
                "enabled": True,
                "weight": 0.15,
                "description": "Device/browser fingerprint reused across multiple users",
            },
            {
                "rule_key": "tampered_price",
                "enabled": True,
                "weight": 0.10,
                "description": "Suspicious price used (e.g., 0.01)",
            },
            {
                "rule_key": "fast_checkout",
                "enabled": True,
                "weight": 0.15,
                "threshold_ms": 3000,
                "description": "Checkout completed faster than humanly possible",
            },
            # Future rules (disabled for now)
            {
                "rule_key": "location_mismatch",
                "enabled": False,
                "weight": 0.15,
                "description": "IP location and billing address mismatch",
            },
            {
                "rule_key": "vpn_proxy_detected",
                "enabled": False,
                "weight": 0.20,
                "description": "Detected VPN or proxy usage from IP",
            },
            {
                "rule_key": "reused_card_hash",
                "enabled": False,
                "weight": 0.15,
                "description": "Card hash reused across multiple users",
            },
        ]

    async def run(self):
        col = self.mongo.get_collection("rules")
        if await col.count_documents({}) == 0:
            await col.insert_many(self.rules_data)
            print("🟢 Rules inserted successfully.")
        else:
            print("🟡 Rules already exist — no new data inserted.")


if __name__ == "__main__":
    asyncio.run(RulesSeeder().run())
