import asyncio
from mongo import MongoManager

class RulesSeeder:
    """
    Inserts default rule definitions into the `rules` collection.
    Includes both basic and advanced algorithm rules.
    """

    def __init__(self):
        self.mongo = MongoManager()
        self.rules_data = [
            # === BASIC FRAUD RULES ===
            {
                "rule_key": "disposable_email",
                "enabled": True,
                "weight": 0.25,
                "category": "basic",
                "description": "Email domain is disposable (e.g., tempmail.com)",
            },
            {
                "rule_key": "suspicious_bin",
                "enabled": True,
                "weight": 0.20,
                "category": "basic",
                "description": "Card BIN is commonly used in fraud",
            },
            {
                "rule_key": "flagged_ip",
                "enabled": True,
                "weight": 0.25,
                "category": "basic",
                "description": "IP address appears in flagged_ips list",
            },
            {
                "rule_key": "reused_fingerprint",
                "enabled": True,
                "weight": 0.15,
                "category": "basic",
                "description": "Device/browser fingerprint reused across multiple users",
            },
            {
                "rule_key": "tampered_price",
                "enabled": True,
                "weight": 0.10,
                "category": "basic",
                "description": "Suspicious price used (e.g., 0.01)",
            },
            {
                "rule_key": "fast_checkout",
                "enabled": True,
                "weight": 0.15,
                "category": "basic",
                "threshold_ms": 3000,
                "description": "Checkout completed faster than humanly possible",
            },
            
            # === ADVANCED ALGORITHM RULES ===
            {
                "rule_key": "velocity_abuse",
                "enabled": True,
                "weight": 0.30,
                "category": "advanced",
                "description": "Multiple transactions in short time windows",
            },
            {
                "rule_key": "suspicious_patterns",
                "enabled": True,
                "weight": 0.25,
                "category": "advanced",
                "description": "Suspicious email patterns (numbered, random, etc.)",
            },
            {
                "rule_key": "geo_anomaly",
                "enabled": True,
                "weight": 0.20,
                "category": "advanced",
                "description": "Impossible travel or geographic anomalies detected",
            },
            {
                "rule_key": "behavioral_deviation",
                "enabled": True,
                "weight": 0.15,
                "category": "advanced",
                "description": "Unusual patterns compared to user's historical behavior",
            },
            {
                "rule_key": "network_analysis",
                "enabled": True,
                "weight": 0.10,
                "category": "advanced",
                "description": "Suspicious network patterns (proxy, VPN, private IPs)",
            },
            {
                "rule_key": "time_pattern_anomaly",
                "enabled": True,
                "weight": 0.10,
                "category": "advanced",
                "description": "Unusual time patterns for user",
            },
            {
                "rule_key": "amount_clustering",
                "enabled": True,
                "weight": 0.05,
                "category": "advanced",
                "description": "Common fraud amounts or suspicious amount patterns",
            },
            {
                "rule_key": "phone_mismatch",
                "enabled": True,
                "weight": 0.15,
                "category": "advanced",
                "description": "Phone country code doesn't match billing country",
            },
            
            # === CARD PATTERN RULES ===
            {
                "rule_key": "same_card_multiple_emails",
                "enabled": True,
                "weight": 0.30,
                "category": "card_patterns",
                "description": "Same card used with multiple different email addresses",
            },
            {
                "rule_key": "card_location_abuse",
                "enabled": True,
                "weight": 0.40,
                "category": "card_patterns",
                "description": "Same card used from multiple different locations",
            },
            {
                "rule_key": "card_device_abuse",
                "enabled": True,
                "weight": 0.40,
                "category": "card_patterns",
                "description": "Same card used from multiple different devices",
            },
            {
                "rule_key": "bin_location_abuse",
                "enabled": True,
                "weight": 0.35,
                "category": "card_patterns",
                "description": "BIN used from many different locations (card testing gang)",
            },
            {
                "rule_key": "rapid_location_change",
                "enabled": True,
                "weight": 0.50,
                "category": "card_patterns",
                "description": "Rapid location change for same card (impossible travel)",
            },
            
            # === FUTURE/DISABLED RULES ===
            {
                "rule_key": "location_mismatch",
                "enabled": False,
                "weight": 0.15,
                "category": "future",
                "description": "IP location and billing address mismatch",
            },
            {
                "rule_key": "vpn_proxy_detected",
                "enabled": False,
                "weight": 0.20,
                "category": "future",
                "description": "Advanced VPN or proxy detection from IP",
            },
            {
                "rule_key": "reused_card_hash",
                "enabled": False,
                "weight": 0.15,
                "category": "future",
                "description": "Card hash reused across multiple accounts",
            },
            {
                "rule_key": "ml_risk_score",
                "enabled": False,
                "weight": 0.40,
                "category": "future",
                "description": "Machine learning model risk score",
            },
        ]

    async def run(self):
        col = self.mongo.get_collection("rules")
        
        # Check if collection is empty
        existing_count = await col.count_documents({})
        
        if existing_count == 0:
            # Insert all rules
            await col.insert_many(self.rules_data)
            print(f"🟢 {len(self.rules_data)} rules inserted successfully.")
            print("📊 Rule categories:")
            print(f"   - Basic rules: {len([r for r in self.rules_data if r.get('category') == 'basic'])}")
            print(f"   - Advanced rules: {len([r for r in self.rules_data if r.get('category') == 'advanced'])}")
            print(f"   - Card pattern rules: {len([r for r in self.rules_data if r.get('category') == 'card_patterns'])}")
            print(f"   - Future rules: {len([r for r in self.rules_data if r.get('category') == 'future'])}")
        else:
            print(f"🟡 Rules already exist ({existing_count} rules) — no new data inserted.")
            print("💡 To update rules, clear the collection first or use update operations.")
            
            # Optionally show what's currently in the database
            enabled_rules = await col.count_documents({"enabled": True})
            print(f"   - Enabled rules: {enabled_rules}")
            print(f"   - Disabled rules: {existing_count - enabled_rules}")

    async def update_rules(self):
        """Update existing rules or add new ones without clearing the collection"""
        col = self.mongo.get_collection("rules")
        
        updated = 0
        inserted = 0
        
        for rule in self.rules_data:
            result = await col.update_one(
                {"rule_key": rule["rule_key"]},
                {"$set": rule},
                upsert=True
            )
            
            if result.modified_count > 0:
                updated += 1
            elif result.upserted_id:
                inserted += 1
        
        print(f"✅ Rules update complete:")
        print(f"   - Updated: {updated} rules")
        print(f"   - Inserted: {inserted} new rules")
        print(f"   - Total: {len(self.rules_data)} rules")

    async def show_current_rules(self):
        """Display current rules in the database"""
        col = self.mongo.get_collection("rules")
        
        print("\n📋 Current Rules in Database:")
        print("=" * 80)
        
        async for rule in col.find().sort("category", 1):
            status = "✅" if rule.get("enabled") else "❌"
            print(f"{status} [{rule.get('category', 'unknown'):12}] {rule['rule_key']:30} | Weight: {rule.get('weight', 0):.2f} | {rule.get('description', 'No description')}")
        
        print("=" * 80)


if __name__ == "__main__":
    import sys
    
    seeder = RulesSeeder()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "update":
            # Update existing rules without clearing
            asyncio.run(seeder.update_rules())
        elif command == "show":
            # Show current rules
            asyncio.run(seeder.show_current_rules())
        else:
            print("Unknown command. Use: update, show, or no argument for initial seed")
    else:
        # Default: seed if empty
        asyncio.run(seeder.run())