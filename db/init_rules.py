import asyncio
from datetime import datetime
from mongo import MongoManager

class RulesSeeder:
    """
    Optimized rules seeder with better organization and performance
    """

    def __init__(self):
        self.mongo = MongoManager()
        
        # Organized and optimized rules (removed redundant ones)
        self.rules_data = [
            # === HIGH-IMPACT FRAUD RULES (Weight >= 0.3) ===
            {
                "rule_key": "blacklisted_pattern",
                "enabled": True,
                "weight": 0.5,
                "category": "critical",
                "description": "Pattern found in fraud blacklist (email, IP, BIN, etc.)",
                "priority": 1
            },
            {
                "rule_key": "velocity_abuse",
                "enabled": True,
                "weight": 0.4,
                "category": "critical",
                "description": "Multiple transactions in short time window",
                "priority": 1,
                "thresholds": {
                    "transactions_per_hour": 10,
                    "transactions_per_day": 50
                }
            },
            {
                "rule_key": "card_location_abuse",
                "enabled": True,
                "weight": 0.45,
                "category": "critical",
                "description": "Same card used from multiple locations",
                "priority": 1
            },
            {
                "rule_key": "impossible_travel",
                "enabled": True,
                "weight": 0.4,
                "category": "critical",
                "description": "Impossible travel between transactions",
                "priority": 1,
                "thresholds": {
                    "max_speed_kmh": 1000  # Max realistic travel speed
                }
            },
            
            # === MEDIUM-IMPACT RULES (Weight 0.15-0.29) ===
            {
                "rule_key": "suspicious_email_pattern",
                "enabled": True,
                "weight": 0.25,
                "category": "medium",
                "description": "Email shows suspicious patterns (numbered, random, etc.)",
                "priority": 2,
                "patterns": [
                    r".*\d{4,}.*@",  # 4+ consecutive digits
                    r".*[a-z]{8,}\d+@",  # Long random string + numbers
                    r".*test.*@"  # Test emails
                ]
            },
            {
                "rule_key": "reused_device_fingerprint",
                "enabled": True,
                "weight": 0.2,
                "category": "medium",
                "description": "Device fingerprint used by multiple users",
                "priority": 2
            },
            {
                "rule_key": "fast_checkout",
                "enabled": True,
                "weight": 0.2,
                "category": "medium",
                "description": "Checkout completed unusually fast",
                "priority": 2,
                "thresholds": {
                    "min_checkout_seconds": 10,
                    "suspicious_seconds": 5
                }
            },
            {
                "rule_key": "suspicious_amount",
                "enabled": True,
                "weight": 0.18,
                "category": "medium",
                "description": "Transaction amount is suspicious",
                "priority": 2,
                "thresholds": {
                    "suspicious_amounts": [0.01, 0.99, 1.00, 9999.99],
                    "high_amount_threshold": 5000.00
                }
            },
            
            # === LOW-IMPACT RULES (Weight < 0.15) ===
            {
                "rule_key": "phone_country_mismatch",
                "enabled": True,
                "weight": 0.12,
                "category": "low",
                "description": "Phone country doesn't match billing country",
                "priority": 3
            },
            {
                "rule_key": "new_device_high_amount",
                "enabled": True,
                "weight": 0.1,
                "category": "low",
                "description": "High amount transaction from new device",
                "priority": 3,
                "thresholds": {
                    "high_amount": 1000.00,
                    "new_device_hours": 24
                }
            },
            {
                "rule_key": "unusual_time_pattern",
                "enabled": True,
                "weight": 0.08,
                "category": "low",
                "description": "Transaction at unusual time for user",
                "priority": 3
            },
            
            # === BEHAVIORAL ANALYSIS RULES ===
            {
                "rule_key": "behavioral_anomaly",
                "enabled": True,
                "weight": 0.15,
                "category": "behavioral",
                "description": "User behavior deviates from normal patterns",
                "priority": 2,
                "thresholds": {
                    "min_mouse_moves": 10,
                    "min_key_presses": 20,
                    "max_typing_speed": 200  # WPM
                }
            },
            {
                "rule_key": "automation_detected",
                "enabled": True,
                "weight": 0.3,
                "category": "behavioral",
                "description": "Automated behavior patterns detected",
                "priority": 1
            },
            
            # === FUTURE/EXPERIMENTAL RULES (Disabled by default) ===
            {
                "rule_key": "ml_risk_score",
                "enabled": False,
                "weight": 0.35,
                "category": "experimental",
                "description": "Machine learning model risk assessment",
                "priority": 1
            },
            {
                "rule_key": "social_graph_analysis",
                "enabled": False,
                "weight": 0.2,
                "category": "experimental",
                "description": "Social network fraud patterns",
                "priority": 2
            }
        ]
        
        # Add metadata to all rules
        for rule in self.rules_data:
            rule["created_at"] = datetime.now()
            rule["last_modified"] = datetime.now()
            rule["version"] = "1.0"

    async def run(self):
        """Initialize rules collection"""
        col = self.mongo.get_collection("rules")
        
        # Check if collection is empty
        existing_count = await col.count_documents({})
        
        if existing_count == 0:
            # Insert all rules
            await col.insert_many(self.rules_data)
            
            # Create indexes for better performance
            await self._create_indexes()
            
            print(f"✅ {len(self.rules_data)} rules inserted successfully.")
            await self._show_summary()
        else:
            print(f"🟡 Rules already exist ({existing_count} rules)")
            await self._show_current_status()

    async def update_rules(self):
        """Update existing rules or add new ones"""
        col = self.mongo.get_collection("rules")
        
        updated = 0
        inserted = 0
        
        for rule in self.rules_data:
            rule["last_modified"] = datetime.now()
            
            result = await col.update_one(
                {"rule_key": rule["rule_key"]},
                {"$set": rule},
                upsert=True
            )
            
            if result.modified_count > 0:
                updated += 1
            elif result.upserted_id:
                inserted += 1
        
        await self._create_indexes()
        
        print(f"✅ Rules update complete:")
        print(f"   Updated: {updated} rules")
        print(f"   Inserted: {inserted} new rules")
        await self._show_summary()

    async def _create_indexes(self):
        """Create performance indexes"""
        col = self.mongo.get_collection("rules")
        
        await col.create_index("rule_key", unique=True)
        await col.create_index("enabled")
        await col.create_index([("category", 1), ("enabled", 1)])
        await col.create_index([("priority", 1), ("weight", -1)])
        await col.create_index("last_modified")
        
        print("📊 Indexes created for better performance")

    async def _show_summary(self):
        """Show rules summary by category"""
        col = self.mongo.get_collection("rules")
        
        print("\n📋 Rules Summary:")
        print("=" * 60)
        
        # Group by category
        pipeline = [
            {"$group": {
                "_id": "$category",
                "total": {"$sum": 1},
                "enabled": {"$sum": {"$cond": ["$enabled", 1, 0]}},
                "avg_weight": {"$avg": "$weight"},
                "max_weight": {"$max": "$weight"}
            }},
            {"$sort": {"max_weight": -1}}
        ]
        
        async for group in col.aggregate(pipeline):
            category = group["_id"]
            total = group["total"]
            enabled = group["enabled"]
            avg_weight = group["avg_weight"]
            max_weight = group["max_weight"]
            
            print(f"{category:12} | Total: {total:2} | Enabled: {enabled:2} | "
                  f"Avg Weight: {avg_weight:.2f} | Max: {max_weight:.2f}")
        
        print("=" * 60)

    async def _show_current_status(self):
        """Show current status of rules"""
        col = self.mongo.get_collection("rules")
        
        enabled_count = await col.count_documents({"enabled": True})
        total_count = await col.count_documents({})
        
        print(f"   Enabled: {enabled_count}/{total_count} rules")
        print("💡 Use 'update' command to refresh rules")

    async def show_current_rules(self):
        """Display current rules organized by priority and category"""
        col = self.mongo.get_collection("rules")
        
        print("\n📋 Current Rules (Organized by Priority)")
        print("=" * 80)
        
        # Sort by priority, then weight (descending)
        async for rule in col.find().sort([("priority", 1), ("weight", -1)]):
            status = "✅" if rule.get("enabled") else "❌"
            priority = "🔴" if rule.get("priority", 3) == 1 else "🟡" if rule.get("priority", 3) == 2 else "🟢"
            
            category = rule.get('category', 'unknown')[:10]
            rule_key = rule['rule_key'][:25]
            weight = rule.get('weight', 0)
            description = rule.get('description', 'No description')[:50]
            
            print(f"{status} {priority} [{category:10}] {rule_key:25} | {weight:.2f} | {description}")
        
        print("=" * 80)
        print("🔴 High Priority | 🟡 Medium Priority | 🟢 Low Priority")

    async def optimize_rules(self):
        """Optimize rules based on performance data"""
        col = self.mongo.get_collection("rules")
        
        print("🔧 Optimizing rules based on effectiveness...")
        
        # This would analyze transaction logs to optimize rule weights
        # For now, just show optimization suggestions
        
        low_weight_rules = []
        async for rule in col.find({"weight": {"$lt": 0.1}, "enabled": True}):
            low_weight_rules.append(rule["rule_key"])
        
        if low_weight_rules:
            print(f"💡 Consider reviewing these low-weight rules: {', '.join(low_weight_rules)}")
        
        high_weight_disabled = []
        async for rule in col.find({"weight": {"$gt": 0.3}, "enabled": False}):
            high_weight_disabled.append(rule["rule_key"])
        
        if high_weight_disabled:
            print(f"⚠️ High-weight rules that are disabled: {', '.join(high_weight_disabled)}")

if __name__ == "__main__":
    import sys
    
    seeder = RulesSeeder()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "update":
            asyncio.run(seeder.update_rules())
        elif command == "show":
            asyncio.run(seeder.show_current_rules())
        elif command == "optimize":
            asyncio.run(seeder.optimize_rules())
        else:
            print("❌ Unknown command. Use: update, show, optimize, or no args for initial seed")
    else:
        # Default: seed if empty
        asyncio.run(seeder.run())