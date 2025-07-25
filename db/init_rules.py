import asyncio
from datetime import datetime
from mongo import MongoManager

class RulesSeeder:
    """
    Optimized rules seeder with better organization and performance
    """

    def __init__(self):
        self.mongo = MongoManager()
        
        # ULTRA STRICT RULES WITH EXTREME WEIGHTS
        self.rules_data = [
            # === CRITICAL FRAUD RULES (Weight 0.5-0.8) ===
            {
                "rule_key": "disposable_email",
                "enabled": True,
                "weight": 0.5,
                "category": "critical",
                "description": "Disposable email domain detected",
                "priority": 1
            },
            {
                "rule_key": "suspicious_bin",
                "enabled": True,
                "weight": 0.6,
                "category": "critical",
                "description": "Suspicious card BIN detected",
                "priority": 1
            },
            {
                "rule_key": "flagged_ip",
                "enabled": True,
                "weight": 0.55,
                "category": "critical",
                "description": "Flagged IP address detected",
                "priority": 1
            },
            {
                "rule_key": "reused_fingerprint",
                "enabled": True,
                "weight": 0.45,
                "category": "critical",
                "description": "Reused device fingerprint detected",
                "priority": 1
            },
            {
                "rule_key": "tampered_price",
                "enabled": True,
                "weight": 0.7,
                "category": "critical",
                "description": "Tampered price detected",
                "priority": 1
            },
            {
                "rule_key": "blacklisted_pattern",
                "enabled": True,
                "weight": 0.8,
                "category": "critical",
                "description": "Pattern found in fraud blacklist",
                "priority": 1
            },
            
            # === CARD ABUSE RULES (Weight 0.6-0.8) ===
            {
                "rule_key": "same_card_multiple_emails",
                "enabled": True,
                "weight": 0.65,
                "category": "critical",
                "description": "Same card used with multiple emails",
                "priority": 1
            },
            {
                "rule_key": "card_location_abuse",
                "enabled": True,
                "weight": 0.75,
                "category": "critical",
                "description": "Same card used from multiple locations",
                "priority": 1
            },
            {
                "rule_key": "card_device_abuse",
                "enabled": True,
                "weight": 0.7,
                "category": "critical",
                "description": "Same card used from multiple devices",
                "priority": 1
            },
            {
                "rule_key": "bin_location_abuse",
                "enabled": True,
                "weight": 0.6,
                "category": "critical",
                "description": "BIN used from multiple locations",
                "priority": 1
            },
            {
                "rule_key": "rapid_location_change",
                "enabled": True,
                "weight": 0.8,
                "category": "critical",
                "description": "Rapid location change detected",
                "priority": 1
            },
            
            # === VELOCITY & TRAVEL RULES (Weight 0.65) ===
            {
                "rule_key": "velocity_abuse",
                "enabled": True,
                "weight": 0.65,
                "category": "critical",
                "description": "Multiple transactions in short time window",
                "priority": 1,
                "thresholds": {
                    "transactions_per_minute": 2,
                    "transactions_per_hour": 5,
                    "transactions_per_day": 20
                }
            },
            {
                "rule_key": "impossible_travel",
                "enabled": True,
                "weight": 0.65,
                "category": "critical",
                "description": "Impossible travel between transactions",
                "priority": 1,
                "thresholds": {
                    "max_speed_kmh": 500
                }
            },
            
            # === PATTERN DETECTION (Weight 0.4-0.6) ===
            {
                "rule_key": "suspicious_email_pattern",
                "enabled": True,
                "weight": 0.45,
                "category": "medium",
                "description": "Email shows suspicious patterns",
                "priority": 2,
                "patterns": [
                    r".*\d{4,}.*@",
                    r".*[a-z]{8,}\d+@",
                    r".*test.*@"
                ]
            },
            {
                "rule_key": "suspicious_patterns",
                "enabled": True,
                "weight": 0.55,
                "category": "advanced",
                "description": "Advanced suspicious patterns detected",
                "priority": 1
            },
            {
                "rule_key": "geo_anomaly",
                "enabled": True,
                "weight": 0.6,
                "category": "advanced",
                "description": "Geographic anomaly detected",
                "priority": 1
            },
            {
                "rule_key": "network_analysis",
                "enabled": True,
                "weight": 0.5,
                "category": "advanced",
                "description": "Network analysis red flags",
                "priority": 2
            },
            {
                "rule_key": "behavioral_deviation",
                "enabled": True,
                "weight": 0.4,
                "category": "advanced",
                "description": "Behavioral deviation from normal",
                "priority": 2
            },
            
            # === VERIFICATION RULES (Weight 0.35-0.4) ===
            {
                "rule_key": "email_verification",
                "enabled": True,
                "weight": 0.35,
                "category": "medium",
                "description": "Email not verified",
                "priority": 2
            },
            {
                "rule_key": "phone_verification",
                "enabled": True,
                "weight": 0.35,
                "category": "medium",
                "description": "Phone not verified",
                "priority": 2
            },
            {
                "rule_key": "phone_mismatch",
                "enabled": True,
                "weight": 0.4,
                "category": "medium",
                "description": "Phone number mismatch",
                "priority": 2
            },
            {
                "rule_key": "phone_country_mismatch",
                "enabled": True,
                "weight": 0.4,
                "category": "medium",
                "description": "Phone country doesn't match billing country",
                "priority": 2
            },
            
            # === MEDIUM-IMPACT RULES (Weight 0.3-0.35) ===
            {
                "rule_key": "reused_device_fingerprint",
                "enabled": True,
                "weight": 0.35,
                "category": "medium",
                "description": "Device fingerprint used by multiple users",
                "priority": 2
            },
            {
                "rule_key": "fast_checkout",
                "enabled": True,
                "weight": 0.3,
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
                "weight": 0.35,
                "category": "medium",
                "description": "Transaction amount is suspicious",
                "priority": 2,
                "thresholds": {
                    "suspicious_amounts": [0.01, 0.99, 1.00, 9999.99],
                    "high_amount_threshold": 5000.00
                }
            },
            {
                "rule_key": "time_pattern_anomaly",
                "enabled": True,
                "weight": 0.3,
                "category": "advanced",
                "description": "Time pattern anomaly detected",
                "priority": 3
            },
            
            # === LOW-IMPACT RULES (Weight 0.2-0.25) ===
            {
                "rule_key": "new_device_high_amount",
                "enabled": True,
                "weight": 0.25,
                "category": "low",
                "description": "High amount transaction from new device",
                "priority": 3,
                "thresholds": {
                    "high_amount": 500.00,
                    "new_device_hours": 12
                }
            },
            {
                "rule_key": "amount_clustering",
                "enabled": True,
                "weight": 0.2,
                "category": "advanced",
                "description": "Amount clustering patterns",
                "priority": 3
            },
            {
                "rule_key": "unusual_time_pattern",
                "enabled": True,
                "weight": 0.2,
                "category": "low",
                "description": "Transaction at unusual time for user",
                "priority": 3
            },
            
            # === BEHAVIORAL ANALYSIS RULES ===
            {
                "rule_key": "behavioral_anomaly",
                "enabled": True,
                "weight": 0.35,
                "category": "behavioral",
                "description": "User behavior deviates from normal patterns",
                "priority": 2,
                "thresholds": {
                    "min_mouse_moves": 5,
                    "min_key_presses": 10,
                    "max_typing_speed": 150
                }
            },
            {
                "rule_key": "automation_detected",
                "enabled": True,
                "weight": 0.6,
                "category": "behavioral",
                "description": "Automated behavior patterns detected",
                "priority": 1
            },
            
            # === FUTURE/EXPERIMENTAL RULES ===
            {
                "rule_key": "ml_risk_score",
                "enabled": True,
                "weight": 0.7,
                "category": "experimental",
                "description": "Machine learning model risk assessment",
                "priority": 1
            },
            {
                "rule_key": "social_graph_analysis",
                "enabled": True,
                "weight": 0.45,
                "category": "experimental",
                "description": "Social network fraud patterns",
                "priority": 2
            }
        ]
        
        # Add metadata to all rules
        for rule in self.rules_data:
            rule["created_at"] = datetime.now()
            rule["last_modified"] = datetime.now()
            rule["version"] = "3.0_ultra_strict"

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
            
            print(f"✅ {len(self.rules_data)} ULTRA STRICT rules inserted successfully.")
            await self._show_summary()
        else:
            print(f"🟡 Rules already exist ({existing_count} rules)")
            print("💡 Use 'update' command to update to ULTRA STRICT mode")
            await self._show_current_status()

    async def update_rules(self):
        """Update existing rules to ULTRA STRICT mode"""
        col = self.mongo.get_collection("rules")
        
        updated = 0
        inserted = 0
        
        for rule in self.rules_data:
            rule["last_modified"] = datetime.now()
            rule["updated_by"] = "ultra_strict_mode_update"
            
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
        
        print(f"✅ ULTRA STRICT mode update complete:")
        print(f"   Updated: {updated} rules")
        print(f"   Inserted: {inserted} new rules")
        print(f"🔥 All rules now have ULTRA STRICT weights!")
        print(f"💀 NOTHING GETS THROUGH NOW!")
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
        
        print("\n📋 ULTRA STRICT Rules Summary:")
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
        
        # Show weight distribution
        high_weight = await col.count_documents({"weight": {"$gte": 0.5}})
        medium_weight = await col.count_documents({"weight": {"$gte": 0.3, "$lt": 0.5}})
        low_weight = await col.count_documents({"weight": {"$lt": 0.3}})
        
        print(f"\n💀 Weight Distribution:")
        print(f"   EXTREME (0.5+): {high_weight} rules")
        print(f"   HIGH (0.3-0.49): {medium_weight} rules")
        print(f"   MEDIUM (<0.3): {low_weight} rules")

    async def _show_current_status(self):
        """Show current status of rules"""
        col = self.mongo.get_collection("rules")
        
        enabled_count = await col.count_documents({"enabled": True})
        total_count = await col.count_documents({})
        
        print(f"   Enabled: {enabled_count}/{total_count} rules")
        print("💡 Use 'update' command to refresh rules to ULTRA STRICT mode")

    async def show_current_rules(self):
        """Display current rules organized by priority and category"""
        col = self.mongo.get_collection("rules")
        
        print("\n📋 Current Rules (ULTRA STRICT MODE)")
        print("=" * 80)
        
        # Sort by priority, then weight (descending)
        async for rule in col.find().sort([("priority", 1), ("weight", -1)]):
            status = "✅" if rule.get("enabled") else "❌"
            priority = "🔴" if rule.get("priority", 3) == 1 else "🟡" if rule.get("priority", 3) == 2 else "🟢"
            
            category = rule.get('category', 'unknown')[:10]
            rule_key = rule['rule_key'][:25]
            weight = rule.get('weight', 0)
            description = rule.get('description', 'No description')[:50]
            
            # Add weight indicator
            if weight >= 0.5:
                weight_indicator = "💀"
            elif weight >= 0.3:
                weight_indicator = "🔥"
            else:
                weight_indicator = "⚡"
            
            print(f"{status} {priority} {weight_indicator} [{category:10}] {rule_key:25} | {weight:.2f} | {description}")
        
        print("=" * 80)
        print("🔴 High Priority | 🟡 Medium Priority | 🟢 Low Priority")
        print("💀 EXTREME Weight | 🔥 HIGH Weight | ⚡ MEDIUM Weight")

    async def optimize_rules(self):
        """Optimize rules based on performance data"""
        col = self.mongo.get_collection("rules")
        
        print("🔧 Optimizing rules based on effectiveness...")
        
        # Show current weight distribution
        high_weight = await col.count_documents({"weight": {"$gte": 0.5}})
        medium_weight = await col.count_documents({"weight": {"$gte": 0.3, "$lt": 0.5}})
        low_weight = await col.count_documents({"weight": {"$lt": 0.3}})
        
        print(f"\n📊 Current Weight Distribution:")
        print(f"   EXTREME (0.5+): {high_weight} rules")
        print(f"   HIGH (0.3-0.49): {medium_weight} rules")
        print(f"   MEDIUM (<0.3): {low_weight} rules")
        
        # Check for disabled high-weight rules
        high_weight_disabled = []
        async for rule in col.find({"weight": {"$gt": 0.5}, "enabled": False}):
            high_weight_disabled.append(rule["rule_key"])
        
        if high_weight_disabled:
            print(f"\n⚠️ EXTREME weight rules that are disabled: {', '.join(high_weight_disabled)}")
            print("   Consider enabling these for MAXIMUM strictness!")
        
        # Show top 5 strictest rules
        print("\n💀 Top 5 STRICTEST Rules:")
        top_rules = await col.find().sort("weight", -1).limit(5).to_list(None)
        for i, rule in enumerate(top_rules):
            print(f"   {i+1}. {rule['rule_key']} - Weight: {rule['weight']}")

if __name__ == "__main__":
    import sys
    
    seeder = RulesSeeder()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "update":
            print("🚀 Updating to ULTRA STRICT mode...")
            print("💀 WARNING: This will make fraud detection EXTREMELY strict!")
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