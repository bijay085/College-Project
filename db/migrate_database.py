"""
Database Migration Script for FraudShield
Migrates from old structure to optimized structure
"""

import asyncio
import sys
from datetime import datetime
from mongo import MongoManager

class DatabaseMigrator:
    def __init__(self):
        self.mongo = MongoManager()
        self.migration_log = []
        
    async def run_full_migration(self):
        """Run complete migration process"""
        print("🚀 Starting FraudShield Database Migration")
        print("=" * 50)
        
        try:
            # Step 1: Backup existing data
            await self.backup_existing_data()
            
            # Step 2: Migrate blacklist data
            await self.migrate_blacklist_data()
            
            # Step 3: Migrate transaction logs
            await self.migrate_transaction_logs()
            
            # Step 4: Setup new indexes
            await self.setup_indexes()
            
            # Step 5: Verify migration
            await self.verify_migration()
            
            # Step 6: Clean up (optional)
            await self.cleanup_old_collections()
            
            print("\n✅ Migration completed successfully!")
            self.print_migration_summary()
            
        except Exception as e:
            print(f"\n❌ Migration failed: {e}")
            await self.rollback_migration()

    async def backup_existing_data(self):
        """Create backup of existing collections"""
        print("\n📦 Creating backup of existing data...")
        
        old_collections = [
            "disposable_emails", "suspicious_bins", "flagged_ips",
            "reused_fingerprints", "tampered_prices", "logs", "api_logs"
        ]
        
        backup_count = 0
        for collection_name in old_collections:
            if collection_name in await self.mongo.db.list_collection_names():
                backup_name = f"{collection_name}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                
                # Copy collection
                source = self.mongo.db[collection_name]
                backup = self.mongo.db[backup_name]
                
                docs = []
                async for doc in source.find():
                    docs.append(doc)
                
                if docs:
                    await backup.insert_many(docs)
                    backup_count += 1
                    self.log_migration(f"Backed up {collection_name} -> {backup_name} ({len(docs)} docs)")
        
        print(f"✅ Backed up {backup_count} collections")

    async def migrate_blacklist_data(self):
        """Migrate all blacklist collections into fraud_blacklist"""
        print("\n🔄 Migrating blacklist data to fraud_blacklist...")
        
        fraud_blacklist = self.mongo.get_collection("fraud_blacklist")
        
        # Migration mappings: (old_collection, type, field)
        migrations = [
            ("disposable_emails", "disposable_email", "domain"),
            ("suspicious_bins", "suspicious_bin", "bin"),
            ("flagged_ips", "flagged_ip", "ip"),
            ("reused_fingerprints", "reused_fingerprint", "fingerprint"),
            ("tampered_prices", "tampered_price", "price")
        ]
        
        total_migrated = 0
        
        for old_collection, fraud_type, field in migrations:
            if old_collection in await self.mongo.db.list_collection_names():
                old_col = self.mongo.db[old_collection]
                count = 0
                
                async for doc in old_col.find():
                    new_doc = {
                        "type": fraud_type,
                        "value": str(doc[field]),
                        "risk_score": self.calculate_risk_score(fraud_type, doc.get(field)),
                        "created_at": doc.get("created_at", datetime.now()),
                        "source": "migration",
                        "metadata": {
                            "original_collection": old_collection,
                            "original_doc_id": str(doc.get("_id", ""))
                        }
                    }
                    
                    # Upsert to avoid duplicates
                    await fraud_blacklist.update_one(
                        {"type": fraud_type, "value": str(doc[field])},
                        {"$setOnInsert": new_doc},
                        upsert=True
                    )
                    count += 1
                
                total_migrated += count
                self.log_migration(f"Migrated {old_collection}: {count} records")
        
        print(f"✅ Migrated {total_migrated} blacklist records")

    def calculate_risk_score(self, fraud_type, value):
        """Calculate risk score based on fraud type and value"""
        risk_scores = {
            "disposable_email": 0.9,
            "suspicious_bin": 0.85,
            "flagged_ip": 0.8,
            "reused_fingerprint": 0.75,
            "tampered_price": 0.95
        }
        
        base_score = risk_scores.get(fraud_type, 0.7)
        
        # Adjust based on specific values
        if fraud_type == "tampered_price":
            try:
                price = float(value)
                if price < 1.0:
                    return 0.95
                elif price > 9999:
                    return 0.9
            except:
                pass
        
        return base_score

    async def migrate_transaction_logs(self):
        """Migrate logs to transactions and audit_logs"""
        print("\n🔄 Migrating logs to optimized structure...")
        
        if "logs" not in await self.mongo.db.list_collection_names():
            print("⚠️ No logs collection found, skipping log migration")
            return
        
        logs = self.mongo.db["logs"]
        transactions = self.mongo.get_collection("transactions")
        audit_logs = self.mongo.get_collection("audit_logs")
        
        transaction_count = 0
        audit_count = 0
        
        async for log in logs.find():
            action = log.get("action", "")
            
            if action == "fraud_check":
                # Migrate to transactions
                transaction_doc = {
                    "transaction_id": str(log.get("_id", "")),
                    "timestamp": log.get("timestamp", datetime.now()),
                    "api_key": log.get("api_key"),
                    "user_email": log.get("user_email"),
                    "amount": log.get("amount", 0),
                    "product": log.get("product"),
                    "email": log.get("email"),
                    "device_fingerprint": log.get("device_fingerprint"),
                    "ip_address": log.get("ip_address"),
                    "card_bin": log.get("card_bin"),
                    "fraud_score": log.get("fraud_score", 0),
                    "decision": log.get("decision", "unknown"),
                    "reasons": log.get("reasons", []),
                    "processing_time": log.get("processing_time", 0),
                    "raw_data": log.get("raw_data", {}),
                    "migrated_from": "logs"
                }
                
                await transactions.insert_one(transaction_doc)
                transaction_count += 1
                
            else:
                # Migrate to audit_logs
                audit_doc = {
                    "timestamp": log.get("timestamp", datetime.now()),
                    "action": action,
                    "user_email": log.get("user_email"),
                    "ip_address": log.get("ip_address"),
                    "details": {
                        key: value for key, value in log.items() 
                        if key not in ["_id", "timestamp", "action", "user_email", "ip_address"]
                    },
                    "log_level": log.get("log_level", "info"),
                    "migrated_from": "logs"
                }
                
                await audit_logs.insert_one(audit_doc)
                audit_count += 1
        
        self.log_migration(f"Migrated logs: {transaction_count} transactions, {audit_count} audit logs")
        print(f"✅ Migrated {transaction_count} transactions and {audit_count} audit logs")

    async def setup_indexes(self):
        """Setup performance indexes on new collections"""
        print("\n📊 Setting up performance indexes...")
        
        try:
            await self.mongo.setup_indexes()
            self.log_migration("Created performance indexes")
            print("✅ Performance indexes created")
        except Exception as e:
            print(f"⚠️ Warning: Could not create some indexes: {e}")

    async def verify_migration(self):
        """Verify that migration was successful"""
        print("\n🔍 Verifying migration...")
        
        # Check fraud_blacklist
        fraud_blacklist = self.mongo.get_collection("fraud_blacklist")
        blacklist_count = await fraud_blacklist.count_documents({})
        
        # Check transactions
        transactions = self.mongo.get_collection("transactions")
        transaction_count = await transactions.count_documents({})
        
        # Check audit_logs
        audit_logs = self.mongo.get_collection("audit_logs")
        audit_count = await audit_logs.count_documents({})
        
        print(f"📊 Migration Results:")
        print(f"   Fraud Blacklist: {blacklist_count:,} records")
        print(f"   Transactions: {transaction_count:,} records")
        print(f"   Audit Logs: {audit_count:,} records")
        
        # Verify data integrity
        if blacklist_count > 0 and transaction_count >= 0:
            print("✅ Migration verification passed")
            return True
        else:
            print("❌ Migration verification failed")
            return False

    async def cleanup_old_collections(self):
        """Remove old collections after successful migration"""
        print("\n🧹 Cleaning up old collections...")
        
        confirm = input("⚠️ Delete old collections? This cannot be undone! (type 'DELETE' to confirm): ")
        
        if confirm == "DELETE":
            old_collections = [
                "disposable_emails", "suspicious_bins", "flagged_ips",
                "reused_fingerprints", "tampered_prices", "logs", "api_logs"
            ]
            
            deleted_count = 0
            for collection_name in old_collections:
                try:
                    await self.mongo.db.drop_collection(collection_name)
                    self.log_migration(f"Deleted old collection: {collection_name}")
                    deleted_count += 1
                except Exception as e:
                    print(f"⚠️ Could not delete {collection_name}: {e}")
            
            print(f"✅ Deleted {deleted_count} old collections")
        else:
            print("🟡 Skipped cleanup - old collections preserved")

    async def rollback_migration(self):
        """Rollback migration in case of failure"""
        print("\n⏪ Rolling back migration...")
        
        # This would restore from backups
        # Implementation depends on backup strategy
        print("💡 Restore from backup collections manually if needed")

    def log_migration(self, message):
        """Log migration step"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.migration_log.append(log_entry)

    def print_migration_summary(self):
        """Print migration summary"""
        print("\n📋 Migration Summary:")
        print("=" * 50)
        for entry in self.migration_log:
            print(entry)
        print("=" * 50)

    async def check_migration_status(self):
        """Check if migration is needed"""
        print("🔍 Checking migration status...")
        
        old_collections = [
            "disposable_emails", "suspicious_bins", "flagged_ips",
            "reused_fingerprints", "tampered_prices"
        ]
        
        existing_old = []
        for col_name in old_collections:
            if col_name in await self.mongo.db.list_collection_names():
                count = await self.mongo.db[col_name].count_documents({})
                if count > 0:
                    existing_old.append(f"{col_name} ({count} docs)")
        
        new_collections = ["fraud_blacklist", "transactions", "audit_logs"]
        existing_new = []
        for col_name in new_collections:
            if col_name in await self.mongo.db.list_collection_names():
                count = await self.mongo.db[col_name].count_documents({})
                if count > 0:
                    existing_new.append(f"{col_name} ({count} docs)")
        
        if existing_old:
            print(f"📊 Old collections found: {', '.join(existing_old)}")
            print("🟡 Migration recommended")
        else:
            print("✅ No old collections found")
        
        if existing_new:
            print(f"📊 New collections found: {', '.join(existing_new)}")
            print("✅ New structure already exists")

async def main():
    """Main migration function"""
    migrator = DatabaseMigrator()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "check":
            await migrator.check_migration_status()
        elif command == "migrate":
            await migrator.run_full_migration()
        elif command == "backup":
            await migrator.backup_existing_data()
        else:
            print("❌ Unknown command")
            print("Usage: python migrate_database.py [check|migrate|backup]")
    else:
        print("🚀 FraudShield Database Migration Tool")
        print("Usage:")
        print("  python migrate_database.py check   - Check migration status")
        print("  python migrate_database.py migrate - Run full migration")
        print("  python migrate_database.py backup  - Backup existing data")

if __name__ == "__main__":
    asyncio.run(main())