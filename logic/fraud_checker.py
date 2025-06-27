# logic/fraud_checker.py - COMPLETE VERSION WITH DEBUG

import sys
import os
import asyncio
import logging
import json
from typing import Dict, List, Set, Optional, Union
import pandas as pd
from datetime import datetime
import traceback
import pymongo  # Using synchronous MongoDB driver

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from db.mongo import MongoManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SyncMetricsTracker:
    """Synchronous metrics tracker using pymongo with DEBUG"""
    
    def __init__(self):
        """Initialize with synchronous MongoDB connection"""
        print("🔧 DEBUG: Initializing SyncMetricsTracker")
        try:
            # Use synchronous pymongo instead of motor for metrics
            self.client = pymongo.MongoClient("mongodb://localhost:27017")
            self.db = self.client.fraudshield
            self.metrics_collection = self.db.metrics
            print("✅ DEBUG: Synchronous metrics database connection established")
            logger.info("✅ Synchronous metrics database connection established")
        except Exception as e:
            print(f"❌ DEBUG: Failed to connect to metrics database: {e}")
            logger.error(f"❌ Failed to connect to metrics database: {e}")
            self.client = None
            self.db = None
            self.metrics_collection = None
        
    def increment_metric(self, metric_name: str, increment: int = 1):
        """Synchronously increment a metric - WITH DEBUG"""
        print(f"🔧 CALLED: increment_metric({metric_name}, {increment})")
        
        if self.metrics_collection is None:
            print(f"❌ No database connection for metric: {metric_name}")
            return False
            
        try:
            print(f"🔧 Connecting to database for {metric_name}...")
            
            result = self.metrics_collection.update_one(
                {"_id": metric_name},
                {
                    "$inc": {"count": increment},
                    "$set": {"last_updated": datetime.now()}
                },
                upsert=True
            )
            
            print(f"🔧 Update result: modified={result.modified_count}, upserted={result.upserted_id}")
            
            # Check what's actually in database
            doc = self.metrics_collection.find_one({"_id": metric_name})
            if doc:
                print(f"🔧 Database now shows {metric_name} = {doc.get('count', 0)}")
            else:
                print(f"🔧 No document found for {metric_name}")
                
            return True
            
        except Exception as e:
            print(f"💥 ERROR updating {metric_name}: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_metric_count(self, metric_name: str) -> int:
        """Get current count for a metric"""
        if self.metrics_collection is None:
            return 0
            
        try:
            doc = self.metrics_collection.find_one({"_id": metric_name})
            return doc.get("count", 0) if doc else 0
        except Exception as e:
            logger.error(f"Failed to get metric {metric_name}: {e}")
            return 0
    
    def initialize_metrics(self):
        """Initialize default metrics synchronously"""
        print("🔧 DEBUG: Initializing metrics...")
        if self.metrics_collection is None:
            print("❌ DEBUG: No database connection for metrics initialization")
            logger.error("No database connection for metrics initialization")
            return False
            
        try:
            default_metrics = [
                ("total_checks", "Total number of fraud checks performed"),
                ("fraud_blocked", "Number of transactions blocked as fraud"),
                ("suspicious_flagged", "Number of transactions flagged as suspicious"),
                ("clean_approved", "Number of transactions approved as clean"),
                ("bulk_analyses", "Number of bulk analysis operations"),
                ("api_requests", "Total API requests processed")
            ]
            
            for metric_name, description in default_metrics:
                self.metrics_collection.update_one(
                    {"_id": metric_name},
                    {
                        "$setOnInsert": {
                            "count": 0,
                            "created_at": datetime.now(),
                            "last_updated": datetime.now(),
                            "description": description
                        }
                    },
                    upsert=True
                )
            
            print("✅ DEBUG: Metrics collection initialized synchronously")
            logger.info("✅ Metrics collection initialized synchronously")
            return True
            
        except Exception as e:
            print(f"💥 DEBUG: Failed to initialize metrics: {e}")
            logger.error(f"Failed to initialize metrics: {e}")
            return False


class FraudChecker:
    """Enhanced Fraud Checker with DEBUG LOGGING"""
    
    def __init__(self) -> None:
        """Initialize the fraud checker and load data from MongoDB"""
        print("🔧 DEBUG: Initializing FraudChecker...")
        logger.info("Initializing FraudChecker with guaranteed working metrics...")
        
        # Initialize sets for blacklists
        self.disposable_domains: Set[str] = set()
        self.flagged_ips: Set[str] = set()
        self.suspicious_bins: Set[str] = set()
        self.reused_fingerprints: Set[str] = set()
        self.tampered_prices: Set[float] = set()
        self.rules: Dict[str, Dict] = {}
        
        # MongoDB connection for async operations (data loading)
        try:
            self.mongo = MongoManager()
            print("✅ DEBUG: MongoDB connection established")
            logger.info("MongoDB connection established")
        except Exception as e:
            print(f"❌ DEBUG: Failed to connect to MongoDB: {e}")
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
        
        # Initialize SYNCHRONOUS metrics tracker
        print("🔧 DEBUG: Creating metrics tracker...")
        self.metrics = SyncMetricsTracker()
        self.metrics.initialize_metrics()
        
        # Load data from MongoDB
        try:
            asyncio.run(self._warm_cache())
            print("✅ DEBUG: FraudChecker initialized successfully")
            logger.info("FraudChecker initialized successfully")
            self._log_cache_stats()
        except Exception as e:
            print(f"❌ DEBUG: Failed to initialize FraudChecker: {e}")
            logger.error(f"Failed to initialize FraudChecker: {e}")
            raise

    async def _warm_cache(self):
        """Load blacklists and rules from MongoDB"""
        logger.info("Loading fraud detection data...")
        
        try:
            # Load blacklists
            await self._load_blacklists()
            
            # Load rules
            await self._load_rules()
            
            logger.info("Cache warming completed successfully")
            
        except Exception as e:
            logger.error(f"Cache warming failed: {e}")
            raise

    async def _load_blacklists(self):
        """Load all blacklist collections"""
        blacklist_configs = [
            ("disposable_emails", "domain", "disposable_domains"),
            ("flagged_ips", "ip", "flagged_ips"),
            ("suspicious_bins", "bin", "suspicious_bins"),
            ("reused_fingerprints", "fingerprint", "reused_fingerprints"),
            ("tampered_prices", "price", "tampered_prices")
        ]
        
        for collection_name, field_name, attr_name in blacklist_configs:
            try:
                docs = await self.mongo.get_collection(collection_name).find().to_list(None)
                data_set = set()
                
                for doc in docs:
                    value = doc.get(field_name)
                    if value is not None:
                        # Special handling for prices (convert to float)
                        if attr_name == "tampered_prices":
                            try:
                                data_set.add(float(value))
                            except (ValueError, TypeError):
                                logger.warning(f"Invalid price value: {value}")
                        else:
                            data_set.add(str(value))
                
                setattr(self, attr_name, data_set)
                logger.info(f"Loaded {len(data_set)} items from {collection_name}")
                
            except Exception as e:
                logger.error(f"Failed to load {collection_name}: {e}")
                setattr(self, attr_name, set())  # Empty set as fallback

    async def _load_rules(self):
        """Load fraud detection rules"""
        try:
            rule_docs = await self.mongo.get_collection("rules").find({"enabled": True}).to_list(None)
            self.rules = {}
            
            for rule in rule_docs:
                rule_key = rule.get("rule_key")
                if rule_key:
                    # Ensure weight is a float
                    try:
                        rule["weight"] = float(rule.get("weight", 0))
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid weight for rule {rule_key}, defaulting to 0")
                        rule["weight"] = 0.0
                    
                    self.rules[rule_key] = rule
            
            logger.info(f"Loaded {len(self.rules)} fraud detection rules")
            
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            self.rules = {}

    def _log_cache_stats(self):
        """Log statistics about loaded data"""
        logger.info("=== Fraud Detection Cache Stats ===")
        logger.info(f"Disposable domains: {len(self.disposable_domains)}")
        logger.info(f"Flagged IPs: {len(self.flagged_ips)}")
        logger.info(f"Suspicious BINs: {len(self.suspicious_bins)}")
        logger.info(f"Reused fingerprints: {len(self.reused_fingerprints)}")
        logger.info(f"Tampered prices: {len(self.tampered_prices)}")
        logger.info(f"Active rules: {len(self.rules)}")
        logger.info("================================")

    def _safe_get_rule_weight(self, rule_key: str) -> float:
        """Safely get rule weight with fallback"""
        rule = self.rules.get(rule_key, {})
        weight = rule.get("weight", 0.0)
        
        if not isinstance(weight, (int, float)):
            logger.warning(f"Invalid weight type for rule {rule_key}: {type(weight)}")
            return 0.0
        
        return float(weight)

    def analyze_transaction(self, tx: dict) -> dict:
        """Analyze a single transaction for fraud indicators WITH DEBUG"""
        try:
            print("🔧 DEBUG: About to call increment_metric for total_checks")
            # Increment total checks metric (SYNCHRONOUSLY)
            success = self.metrics.increment_metric("total_checks")
            print(f"🔧 DEBUG: increment_metric for total_checks returned: {success}")
            
            score = 0.0
            reasons = []
            
            # Validate input
            if not isinstance(tx, dict):
                logger.warning("Transaction must be a dictionary")
                return self._create_error_result(tx, "Invalid transaction format")
            
            # Check disposable email
            email = str(tx.get("email", "")).strip().lower()
            if email and "@" in email:
                domain = email.split("@")[-1]
                if domain in self.disposable_domains:
                    weight = self._safe_get_rule_weight("disposable_email")
                    score += weight
                    reasons.append("disposable_email")
                    print(f"🔧 DEBUG: Disposable email detected: {domain}, weight: {weight}")
                    logger.debug(f"Disposable email detected: {domain}")
            
            # Check suspicious BIN
            card_number = str(tx.get("card_number", "")).strip()
            if len(card_number) >= 6:
                bin_number = card_number[:6]
                if bin_number in self.suspicious_bins:
                    weight = self._safe_get_rule_weight("suspicious_bin")
                    score += weight
                    reasons.append("suspicious_bin")
                    print(f"🔧 DEBUG: Suspicious BIN detected: {bin_number}, weight: {weight}")
                    logger.debug(f"Suspicious BIN detected: {bin_number}")
            
            # Check flagged IP
            ip = str(tx.get("ip", "")).strip()
            if ip in self.flagged_ips:
                weight = self._safe_get_rule_weight("flagged_ip")
                score += weight
                reasons.append("flagged_ip")
                print(f"🔧 DEBUG: Flagged IP detected: {ip}, weight: {weight}")
                logger.debug(f"Flagged IP detected: {ip}")
            
            # Check reused fingerprint
            fingerprint = str(tx.get("fingerprint", "")).strip()
            if fingerprint in self.reused_fingerprints:
                weight = self._safe_get_rule_weight("reused_fingerprint")
                score += weight
                reasons.append("reused_fingerprint")
                print(f"🔧 DEBUG: Reused fingerprint detected: {fingerprint}, weight: {weight}")
                logger.debug(f"Reused fingerprint detected: {fingerprint}")
            
            # Check tampered price
            try:
                price = float(tx.get("price", 0))
                if price in self.tampered_prices:
                    weight = self._safe_get_rule_weight("tampered_price")
                    score += weight
                    reasons.append("tampered_price")
                    print(f"🔧 DEBUG: Tampered price detected: {price}, weight: {weight}")
                    logger.debug(f"Tampered price detected: {price}")
            except (ValueError, TypeError):
                logger.warning(f"Invalid price value: {tx.get('price')}")
            
            # Determine decision based on score and update metrics
            print(f"🔧 DEBUG: Final score: {score}, about to determine decision")
            if score >= 0.7:
                decision = "fraud"
                print("🔧 DEBUG: About to call increment_metric for fraud_blocked")
                success = self.metrics.increment_metric("fraud_blocked")
                print(f"🔧 DEBUG: increment_metric for fraud_blocked returned: {success}")
            elif score >= 0.4:
                decision = "suspicious"
                print("🔧 DEBUG: About to call increment_metric for suspicious_flagged")
                success = self.metrics.increment_metric("suspicious_flagged")
                print(f"🔧 DEBUG: increment_metric for suspicious_flagged returned: {success}")
            else:
                decision = "not_fraud"
                print("🔧 DEBUG: About to call increment_metric for clean_approved")
                success = self.metrics.increment_metric("clean_approved")
                print(f"🔧 DEBUG: increment_metric for clean_approved returned: {success}")
            
            result = {
                **tx,
                "fraud_score": round(score, 2),
                "decision": decision,
                "triggered_rules": reasons,
                "analysis_timestamp": datetime.now().isoformat()
            }
            
            print(f"🔧 DEBUG: Transaction analyzed: score={score}, decision={decision}")
            logger.debug(f"Transaction analyzed: score={score}, decision={decision}")
            return result
            
        except Exception as e:
            print(f"💥 DEBUG: Error analyzing transaction: {e}")
            logger.error(f"Error analyzing transaction: {e}")
            logger.error(traceback.format_exc())
            return self._create_error_result(tx, f"Analysis failed: {str(e)}")

    def _create_error_result(self, tx: dict, error_msg: str) -> dict:
        """Create error result for failed analysis"""
        base_tx = tx if isinstance(tx, dict) else {}
        return {
            **base_tx,
            "fraud_score": 0.0,
            "decision": "error",
            "triggered_rules": [],
            "error": error_msg,
            "analysis_timestamp": datetime.now().isoformat()
        }

    def analyze_bulk(self, file_obj) -> List[dict]:
        """Analyze multiple transactions from uploaded file WITH DEBUG"""
        try:
            print(f"🔧 DEBUG: Starting bulk analysis of file: {getattr(file_obj, 'filename', 'unknown')}")
            logger.info(f"Starting bulk analysis of file: {getattr(file_obj, 'filename', 'unknown')}")
            
            # Increment bulk analysis metric
            print("🔧 DEBUG: About to call increment_metric for bulk_analyses")
            success = self.metrics.increment_metric("bulk_analyses")
            print(f"🔧 DEBUG: increment_metric for bulk_analyses returned: {success}")
            
            # Read file into DataFrame
            df = self._read_file_to_dataframe(file_obj)
            
            if df is None or df.empty:
                raise ValueError("File is empty or could not be read")
            
            print(f"🔧 DEBUG: Processing {len(df)} transactions")
            logger.info(f"Processing {len(df)} transactions")
            
            # Analyze each transaction
            results = []
            errors = 0
            
            # Track counts for verification
            fraud_count = 0
            suspicious_count = 0
            clean_count = 0
            
            for index, row in df.iterrows():
                try:
                    # Convert pandas Series to dict and handle NaN values
                    tx_dict = row.to_dict()
                    
                    # Replace NaN values with None or appropriate defaults
                    tx_dict = self._clean_transaction_data(tx_dict)
                    
                    if isinstance(index, int):
                        tx_number = index + 1
                    else:
                        tx_number = index
                    print(f"🔧 DEBUG: Analyzing transaction {tx_number}")
                    result = self.analyze_transaction(tx_dict)
                    results.append(result)
                    
                    # Count results for verification
                    decision = result.get("decision")
                    if decision == "fraud":
                        fraud_count += 1
                    elif decision == "suspicious":
                        suspicious_count += 1
                    elif decision == "not_fraud":
                        clean_count += 1
                    elif decision == "error":
                        errors += 1
                        
                except Exception as e:
                    print(f"💥 DEBUG: Error processing row {index}: {e}")
                    logger.error(f"Error processing row {index}: {e}")
                    error_result = self._create_error_result(
                        {"row_index": index}, 
                        f"Row processing failed: {str(e)}"
                    )
                    results.append(error_result)
                    errors += 1
            
            # Log detailed results for verification
            print(f"🔧 DEBUG: Bulk analysis completed: {len(results)} processed, {errors} errors")
            print(f"🔧 DEBUG: Results breakdown: {fraud_count} fraud, {suspicious_count} suspicious, {clean_count} clean")
            logger.info(f"Bulk analysis completed: {len(results)} processed, {errors} errors")
            logger.info(f"Results breakdown: {fraud_count} fraud, {suspicious_count} suspicious, {clean_count} clean")
            
            # Verify metrics were updated
            total_checks = self.metrics.get_metric_count("total_checks")
            fraud_blocked = self.metrics.get_metric_count("fraud_blocked")
            suspicious_flagged = self.metrics.get_metric_count("suspicious_flagged")
            clean_approved = self.metrics.get_metric_count("clean_approved")
            bulk_analyses = self.metrics.get_metric_count("bulk_analyses")
            
            print(f"📊 DEBUG: CURRENT METRICS IN DATABASE:")
            print(f"   Total checks: {total_checks}")
            print(f"   Fraud blocked: {fraud_blocked}")
            print(f"   Suspicious flagged: {suspicious_flagged}")
            print(f"   Clean approved: {clean_approved}")
            print(f"   Bulk analyses: {bulk_analyses}")
            logger.info(f"📊 CURRENT METRICS IN DATABASE:")
            logger.info(f"   Total checks: {total_checks}")
            logger.info(f"   Fraud blocked: {fraud_blocked}")
            logger.info(f"   Suspicious flagged: {suspicious_flagged}")
            logger.info(f"   Clean approved: {clean_approved}")
            logger.info(f"   Bulk analyses: {bulk_analyses}")
            
            return results
            
        except Exception as e:
            print(f"💥 DEBUG: Bulk analysis failed: {e}")
            logger.error(f"Bulk analysis failed: {e}")
            logger.error(traceback.format_exc())
            raise ValueError(f"Bulk analysis failed: {str(e)}")

    def _read_file_to_dataframe(self, file_obj) -> Optional[pd.DataFrame]:
        """Read uploaded file into pandas DataFrame"""
        try:
            filename = getattr(file_obj, 'filename', '').lower()
            
            # Reset file pointer to beginning
            file_obj.seek(0)
            
            if filename.endswith(('.csv', '.txt')):
                df = pd.read_csv(file_obj)
                logger.info(f"Read CSV file with {len(df)} rows")
                
            elif filename.endswith('.json'):
                df = pd.read_json(file_obj)
                logger.info(f"Read JSON file with {len(df)} rows")
                
            elif filename.endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file_obj)
                logger.info(f"Read Excel file with {len(df)} rows")
                
            else:
                raise ValueError(f"Unsupported file format: {filename}")
            
            # Basic validation
            if df.empty:
                raise ValueError("File contains no data")
            
            logger.info(f"File columns: {list(df.columns)}")
            return df
            
        except Exception as e:
            logger.error(f"Failed to read file: {e}")
            raise ValueError(f"Failed to read file: {str(e)}")

    def _clean_transaction_data(self, tx_dict: dict) -> dict:
        """Clean transaction data and handle missing values"""
        cleaned = {}
        
        for key, value in tx_dict.items():
            # Handle pandas NaN values
            if pd.isna(value):
                cleaned[key] = "" if key in ["email", "ip", "fingerprint"] else 0
            else:
                cleaned[key] = value
        
        return cleaned

    async def get_stats(self) -> dict:
        """Get fraud checker statistics including real metrics"""
        try:
            # Get real metrics from database using synchronous connection
            real_metrics = {}
            if self.metrics.metrics_collection is not None:
                for doc in self.metrics.metrics_collection.find():
                    real_metrics[doc["_id"]] = doc.get("count", 0)
            
            return {
                "cache_stats": {
                    "disposable_domains": len(self.disposable_domains),
                    "flagged_ips": len(self.flagged_ips),
                    "suspicious_bins": len(self.suspicious_bins),
                    "reused_fingerprints": len(self.reused_fingerprints),
                    "tampered_prices": len(self.tampered_prices),
                    "active_rules": len(self.rules)
                },
                "detection_metrics": {
                    "total_checks": real_metrics.get("total_checks", 0),
                    "fraud_blocked": real_metrics.get("fraud_blocked", 0),
                    "suspicious_flagged": real_metrics.get("suspicious_flagged", 0),
                    "clean_approved": real_metrics.get("clean_approved", 0),
                    "bulk_analyses": real_metrics.get("bulk_analyses", 0),
                    "api_requests": real_metrics.get("api_requests", 0)
                },
                "rules": {key: {"weight": rule.get("weight", 0)} for key, rule in self.rules.items()},
                "last_updated": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            # Return fallback stats
            return {
                "cache_stats": {
                    "disposable_domains": len(self.disposable_domains),
                    "flagged_ips": len(self.flagged_ips),
                    "suspicious_bins": len(self.suspicious_bins),
                    "reused_fingerprints": len(self.reused_fingerprints),
                    "tampered_prices": len(self.tampered_prices),
                    "active_rules": len(self.rules)
                },
                "detection_metrics": {
                    "total_checks": 0,
                    "fraud_blocked": 0,
                    "suspicious_flagged": 0,
                    "clean_approved": 0,
                    "bulk_analyses": 0,
                    "api_requests": 0
                },
                "rules": {key: {"weight": rule.get("weight", 0)} for key, rule in self.rules.items()},
                "last_updated": datetime.now().isoformat()
            }


# ============================================================================
# CLI Test Tool
# ============================================================================

if __name__ == "__main__":
    print("🚀 Testing FraudChecker with GUARANTEED working metrics...")
    
    # Install pymongo if not available
    try:
        import pymongo
    except ImportError:
        print("❌ pymongo not installed. Installing...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pymongo"])
        import pymongo
    
    checker = FraudChecker()
    
    # Test single transaction
    test_tx = {
        "email": "test@tempmail.com",  # Should trigger disposable email rule
        "card_number": "123456789012345",  # Should trigger suspicious BIN
        "ip": "203.0.113.45",  # Should trigger flagged IP
        "fingerprint": "fp_abc123",  # Should trigger reused fingerprint
        "price": 0.01  # Should trigger tampered price
    }
    
    print("\n🧪 Testing single transaction:")
    print("BEFORE - Metrics in database:")
    print(f"  Total checks: {checker.metrics.get_metric_count('total_checks')}")
    print(f"  Fraud blocked: {checker.metrics.get_metric_count('fraud_blocked')}")
    
    result = checker.analyze_transaction(test_tx)
    print(f"Result: {result}")
    
    print("\nAFTER - Metrics in database:")
    print(f"  Total checks: {checker.metrics.get_metric_count('total_checks')}")
    print(f"  Fraud blocked: {checker.metrics.get_metric_count('fraud_blocked')}")
    
    print("\n📊 Metrics should now be updated in the database!")
    print("Run: python db/init_metrics.py show")