# logic/fraud_checker.py - Enhanced with Dynamic Thresholds
import sys
import os
import asyncio
import logging
import json
from typing import Dict, List, Set, Optional, Union
import pandas as pd
from datetime import datetime
import traceback

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from db.mongo import MongoManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FraudChecker:
    """Enhanced Fraud Checker with dynamic thresholds and better error handling"""
    
    def __init__(self) -> None:
        """Initialize the fraud checker and load data from MongoDB"""
        logger.info("Initializing FraudChecker...")
        
        # Initialize sets for blacklists
        self.disposable_domains: Set[str] = set()
        self.flagged_ips: Set[str] = set()
        self.suspicious_bins: Set[str] = set()
        self.reused_fingerprints: Set[str] = set()
        self.tampered_prices: Set[float] = set()
        self.rules: Dict[str, Dict] = {}
        
        # Dynamic thresholds (can be updated via API)
        self.fraud_threshold: float = 0.7
        self.suspicious_threshold: float = 0.4
        
        # MongoDB connection
        try:
            self.mongo = MongoManager()
            logger.info("MongoDB connection established")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
        
        # Load data from MongoDB
        try:
            asyncio.run(self._warm_cache())
            logger.info("FraudChecker initialized successfully")
            self._log_cache_stats()
        except Exception as e:
            logger.error(f"Failed to initialize FraudChecker: {e}")
            raise

    def update_thresholds(self, fraud_threshold: float, suspicious_threshold: float) -> None:
        """
        Update fraud detection thresholds.
        
        Args:
            fraud_threshold: New fraud threshold (0.0 to 1.0)
            suspicious_threshold: New suspicious threshold (0.0 to 1.0)
        """
        if not (0 <= fraud_threshold <= 1) or not (0 <= suspicious_threshold <= 1):
            raise ValueError("Thresholds must be between 0 and 1")
        
        if suspicious_threshold >= fraud_threshold:
            raise ValueError("Suspicious threshold must be less than fraud threshold")
        
        self.fraud_threshold = fraud_threshold
        self.suspicious_threshold = suspicious_threshold
        
        logger.info(f"Thresholds updated: fraud={fraud_threshold}, suspicious={suspicious_threshold}")

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
        logger.info(f"Current thresholds: fraud={self.fraud_threshold}, suspicious={self.suspicious_threshold}")
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
        """Analyze a single transaction for fraud indicators"""
        try:
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
                    logger.debug(f"Disposable email detected: {domain}")
            
            # Check suspicious BIN
            card_number = str(tx.get("card_number", "")).strip()
            if len(card_number) >= 6:
                bin_number = card_number[:6]
                if bin_number in self.suspicious_bins:
                    weight = self._safe_get_rule_weight("suspicious_bin")
                    score += weight
                    reasons.append("suspicious_bin")
                    logger.debug(f"Suspicious BIN detected: {bin_number}")
            
            # Check flagged IP
            ip = str(tx.get("ip", "")).strip()
            if ip in self.flagged_ips:
                weight = self._safe_get_rule_weight("flagged_ip")
                score += weight
                reasons.append("flagged_ip")
                logger.debug(f"Flagged IP detected: {ip}")
            
            # Check reused fingerprint
            fingerprint = str(tx.get("fingerprint", "")).strip()
            if fingerprint in self.reused_fingerprints:
                weight = self._safe_get_rule_weight("reused_fingerprint")
                score += weight
                reasons.append("reused_fingerprint")
                logger.debug(f"Reused fingerprint detected: {fingerprint}")
            
            # Check tampered price
            try:
                price = float(tx.get("price", 0))
                if price in self.tampered_prices:
                    weight = self._safe_get_rule_weight("tampered_price")
                    score += weight
                    reasons.append("tampered_price")
                    logger.debug(f"Tampered price detected: {price}")
            except (ValueError, TypeError):
                logger.warning(f"Invalid price value: {tx.get('price')}")
            
            # Determine decision based on current thresholds
            if score >= self.fraud_threshold:
                decision = "fraud"
            elif score >= self.suspicious_threshold:
                decision = "suspicious"
            else:
                decision = "not_fraud"
            
            result = {
                **tx,
                "fraud_score": round(score, 2),
                "decision": decision,
                "triggered_rules": reasons,
                "analysis_timestamp": datetime.now().isoformat(),
                "thresholds_used": {
                    "fraud_threshold": self.fraud_threshold,
                    "suspicious_threshold": self.suspicious_threshold
                }
            }
            
            logger.debug(f"Transaction analyzed: score={score}, decision={decision}")
            return result
            
        except Exception as e:
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
            "analysis_timestamp": datetime.now().isoformat(),
            "thresholds_used": {
                "fraud_threshold": self.fraud_threshold,
                "suspicious_threshold": self.suspicious_threshold
            }
        }

    def analyze_bulk(self, file_obj, fraud_threshold=None, suspicious_threshold=None) -> List[dict]:
        """Analyze multiple transactions from uploaded file with optional threshold override"""
        try:
            logger.info(f"Starting bulk analysis of file: {getattr(file_obj, 'filename', 'unknown')}")
            
            # Temporarily override thresholds if provided
            original_fraud_threshold = self.fraud_threshold
            original_suspicious_threshold = self.suspicious_threshold
            
            if fraud_threshold is not None:
                self.fraud_threshold = fraud_threshold
            if suspicious_threshold is not None:
                self.suspicious_threshold = suspicious_threshold
            
            try:
                # Read file into DataFrame
                df = self._read_file_to_dataframe(file_obj)
                
                if df is None or df.empty:
                    raise ValueError("File is empty or could not be read")
                
                logger.info(f"Processing {len(df)} transactions with thresholds: fraud={self.fraud_threshold}, suspicious={self.suspicious_threshold}")
                
                # Analyze each transaction
                results = []
                errors = 0
                
                for index, row in df.iterrows():
                    try:
                        # Convert pandas Series to dict and handle NaN values
                        tx_dict = row.to_dict()
                        
                        # Replace NaN values with None or appropriate defaults
                        tx_dict = self._clean_transaction_data(tx_dict)
                        
                        result = self.analyze_transaction(tx_dict)
                        results.append(result)
                        
                        if result.get("decision") == "error":
                            errors += 1
                            
                    except Exception as e:
                        logger.error(f"Error processing row {index}: {e}")
                        error_result = self._create_error_result(
                            {"row_index": index}, 
                            f"Row processing failed: {str(e)}"
                        )
                        results.append(error_result)
                        errors += 1
                
                logger.info(f"Bulk analysis completed: {len(results)} processed, {errors} errors")
                return results
                
            finally:
                # Restore original thresholds
                self.fraud_threshold = original_fraud_threshold
                self.suspicious_threshold = original_suspicious_threshold
                
        except Exception as e:
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

    def get_stats(self) -> dict:
        """Get fraud checker statistics"""
        return {
            "cache_stats": {
                "disposable_domains": len(self.disposable_domains),
                "flagged_ips": len(self.flagged_ips),
                "suspicious_bins": len(self.suspicious_bins),
                "reused_fingerprints": len(self.reused_fingerprints),
                "tampered_prices": len(self.tampered_prices),
                "active_rules": len(self.rules)
            },
            "current_thresholds": {
                "fraud_threshold": self.fraud_threshold,
                "suspicious_threshold": self.suspicious_threshold
            },
            "rules": {key: {"weight": rule.get("weight", 0)} for key, rule in self.rules.items()},
            "last_updated": datetime.now().isoformat()
        }


# ============================================================================
# CLI Test Tool
# ============================================================================

def test_file_analysis(file_path: str):
    """Test fraud checker with a file"""
    try:
        logger.info(f"Testing file: {file_path}")
        
        # Initialize fraud checker
        checker = FraudChecker()
        
        # Create file-like object for testing
        class FileWrapper:
            def __init__(self, file_path):
                self.filename = os.path.basename(file_path)
                self._file = open(file_path, 'rb')
            
            def seek(self, pos, whence=0):
                return self._file.seek(pos, whence)
            
            def read(self, size=-1):
                return self._file.read(size)
            
            def __enter__(self):
                return self
            
            def __exit__(self, exc_type, exc_val, exc_tb):
                self._file.close()
        
        # Test the analysis
        with FileWrapper(file_path) as file_obj:
            results = checker.analyze_bulk(file_obj)
        
        # Print results
        print("\n=== FRAUD ANALYSIS RESULTS ===")
        print(f"Total transactions analyzed: {len(results)}")
        
        # Count decisions
        decision_counts = {}
        for result in results:
            decision = result.get("decision", "unknown")
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
        
        print(f"Decision breakdown: {decision_counts}")
        print(f"Thresholds used: fraud={checker.fraud_threshold}, suspicious={checker.suspicious_threshold}")
        
        # Show first 5 results
        print(f"\nFirst {min(5, len(results))} results:")
        print(json.dumps(results[:5], indent=2, default=str))
        
        if len(results) > 5:
            print(f"\n... and {len(results) - 5} more")
        
        # Show statistics
        stats = checker.get_stats()
        print(f"\nFraud Checker Stats:")
        print(json.dumps(stats["cache_stats"], indent=2))
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        logger.error(traceback.format_exc())
        return False
    
    return True


# CLI entry point
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m logic.fraud_checker <path/to/file>")
        print("Example: python -m logic.fraud_checker test_data.csv")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist")
        sys.exit(1)
    
    success = test_file_analysis(file_path)
    sys.exit(0 if success else 1)