# logic/fraud_checker.py - ENHANCED VERSION WITH ADVANCED ALGORITHMS

import sys
import os
import asyncio
import logging
import json
import re
import hashlib
from typing import Dict, List, Set, Optional, Union, Tuple
import pandas as pd
from datetime import datetime, timedelta
import traceback
import pymongo
from collections import defaultdict, Counter
import math
import ipaddress

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
                ("api_requests", "Total API requests processed"),
                ("velocity_alerts", "Velocity-based fraud alerts"),
                ("pattern_anomalies", "Pattern anomaly detections"),
                ("geo_anomalies", "Geographic anomaly detections"),
                ("behavioral_alerts", "Behavioral pattern alerts")
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
    """Enhanced Fraud Checker with ADVANCED ALGORITHMS and DEBUG LOGGING"""
    
    def __init__(self) -> None:
        """Initialize the fraud checker and load data from MongoDB"""
        print("🔧 DEBUG: Initializing FraudChecker with advanced algorithms...")
        logger.info("Initializing FraudChecker with guaranteed working metrics...")
        
        # Initialize sets for blacklists
        self.disposable_domains: Set[str] = set()
        self.flagged_ips: Set[str] = set()
        self.suspicious_bins: Set[str] = set()
        self.reused_fingerprints: Set[str] = set()
        self.tampered_prices: Set[float] = set()
        self.rules: Dict[str, Dict] = {}
        
        # Advanced algorithm caches
        self.transaction_history: Dict[str, List[Dict]] = defaultdict(list)
        self.ip_reputation_cache: Dict[str, float] = {}
        self.email_patterns: Dict[str, int] = defaultdict(int)
        self.velocity_cache: Dict[str, List[datetime]] = defaultdict(list)
        self.behavioral_profiles: Dict[str, Dict] = {}
        self.geo_patterns: Dict[str, List[Tuple]] = defaultdict(list)
        
        # Risk scoring weights for advanced algorithms
        self.advanced_weights = {
            'velocity_abuse': 0.3,
            'suspicious_patterns': 0.25,
            'geo_anomaly': 0.2,
            'behavioral_deviation': 0.15,
            'network_analysis': 0.1,
            'time_pattern_anomaly': 0.1,
            'amount_clustering': 0.05
        }
        
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
            
            # Load transaction history for advanced algorithms
            await self._load_transaction_history()
            
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

    async def _load_transaction_history(self):
        """Load recent transaction history for advanced pattern analysis"""
        try:
            # Load last 30 days of transactions for pattern analysis
            cutoff_date = datetime.now() - timedelta(days=30)
            
            transactions = await self.mongo.get_collection("transactions").find({
                "timestamp": {"$gte": cutoff_date}
            }).to_list(None)
            
            for tx in transactions:
                email = tx.get("email", "")
                if email:
                    self.transaction_history[email].append(tx)
            
            logger.info(f"Loaded transaction history for {len(self.transaction_history)} users")
            
        except Exception as e:
            logger.error(f"Failed to load transaction history: {e}")

    def _log_cache_stats(self):
        """Log statistics about loaded data"""
        logger.info("=== Fraud Detection Cache Stats ===")
        logger.info(f"Disposable domains: {len(self.disposable_domains)}")
        logger.info(f"Flagged IPs: {len(self.flagged_ips)}")
        logger.info(f"Suspicious BINs: {len(self.suspicious_bins)}")
        logger.info(f"Reused fingerprints: {len(self.reused_fingerprints)}")
        logger.info(f"Tampered prices: {len(self.tampered_prices)}")
        logger.info(f"Active rules: {len(self.rules)}")
        logger.info(f"User histories: {len(self.transaction_history)}")
        logger.info("================================")

    def _safe_get_rule_weight(self, rule_key: str) -> float:
        """Safely get rule weight with fallback"""
        rule = self.rules.get(rule_key, {})
        weight = rule.get("weight", 0.0)
        
        if not isinstance(weight, (int, float)):
            logger.warning(f"Invalid weight type for rule {rule_key}: {type(weight)}")
            return 0.0
        
        return float(weight)

    # ============================================================================
    # ADVANCED ALGORITHM METHODS
    # ============================================================================

    def _analyze_velocity_patterns(self, tx: dict) -> Tuple[float, List[str]]:
        """Advanced velocity analysis with multiple time windows"""
        reasons = []
        score = 0.0
        
        email = tx.get("email", "").strip().lower()
        current_time = datetime.now()
        
        if not email:
            return score, reasons
        
        # Update velocity cache
        self.velocity_cache[email].append(current_time)
        
        # Analyze different time windows
        time_windows = {
            "1_minute": timedelta(minutes=1),
            "5_minutes": timedelta(minutes=5),
            "1_hour": timedelta(hours=1),
            "1_day": timedelta(days=1)
        }
        
        thresholds = {
            "1_minute": 3,
            "5_minutes": 5,
            "1_hour": 10,
            "1_day": 50
        }
        
        for window_name, window_delta in time_windows.items():
            cutoff = current_time - window_delta
            recent_txs = [t for t in self.velocity_cache[email] if t >= cutoff]
            
            threshold = thresholds[window_name]
            if len(recent_txs) > threshold:
                velocity_score = min(0.3, (len(recent_txs) - threshold) * 0.05)
                score += velocity_score
                reasons.append(f"velocity_abuse_{window_name}")
                print(f"🔧 DEBUG: Velocity abuse detected in {window_name}: {len(recent_txs)} txs")
        
        # Clean old entries (keep last 24 hours)
        cutoff_24h = current_time - timedelta(hours=24)
        self.velocity_cache[email] = [t for t in self.velocity_cache[email] if t >= cutoff_24h]
        
        return score, reasons

    def _analyze_behavioral_patterns(self, tx: dict) -> Tuple[float, List[str]]:
        """Analyze behavioral deviations from user's normal patterns"""
        reasons = []
        score = 0.0
        
        email = tx.get("email", "").strip().lower()
        if not email or email not in self.transaction_history:
            return score, reasons
        
        user_history = self.transaction_history[email]
        if len(user_history) < 3:  # Need minimum history
            return score, reasons
        
        current_amount = float(tx.get("price", 0))
        current_hour = datetime.now().hour
        current_ip = tx.get("ip", "")
        
        # Analyze amount patterns
        historical_amounts = [float(h.get("price", 0)) for h in user_history]
        avg_amount = sum(historical_amounts) / len(historical_amounts)
        std_amount = math.sqrt(sum((x - avg_amount) ** 2 for x in historical_amounts) / len(historical_amounts))
        
        if std_amount > 0 and abs(current_amount - avg_amount) > 3 * std_amount:
            score += 0.15
            reasons.append("unusual_amount_pattern")
            print(f"🔧 DEBUG: Unusual amount pattern: {current_amount} vs avg {avg_amount:.2f}")
        
        # Analyze time patterns
        historical_hours = [datetime.fromisoformat(h.get("timestamp", "")).hour 
                           for h in user_history if h.get("timestamp")]
        if historical_hours:
            hour_counts = Counter(historical_hours)
            if hour_counts[current_hour] == 0 and len(historical_hours) > 5:
                score += 0.1
                reasons.append("unusual_time_pattern")
                print(f"🔧 DEBUG: Unusual time pattern: hour {current_hour}")
        
        # Analyze IP patterns
        historical_ips = set(h.get("ip", "") for h in user_history)
        if current_ip and current_ip not in historical_ips and len(historical_ips) < 3:
            score += 0.1
            reasons.append("new_ip_pattern")
            print(f"🔧 DEBUG: New IP pattern: {current_ip}")
        
        return score, reasons

    def _analyze_geographic_anomalies(self, tx: dict) -> Tuple[float, List[str]]:
        """Detect impossible geographic travel patterns"""
        reasons = []
        score = 0.0
        
        email = tx.get("email", "").strip().lower()
        current_ip = tx.get("ip", "")
        
        if not email or not current_ip:
            return score, reasons
        
        # Simple geographic analysis (in production, use GeoIP database)
        current_time = datetime.now()
        
        if email in self.geo_patterns:
            last_location_data = self.geo_patterns[email][-1] if self.geo_patterns[email] else None
            
            if last_location_data:
                last_ip, last_time = last_location_data
                time_diff = (current_time - last_time).total_seconds() / 3600  # hours
                
                # Simple check: if IP subnet changes too quickly
                if self._get_ip_subnet(current_ip) != self._get_ip_subnet(last_ip) and time_diff < 1:
                    score += 0.2
                    reasons.append("impossible_travel")
                    print(f"🔧 DEBUG: Impossible travel detected: {last_ip} -> {current_ip} in {time_diff:.2f}h")
        
        # Update geo patterns
        self.geo_patterns[email].append((current_ip, current_time))
        
        # Keep only last 10 locations per user
        if len(self.geo_patterns[email]) > 10:
            self.geo_patterns[email] = self.geo_patterns[email][-10:]
        
        return score, reasons

    def _get_ip_subnet(self, ip: str) -> str:
        """Get IP subnet for basic geographic comparison"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                # Class B subnet
                return str(ipaddress.ip_network(f"{ip}/16", strict=False))
            else:
                # IPv6 /64 subnet
                return str(ipaddress.ip_network(f"{ip}/64", strict=False))
        except:
            return ip  # Fallback to original IP

    def _analyze_network_patterns(self, tx: dict) -> Tuple[float, List[str]]:
        """Analyze network-level fraud indicators"""
        reasons = []
        score = 0.0
        
        ip = tx.get("ip", "")
        if not ip:
            return score, reasons
        
        # Check for suspicious IP patterns
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private/local IPs in production environment
            if ip_obj.is_private or ip_obj.is_loopback:
                score += 0.1
                reasons.append("private_ip_usage")
                print(f"🔧 DEBUG: Private IP detected: {ip}")
            
            # Check for known VPN/Proxy ranges (simplified)
            if self._is_known_proxy_range(ip):
                score += 0.15
                reasons.append("proxy_ip_detected")
                print(f"🔧 DEBUG: Proxy IP detected: {ip}")
                
        except ValueError:
            score += 0.05
            reasons.append("invalid_ip_format")
            print(f"🔧 DEBUG: Invalid IP format: {ip}")
        
        return score, reasons

    def _is_known_proxy_range(self, ip: str) -> bool:
        """Check if IP belongs to known proxy/VPN ranges (simplified)"""
        # In production, use proper proxy/VPN detection service
        proxy_ranges = [
            "10.0.0.0/8",
            "192.168.0.0/16",
            "172.16.0.0/12"
        ]
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for range_str in proxy_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
        except:
            pass
        
        return False

    def _analyze_email_patterns(self, tx: dict) -> Tuple[float, List[str]]:
        """Advanced email pattern analysis"""
        reasons = []
        score = 0.0
        
        email = tx.get("email", "").strip().lower()
        if not email or "@" not in email:
            return score, reasons
        
        local_part, domain = email.split("@", 1)
        
        # Pattern 1: Sequential/numbered emails
        if re.search(r'\d{3,}', local_part):
            score += 0.1
            reasons.append("numbered_email_pattern")
            print(f"🔧 DEBUG: Numbered email pattern: {email}")
        
        # Pattern 2: Random-looking local parts
        if len(local_part) > 8 and not re.search(r'[aeiou]', local_part):
            score += 0.05
            reasons.append("random_email_pattern")
            print(f"🔧 DEBUG: Random email pattern: {email}")
        
        # Pattern 3: Plus addressing abuse
        if '+' in local_part and local_part.count('+') > 1:
            score += 0.1
            reasons.append("plus_addressing_abuse")
            print(f"🔧 DEBUG: Plus addressing abuse: {email}")
        
        # Pattern 4: Recently created patterns
        creation_patterns = ["2024", "2025", "new", "temp"]
        if any(pattern in local_part for pattern in creation_patterns):
            score += 0.05
            reasons.append("recent_creation_pattern")
            print(f"🔧 DEBUG: Recent creation pattern: {email}")
        
        return score, reasons

    def _analyze_amount_clustering(self, tx: dict) -> Tuple[float, List[str]]:
        """Detect suspicious amount clustering patterns"""
        reasons = []
        score = 0.0
        
        current_amount = float(tx.get("price", 0))
        
        # Check for common fraud amounts
        fraud_amounts = [0.01, 1.00, 9.99, 99.99, 999.99]
        if current_amount in fraud_amounts:
            score += 0.05
            reasons.append("common_fraud_amount")
            print(f"🔧 DEBUG: Common fraud amount: {current_amount}")
        
        # Check for round number patterns
        if current_amount > 10 and current_amount % 100 == 0:
            score += 0.03
            reasons.append("round_amount_pattern")
            print(f"🔧 DEBUG: Round amount pattern: {current_amount}")
        
        return score, reasons

    def _calculate_composite_risk_score(self, base_score: float, advanced_scores: Dict[str, float]) -> float:
        """Calculate composite risk score using weighted combination"""
        total_advanced_score = 0.0
        
        for algorithm, score in advanced_scores.items():
            weight = self.advanced_weights.get(algorithm, 0.1)
            total_advanced_score += score * weight
        
        # Combine base score with advanced algorithms using weighted average
        # Base score has 60% weight, advanced algorithms have 40% weight
        composite_score = (base_score * 0.6) + (total_advanced_score * 0.4)
        
        # Apply sigmoid normalization to keep score between 0 and 1
        normalized_score = 1 / (1 + math.exp(-5 * (composite_score - 0.5)))
        
        return min(normalized_score, 1.0)

    # ============================================================================
    # MAIN ANALYSIS METHOD (ENHANCED)
    # ============================================================================

    def analyze_transaction(self, tx: dict) -> dict:
        """Analyze a single transaction for fraud indicators WITH ADVANCED ALGORITHMS"""
        try:
            print("🔧 DEBUG: About to call increment_metric for total_checks")
            # Increment total checks metric (SYNCHRONOUSLY)
            success = self.metrics.increment_metric("total_checks")
            print(f"🔧 DEBUG: increment_metric for total_checks returned: {success}")
            
            base_score = 0.0
            reasons = []
            advanced_scores = {}
            all_advanced_reasons = []
            
            # Validate input
            if not isinstance(tx, dict):
                logger.warning("Transaction must be a dictionary")
                return self._create_error_result(tx, "Invalid transaction format")
            
            # === BASIC FRAUD CHECKS (ORIGINAL) ===
            
            # Check disposable email
            email = str(tx.get("email", "")).strip().lower()
            if email and "@" in email:
                domain = email.split("@")[-1]
                if domain in self.disposable_domains:
                    weight = self._safe_get_rule_weight("disposable_email")
                    base_score += weight
                    reasons.append("disposable_email")
                    print(f"🔧 DEBUG: Disposable email detected: {domain}, weight: {weight}")
                    logger.debug(f"Disposable email detected: {domain}")
            
            # Check suspicious BIN
            card_number = str(tx.get("card_number", "")).strip()
            if len(card_number) >= 6:
                bin_number = card_number[:6]
                if bin_number in self.suspicious_bins:
                    weight = self._safe_get_rule_weight("suspicious_bin")
                    base_score += weight
                    reasons.append("suspicious_bin")
                    print(f"🔧 DEBUG: Suspicious BIN detected: {bin_number}, weight: {weight}")
                    logger.debug(f"Suspicious BIN detected: {bin_number}")
            
            # Check flagged IP
            ip = str(tx.get("ip", "")).strip()
            if ip in self.flagged_ips:
                weight = self._safe_get_rule_weight("flagged_ip")
                base_score += weight
                reasons.append("flagged_ip")
                print(f"🔧 DEBUG: Flagged IP detected: {ip}, weight: {weight}")
                logger.debug(f"Flagged IP detected: {ip}")
            
            # Check reused fingerprint
            fingerprint = str(tx.get("fingerprint", "")).strip()
            if fingerprint in self.reused_fingerprints:
                weight = self._safe_get_rule_weight("reused_fingerprint")
                base_score += weight
                reasons.append("reused_fingerprint")
                print(f"🔧 DEBUG: Reused fingerprint detected: {fingerprint}, weight: {weight}")
                logger.debug(f"Reused fingerprint detected: {fingerprint}")
            
            # Check tampered price
            try:
                price = float(tx.get("price", 0))
                if price in self.tampered_prices:
                    weight = self._safe_get_rule_weight("tampered_price")
                    base_score += weight
                    reasons.append("tampered_price")
                    print(f"🔧 DEBUG: Tampered price detected: {price}, weight: {weight}")
                    logger.debug(f"Tampered price detected: {price}")
            except (ValueError, TypeError):
                logger.warning(f"Invalid price value: {tx.get('price')}")
            
            # === ADVANCED ALGORITHM CHECKS ===
            
            print("🔧 DEBUG: Running advanced fraud algorithms...")
            
            # 1. Velocity Pattern Analysis
            velocity_score, velocity_reasons = self._analyze_velocity_patterns(tx)
            if velocity_score > 0:
                advanced_scores['velocity_abuse'] = velocity_score
                all_advanced_reasons.extend(velocity_reasons)
                self.metrics.increment_metric("velocity_alerts")
            
            # 2. Behavioral Pattern Analysis
            behavioral_score, behavioral_reasons = self._analyze_behavioral_patterns(tx)
            if behavioral_score > 0:
                advanced_scores['behavioral_deviation'] = behavioral_score
                all_advanced_reasons.extend(behavioral_reasons)
                self.metrics.increment_metric("behavioral_alerts")
            
            # 3. Geographic Anomaly Detection
            geo_score, geo_reasons = self._analyze_geographic_anomalies(tx)
            if geo_score > 0:
                advanced_scores['geo_anomaly'] = geo_score
                all_advanced_reasons.extend(geo_reasons)
                self.metrics.increment_metric("geo_anomalies")
            
            # 4. Network Pattern Analysis
            network_score, network_reasons = self._analyze_network_patterns(tx)
            if network_score > 0:
                advanced_scores['network_analysis'] = network_score
                all_advanced_reasons.extend(network_reasons)
            
            # 5. Email Pattern Analysis
            email_score, email_reasons = self._analyze_email_patterns(tx)
            if email_score > 0:
                advanced_scores['suspicious_patterns'] = email_score
                all_advanced_reasons.extend(email_reasons)
                self.metrics.increment_metric("pattern_anomalies")
            
            # 6. Amount Clustering Analysis
            amount_score, amount_reasons = self._analyze_amount_clustering(tx)
            if amount_score > 0:
                advanced_scores['amount_clustering'] = amount_score
                all_advanced_reasons.extend(amount_reasons)
            
            # Calculate composite risk score
            composite_score = self._calculate_composite_risk_score(base_score, advanced_scores)
            
            # Combine all reasons
            all_reasons = reasons + all_advanced_reasons
            
            # Determine decision based on composite score and update metrics
            print(f"🔧 DEBUG: Base score: {base_score}, Composite score: {composite_score}")
            print(f"🔧 DEBUG: Advanced scores: {advanced_scores}")
            
            if composite_score >= 0.7:
                decision = "fraud"
                print("🔧 DEBUG: About to call increment_metric for fraud_blocked")
                success = self.metrics.increment_metric("fraud_blocked")
                print(f"🔧 DEBUG: increment_metric for fraud_blocked returned: {success}")
            elif composite_score >= 0.4:
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
                "fraud_score": round(composite_score, 3),
                "base_score": round(base_score, 3),
                "advanced_scores": {k: round(v, 3) for k, v in advanced_scores.items()},
                "decision": decision,
                "triggered_rules": all_reasons,
                "analysis_timestamp": datetime.now().isoformat(),
                "algorithm_version": "2.0_advanced"
            }
            
            print(f"🔧 DEBUG: Transaction analyzed: composite_score={composite_score:.3f}, decision={decision}")
            print(f"🔧 DEBUG: Advanced algorithms triggered: {list(advanced_scores.keys())}")
            logger.debug(f"Transaction analyzed: score={composite_score:.3f}, decision={decision}")
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
            "base_score": 0.0,
            "advanced_scores": {},
            "decision": "error",
            "triggered_rules": [],
            "error": error_msg,
            "analysis_timestamp": datetime.now().isoformat(),
            "algorithm_version": "2.0_advanced"
        }

    def analyze_bulk(self, file_obj) -> List[dict]:
        """Analyze multiple transactions from uploaded file WITH ADVANCED ALGORITHMS"""
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
            
            print(f"🔧 DEBUG: Processing {len(df)} transactions with advanced algorithms")
            logger.info(f"Processing {len(df)} transactions with advanced algorithms")
            
            # Analyze each transaction
            results = []
            errors = 0
            
            # Track counts for verification
            fraud_count = 0
            suspicious_count = 0
            clean_count = 0
            advanced_detections = defaultdict(int)
            
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
                    print(f"🔧 DEBUG: Analyzing transaction {tx_number} with advanced algorithms")
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
                    
                    # Count advanced algorithm detections
                    for algo in result.get("advanced_scores", {}):
                        advanced_detections[algo] += 1
                        
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
            print(f"🔧 DEBUG: Advanced bulk analysis completed: {len(results)} processed, {errors} errors")
            print(f"🔧 DEBUG: Results breakdown: {fraud_count} fraud, {suspicious_count} suspicious, {clean_count} clean")
            print(f"🔧 DEBUG: Advanced detections: {dict(advanced_detections)}")
            logger.info(f"Advanced bulk analysis completed: {len(results)} processed, {errors} errors")
            logger.info(f"Results breakdown: {fraud_count} fraud, {suspicious_count} suspicious, {clean_count} clean")
            logger.info(f"Advanced algorithm detections: {dict(advanced_detections)}")
            
            # Verify metrics were updated
            total_checks = self.metrics.get_metric_count("total_checks")
            fraud_blocked = self.metrics.get_metric_count("fraud_blocked")
            suspicious_flagged = self.metrics.get_metric_count("suspicious_flagged")
            clean_approved = self.metrics.get_metric_count("clean_approved")
            bulk_analyses = self.metrics.get_metric_count("bulk_analyses")
            velocity_alerts = self.metrics.get_metric_count("velocity_alerts")
            pattern_anomalies = self.metrics.get_metric_count("pattern_anomalies")
            geo_anomalies = self.metrics.get_metric_count("geo_anomalies")
            behavioral_alerts = self.metrics.get_metric_count("behavioral_alerts")
            
            print(f"📊 DEBUG: CURRENT METRICS IN DATABASE:")
            print(f"   Total checks: {total_checks}")
            print(f"   Fraud blocked: {fraud_blocked}")
            print(f"   Suspicious flagged: {suspicious_flagged}")
            print(f"   Clean approved: {clean_approved}")
            print(f"   Bulk analyses: {bulk_analyses}")
            print(f"   Velocity alerts: {velocity_alerts}")
            print(f"   Pattern anomalies: {pattern_anomalies}")
            print(f"   Geo anomalies: {geo_anomalies}")
            print(f"   Behavioral alerts: {behavioral_alerts}")
            
            return results
            
        except Exception as e:
            print(f"💥 DEBUG: Advanced bulk analysis failed: {e}")
            logger.error(f"Advanced bulk analysis failed: {e}")
            logger.error(traceback.format_exc())
            raise ValueError(f"Advanced bulk analysis failed: {str(e)}")

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
        """Get fraud checker statistics including real metrics and advanced algorithm stats"""
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
                    "active_rules": len(self.rules),
                    "user_histories": len(self.transaction_history),
                    "velocity_cache_size": len(self.velocity_cache),
                    "geo_patterns_size": len(self.geo_patterns)
                },
                "detection_metrics": {
                    "total_checks": real_metrics.get("total_checks", 0),
                    "fraud_blocked": real_metrics.get("fraud_blocked", 0),
                    "suspicious_flagged": real_metrics.get("suspicious_flagged", 0),
                    "clean_approved": real_metrics.get("clean_approved", 0),
                    "bulk_analyses": real_metrics.get("bulk_analyses", 0),
                    "api_requests": real_metrics.get("api_requests", 0),
                    "velocity_alerts": real_metrics.get("velocity_alerts", 0),
                    "pattern_anomalies": real_metrics.get("pattern_anomalies", 0),
                    "geo_anomalies": real_metrics.get("geo_anomalies", 0),
                    "behavioral_alerts": real_metrics.get("behavioral_alerts", 0)
                },
                "algorithm_info": {
                    "version": "2.0_advanced",
                    "enabled_algorithms": list(self.advanced_weights.keys()),
                    "algorithm_weights": self.advanced_weights
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
                    "active_rules": len(self.rules),
                    "user_histories": len(self.transaction_history),
                    "velocity_cache_size": len(self.velocity_cache),
                    "geo_patterns_size": len(self.geo_patterns)
                },
                "detection_metrics": {
                    "total_checks": 0,
                    "fraud_blocked": 0,
                    "suspicious_flagged": 0,
                    "clean_approved": 0,
                    "bulk_analyses": 0,
                    "api_requests": 0,
                    "velocity_alerts": 0,
                    "pattern_anomalies": 0,
                    "geo_anomalies": 0,
                    "behavioral_alerts": 0
                },
                "algorithm_info": {
                    "version": "2.0_advanced",
                    "enabled_algorithms": list(self.advanced_weights.keys()),
                    "algorithm_weights": self.advanced_weights
                },
                "rules": {key: {"weight": rule.get("weight", 0)} for key, rule in self.rules.items()},
                "last_updated": datetime.now().isoformat()
            }


# ============================================================================
# CLI Test Tool
# ============================================================================

if __name__ == "__main__":
    print("🚀 Testing Enhanced FraudChecker with ADVANCED ALGORITHMS...")
    
    # Install pymongo if not available
    try:
        import pymongo
    except ImportError:
        print("❌ pymongo not installed. Installing...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pymongo"])
        import pymongo
    
    checker = FraudChecker()
    
    # Test single transaction with multiple fraud indicators
    test_tx = {
        "email": "user123456@tempmail.com",  # Should trigger disposable email + numbered pattern
        "card_number": "123456789012345",    # Should trigger suspicious BIN
        "ip": "203.0.113.45",               # Should trigger flagged IP + network analysis
        "fingerprint": "fp_abc123",         # Should trigger reused fingerprint
        "price": 0.01                       # Should trigger tampered price + fraud amount
    }
    
    print("\n🧪 Testing single transaction with advanced algorithms:")
    print("BEFORE - Metrics in database:")
    print(f"  Total checks: {checker.metrics.get_metric_count('total_checks')}")
    print(f"  Fraud blocked: {checker.metrics.get_metric_count('fraud_blocked')}")
    print(f"  Velocity alerts: {checker.metrics.get_metric_count('velocity_alerts')}")
    print(f"  Pattern anomalies: {checker.metrics.get_metric_count('pattern_anomalies')}")
    
    result = checker.analyze_transaction(test_tx)
    print(f"\nAdvanced Analysis Result:")
    print(f"  Composite Score: {result.get('fraud_score')}")
    print(f"  Base Score: {result.get('base_score')}")
    print(f"  Advanced Scores: {result.get('advanced_scores')}")
    print(f"  Decision: {result.get('decision')}")
    print(f"  Triggered Rules: {result.get('triggered_rules')}")
    
    print("\nAFTER - Metrics in database:")
    print(f"  Total checks: {checker.metrics.get_metric_count('total_checks')}")
    print(f"  Fraud blocked: {checker.metrics.get_metric_count('fraud_blocked')}")
    print(f"  Velocity alerts: {checker.metrics.get_metric_count('velocity_alerts')}")
    print(f"  Pattern anomalies: {checker.metrics.get_metric_count('pattern_anomalies')}")
    
    # Test velocity patterns with multiple rapid transactions
    print("\n🧪 Testing velocity patterns with rapid transactions:")
    for i in range(5):
        velocity_test_tx = {
            "email": "velocity_test@example.com",
            "price": 10.00 + i,
            "ip": "192.168.1.100"
        }
        result = checker.analyze_transaction(velocity_test_tx)
        print(f"  Transaction {i+1}: Score={result.get('fraud_score')}, Advanced={result.get('advanced_scores')}")
    
    print("\n📊 Advanced algorithms now active! Enhanced fraud detection ready!")
    print("Run: python db/init_metrics.py show")