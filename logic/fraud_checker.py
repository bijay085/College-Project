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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SyncMetricsTracker:
    def __init__(self):
        try:
            self.client = pymongo.MongoClient("mongodb://localhost:27017")
            self.db = self.client.fraudshield
            self.metrics_collection = self.db.metrics
            logger.info("✅ Synchronous metrics database connection established")
        except Exception as e:
            logger.error(f"❌ Failed to connect to metrics database: {e}")
            self.client = None
            self.db = None
            self.metrics_collection = None

    def increment_metric(self, metric_name: str, increment: int = 1):
        if self.metrics_collection is None:
            return False
            
        try:
            result = self.metrics_collection.update_one(
                {"_id": metric_name},
                {
                    "$inc": {"count": increment},
                    "$set": {"last_updated": datetime.now()}
                },
                upsert=True
            )
            return True
        except Exception as e:
            logger.error(f"Failed to increment metric {metric_name}: {e}")
            return False
    
    def get_metric_count(self, metric_name: str) -> int:
        if self.metrics_collection is None:
            return 0
            
        try:
            doc = self.metrics_collection.find_one({"_id": metric_name})
            return doc.get("count", 0) if doc else 0
        except Exception as e:
            logger.error(f"Failed to get metric {metric_name}: {e}")
            return 0
    
    def initialize_metrics(self):
        if self.metrics_collection is None:
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
                ("behavioral_alerts", "Behavioral pattern alerts"),
                ("auto_blacklisted_cards", "Number of cards auto-blacklisted for suspicious usage")
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
            
            logger.info("✅ Metrics collection initialized synchronously")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize metrics: {e}")
            return False

class FraudChecker:
    def __init__(self) -> None:
        logger.info("Initializing FraudChecker with optimized database structure...")
        
        self.disposable_domains: Set[str] = set()
        self.flagged_ips: Set[str] = set()
        self.suspicious_bins: Set[str] = set()
        self.reused_fingerprints: Set[str] = set()
        self.tampered_prices: Set[float] = set()
        self.rules: Dict[str, Dict] = {}
        
        self.transaction_history: Dict[str, List[Dict]] = defaultdict(list)
        self.ip_reputation_cache: Dict[str, float] = {}
        self.email_patterns: Dict[str, int] = defaultdict(int)
        self.velocity_cache: Dict[str, List[datetime]] = defaultdict(list)
        self.behavioral_profiles: Dict[str, Dict] = {}
        self.geo_patterns: Dict[str, List[Tuple]] = defaultdict(list)
        
        self.advanced_weights = {}  

        try:
            self.mongo = MongoManager()
            logger.info("MongoDB connection established")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
        
        self.metrics = SyncMetricsTracker()
        self.metrics.initialize_metrics()
        
        self.card_to_locations = {}
        self.card_to_devices = {}
        self.bin_to_locations = {}
        self.bin_to_devices = {}
        self.card_to_emails = {}

        try:
            asyncio.run(self._warm_cache())
            logger.info("FraudChecker initialized successfully")
            self._log_cache_stats()
        except Exception as e:
            logger.error(f"Failed to initialize FraudChecker: {e}")
            raise

    async def _warm_cache(self):
        logger.info("Loading fraud detection data from optimized database...")
        
        try:
            await self._load_blacklists_from_fraud_blacklist()
            await self._load_rules()
            await self._load_transaction_history()
            logger.info("Cache warming completed successfully")
        except Exception as e:
            logger.error(f"Cache warming failed: {e}")
            raise

    async def _load_blacklists_from_fraud_blacklist(self):
        """Load all blacklists from the consolidated fraud_blacklist collection"""
        try:
            fraud_blacklist_col = self.mongo.get_collection("fraud_blacklist")
            blacklists = await fraud_blacklist_col.find().to_list(None)
            
            disposable_emails = set()
            flagged_ips = set()
            suspicious_bins = set()
            reused_fingerprints = set()
            tampered_prices = set()
            
            for item in blacklists:
                item_type = item.get("type")
                value = item.get("value")
                
                if not value:
                    continue
                    
                if item_type == "disposable_email":
                    disposable_emails.add(str(value))
                elif item_type == "flagged_ip":
                    flagged_ips.add(str(value))
                elif item_type == "suspicious_bin":
                    suspicious_bins.add(str(value))
                elif item_type == "reused_fingerprint":
                    reused_fingerprints.add(str(value))
                elif item_type == "tampered_price":
                    try:
                        tampered_prices.add(float(value))
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid tampered price value: {value}")
            
            self.disposable_domains = disposable_emails
            self.flagged_ips = flagged_ips
            self.suspicious_bins = suspicious_bins
            self.reused_fingerprints = reused_fingerprints
            self.tampered_prices = tampered_prices
            
            logger.info(f"Loaded from fraud_blacklist: {len(blacklists)} total items")
            logger.info(f"  - Disposable emails: {len(self.disposable_domains)}")
            logger.info(f"  - Flagged IPs: {len(self.flagged_ips)}")
            logger.info(f"  - Suspicious BINs: {len(self.suspicious_bins)}")
            logger.info(f"  - Reused fingerprints: {len(self.reused_fingerprints)}")
            logger.info(f"  - Tampered prices: {len(self.tampered_prices)}")
            
        except Exception as e:
            logger.error(f"Failed to load from fraud_blacklist: {e}")
            self.disposable_domains = set()
            self.flagged_ips = set()
            self.suspicious_bins = set()
            self.reused_fingerprints = set()
            self.tampered_prices = set()

    async def _load_rules(self):
        try:
            rule_docs = await self.mongo.get_collection("rules").find({"enabled": True}).to_list(None)
            self.rules = {}
            self.advanced_weights = {}
            
            advanced_categories = ['advanced', 'card_patterns']
            
            for rule in rule_docs:
                rule_key = rule.get("rule_key")
                if rule_key:
                    try:
                        rule["weight"] = float(rule.get("weight", 0))
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid weight for rule {rule_key}, defaulting to 0")
                        rule["weight"] = 0.0
                    
                    self.rules[rule_key] = rule
                    
                    category = rule.get("category", "")
                    if category in advanced_categories:
                        self.advanced_weights[rule_key] = rule["weight"]
            
            logger.info(f"Loaded {len(self.rules)} fraud detection rules")
            logger.info(f"Advanced weights loaded from DB: {self.advanced_weights}")
            
            if not self.advanced_weights:
                logger.warning("No advanced rules found in DB, using fallback weights")
                self.advanced_weights = {
                    'velocity_abuse': 0.4,
                    'suspicious_patterns': 0.35,
                    'geo_anomaly': 0.35,
                    'behavioral_deviation': 0.25,
                    'network_analysis': 0.3,
                    'time_pattern_anomaly': 0.2,
                    'amount_clustering': 0.15,
                    'phone_mismatch': 0.25,
                    'email_verification': 0.2,
                    'phone_verification': 0.2
                }
                
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            self.rules = {}
            self.advanced_weights = {
                'velocity_abuse': 0.4,
                'suspicious_patterns': 0.35,
                'geo_anomaly': 0.35,
                'behavioral_deviation': 0.25,
                'network_analysis': 0.3,
                'time_pattern_anomaly': 0.2,
                'amount_clustering': 0.15,
                'phone_mismatch': 0.25,
                'email_verification': 0.2,
                'phone_verification': 0.2
            }

    async def _load_transaction_history(self):
        try:
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
        rule = self.rules.get(rule_key, {})
        weight = rule.get("weight", 0.0)
        
        if not isinstance(weight, (int, float)):
            logger.warning(f"Invalid weight type for rule {rule_key}: {type(weight)}")
            return 0.0
        
        # BALANCED: More reasonable fallback weights
        if weight == 0:
            fallback_weights = {
                "disposable_email": 0.25,
                "suspicious_bin": 0.3,
                "flagged_ip": 0.25,
                "reused_fingerprint": 0.2,
                "tampered_price": 0.35,
                "blacklisted_pattern": 0.4,
                "same_card_multiple_emails": 0.3,
                "card_location_abuse": 0.35,
                "card_device_abuse": 0.3,
                "bin_location_abuse": 0.25,
                "rapid_location_change": 0.4,
                "velocity_abuse": 0.3,
                "impossible_travel": 0.3,
                "suspicious_email_pattern": 0.15,
                "suspicious_patterns": 0.2,
                "geo_anomaly": 0.25,
                "network_analysis": 0.15,
                "behavioral_deviation": 0.15,
                "email_verification": 0.1,
                "phone_verification": 0.1,
                "phone_mismatch": 0.15,
                "phone_country_mismatch": 0.15
            }
            weight = fallback_weights.get(rule_key, 0.1)
            logger.warning(f"Using fallback weight for {rule_key}: {weight}")
        
        return float(weight)

    def _analyze_velocity_patterns(self, tx: dict) -> Tuple[float, List[str]]:
        reasons = []
        score = 0.0
        
        email = tx.get("email", "").strip().lower()
        current_time = datetime.now()
        
        if not email:
            return score, reasons
        
        self.velocity_cache[email].append(current_time)
        
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
        
        cutoff_24h = current_time - timedelta(hours=24)
        self.velocity_cache[email] = [t for t in self.velocity_cache[email] if t >= cutoff_24h]
        
        return score, reasons

    def _analyze_behavioral_patterns(self, tx: dict) -> Tuple[float, List[str]]:
        reasons = []
        score = 0.0
        
        email = tx.get("email", "").strip().lower()
        if not email or email not in self.transaction_history:
            return score, reasons
        
        user_history = self.transaction_history[email]
        if len(user_history) < 3:
            return score, reasons
        
        current_amount = float(tx.get("price", 0))
        current_hour = datetime.now().hour
        current_ip = tx.get("ip", "")
        
        historical_amounts = [float(h.get("price", 0)) for h in user_history]
        avg_amount = sum(historical_amounts) / len(historical_amounts)
        std_amount = math.sqrt(sum((x - avg_amount) ** 2 for x in historical_amounts) / len(historical_amounts))
        
        if std_amount > 0 and abs(current_amount - avg_amount) > 3 * std_amount:
            score += 0.15
            reasons.append("unusual_amount_pattern")
        
        historical_hours = [datetime.fromisoformat(h.get("timestamp", "")).hour 
                           for h in user_history if h.get("timestamp")]
        if historical_hours:
            hour_counts = Counter(historical_hours)
            if hour_counts[current_hour] == 0 and len(historical_hours) > 5:
                score += 0.1
                reasons.append("unusual_time_pattern")
        
        historical_ips = set(h.get("ip", "") for h in user_history)
        if current_ip and current_ip not in historical_ips and len(historical_ips) < 3:
            score += 0.1
            reasons.append("new_ip_pattern")
        
        return score, reasons

    def _analyze_geographic_anomalies(self, tx: dict) -> Tuple[float, List[str]]:
        reasons = []
        score = 0.0
        
        email = tx.get("email", "").strip().lower()
        current_ip = tx.get("ip", "")
        
        if not email or not current_ip:
            return score, reasons
        
        current_time = datetime.now()
        
        if email in self.geo_patterns:
            last_location_data = self.geo_patterns[email][-1] if self.geo_patterns[email] else None
            
            if last_location_data:
                last_ip, last_time = last_location_data
                time_diff = (current_time - last_time).total_seconds() / 3600
                
                if self._get_ip_subnet(current_ip) != self._get_ip_subnet(last_ip) and time_diff < 1:
                    score += 0.2
                    reasons.append("impossible_travel")
        
        self.geo_patterns[email].append((current_ip, current_time))
        
        if len(self.geo_patterns[email]) > 10:
            self.geo_patterns[email] = self.geo_patterns[email][-10:]
        
        return score, reasons

    def _get_ip_subnet(self, ip: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                return str(ipaddress.ip_network(f"{ip}/16", strict=False))
            else:
                return str(ipaddress.ip_network(f"{ip}/64", strict=False))
        except:
            return ip

    def _analyze_network_patterns(self, tx: dict) -> Tuple[float, List[str]]:
        reasons = []
        score = 0.0
        
        ip = tx.get("ip", "")
        if not ip:
            return score, reasons
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.is_private or ip_obj.is_loopback:
                score += 0.1
                reasons.append("private_ip_usage")
            
            if self._is_known_proxy_range(ip):
                score += 0.15
                reasons.append("proxy_ip_detected")
                
        except ValueError:
            score += 0.05
            reasons.append("invalid_ip_format")
        
        return score, reasons

    def _is_known_proxy_range(self, ip: str) -> bool:
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
        reasons = []
        score = 0.0
        
        email = tx.get("email", "").strip().lower()
        if not email or "@" not in email:
            return score, reasons
        
        local_part, domain = email.split("@", 1)
        
        if re.search(r'\d{3,}', local_part):
            score += 0.1
            reasons.append("numbered_email_pattern")
        
        if len(local_part) > 8 and not re.search(r'[aeiou]', local_part):
            score += 0.05
            reasons.append("random_email_pattern")
        
        if '+' in local_part and local_part.count('+') > 1:
            score += 0.1
            reasons.append("plus_addressing_abuse")
        
        creation_patterns = ["2024", "2025", "new", "temp"]
        if any(pattern in local_part for pattern in creation_patterns):
            score += 0.05
            reasons.append("recent_creation_pattern")
        
        return score, reasons

    def _analyze_amount_clustering(self, tx: dict) -> Tuple[float, List[str]]:
        reasons = []
        score = 0.0
        
        current_amount = float(tx.get("price", 0))
        
        fraud_amounts = [0.01, 1.00, 9.99, 99.99, 999.99]
        if current_amount in fraud_amounts:
            score += 0.05
            reasons.append("common_fraud_amount")
        
        if current_amount > 10 and current_amount % 100 == 0:
            score += 0.03
            reasons.append("round_amount_pattern")
        
        return score, reasons

    def _analyze_phone_country_mismatch(self, tx: dict) -> Tuple[float, List[str]]:
        reasons = []
        score = 0.0
        
        phone = str(tx.get("phone", "")).strip()
        billing_country = str(tx.get("billing_country", "")).strip()
        
        if not phone or not billing_country:
            return score, reasons
        
        if phone.startswith('+'):
            try:
                import phonenumbers
                
                parsed = phonenumbers.parse(phone, None)
                
                if phonenumbers.is_valid_number(parsed):
                    phone_country = phonenumbers.region_code_for_number(parsed)
                    
                    if phone_country != billing_country:
                        score += 0.15
                        reasons.append("phone_country_mismatch")
                        logger.debug(f"Phone/billing country mismatch: {phone_country} != {billing_country}")
                else:
                    score += 0.1
                    reasons.append("invalid_phone_format")
                    
            except Exception as e:
                score += 0.05
                reasons.append("phone_parse_error")
        
        return score, reasons

    def _analyze_verification_status(self, tx: dict) -> Tuple[float, List[str]]:
        """Analyze email and phone verification status"""
        reasons = []
        score = 0.0
        
        email_verified = tx.get("email_verified", False)
        phone_verified = tx.get("phone_verified", False)
        
        # Only penalize if BOTH are unverified or if there are other red flags
        base_violations = len([r for r in ["disposable_email", "suspicious_bin", "flagged_ip", "tampered_price", "reused_fingerprint"] 
                             if r in str(tx)])
        
        if not email_verified and not phone_verified:
            # Heavy penalty only if other red flags exist
            if base_violations > 0:
                score += 0.25
                reasons.append("no_verification_with_red_flags")
            else:
                score += 0.05
                reasons.append("no_verification")
        elif not email_verified:
            if base_violations > 0:
                score += 0.1
                reasons.append("email_not_verified")
            else:
                score += 0.02
                reasons.append("email_not_verified_minor")
        elif not phone_verified:
            if base_violations > 0:
                score += 0.1
                reasons.append("phone_not_verified")
            else:
                score += 0.02
                reasons.append("phone_not_verified_minor")
        
        return score, reasons

    def _calculate_composite_risk_score(self, base_score: float, advanced_scores: Dict[str, float]) -> float:
        total_advanced_score = 0.0
        
        for algorithm, score in advanced_scores.items():
            weight = self.advanced_weights.get(algorithm, 0.1)
            total_advanced_score += score * weight
        
        # Count how many rules were triggered
        total_rules_triggered = len(advanced_scores) if hasattr(advanced_scores, '__len__') else 0
        
        # BALANCED: More reasonable weighting
        if base_score >= 0.6:
            composite_score = base_score * 0.7 + total_advanced_score * 0.3
        elif base_score >= 0.3:
            composite_score = base_score * 0.6 + total_advanced_score * 0.4
        else:
            composite_score = base_score * 0.5 + total_advanced_score * 0.5
        
        # Moderate amplification based on rule count
        if total_rules_triggered >= 10:
            adjusted_score = composite_score * 1.3
        elif total_rules_triggered >= 7:
            adjusted_score = composite_score * 1.2
        elif total_rules_triggered >= 5:
            adjusted_score = composite_score * 1.15
        elif total_rules_triggered >= 3:
            adjusted_score = composite_score * 1.1
        else:
            adjusted_score = composite_score * 1.05
        
        # Reasonable minimums based on base score
        if base_score >= 0.8:
            adjusted_score = max(adjusted_score, 0.7)
        elif base_score >= 0.6:
            adjusted_score = max(adjusted_score, 0.5)
        elif base_score >= 0.4:
            adjusted_score = max(adjusted_score, 0.35)
        
        final_score = min(adjusted_score, 0.99)
        
        return round(final_score, 3)

    def analyze_transaction(self, tx: dict) -> dict:
        try:
            self.metrics.increment_metric("total_checks")
            
            base_score = 0.0
            reasons = []
            advanced_scores = {}
            all_advanced_reasons = []
            
            if not isinstance(tx, dict):
                logger.warning("Transaction must be a dictionary")
                return self._create_error_result(tx, "Invalid transaction format")
            
            email = str(tx.get("email", "")).strip().lower()
            if email and "@" in email:
                domain = email.split("@")[-1]
                if domain in self.disposable_domains:
                    weight = self._safe_get_rule_weight("disposable_email")
                    if weight == 0:  # Fallback if rule not found
                        weight = 0.5
                    base_score += weight
                    reasons.append("disposable_email")
                    logger.debug(f"Disposable email detected: {domain}")
            
            card_number = str(tx.get("card_number", "")).strip()
            if len(card_number) >= 6:
                bin_number = card_number[:6]
                if bin_number in self.suspicious_bins:
                    weight = self._safe_get_rule_weight("suspicious_bin")
                    if weight == 0:  # Fallback
                        weight = 0.6
                    base_score += weight
                    reasons.append("suspicious_bin")
                    logger.debug(f"Suspicious BIN detected: {bin_number}")
            
            ip = str(tx.get("ip", "")).strip()
            if ip in self.flagged_ips:
                weight = self._safe_get_rule_weight("flagged_ip")
                if weight == 0:  # Fallback
                    weight = 0.55
                base_score += weight
                reasons.append("flagged_ip")
                logger.debug(f"Flagged IP detected: {ip}")
            
            fingerprint = str(tx.get("fingerprint", "")).strip()
            if fingerprint in self.reused_fingerprints:
                weight = self._safe_get_rule_weight("reused_fingerprint")
                if weight == 0:  # Fallback
                    weight = 0.45
                base_score += weight
                reasons.append("reused_fingerprint")
                logger.debug(f"Reused fingerprint detected: {fingerprint}")
            
            try:
                price = float(tx.get("price", 0))
                if price in self.tampered_prices:
                    weight = self._safe_get_rule_weight("tampered_price")
                    if weight == 0:  # Fallback
                        weight = 0.7
                    base_score += weight
                    reasons.append("tampered_price")
                    logger.debug(f"Tampered price detected: {price}")
            except (ValueError, TypeError):
                logger.warning(f"Invalid price value: {tx.get('price')}")
            
            # BALANCED: Base score based on severity
            if len(reasons) >= 5:
                logger.warning(f"Many base violations ({len(reasons)}). Setting high base score.")
                base_score = max(base_score, 0.8)
            elif len(reasons) >= 4:
                base_score = max(base_score, 0.6)
            elif len(reasons) >= 3:
                base_score = max(base_score, 0.45)
            elif len(reasons) >= 2:
                base_score = max(base_score, 0.3)
            elif len(reasons) >= 1:
                base_score = max(base_score, 0.15)
            
            # Don't penalize if NO base violations
            if len(reasons) == 0:
                base_score = 0.0
            
            if card_number and len(card_number) >= 6 and email:
                card_hash = hashlib.sha256(card_number.encode()).hexdigest()
                
                if not hasattr(self, 'card_to_emails'):
                    self.card_to_emails = {}
                
                if card_hash not in self.card_to_emails:
                    self.card_to_emails[card_hash] = set()
                
                self.card_to_emails[card_hash].add(email)
                
                email_count = len(self.card_to_emails[card_hash])
                if email_count > 1:
                    weight = self._safe_get_rule_weight("same_card_multiple_emails")
                    if weight == 0:
                        weight = 0.5 if email_count == 2 else 0.65
                    base_score += weight
                    reasons.append(f"same_card_multiple_emails_{email_count}")
                    logger.debug(f"Same card used with {email_count} different emails")
            
            if card_number and len(card_number) >= 6:
                card_hash = hashlib.sha256(card_number.encode()).hexdigest()
                bin_number = card_number[:6]
                current_location = ip
                current_device = fingerprint

                if card_hash not in self.card_to_locations:
                    self.card_to_locations[card_hash] = set()
                    self.card_to_devices[card_hash] = set()

                if bin_number not in self.bin_to_locations:
                    self.bin_to_locations[bin_number] = set()
                    self.bin_to_devices[bin_number] = set()

                if current_location:
                    self.card_to_locations[card_hash].add(current_location)
                    self.bin_to_locations[bin_number].add(current_location)

                if current_device:
                    self.card_to_devices[card_hash].add(current_device)
                    self.bin_to_devices[bin_number].add(current_device)

                auto_blacklist = False
                blacklist_reason = ""

                if len(self.card_to_locations[card_hash]) >= 3:
                    auto_blacklist = True
                    blacklist_reason = f"card_used_from_{len(self.card_to_locations[card_hash])}_different_locations"
                    weight = self._safe_get_rule_weight("card_location_abuse")
                    if weight == 0:
                        weight = 0.75
                    base_score += weight
                    reasons.append(blacklist_reason)

                elif len(self.card_to_devices[card_hash]) >= 3:
                    auto_blacklist = True
                    blacklist_reason = f"card_used_from_{len(self.card_to_devices[card_hash])}_different_devices"
                    weight = self._safe_get_rule_weight("card_device_abuse")
                    if weight == 0:
                        weight = 0.7
                    base_score += weight
                    reasons.append(blacklist_reason)

                elif len(self.bin_to_locations[bin_number]) >= 5:
                    auto_blacklist = True
                    blacklist_reason = f"bin_used_from_{len(self.bin_to_locations[bin_number])}_different_locations"
                    weight = self._safe_get_rule_weight("bin_location_abuse")
                    if weight == 0:
                        weight = 0.6
                    base_score += weight
                    reasons.append(blacklist_reason)

                if current_location and card_hash in self.card_to_locations:
                    if len(self.card_to_locations[card_hash]) > 1 and current_location not in self.card_to_locations[card_hash]:
                        auto_blacklist = True
                        blacklist_reason = "rapid_location_change_same_card"
                        weight = self._safe_get_rule_weight("rapid_location_change")
                        if weight == 0:
                            weight = 0.8
                        base_score += weight
                        reasons.append(blacklist_reason)

                if auto_blacklist:
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            loop.create_task(self._auto_blacklist_suspicious_cards(card_hash, bin_number, blacklist_reason))
                        else:
                            self._sync_auto_blacklist_suspicious_cards(card_hash, bin_number, blacklist_reason)
                    except RuntimeError:
                        self._sync_auto_blacklist_suspicious_cards(card_hash, bin_number, blacklist_reason)
                    self.metrics.increment_metric("auto_blacklisted_cards")
            
            velocity_score, velocity_reasons = self._analyze_velocity_patterns(tx)
            if velocity_score > 0:
                advanced_scores['velocity_abuse'] = velocity_score
                all_advanced_reasons.extend(velocity_reasons)
                self.metrics.increment_metric("velocity_alerts")
            
            behavioral_score, behavioral_reasons = self._analyze_behavioral_patterns(tx)
            if behavioral_score > 0:
                advanced_scores['behavioral_deviation'] = behavioral_score
                all_advanced_reasons.extend(behavioral_reasons)
                self.metrics.increment_metric("behavioral_alerts")
            
            geo_score, geo_reasons = self._analyze_geographic_anomalies(tx)
            if geo_score > 0:
                advanced_scores['geo_anomaly'] = geo_score
                all_advanced_reasons.extend(geo_reasons)
                self.metrics.increment_metric("geo_anomalies")
            
            network_score, network_reasons = self._analyze_network_patterns(tx)
            if network_score > 0:
                advanced_scores['network_analysis'] = network_score
                all_advanced_reasons.extend(network_reasons)
            
            email_score, email_reasons = self._analyze_email_patterns(tx)
            if email_score > 0:
                advanced_scores['suspicious_patterns'] = email_score
                all_advanced_reasons.extend(email_reasons)
                self.metrics.increment_metric("pattern_anomalies")
            
            amount_score, amount_reasons = self._analyze_amount_clustering(tx)
            if amount_score > 0:
                advanced_scores['amount_clustering'] = amount_score
                all_advanced_reasons.extend(amount_reasons)

            phone_score, phone_reasons = self._analyze_phone_country_mismatch(tx)
            if phone_score > 0:
                advanced_scores['phone_mismatch'] = phone_score
                all_advanced_reasons.extend(phone_reasons)
            
            verification_score, verification_reasons = self._analyze_verification_status(tx)
            if verification_score > 0:
                advanced_scores['verification_status'] = verification_score
                all_advanced_reasons.extend(verification_reasons)
            
            composite_score = self._calculate_composite_risk_score(base_score, advanced_scores)
            
            all_reasons = reasons + all_advanced_reasons
            
            # Recalculate with total rules count
            total_rules = len(all_reasons)
            if total_rules >= 5:
                # Many rules triggered - boost the score significantly
                rule_penalty = min(0.05 * total_rules, 0.5)
                composite_score = min(composite_score + rule_penalty, 0.99)
                
                # Ensure minimum scores for many violations
                if total_rules >= 12:
                    composite_score = max(composite_score, 0.95)
                elif total_rules >= 10:
                    composite_score = max(composite_score, 0.9)
                elif total_rules >= 8:
                    composite_score = max(composite_score, 0.85)
                elif total_rules >= 6:
                    composite_score = max(composite_score, 0.75)
            
            if composite_score >= 0.7:
                decision = "fraud"
                self.metrics.increment_metric("fraud_blocked")
            elif composite_score >= 0.35:
                decision = "suspicious"
                self.metrics.increment_metric("suspicious_flagged")
            else:
                decision = "not_fraud"
                self.metrics.increment_metric("clean_approved")
            
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
            
            logger.debug(f"Transaction analyzed: score={composite_score:.3f}, decision={decision}")
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing transaction: {e}")
            logger.error(traceback.format_exc())
            return self._create_error_result(tx, f"Analysis failed: {str(e)}")
        
    def _create_error_result(self, tx: dict, error_msg: str) -> dict:
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
        try:
            logger.info(f"Starting bulk analysis of file: {getattr(file_obj, 'filename', 'unknown')}")
            
            self.metrics.increment_metric("bulk_analyses")
            
            df = self._read_file_to_dataframe(file_obj)
            
            if df is None or df.empty:
                raise ValueError("File is empty or could not be read")
            
            logger.info(f"Processing {len(df)} transactions with advanced algorithms")
            
            results = []
            errors = 0
            
            fraud_count = 0
            suspicious_count = 0
            clean_count = 0
            advanced_detections = defaultdict(int)
            
            for index, row in df.iterrows():
                try:
                    tx_dict = row.to_dict()
                    
                    tx_dict = self._clean_transaction_data(tx_dict)
                    
                    if isinstance(index, int):
                        tx_number = index + 1
                    else:
                        tx_number = index
                    result = self.analyze_transaction(tx_dict)
                    results.append(result)
                    
                    decision = result.get("decision")
                    if decision == "fraud":
                        fraud_count += 1
                    elif decision == "suspicious":
                        suspicious_count += 1
                    elif decision == "not_fraud":
                        clean_count += 1
                    elif decision == "error":
                        errors += 1
                    
                    for algo in result.get("advanced_scores", {}):
                        advanced_detections[algo] += 1
                        
                except Exception as e:
                    logger.error(f"Error processing row {index}: {e}")
                    error_result = self._create_error_result(
                        {"row_index": index}, 
                        f"Row processing failed: {str(e)}"
                    )
                    results.append(error_result)
                    errors += 1
            
            logger.info(f"Advanced bulk analysis completed: {len(results)} processed, {errors} errors")
            logger.info(f"Results breakdown: {fraud_count} fraud, {suspicious_count} suspicious, {clean_count} clean")
            logger.info(f"Advanced algorithm detections: {dict(advanced_detections)}")
            
            return results
            
        except Exception as e:
            logger.error(f"Advanced bulk analysis failed: {e}")
            logger.error(traceback.format_exc())
            raise ValueError(f"Advanced bulk analysis failed: {str(e)}")

    def _read_file_to_dataframe(self, file_obj) -> Optional[pd.DataFrame]:
        try:
            filename = getattr(file_obj, 'filename', '').lower()
            
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
            
            if df.empty:
                raise ValueError("File contains no data")
            
            logger.info(f"File columns: {list(df.columns)}")
            return df
            
        except Exception as e:
            logger.error(f"Failed to read file: {e}")
            raise ValueError(f"Failed to read file: {str(e)}")

    def _clean_transaction_data(self, tx_dict: dict) -> dict:
        cleaned = {}
        
        for key, value in tx_dict.items():
            if pd.isna(value):
                cleaned[key] = "" if key in ["email", "ip", "fingerprint"] else 0
            else:
                cleaned[key] = value
        
        return cleaned

    async def get_stats(self) -> dict:
        try:
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

    async def _auto_blacklist_suspicious_cards(self, card_hash: str, bin_number: str, reason: str):
        try:
            if bin_number:
                fraud_blacklist_entry = {
                    "type": "suspicious_bin",
                    "value": bin_number,
                    "risk_score": 0.9,
                    "source": "auto_blacklist",
                    "created_at": datetime.now(),
                    "metadata": {
                        "reason": reason,
                        "card_hash": card_hash[:16] + "...",
                        "auto_blacklisted": True
                    }
                }
                
                await self.mongo.get_collection("fraud_blacklist").update_one(
                    {"type": "suspicious_bin", "value": bin_number},
                    {"$set": fraud_blacklist_entry},
                    upsert=True
                )
                
                self.suspicious_bins.add(bin_number)
                logger.info(f"Auto-blacklisted BIN: {bin_number} Reason: {reason}")

        except Exception as e:
            logger.error(f"Failed to auto-blacklist: {e}")

    def _sync_auto_blacklist_suspicious_cards(self, card_hash: str, bin_number: str, reason: str):
        try:
            if bin_number and self.mongo.client:
                fraud_blacklist_entry = {
                    "type": "suspicious_bin",
                    "value": bin_number,
                    "risk_score": 0.9,
                    "source": "auto_blacklist",
                    "created_at": datetime.now(),
                    "metadata": {
                        "reason": reason,
                        "card_hash": card_hash[:16] + "...",
                        "auto_blacklisted": True
                    }
                }
                
                self.mongo.db.fraud_blacklist.update_one(
                    {"type": "suspicious_bin", "value": bin_number},
                    {"$set": fraud_blacklist_entry},
                    upsert=True
                )
                
                self.suspicious_bins.add(bin_number)
                logger.info(f"Auto-blacklisted BIN: {bin_number} Reason: {reason}")

        except Exception as e:
            logger.error(f"Failed to sync auto-blacklist: {e}")

    async def refresh_blacklists(self):
        try:
            await self._load_blacklists_from_fraud_blacklist()
            logger.info("Blacklists refreshed from fraud_blacklist collection")
        except Exception as e:
            logger.error(f"Failed to refresh blacklists: {e}")

if __name__ == "__main__":
    print("🚀 Testing Enhanced FraudChecker with Optimized Database...")
    
    try:
        import pymongo
    except ImportError:
        print("❌ pymongo not installed. Installing...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pymongo"])
        import pymongo
    
    checker = FraudChecker()
    
    test_tx = {
        "email": "user123456@tempmail.com",
        "card_number": "123456789012345",
        "ip": "203.0.113.45",
        "fingerprint": "fp_abc123",
        "price": 0.01,
        "phone": "+1234567890",
        "billing_country": "US",
        "email_verified": False,
        "phone_verified": False
    }
    
    print("\n🧪 Testing single transaction with optimized database:")
    print("BEFORE - Metrics in database:")
    print(f"  Total checks: {checker.metrics.get_metric_count('total_checks')}")
    print(f"  Fraud blocked: {checker.metrics.get_metric_count('fraud_blocked')}")
    
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
    
    print("\n✅ FraudChecker with optimized database is ready!")