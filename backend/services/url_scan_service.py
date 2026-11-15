"""
URL Scan Orchestration Service (Phase 6)
========================================
Coordinates URL input sanitization, threat intelligence lookup, feature extraction,
ML inference, SHAP explainability, and database persistence.
"""

import os
import time
import hashlib
import joblib
import numpy as np

from ml.feature_extraction.url_features import extract_url_features, FEATURE_NAMES
from ml.evaluation.explainers import UrlExplainabilityEngine
from backend.services.threat_intel_service import ThreatIntelligenceService
from backend.models.db_models import ScanRecord, URLFeatureSnapshot, ExplanationRecord
from backend.utils.security import validate_and_sanitize_url
from backend.utils.logger import get_logger

logger = get_logger("url_scan_service")
SAVED_MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "ml", "saved_models")


class URLScanService:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self.threat_intel = ThreatIntelligenceService()
        self.explainer = UrlExplainabilityEngine()
        self.model = None
        self._load_model()

    def _load_model(self):
        model_path = os.path.join(SAVED_MODELS_DIR, "url_model_champion.joblib")
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                logger.info(f"Loaded champion URL model from {model_path}")
            except Exception as e:
                logger.error(f"Failed to load URL champion model: {e}")

    def scan_url(self, raw_url: str) -> dict:
        start_time = time.time()
        
        # 1. Validation & SSRF defense
        safe_url = validate_and_sanitize_url(raw_url)

        # 2. Threat Intelligence feed check
        threat_match = self.threat_intel.check_url(safe_url)

        # 3. Feature extraction (18 numerical features)
        features = extract_url_features(safe_url)
        vector = np.array([[features[name] for name in FEATURE_NAMES]], dtype=np.float32)

        # 4. ML Model Prediction
        if self.model is not None:
            if hasattr(self.model, "predict_proba"):
                prob_phishing = float(self.model.predict_proba(vector)[0, 1])
            else:
                prob_phishing = float(self.model.predict(vector)[0])
        else:
            # Fallback heuristic calculation if model not yet saved
            prob_phishing = 0.85 if features["is_ip_address"] or features["is_high_risk_tld"] else 0.10

        # Adjust score if threat intel confirmed match
        if threat_match.get("matched"):
            prob_phishing = max(prob_phishing, 0.98)

        # 5. Determine Verdict and Risk Level
        if prob_phishing >= 0.70:
            verdict = "PHISHING"
            risk_level = "CRITICAL" if prob_phishing >= 0.88 else "HIGH"
        elif prob_phishing >= 0.40:
            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM"
        else:
            verdict = "LEGITIMATE"
            risk_level = "LOW"

        # 6. SHAP Explainability
        explanation = self.explainer.explain_url(features, top_k=5)

        execution_time_ms = int((time.time() - start_time) * 1000)

        # 7. Persist to Database
        scan_id = None
        session = self.db_session_factory()
        try:
            url_hash = hashlib.sha256(safe_url.encode("utf-8")).hexdigest()
            scan_record = ScanRecord(
                scan_type="URL",
                input_summary=safe_url[:500],
                input_hash=url_hash,
                verdict=verdict,
                confidence_score=prob_phishing,
                risk_level=risk_level,
                execution_time_ms=execution_time_ms,
                threat_intel_matched=threat_match.get("matched", False)
            )
            session.add(scan_record)
            session.flush()

            scan_id = scan_record.id

            feature_snapshot = URLFeatureSnapshot(
                scan_id=scan_id,
                url_length=features["url_length"],
                domain_length=features["domain_length"],
                dot_count=features["dot_count"],
                hyphen_count=features["hyphen_count"],
                special_char_count=features["special_char_count"],
                has_https=features["has_https"],
                is_ip_address=features["is_ip_address"],
                subdomain_count=features["subdomain_count"],
                suspicious_keyword_count=features["suspicious_keyword_count"],
                is_shortened=features["is_shortened"],
                shannon_entropy=features["shannon_entropy"],
                domain_entropy=features["domain_entropy"],
                is_high_risk_tld=features["is_high_risk_tld"],
                brand_in_subdomain=features["brand_in_subdomain"]
            )
            session.add(feature_snapshot)

            explanation_snapshot = ExplanationRecord(
                scan_id=scan_id,
                top_contributing_features=explanation["top_contributing_features"],
                human_readable_reasons=explanation["human_readable_reasons"],
                all_shap_values=explanation["all_shap_values"]
            )
            session.add(explanation_snapshot)

            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to persist scan record to database: {e}")
        finally:
            session.close()

        # 8. Return comprehensive API payload
        return {
            "scan_id": scan_id,
            "target": safe_url,
            "verdict": verdict,
            "confidence_score": round(prob_phishing, 4),
            "risk_level": risk_level,
            "features": features,
            "explanation": explanation,
            "threat_intelligence": threat_match,
            "execution_time_ms": execution_time_ms
        }
