"""
Email Scan Orchestration Service (Phase 6)
==========================================
Coordinates email preprocessing, NLP inference, embedded link inspection,
social engineering detection, explainability, and database storage.
"""

import os
import time
import hashlib
import joblib

from ml.feature_extraction.email_features import extract_full_email_features
from ml.evaluation.explainers import EmailExplainabilityEngine
from backend.models.db_models import ScanRecord, EmailFeatureSnapshot, ExplanationRecord
from backend.utils.security import validate_email_input
from backend.utils.logger import get_logger

logger = get_logger("email_scan_service")
SAVED_MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "ml", "saved_models")


class EmailScanService:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self.explainer = EmailExplainabilityEngine()
        self.model = None
        self.vectorizer = None
        self._load_pipeline()

    def _load_pipeline(self):
        model_path = os.path.join(SAVED_MODELS_DIR, "email_model_champion.joblib")
        vec_path = os.path.join(SAVED_MODELS_DIR, "email_tfidf_vectorizer.joblib")
        if os.path.exists(model_path) and os.path.exists(vec_path):
            try:
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vec_path)
                logger.info(f"Loaded email model pipeline from {model_path}")
            except Exception as e:
                logger.error(f"Failed to load email pipeline: {e}")

    def scan_email(self, subject: str, body: str, sender: str = "") -> dict:
        start_time = time.time()

        # 1. Validation & Input Sanitization
        clean_subj, clean_body, clean_sender = validate_email_input(subject, body, sender)

        # 2. NLP and Feature Extraction
        email_data = extract_full_email_features(clean_subj, clean_body, clean_sender)
        cleaned_text = email_data["cleaned_nlp_text"]

        # 3. Model Inference via TF-IDF Pipeline
        prob_phishing = 0.50
        if self.model is not None and self.vectorizer is not None and cleaned_text:
            try:
                X_vec = self.vectorizer.transform([cleaned_text])
                if hasattr(self.model, "predict_proba"):
                    prob_phishing = float(self.model.predict_proba(X_vec)[0, 1])
                else:
                    prob_phishing = float(self.model.predict(X_vec)[0])
            except Exception as e:
                logger.error(f"Inference error in email model: {e}")

        # 4. Composite Risk Reconciliation
        # Boost confidence if suspicious links or high urgency cues are present
        if email_data["has_suspicious_links"]:
            prob_phishing = max(prob_phishing, 0.85)
        if email_data["urgency_score"] >= 0.75:
            prob_phishing = min(1.0, prob_phishing + 0.15)
        if email_data["sender_analysis"]["has_anomalies"]:
            prob_phishing = min(1.0, prob_phishing + 0.10)

        # 5. Verdict & Risk Determination
        if prob_phishing >= 0.70:
            verdict = "PHISHING"
            risk_level = "CRITICAL" if prob_phishing >= 0.88 else "HIGH"
        elif prob_phishing >= 0.40:
            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM"
        else:
            verdict = "LEGITIMATE"
            risk_level = "LOW"

        # 6. Explainability
        explanation = self.explainer.explain_email(cleaned_text, top_k=6)
        
        # Build human-readable reasons combining NLP & heuristics
        reasons = []
        if email_data["has_suspicious_links"]:
            reasons.append("Email contains suspicious or unencrypted destination links.")
        if email_data["urgency_score"] >= 0.50:
            reasons.append(f"High urgency score ({email_data['urgency_score']}) indicates pressure tactics.")
        if email_data["social_engineering"]["categories"]:
            cats = ", ".join(email_data["social_engineering"]["categories"])
            reasons.append(f"Detected social engineering patterns: {cats}.")
        if email_data["sender_analysis"]["anomalies"]:
            reasons.extend(email_data["sender_analysis"]["anomalies"])
        if not reasons:
            reasons.append("Email linguistics match typical benign corporate communications.")

        explanation["human_readable_reasons"] = reasons

        execution_time_ms = int((time.time() - start_time) * 1000)

        # 7. Persist to Database
        scan_id = None
        session = self.db_session_factory()
        try:
            summary_preview = f"[{clean_subj}] {clean_body}"[:500]
            email_hash = hashlib.sha256(summary_preview.encode("utf-8")).hexdigest()
            scan_record = ScanRecord(
                scan_type="EMAIL",
                input_summary=summary_preview,
                input_hash=email_hash,
                verdict=verdict,
                confidence_score=prob_phishing,
                risk_level=risk_level,
                execution_time_ms=execution_time_ms,
                threat_intel_matched=email_data["has_suspicious_links"]
            )
            session.add(scan_record)
            session.flush()

            scan_id = scan_record.id

            feature_snapshot = EmailFeatureSnapshot(
                scan_id=scan_id,
                sender_address=clean_sender,
                subject=clean_subj,
                urgency_score=email_data["urgency_score"],
                has_suspicious_links=email_data["has_suspicious_links"],
                social_engineering_patterns=email_data["social_engineering"]["categories"],
                detected_keywords=[kw["word"] for kw in explanation.get("top_keywords", [])]
            )
            session.add(feature_snapshot)

            explanation_snapshot = ExplanationRecord(
                scan_id=scan_id,
                top_contributing_features=explanation.get("top_keywords", []),
                human_readable_reasons=reasons,
                all_shap_values={}
            )
            session.add(explanation_snapshot)

            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to persist email scan record: {e}")
        finally:
            session.close()

        # 8. Return response
        return {
            "scan_id": scan_id,
            "sender": clean_sender,
            "subject": clean_subj,
            "verdict": verdict,
            "confidence_score": round(prob_phishing, 4),
            "risk_level": risk_level,
            "indicators": {
                "urgency_score": email_data["urgency_score"],
                "social_engineering": email_data["social_engineering"],
                "sender_analysis": email_data["sender_analysis"],
                "embedded_links": email_data["embedded_link_assessments"]
            },
            "explanation": explanation,
            "execution_time_ms": execution_time_ms
        }
