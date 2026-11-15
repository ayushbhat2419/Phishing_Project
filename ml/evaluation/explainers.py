"""
Explainable AI (XAI) Engine (Phase 5)
=====================================
Generates feature attributions and human-interpretable risk explanations
using SHAP (Shapley Additive exPlanations) and heuristic indicator mapping.

Supports:
- URL Feature Attributions via SHAP TreeExplainer & Heuristic Mapping
- Email NLP Keyword Importance via TF-IDF coefficient impact
"""

import os
import joblib
import numpy as np
import shap
from ml.feature_extraction.url_features import FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAVED_MODELS_DIR = os.path.join(BASE_DIR, "saved_models")

# Human-readable semantic explanations for each feature
FEATURE_EXPLANATIONS = {
    "url_length": {
        "title": "URL Length",
        "description": "Excessively long URLs are often used to conceal target hostnames or embed malicious payload redirects."
    },
    "domain_length": {
        "title": "Domain Length",
        "description": "Abnormally long domain names frequently indicate randomly generated or deceptive registration patterns."
    },
    "dot_count": {
        "title": "Period (.) Count",
        "description": "Multiple dots are commonly used in subdomain chaining to mimic legitimate subdomains."
    },
    "hyphen_count": {
        "title": "Hyphen (-) Count",
        "description": "Hyphens are widely used in typosquatting and deceptive brand mimicry (e.g., 'paypal-security-update')."
    },
    "special_char_count": {
        "title": "Special Characters",
        "description": "Frequent special characters (?, @, =, &, %) indicate complex parameter obfuscation."
    },
    "has_https": {
        "title": "HTTPS Encryption",
        "description": "Absence of HTTPS (unencrypted HTTP) exposes credentials to interception and signals questionable origins."
    },
    "is_ip_address": {
        "title": "Direct IP Address Usage",
        "description": "Using an IP address in place of a registered domain is a classic evasion tactic used by disposable phishing servers."
    },
    "subdomain_count": {
        "title": "Subdomain Depth",
        "description": "Deep subdomain hierarchies allow attackers to host phishing forms under legitimate-sounding hostnames."
    },
    "suspicious_keyword_count": {
        "title": "Security & Banking Keywords",
        "description": "Presence of keywords like 'login', 'verify', 'update', or 'account' in unconventional domains."
    },
    "is_shortened": {
        "title": "URL Shortener Detected",
        "description": "Shortening services obscure the final destination domain from standard gateway inspection."
    },
    "shannon_entropy": {
        "title": "URL Shannon Entropy",
        "description": "High randomness/entropy suggests algorithmically generated domains (DGA) or encoded parameters."
    },
    "domain_entropy": {
        "title": "Domain Shannon Entropy",
        "description": "High entropy in domain labels indicates automated disposable domain registration."
    },
    "digit_count": {
        "title": "Numeric Digit Count",
        "description": "Multiple digits embedded in hostnames are typical of botnet and phishing staging hosts."
    },
    "digit_ratio": {
        "title": "Digit-to-Character Ratio",
        "description": "High proportion of digits in the URL."
    },
    "path_depth": {
        "title": "URL Path Depth",
        "description": "Deep directory paths are commonly created on compromised legitimate websites to host phishing kits."
    },
    "has_at_symbol": {
        "title": "Userinfo (@) Symbol",
        "description": "The '@' symbol in URLs causes browsers to ignore all preceding text and connect to the host following it."
    },
    "is_high_risk_tld": {
        "title": "High-Risk Top-Level Domain",
        "description": "TLDs such as .xyz, .top, .work, or .click are statistically associated with low-cost spam and phishing operations."
    },
    "brand_in_subdomain": {
        "title": "Brand Impersonation in Subdomain",
        "description": "A well-known brand name is embedded as a subdomain under an unrelated registered domain."
    }
}


class UrlExplainabilityEngine:
    """Computes SHAP feature contributions and plain-English explanations for URL predictions."""

    def __init__(self):
        self.rf_model = None
        self.explainer = None
        self._load_model()

    def _load_model(self):
        rf_path = os.path.join(SAVED_MODELS_DIR, "url_model_random_forest.joblib")
        if os.path.exists(rf_path):
            try:
                self.rf_model = joblib.load(rf_path)
                # Initialize TreeExplainer
                self.explainer = shap.TreeExplainer(self.rf_model)
            except Exception as e:
                print(f"[!] Warning: Could not initialize TreeExplainer: {e}")

    def explain_url(self, feature_dict: dict, top_k: int = 5) -> dict:
        """
        Calculates feature attributions for a single URL feature dictionary.
        Returns top contributing features and human-readable reasonings.
        """
        # Convert dictionary to ordered vector
        vector = np.array([[feature_dict[name] for name in FEATURE_NAMES]], dtype=np.float32)

        shap_values_dict = {}
        top_factors = []

        if self.explainer is not None:
            try:
                # TreeExplainer produces shape (samples, features, classes) or (samples, features)
                raw_shap = self.explainer.shap_values(vector)
                
                # For binary classification: index 1 corresponds to phishing class
                if isinstance(raw_shap, list) and len(raw_shap) == 2:
                    phishing_shap = raw_shap[1][0]
                elif hasattr(raw_shap, "shape") and len(raw_shap.shape) == 3:
                    phishing_shap = raw_shap[0, :, 1]
                else:
                    phishing_shap = raw_shap[0]

                # Map values to feature names
                for name, val in zip(FEATURE_NAMES, phishing_shap):
                    shap_values_dict[name] = round(float(val), 4)

                # Sort by absolute SHAP impact
                sorted_features = sorted(
                    shap_values_dict.items(),
                    key=lambda item: abs(item[1]),
                    reverse=True
                )

                for name, val in sorted_features[:top_k]:
                    feat_info = FEATURE_EXPLANATIONS.get(name, {"title": name, "description": ""})
                    raw_val = feature_dict.get(name)
                    
                    if val > 0:
                        impact_type = "Increases Phishing Risk"
                    elif val < 0:
                        impact_type = "Decreases Phishing Risk (Benign Indicator)"
                    else:
                        impact_type = "Neutral"

                    top_factors.append({
                        "feature_name": name,
                        "title": feat_info["title"],
                        "shap_value": val,
                        "feature_value": raw_val,
                        "impact_type": impact_type,
                        "description": feat_info["description"]
                    })
            except Exception as e:
                print(f"[!] Warning: SHAP computation error: {e}")

        # Fallback to rule-based heuristic highlights if SHAP was not computable
        if not top_factors:
            top_factors = self._rule_based_explanations(feature_dict)

        # Generate human-readable summary bullets
        human_reasons = []
        for factor in top_factors:
            if factor["shap_value"] > 0 or factor.get("impact_type") == "Increases Phishing Risk":
                human_reasons.append(f"{factor['title']}: {factor['description']}")

        if not human_reasons:
            human_reasons.append("Structural properties align with typical legitimate web destinations.")

        return {
            "top_contributing_features": top_factors,
            "all_shap_values": shap_values_dict,
            "human_readable_reasons": human_reasons[:4]
        }

    def _rule_based_explanations(self, feat_dict: dict) -> list:
        factors = []
        if feat_dict.get("is_ip_address"):
            factors.append({
                "feature_name": "is_ip_address",
                "title": "Direct IP Address Usage",
                "shap_value": 0.35,
                "feature_value": 1,
                "impact_type": "Increases Phishing Risk",
                "description": FEATURE_EXPLANATIONS["is_ip_address"]["description"]
            })
        if feat_dict.get("brand_in_subdomain"):
            factors.append({
                "feature_name": "brand_in_subdomain",
                "title": "Brand Impersonation in Subdomain",
                "shap_value": 0.30,
                "feature_value": 1,
                "impact_type": "Increases Phishing Risk",
                "description": FEATURE_EXPLANATIONS["brand_in_subdomain"]["description"]
            })
        if feat_dict.get("is_high_risk_tld"):
            factors.append({
                "feature_name": "is_high_risk_tld",
                "title": "High-Risk Top-Level Domain",
                "shap_value": 0.25,
                "feature_value": 1,
                "impact_type": "Increases Phishing Risk",
                "description": FEATURE_EXPLANATIONS["is_high_risk_tld"]["description"]
            })
        if not feat_dict.get("has_https"):
            factors.append({
                "feature_name": "has_https",
                "title": "Missing HTTPS Encryption",
                "shap_value": 0.20,
                "feature_value": 0,
                "impact_type": "Increases Phishing Risk",
                "description": FEATURE_EXPLANATIONS["has_https"]["description"]
            })
        if feat_dict.get("subdomain_count", 0) >= 2:
            factors.append({
                "feature_name": "subdomain_count",
                "title": "High Subdomain Count",
                "shap_value": 0.15,
                "feature_value": feat_dict["subdomain_count"],
                "impact_type": "Increases Phishing Risk",
                "description": FEATURE_EXPLANATIONS["subdomain_count"]["description"]
            })
        return factors


class EmailExplainabilityEngine:
    """Explains email text predictions using TF-IDF feature weights & model coefficients."""

    def __init__(self):
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
            except Exception as e:
                print(f"[!] Could not load email model pipeline: {e}")

    def explain_email(self, cleaned_text: str, top_k: int = 5) -> dict:
        if not self.model or not self.vectorizer or not cleaned_text:
            return {"top_keywords": [], "summary": "Model pipeline not loaded or text is empty."}

        try:
            vec = self.vectorizer.transform([cleaned_text])
            feature_names = self.vectorizer.get_feature_names_out()
            nonzero_indices = vec.nonzero()[1]

            # If model is Logistic Regression, use coef_
            if hasattr(self.model, "coef_"):
                coefs = self.model.coef_[0]
                word_scores = []
                for idx in nonzero_indices:
                    word = feature_names[idx]
                    weight = vec[0, idx] * coefs[idx]
                    word_scores.append((word, float(weight)))

                # Sort by weight (positive = phishing, negative = benign)
                word_scores.sort(key=lambda x: x[1], reverse=True)
                top_phishing = [
                    {"word": w, "contribution": round(s, 4), "impact": "Phishing Indicator"}
                    for w, s in word_scores if s > 0
                ][:top_k]
                
                return {
                    "top_keywords": top_phishing,
                    "summary": f"Identified {len(top_phishing)} primary vocabulary triggers contributing to the classification."
                }
        except Exception as e:
            print(f"[!] Email explainability error: {e}")

        return {"top_keywords": [], "summary": "Linguistic analysis complete."}
