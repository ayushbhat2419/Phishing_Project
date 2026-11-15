"""
Email NLP Feature Extraction & Heuristic Engine (Phase 4)
=========================================================
Extracts linguistic, behavioral, and structural security indicators from email
content, headers, and embedded links.

Capabilities:
1. Text Preprocessing: HTML stripping, lowercasing, stop-word filtering, lemmatization
2. Urgency & Coercion Scoring: Detects high-pressure artificial deadlines
3. Social Engineering Pattern Detection: Identifies credential harvesting, financial fraud
4. Sender Domain Anomaly Detection: Checks for typosquatting / generic freemail mismatches
5. Embedded Link Extraction: Discovers URLs in email body for deep structural inspection
"""

import re
import string
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from ml.feature_extraction.url_features import extract_url_features

# Ensure NLTK resources
try:
    STOP_WORDS = set(stopwords.words("english"))
    LEMMATIZER = WordNetLemmatizer()
except Exception:
    STOP_WORDS = set()
    LEMMATIZER = None


# High-urgency and fear-inducing tokens
URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate", "suspended", "suspend", "locked",
    "expire", "expiration", "unauthorized", "unusual", "compromised", "terminate",
    "permanent", "permanently", "within 24 hours", "within 2 hours", "action required",
    "final notice", "critical", "security alert", "fraud alert", "breach"
]

# Social engineering attack categories & signatures
SOCIAL_ENGINEERING_PATTERNS = {
    "Credential Harvesting": [
        "verify your password", "confirm your credentials", "reset your password",
        "update your login", "confirm your account", "re-authenticate", "sign in to verify"
    ],
    "Financial & Wire Fraud": [
        "wire transfer", "confidential meeting", "direct deposit", "w2 form",
        "payroll update", "invoice attached", "unclaimed refund", "bitcoin", "crypto"
    ],
    "Account Takeover Threat": [
        "account suspended", "access restricted", "account on hold",
        "permanently deleted", "closed within", "unrecognized browser"
    ],
    "Delivery / Surcharge Scam": [
        "parcel held", "customs fee", "unpaid customs", "delivery failed",
        "address confirmation", "reschedule delivery"
    ]
}


def clean_text_for_nlp(text: str) -> str:
    """
    Cleans raw email text: strips HTML tags, lowercases, removes punctuation,
    removes stop words, and lemmatizes tokens for TF-IDF vectorization.
    """
    if not text:
        return ""

    # Remove HTML tags
    cleaned = re.sub(r"<[^>]+>", " ", text)
    # Remove URLs from raw text before tokenizing (URLs analyzed separately)
    cleaned = re.sub(r"https?://\S+|www\.\S+", " ", cleaned)
    # Lowercase
    cleaned = cleaned.lower()
    # Remove punctuation
    cleaned = cleaned.translate(str.maketrans("", "", string.punctuation))
    
    tokens = cleaned.split()
    filtered_tokens = []
    for tok in tokens:
        if tok.isalpha() and tok not in STOP_WORDS and len(tok) > 2:
            if LEMMATIZER:
                try:
                    tok = LEMMATIZER.lemmatize(tok)
                except Exception:
                    pass
            filtered_tokens.append(tok)

    return " ".join(filtered_tokens)


def extract_embedded_urls(text: str) -> list:
    """Finds all HTTP/HTTPS and www URLs within the email text."""
    if not text:
        return []
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)


def compute_urgency_score(text: str) -> float:
    """Calculates a normalized urgency score [0.0, 1.0] based on coercive language."""
    if not text:
        return 0.0
    text_lower = text.lower()
    matched = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    # Normalize with saturating curve: 4+ keywords => 1.0
    score = min(1.0, matched / 4.0)
    return round(score, 3)


def detect_social_engineering(text: str) -> dict:
    """Detects social engineering categories and specific matching phrases."""
    text_lower = text.lower()
    detected_categories = []
    matched_phrases = []

    for category, phrases in SOCIAL_ENGINEERING_PATTERNS.items():
        found = [p for p in phrases if p in text_lower]
        if found:
            detected_categories.append(category)
            matched_phrases.extend(found)

    return {
        "categories": detected_categories,
        "matched_phrases": list(set(matched_phrases))
    }


def analyze_sender_domain(sender: str, body: str) -> dict:
    """Checks for sender anomalies (e.g., impersonation of corporate entities via freemail/typosquat)."""
    sender = sender.lower() if sender else ""
    anomalies = []

    if "@" in sender:
        domain = sender.split("@")[-1].strip()
        # Look for numbers substituted in brand names (e.g. micros0ft, paypa1)
        if re.search(r"[a-z]+[0-9]+[a-z]*\.(?:com|org|net|xyz|top|site)", domain):
            anomalies.append(f"Alphanumeric substitution in sender domain: '{domain}'")
        if any(tld in domain for tld in [".xyz", ".top", ".club", ".click", ".ru", ".work"]):
            anomalies.append(f"Sender using high-risk disposable TLD: '{domain}'")
    else:
        if sender:
            anomalies.append(f"Malformed or missing sender domain: '{sender}'")

    return {
        "anomalies": anomalies,
        "has_anomalies": len(anomalies) > 0
    }


def extract_full_email_features(subject: str, body: str, sender: str = "") -> dict:
    """
    Orchestrates full feature extraction for email analysis.
    Returns:
    - Cleaned text string for ML TF-IDF classification
    - Urgency score
    - Social engineering patterns
    - Sender anomalies
    - Extracted embedded URLs and their individual risk assessments
    """
    full_raw = f"{subject} {body}"
    cleaned_nlp_text = clean_text_for_nlp(full_raw)
    urgency = compute_urgency_score(full_raw)
    se_analysis = detect_social_engineering(full_raw)
    sender_analysis = analyze_sender_domain(sender, body)
    
    # Embedded links
    embedded_urls = extract_embedded_urls(body)
    embedded_link_assessments = []
    for link in embedded_urls:
        feats = extract_url_features(link)
        suspicious_flags = []
        if feats["is_ip_address"]:
            suspicious_flags.append("Direct IP address used instead of domain name")
        if not feats["has_https"]:
            suspicious_flags.append("Unencrypted connection (HTTP)")
        if feats["is_shortened"]:
            suspicious_flags.append("URL shortener used to hide final destination")
        if feats["is_high_risk_tld"]:
            suspicious_flags.append("High-risk top level domain")
        if feats["brand_in_subdomain"]:
            suspicious_flags.append("Brand impersonation in subdomain")
            
        embedded_link_assessments.append({
            "url": link,
            "features": feats,
            "suspicious_flags": suspicious_flags,
            "is_suspicious": len(suspicious_flags) > 0
        })

    return {
        "cleaned_nlp_text": cleaned_nlp_text,
        "urgency_score": urgency,
        "social_engineering": se_analysis,
        "sender_analysis": sender_analysis,
        "embedded_urls": embedded_urls,
        "embedded_link_assessments": embedded_link_assessments,
        "has_suspicious_links": any(l["is_suspicious"] for l in embedded_link_assessments)
    }
