"""
URL Feature Extraction Engine (Phase 3)
=======================================
Extracts comprehensive lexical, structural, and behavioral features from URLs
strictly via static analysis without outbound network requests (SSRF prevention).

Features Extracted (18 numerical attributes):
 1. url_length: Total character count of full URL
 2. domain_length: Length of the extracted domain/hostname
 3. dot_count: Total period (.) occurrences in URL
 4. hyphen_count: Total hyphen (-) occurrences in URL
 5. special_char_count: Occurrences of @, ?, =, &, %, _, ~, !
 6. has_https: 1 if scheme is https, 0 otherwise
 7. is_ip_address: 1 if hostname is IPv4/IPv6, 0 otherwise
 8. subdomain_count: Number of subdomains preceding registered domain
 9. suspicious_keyword_count: Presence of high-risk security/banking keywords
10. is_shortened: 1 if domain belongs to a known URL shortener service
11. shannon_entropy: Information entropy of the URL string
12. domain_entropy: Information entropy of the domain string
13. digit_count: Total number of numeric digits in the URL
14. digit_ratio: Ratio of digits to total URL length
15. path_depth: Directory depth count in URL path
16. has_at_symbol: 1 if '@' is present (credential obfuscation vector)
17. is_high_risk_tld: 1 if TLD is statistically associated with abuse
18. brand_in_subdomain: 1 if known corporate brand appears in subdomain
"""

import math
import re
from urllib.parse import urlparse
from collections import Counter


# Known URL shortening domains
SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "bitly.com", "cutt.ly", "rebrand.ly", "tiny.cc", "goo.gl", "qr.ae",
    "shorturl.at", "shorte.st"
}

# Suspicious keywords frequently observed in phishing campaigns
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "banking", "secure",
    "account", "password", "credential", "confirm", "wallet", "invoice",
    "billing", "payment", "support", "security", "recovery", "suspend",
    "unauthorized", "unusual", "locked", "service", "admin", "ebayisapi"
]

# High-risk Top-Level Domains frequently abused for disposable phishing campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "work", "click", "club", "site", "ru", "link", "info",
    "live", "biz", "icu", "loan", "men", "stream", "gq", "cf", "ml", "ga"
}

# Legitimate brand keywords often impersonated in subdomains
TARGET_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "citi", "apple",
    "microsoft", "office365", "google", "netflix", "amazon", "dhl",
    "fedex", "usps", "facebook", "meta", "instagram", "coinbase", "binance"
]


def calculate_entropy(text: str) -> float:
    """Computes Shannon entropy of an arbitrary string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = Counter(text)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_ip(hostname: str) -> int:
    """Detects whether hostname is an IPv4 or IPv6 address."""
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ipv4_pattern, hostname):
        return 1
    # Check IPv6 or hex-encoded IP
    if ":" in hostname or hostname.startswith("0x"):
        return 1
    return 0


def extract_url_features(url: str) -> dict:
    """
    Extracts all 18 structural and lexical features from candidate URL.
    Returns dictionary with clean feature names and strictly typed numeric values.
    """
    url_clean = str(url).strip()
    
    # Ensure scheme for correct parsing
    if not re.match(r"^[a-zA-Z]+://", url_clean):
        parsed = urlparse("http://" + url_clean)
    else:
        parsed = urlparse(url_clean)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # 1. Length metrics
    url_length = len(url_clean)
    domain_length = len(hostname)

    # 2. Character counts
    dot_count = url_clean.count(".")
    hyphen_count = url_clean.count("-")
    special_chars = sum(url_clean.count(c) for c in "@?=%&_~!$*+,;")
    has_at_symbol = 1 if "@" in url_clean else 0

    # 3. Protocol & IP characteristics
    has_https = 1 if parsed.scheme.lower() == "https" else 0
    is_ip_address = is_ip(hostname)

    # 4. Domain & Subdomain analysis
    parts = hostname.split(".")
    if is_ip_address:
        subdomain_count = 0
        tld = ""
    elif len(parts) > 2:
        # e.g., "secure.login.bank.com" -> subdomains: "secure", "login"
        subdomain_count = len(parts) - 2
        tld = parts[-1]
    elif len(parts) == 2:
        subdomain_count = 0
        tld = parts[-1]
    else:
        subdomain_count = 0
        tld = parts[0] if parts else ""

    # 5. Shortener detection
    is_shortened = 1 if hostname in SHORTENING_SERVICES else 0

    # 6. Keyword and brand presence
    url_lower = url_clean.lower()
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Check if a target brand name is deceptive in subdomain
    brand_in_subdomain = 0
    if subdomain_count > 0:
        subdomain_str = ".".join(parts[:-2])
        if any(brand in subdomain_str for brand in TARGET_BRANDS):
            brand_in_subdomain = 1

    # 7. Entropy calculations
    shannon_entropy = calculate_entropy(url_clean)
    domain_entropy = calculate_entropy(hostname)

    # 8. Numeric content
    digits = sum(c.isdigit() for c in url_clean)
    digit_ratio = round(digits / url_length, 4) if url_length > 0 else 0.0

    # 9. Path depth
    path_depth = len([p for p in path.split("/") if p])

    # 10. TLD risk evaluation
    is_high_risk_tld = 1 if tld in HIGH_RISK_TLDS else 0

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "special_char_count": special_chars,
        "has_https": has_https,
        "is_ip_address": is_ip_address,
        "subdomain_count": subdomain_count,
        "suspicious_keyword_count": suspicious_keyword_count,
        "is_shortened": is_shortened,
        "shannon_entropy": shannon_entropy,
        "domain_entropy": domain_entropy,
        "digit_count": digits,
        "digit_ratio": digit_ratio,
        "path_depth": path_depth,
        "has_at_symbol": has_at_symbol,
        "is_high_risk_tld": is_high_risk_tld,
        "brand_in_subdomain": brand_in_subdomain
    }


FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "dot_count",
    "hyphen_count",
    "special_char_count",
    "has_https",
    "is_ip_address",
    "subdomain_count",
    "suspicious_keyword_count",
    "is_shortened",
    "shannon_entropy",
    "domain_entropy",
    "digit_count",
    "digit_ratio",
    "path_depth",
    "has_at_symbol",
    "is_high_risk_tld",
    "brand_in_subdomain"
]


def extract_features_vector(url: str):
    """Returns extracted features as an ordered numerical list aligned with FEATURE_NAMES."""
    feat_dict = extract_url_features(url)
    return [feat_dict[name] for name in FEATURE_NAMES]
