"""
Unit Tests for URL Feature Extraction Engine
============================================
Validates extraction of lexical, structural, and behavioral features.
"""

import pytest
from ml.feature_extraction.url_features import (
    extract_url_features,
    extract_features_vector,
    calculate_entropy,
    is_ip,
    FEATURE_NAMES
)


def test_ip_address_detection():
    assert is_ip("192.168.1.1") == 1
    assert is_ip("185.220.101.45") == 1
    assert is_ip("google.com") == 0
    assert is_ip("paypal.com.account-update.xyz") == 0


def test_entropy_calculation():
    # Identical string has zero entropy
    assert calculate_entropy("aaaaaa") == 0.0
    # Diverse string has positive entropy
    assert calculate_entropy("a1B!c2D@") > 2.5


def test_feature_extraction_phishing_url():
    url = "http://paypal-security-alert.account-verification-service.xyz/login.php"
    feats = extract_url_features(url)

    assert feats["has_https"] == 0
    assert feats["is_high_risk_tld"] == 1
    assert feats["suspicious_keyword_count"] >= 2
    assert feats["subdomain_count"] >= 1
    assert len(feats) == len(FEATURE_NAMES)


def test_feature_extraction_benign_url():
    url = "https://docs.python.org/3/library/urllib.parse.html"
    feats = extract_url_features(url)

    assert feats["has_https"] == 1
    assert feats["is_ip_address"] == 0
    assert feats["is_high_risk_tld"] == 0
    assert feats["is_shortened"] == 0


def test_features_vector_alignment():
    url = "https://github.com/torvalds/linux"
    vec = extract_features_vector(url)
    assert len(vec) == len(FEATURE_NAMES)
    assert isinstance(vec, list)
