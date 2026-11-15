"""
Unit Tests for Email NLP Feature Extraction Engine
==================================================
Validates text normalization, urgency scoring, social engineering detection,
and embedded link extraction.
"""

import pytest
from ml.feature_extraction.email_features import (
    clean_text_for_nlp,
    compute_urgency_score,
    detect_social_engineering,
    extract_embedded_urls,
    extract_full_email_features
)


def test_clean_text_for_nlp():
    raw_html = "<p>Dear user, please <b>verify</b> your password immediately! Visit https://example.com</p>"
    cleaned = clean_text_for_nlp(raw_html)
    assert "<p>" not in cleaned
    assert "https://" not in cleaned
    assert "verify" in cleaned
    assert "password" in cleaned


def test_urgency_score_calculation():
    urgent_text = "URGENT: Your account is suspended immediately within 24 hours. Action required!"
    benign_text = "Hi team, please find the attached notes for our weekly sync on Friday."
    
    score_urgent = compute_urgency_score(urgent_text)
    score_benign = compute_urgency_score(benign_text)

    assert score_urgent >= 0.75
    assert score_benign == 0.0


def test_social_engineering_detection():
    phishing_text = "Urgent: confirm your password to prevent your account from being permanently deleted."
    se = detect_social_engineering(phishing_text)

    assert len(se["categories"]) > 0
    assert "Credential Harvesting" in se["categories"] or "Account Takeover Threat" in se["categories"]


def test_embedded_url_extraction():
    body = "Click here: http://192.168.1.100/login or visit https://secure.bank.com/portal to update."
    urls = extract_embedded_urls(body)
    assert len(urls) == 2
    assert "http://192.168.1.100/login" in urls


def test_full_email_feature_orchestration():
    res = extract_full_email_features(
        subject="URGENT: Account locked",
        body="Access restricted. Verify at http://192.168.1.100/auth",
        sender="security@micros0ft.xyz"
    )
    assert res["urgency_score"] > 0
    assert res["has_suspicious_links"] is True
    assert len(res["embedded_link_assessments"]) == 1
    assert res["embedded_link_assessments"][0]["features"]["is_ip_address"] == 1
