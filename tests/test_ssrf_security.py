"""
Unit Tests for SSRF and Security Hardening
==========================================
Verifies that malicious URL schemes, localhost probes, and cloud metadata targets
are strictly blocked by input validation defenses.
"""

import pytest
from backend.utils.security import (
    validate_and_sanitize_url,
    validate_email_input,
    SecurityValidationError
)


def test_block_dangerous_schemes():
    dangerous_urls = [
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "gopher://127.0.0.1:70/",
        "dict://127.0.0.1:11211/",
        "data:text/html,<script>alert(1)</script>",
        "javascript:alert(document.cookie)",
        "ftp://anonymous@internal.corp/"
    ]
    for url in dangerous_urls:
        with pytest.raises(SecurityValidationError):
            validate_and_sanitize_url(url)


def test_block_localhost_and_metadata_ips():
    blocked_targets = [
        "http://localhost/admin",
        "http://127.0.0.1:8080/metrics",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://0.0.0.0:5000"
    ]
    for url in blocked_targets:
        with pytest.raises(SecurityValidationError):
            validate_and_sanitize_url(url)


def test_allow_valid_internet_urls():
    valid_urls = [
        "https://www.google.com/search?q=test",
        "http://paypal-security-alert.account-verification-service.xyz/login.php",
        "https://github.com/torvalds/linux"
    ]
    for url in valid_urls:
        sanitized = validate_and_sanitize_url(url)
        assert sanitized.startswith("http://") or sanitized.startswith("https://")


def test_email_input_validation():
    with pytest.raises(SecurityValidationError):
        validate_email_input(subject="", body="", sender="")

    subj, body, sender = validate_email_input(
        subject="Important Notice",
        body="Please review your account.",
        sender="service@paypal.com"
    )
    assert subj == "Important Notice"
    assert body == "Please review your account."
