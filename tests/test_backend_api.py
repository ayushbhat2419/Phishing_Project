"""
API Endpoint & Security Integration Tests (Phase 6)
===================================================
Tests health, metrics, URL detection, Email detection, Dashboard,
and SSRF security rejection rules using Flask test client.
"""

import json
import pytest
from backend.app import create_app


@pytest.fixture
def client():
    app = create_app("testing")
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    """Verifies backend health check returns status healthy."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] in ("healthy", "degraded")
    assert "models_loaded" in data
    assert data["api_version"] == "1.0.0"


def test_models_metrics_endpoint(client):
    """Verifies model metrics retrieval."""
    res = client.get("/api/v1/models/metrics")
    assert res.status_code == 200
    data = res.get_json()
    assert "url_models" in data
    assert "email_models" in data


def test_scan_url_phishing(client):
    """Tests URL scanner on a known deceptive phishing URL."""
    payload = {"url": "http://paypal-security-alert.account-verification-service.xyz/login.php"}
    res = client.post("/api/v1/scan/url", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["verdict"] in ("PHISHING", "SUSPICIOUS")
    assert data["confidence_score"] >= 0.70
    assert "explanation" in data
    assert "features" in data
    assert len(data["explanation"]["top_contributing_features"]) > 0


def test_scan_url_legitimate(client):
    """Tests URL scanner on a known authoritative benign URL."""
    payload = {"url": "https://docs.python.org/3/library/urllib.parse.html"}
    res = client.post("/api/v1/scan/url", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["verdict"] == "LEGITIMATE"
    assert data["risk_level"] == "LOW"


def test_ssrf_protection_blocked(client):
    """Tests rejection of dangerous URI schemes and localhost targets."""
    # Scheme violation
    res = client.post("/api/v1/scan/url", json={"url": "file:///etc/passwd"})
    assert res.status_code == 422
    assert "Security Validation Failed" in res.get_json()["error"]

    # Localhost / SSRF probe
    res = client.post("/api/v1/scan/url", json={"url": "http://127.0.0.1:8080/admin"})
    assert res.status_code == 422


def test_scan_email_phishing(client):
    """Tests Email scanner on an urgent credential theft email."""
    payload = {
        "sender": "security@micros0ft-support.xyz",
        "subject": "URGENT: Your account is suspended within 24 hours",
        "body": "Your access has been locked due to unauthorized activity. Confirm your password at http://192.168.1.100/verify immediately or account will be permanently closed."
    }
    res = client.post("/api/v1/scan/email", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["verdict"] == "PHISHING"
    assert data["confidence_score"] >= 0.70
    assert data["indicators"]["urgency_score"] > 0.0
    assert len(data["indicators"]["embedded_links"]) > 0


def test_dashboard_and_history(client):
    """Verifies dashboard counters increment and history is retrievable."""
    # Perform a scan first
    client.post("/api/v1/scan/url", json={"url": "https://www.google.com"})

    # Check dashboard
    res_dash = client.get("/api/v1/dashboard/stats")
    assert res_dash.status_code == 200
    dash_data = res_dash.get_json()
    assert dash_data["summary"]["total_scans"] >= 1

    # Check history
    res_hist = client.get("/api/v1/history?page=1&limit=10")
    assert res_hist.status_code == 200
    hist_data = res_hist.get_json()
    assert len(hist_data["records"]) >= 1
