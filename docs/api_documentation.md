# PhishShield AI - RESTful API Specification (v1.0.0)

Base URL: `http://127.0.0.1:5001/api/v1`  
Protocol: `HTTP / HTTPS`  
Data Format: `application/json`

---

## 1. URL Detection Endpoint

### `POST /scan/url`
Accepts a candidate URL, performs SSRF security validation, cross-references threat intelligence feeds, extracts 18 lexical and structural features, and predicts malicious probability using trained tree ensemble models with SHAP explainability.

#### Request Headers
| Header | Value | Description |
| :--- | :--- | :--- |
| `Content-Type` | `application/json` | Required |

#### Request Body Schema
```json
{
  "url": "string (Required. Max length: 2048 chars)"
}
```

#### Example cURL
```bash
curl -X POST http://127.0.0.1:5001/api/v1/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-security-alert.account-verification-service.xyz/login.php"}'
```

#### Success Response (`200 OK`)
```json
{
  "scan_id": "9d71c893-cb91-4cf3-94c9-b684cb32d43e",
  "target": "http://paypal-security-alert.account-verification-service.xyz/login.php",
  "verdict": "PHISHING",
  "confidence_score": 1.0,
  "risk_level": "CRITICAL",
  "features": {
    "url_length": 70,
    "domain_length": 47,
    "dot_count": 3,
    "hyphen_count": 4,
    "special_char_count": 0,
    "has_https": 0,
    "is_ip_address": 0,
    "subdomain_count": 1,
    "suspicious_keyword_count": 3,
    "is_shortened": 0,
    "shannon_entropy": 4.542,
    "domain_entropy": 4.128,
    "is_high_risk_tld": 1,
    "brand_in_subdomain": 0
  },
  "explanation": {
    "top_contributing_features": [
      {
        "feature_name": "has_https",
        "title": "HTTPS Encryption",
        "shap_value": 0.1855,
        "feature_value": 0,
        "impact_type": "Increases Phishing Risk",
        "description": "Absence of HTTPS (unencrypted HTTP) exposes credentials to interception."
      },
      {
        "feature_name": "is_high_risk_tld",
        "title": "High-Risk Top-Level Domain",
        "shap_value": 0.0547,
        "feature_value": 1,
        "impact_type": "Increases Phishing Risk",
        "description": "TLDs such as .xyz, .top, or .work are statistically associated with low-cost phishing."
      }
    ],
    "human_readable_reasons": [
      "HTTPS Encryption: Absence of HTTPS exposes credentials to interception.",
      "High-Risk Top-Level Domain: TLD .xyz is statistically associated with abuse."
    ]
  },
  "threat_intelligence": {
    "matched": true,
    "provider": "OpenPhish / PhishTank Feed",
    "status": "KNOWN_THREAT_DATABASE_MATCH",
    "threat_details": "OpenPhish Active Feed: Impersonation campaign"
  },
  "execution_time_ms": 18
}
```

#### Error Responses
- **`400 Bad Request`**: Missing `url` parameter.
- **`422 Unprocessable Entity`**: Security validation failed (e.g. SSRF loopback attempt `http://127.0.0.1`, prohibited scheme `file://`, or length exceeded).

---

## 2. Email Detection Endpoint

### `POST /scan/email`
Ingests email subject, body, and sender header. Performs NLP preprocessing, TF-IDF vectorization, linguistic urgency analysis, social engineering pattern recognition, and embedded link inspection.

#### Request Body Schema
```json
{
  "subject": "string (Optional if body provided)",
  "body": "string (Optional if subject provided)",
  "sender": "string (Optional)"
}
```

#### Example cURL
```bash
curl -X POST http://127.0.0.1:5001/api/v1/scan/email \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "security-alert@micros0ft-live-protection.com",
    "subject": "URGENT: Your Office 365 Account is Suspended - Action Required",
    "body": "Your account has been locked. Verify immediately at http://192.168.1.100/secure-login or your account will be permanently deleted within 24 hours."
  }'
```

#### Success Response (`200 OK`)
```json
{
  "scan_id": "4c6981fa-ea11-470a-8bf8-984bb3018e69",
  "sender": "security-alert@micros0ft-live-protection.com",
  "subject": "URGENT: Your Office 365 Account is Suspended - Action Required",
  "verdict": "PHISHING",
  "confidence_score": 0.95,
  "risk_level": "CRITICAL",
  "indicators": {
    "urgency_score": 0.85,
    "social_engineering": {
      "categories": ["Credential Harvesting", "Account Takeover Threat"],
      "matched_phrases": ["account suspended", "permanently deleted", "verify immediately"]
    },
    "sender_analysis": {
      "has_anomalies": true,
      "anomalies": ["Alphanumeric substitution in sender domain: 'micros0ft-live-protection.com'"]
    },
    "embedded_links": [
      {
        "url": "http://192.168.1.100/secure-login",
        "is_suspicious": true,
        "suspicious_flags": [
          "Direct IP address used instead of domain name",
          "Unencrypted connection (HTTP)"
        ]
      }
    ]
  },
  "explanation": {
    "top_keywords": [
      {"word": "suspended", "contribution": 0.421, "impact": "Phishing Indicator"},
      {"word": "permanently", "contribution": 0.318, "impact": "Phishing Indicator"}
    ],
    "human_readable_reasons": [
      "Email contains suspicious or unencrypted destination links.",
      "High urgency score (0.85) indicates pressure tactics.",
      "Detected social engineering patterns: Credential Harvesting, Account Takeover Threat."
    ]
  },
  "execution_time_ms": 34
}
```

---

## 3. Security Dashboard Telemetry

### `GET /dashboard/stats`
Returns aggregated scan volume, category breakdowns, risk distribution counters, and recent scan logs.

#### Success Response (`200 OK`)
```json
{
  "summary": {
    "total_scans": 142,
    "url_scans": 98,
    "email_scans": 44,
    "phishing_detected": 46,
    "suspicious_detected": 18,
    "legitimate_detected": 78,
    "threat_intel_matches": 12
  },
  "risk_distribution": {
    "critical": 32,
    "high": 14,
    "medium": 18,
    "low": 78
  },
  "recent_scans": [ ... ]
}
```

---

## 4. Scan History & Detail

### `GET /history?page=1&limit=20&type=URL&verdict=PHISHING`
Paginated audit query with filtering options.

### `GET /history/<scan_id>`
Retrieves complete historical snapshot including full 18-attribute feature vector and SHAP values.

---

## 5. System Health & Model Performance

### `GET /health`
Returns health of loaded ML models and database connectivity.

### `GET /models/metrics`
Returns cross-validated test set metrics (Accuracy, Precision, Recall, F1, ROC-AUC, and Confusion Matrices) for all trained classifiers.
