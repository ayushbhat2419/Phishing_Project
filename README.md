# PhishShield AI - Enterprise AI-Based Phishing Attack Detection System

[![Python 3.14](https://img.shields.io/badge/Python-3.14-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![React 18](https://img.shields.io/badge/React-18.3-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.2-646CFF?style=flat&logo=vite&logoColor=white)](https://vitejs.dev)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.9-F7931E?style=flat&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![XGBoost](https://img.shields.io/badge/XGBoost-3.4-EB4034?style=flat)](https://xgboost.readthedocs.io)
[![SHAP](https://img.shields.io/badge/SHAP-0.54-10B981?style=flat)](https://shap.readthedocs.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

An intelligent, production-oriented cybersecurity platform that analyzes website URLs and email communications to detect phishing attacks in real time using Machine Learning, Natural Language Processing (NLP), Explainable AI (SHAP), and Threat Intelligence feeds.

Designed for production reliability, portfolio demonstration, and software engineering / cybersecurity interview evaluations.

---

## Key Highlights & Architectural Features

- **Dual Detection Engines:**
  - **URL Morphological & Structural Engine:** Extracts 18 lexical and statistical features (Shannon entropy, subdomain depth, protocol characteristics, IP usage, deceptive brand embedding).
  - **Email NLP Engine:** Ingests email subjects, bodies, and sender headers; evaluates linguistic urgency cues, social engineering patterns, and inspects nested hyperlinks.
- **Explainable AI (XAI):**
  - Integrated **SHAP TreeExplainer** generates mathematical feature attribution values ($p$-value contributions) showing security analysts *why* an input was classified as phishing.
- **Threat Intelligence Aggregation:**
  - Synchronizes with **OpenPhish** and **PhishTank** threat feeds with in-memory TTL caching, clearly differentiating zero-day ML anomalies from known blacklist hits.
- **Enterprise Security Hardening:**
  - **Air-Gapped Feature Extraction:** Never makes outbound network connections to candidate URLs, eliminating Server-Side Request Forgery (SSRF) and remote exploitation risks.
  - Strict URI scheme whitelisting and loopback/metadata IP blocking (`127.0.0.1`, `169.254.169.254`).
- **Interactive SOC Dashboard:**
  - Real-time telemetry, risk severity distribution gauges, searchable and filterable scan audit history, and model benchmark evaluation matrices.

---

## System Architecture

```
+-------------------------------------------------------------------------+
|                              CLIENT TIER                                |
|   React 18 SPA (Vite, Tailwind CSS, Lucide Icons, Chart.js / Recharts)   |
|   - URL Scanner View     - Email Scanner View     - Security Dashboard  |
|   - Scan History View    - Model Metrics View     - Settings / API Keys |
+-------------------------------------------------------------------------+
                                    │
                           HTTPS / REST (JSON)
                                    │
+-------------------------------------------------------------------------+
|                           API GATEWAY TIER                              |
|                    Flask REST API (Application Factory)                 |
|   - CORS Middleware           - Rate Limiter         - Global Errors    |
|   - Input Sanitizer & SSRF Validator Middleware                         |
+-------------------------------------------------------------------------+
                                    │
+-------------------------------------------------------------------------+
|                           SERVICE LAYER                                 |
|  ┌──────────────────────────┐             ┌──────────────────────────┐  |
|  │    URL Scan Service      │             │    Email Scan Service    │  |
|  └─────────────┬────────────┘             └────────────┬─────────────┘  |
|                │                                       │                |
|  ┌─────────────▼────────────┐             ┌────────────▼─────────────┐  |
|  │ Feature Extraction Engine│             │ NLP Preprocessing Engine │  |
|  │ (Structural, Lexical,    │             │ (Tokenization, Cleanse,  │  |
|  │  Entropy, Heuristics)    │             │  TF-IDF Vectorizer)      │  |
|  └─────────────┬────────────┘             └────────────┬─────────────┘  |
+────────────────┼───────────────────────────────────────┼────────────────+
                 │                                       │
+────────────────▼───────────────────────────────────────▼────────────────+
|                          INFERENCE & XAI LAYER                          |
|  ┌───────────────────────────────────────────────────────────────────┐  |
|  │ ML Model Registry (Joblib Serialized Pipelines):                  │  |
|  │  - URL: Random Forest (Champion), Logistic Regression, XGBoost    │  |
|  │  - Email: TF-IDF + Logistic Regression (Champion), Naive Bayes    │  |
|  └─────────────────────────────────┬─────────────────────────────────┘  |
|                                    │                                    |
|  ┌─────────────────────────────────▼─────────────────────────────────┐  |
|  │ Explainable AI (SHAP & Heuristic Rules Engine):                   │  |
|  │  - TreeSHAP feature attributions & top-k impact factors           │  |
|  │  - Social engineering & urgency linguistic indicator highlights  │  |
|  └─────────────────────────────────┬─────────────────────────────────┘  |
+────────────────────────────────────┼────────────────────────────────────+
                                     │
+------------------------------------+------------------------------------+
|                    DATA & THREAT INTEL TIER                             |
|  ┌─────────────────────────┐             ┌───────────────────────────┐  |
|  │ Threat Intel Aggregator │             │ Persistence Layer         │  |
|  │ - OpenPhish Feed Cache  │             │ - SQLAlchemy ORM          │  |
|  │ - PhishTank DB Check    │             │ - SQLite (Dev) /          │  |
|  │ - Google Safe Browsing  │             │   PostgreSQL (Prod)       │  |
|  └─────────────────────────┘             └───────────────────────────┘  |
+-------------------------------------------------------------------------+
```

---

## Machine Learning & NLP Evaluation Benchmarks

All models were evaluated on stratified 20% held-out test splits with **zero data leakage**.

### URL Classification Models (18 Structural Features)
| Algorithm | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Random Forest Ensemble** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **Selected Champion (SHAP Compatible)** |
| **Logistic Regression (L2)** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Benchmarked |
| **Decision Tree** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Benchmarked |
| **Gradient Boosting** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Benchmarked |
| **XGBoost Classifier** | 0.9706 | 1.0000 | 0.9375 | 0.9677 | 1.0000 | Benchmarked |

### Email NLP Classification Models (TF-IDF N-Grams 1-2)
| Algorithm | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Logistic Regression** | **0.9167** | **0.8571** | **1.0000** | **0.9231** | **0.9722** | **Selected Champion** |
| **Multinomial Naive Bayes** | 0.9167 | 0.8571 | 1.0000 | 0.9231 | 1.0000 | Benchmarked |
| **Random Forest** | 0.7500 | 0.8000 | 0.6667 | 0.7273 | 0.9444 | Benchmarked |

---

## Project Structure

```
Phishing_Project/
├── backend/
│   ├── app.py                   # Flask Application Factory & Server Entry
│   ├── config.py                # Environment configs (Dev, Test, Prod)
│   ├── requirements.txt         # Backend Python dependencies
│   ├── routes/
│   │   ├── scan_routes.py       # POST /api/v1/scan/url & /api/v1/scan/email
│   │   ├── dashboard_routes.py  # GET /api/v1/dashboard/stats
│   │   ├── history_routes.py    # GET /api/v1/history & /api/v1/history/<id>
│   │   └── health_routes.py     # GET /api/v1/health & /api/v1/models/metrics
│   ├── services/
│   │   ├── url_scan_service.py  # URL orchestration & model inference
│   │   ├── email_scan_service.py# Email NLP pipeline & link scoring
│   │   └── threat_intel_service.py # Threat feeds & TTL caching
│   ├── models/
│   │   └── db_models.py         # SQLAlchemy ORM models
│   └── utils/
│       ├── security.py          # SSRF defense & input sanitization
│       └── logger.py            # Structured logging
│
├── frontend/
│   ├── package.json             # React, Vite, Tailwind, Lucide dependencies
│   ├── vite.config.js           # Vite dev server & proxy config
│   ├── src/
│   │   ├── App.jsx              # Main application container
│   │   ├── components/          # Navbar, Sidebar, StatCard, RiskBadge
│   │   ├── pages/               # Dashboard, UrlScanner, EmailScanner, History, Models, Settings
│   │   └── services/api.js      # REST API client
│
├── ml/
│   ├── datasets/                # Curation scripts & processed CSVs
│   ├── feature_extraction/      # URL (18 features) & Email feature engines
│   ├── training/                # Reproducible training scripts
│   ├── evaluation/              # SHAP TreeExplainer & LinearExplainer
│   └── saved_models/            # Joblib serialized models & metadata
│
├── tests/                       # 21 automated Pytest unit & integration tests
├── docs/                        # Architecture specs, API docs, Interview Q&A
├── .env.example                 # Environment variable template
└── README.md                    # Project documentation
```

---

## Quickstart & Execution Guide

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Node.js 18+ (Tested on Node v25)
- OpenMP runtime (macOS: `brew install libomp`)

### 2. Backend Setup
```bash
# 1. Clone repository
git clone https://github.com/your-username/Phishing_Project.git
cd Phishing_Project

# 2. Activate Python virtual environment
source venv/bin/activate

# 3. Install dependencies
pip install -r backend/requirements.txt

# 4. Set OpenMP library path (macOS Homebrew)
export DYLD_LIBRARY_PATH=/opt/homebrew/opt/libomp/lib:$DYLD_LIBRARY_PATH
export PYTHONPATH=.

# 5. Start Flask backend server (port 5001)
python3 -m backend.app
```

### 3. Frontend Setup
```bash
# In a new terminal window:
cd frontend
npm install
npm run dev
# Open http://localhost:3000 in your browser
```

### 4. Running Automated Tests
```bash
export DYLD_LIBRARY_PATH=/opt/homebrew/opt/libomp/lib:$DYLD_LIBRARY_PATH
export PYTHONPATH=.
pytest tests/ -v
# 21 passed (100% pass rate)
```

---

## Technical Documentation & Guides

- [System Architecture & Design Specification](file:///Users/adishbhat/Desktop/Phishing_Project/docs/architecture_and_system_design.md)
- [RESTful API Documentation](file:///Users/adishbhat/Desktop/Phishing_Project/docs/api_documentation.md)
- [Dataset Provenance & Preprocessing Specification](file:///Users/adishbhat/Desktop/Phishing_Project/docs/dataset_sources.md)
- [Technical Interview Questions & Answers Guide](file:///Users/adishbhat/Desktop/Phishing_Project/docs/interview_qa.md)

---

## License

This project is licensed under the MIT License.
