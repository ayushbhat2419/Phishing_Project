# PhishShield AI

An AI-based phishing detection system that analyzes URLs and email content to identify cyber threats using Machine Learning, NLP, and Explainable AI (SHAP).

[![Python](https://img.shields.io/badge/Python-3.14-blue.svg)](https://python.org)
[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.9-orange.svg)](https://scikit-learn.org)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-3.4-38b2ac.svg)](https://tailwindcss.com)

---

## Features

- **URL Phishing Scanner:** Analyzes 18 structural and lexical features (entropy, subdomain depth, IP usage, deceptive keywords) with tree ensembles.
- **Email Phishing Scanner:** NLP preprocessing, TF-IDF vectorization, urgency scoring, social engineering detection, and embedded link extraction.
- **Explainable AI (SHAP):** TreeSHAP feature attribution explaining *why* an input was flagged.
- **Threat Intelligence:** Cross-references with OpenPhish and PhishTank feeds with local caching.
- **Security Hardening:** Air-gapped static feature extraction (no outbound HTTP calls) with strict SSRF defense.
- **Interactive SOC Dashboard:** Real-time metrics, risk distribution, scan history, and benchmark tables.

---

## Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React 18, Vite, Tailwind CSS, Lucide Icons |
| **Backend** | Python 3, Flask, SQLAlchemy, Marshmallow |
| **Machine Learning** | Scikit-learn (Random Forest, Logistic Regression), XGBoost |
| **NLP** | NLTK, TF-IDF Vectorizer |
| **Explainability** | SHAP (TreeExplainer) |
| **Database** | SQLite (Dev) / PostgreSQL (Prod) |

---

## Quickstart

### 1. Prerequisites
- Python 3.10+
- Node.js 18+
- macOS only: `brew install libomp`

### 2. Backend Setup
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Start backend server (port 5001)
export DYLD_LIBRARY_PATH=/opt/homebrew/opt/libomp/lib:$DYLD_LIBRARY_PATH
export PYTHONPATH=.
python3 -m backend.app
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000
```

### 4. Run Tests
```bash
export DYLD_LIBRARY_PATH=/opt/homebrew/opt/libomp/lib:$DYLD_LIBRARY_PATH
export PYTHONPATH=.
pytest tests/ -v
```

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/scan/url` | Scans URL, extracts 18 features, returns verdict & SHAP explanation |
| `POST` | `/api/v1/scan/email` | Analyzes email text/sender, urgency score, and embedded links |
| `GET` | `/api/v1/dashboard/stats` | Telemetry stats, risk breakdown, and recent scans |
| `GET` | `/api/v1/history` | Paginated scan history with filtering |
| `GET` | `/api/v1/models/metrics` | Evaluation metrics across all trained ML & NLP models |
| `GET` | `/api/v1/health` | Backend and model loading health check |

---

## Project Structure

```
Phishing_Project/
├── backend/            # Flask API, routes, services & security utils
├── frontend/           # React + Tailwind web application
├── ml/                 # Feature extraction, training scripts & saved models
├── tests/              # 21 automated unit & integration tests
├── docs/               # Architecture, API docs & interview Q&A
└── README.md
```

---

## Documentation

Detailed technical documents are available in `docs/`:
- [Architecture & System Design](file:///Users/adishbhat/Desktop/Phishing_Project/docs/architecture_and_system_design.md)
- [API Documentation](file:///Users/adishbhat/Desktop/Phishing_Project/docs/api_documentation.md)
- [Dataset Specifications](file:///Users/adishbhat/Desktop/Phishing_Project/docs/dataset_sources.md)
- [Technical Interview Q&A](file:///Users/adishbhat/Desktop/Phishing_Project/docs/interview_qa.md)
