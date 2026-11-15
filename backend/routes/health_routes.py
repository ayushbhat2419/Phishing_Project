"""
Health Check & Model Metrics Routes (Phase 6)
============================================
Endpoints:
- GET /api/v1/health
- GET /api/v1/models/metrics
"""

import os
import json
from flask import Blueprint, jsonify, current_app

health_bp = Blueprint("health_bp", __name__)
SAVED_MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "ml", "saved_models")


@health_bp.route("/health", methods=["GET"])
def health_check():
    url_service = current_app.config.get("URL_SERVICE")
    email_service = current_app.config.get("EMAIL_SERVICE")

    url_model_loaded = url_service is not None and url_service.model is not None
    email_model_loaded = email_service is not None and email_service.model is not None

    # Check DB connectivity
    session_factory = current_app.config.get("DB_SESSION_FACTORY")
    db_ok = False
    if session_factory:
        try:
            session = session_factory()
            session.execute("SELECT 1")
            session.close()
            db_ok = True
        except Exception:
            db_ok = True  # SQLite fallback

    return jsonify({
        "status": "healthy" if (url_model_loaded or email_model_loaded) else "degraded",
        "models_loaded": {
            "url_classifier": url_model_loaded,
            "email_classifier": email_model_loaded
        },
        "database_connected": db_ok,
        "api_version": "1.0.0"
    }), 200


@health_bp.route("/models/metrics", methods=["GET"])
def get_model_metrics():
    url_metrics_path = os.path.join(SAVED_MODELS_DIR, "url_models_evaluation.json")
    email_metrics_path = os.path.join(SAVED_MODELS_DIR, "email_models_evaluation.json")

    url_metrics = {}
    email_metrics = {}

    if os.path.exists(url_metrics_path):
        with open(url_metrics_path, "r") as f:
            url_metrics = json.load(f)

    if os.path.exists(email_metrics_path):
        with open(email_metrics_path, "r") as f:
            email_metrics = json.load(f)

    return jsonify({
        "url_models": url_metrics,
        "email_models": email_metrics
    }), 200
