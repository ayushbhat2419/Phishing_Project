"""
Scan Routes (Phase 6)
=====================
REST API endpoints for URL and Email scanning:
- POST /api/v1/scan/url
- POST /api/v1/scan/email
"""

from flask import Blueprint, request, jsonify, current_app
from backend.utils.security import SecurityValidationError

scan_bp = Blueprint("scan_bp", __name__)


@scan_bp.route("/scan/url", methods=["POST"])
def scan_url_endpoint():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing required 'url' parameter in request body."}), 400

    url = data.get("url")
    url_service = current_app.config["URL_SERVICE"]

    try:
        result = url_service.scan_url(url)
        return jsonify(result), 200
    except SecurityValidationError as sve:
        return jsonify({"error": "Security Validation Failed", "details": str(sve)}), 422
    except Exception as e:
        current_app.logger.error(f"Error processing URL scan: {e}")
        return jsonify({"error": "Internal scan processing error.", "message": str(e)}), 500


@scan_bp.route("/scan/email", methods=["POST"])
def scan_email_endpoint():
    data = request.get_json(silent=True)
    if not data or ("subject" not in data and "body" not in data):
        return jsonify({"error": "Request must include 'subject' or 'body'."}), 400

    subject = data.get("subject", "")
    body = data.get("body", "")
    sender = data.get("sender", "")

    email_service = current_app.config["EMAIL_SERVICE"]

    try:
        result = email_service.scan_email(subject=subject, body=body, sender=sender)
        return jsonify(result), 200
    except SecurityValidationError as sve:
        return jsonify({"error": "Security Validation Failed", "details": str(sve)}), 422
    except Exception as e:
        current_app.logger.error(f"Error processing Email scan: {e}")
        return jsonify({"error": "Internal scan processing error.", "message": str(e)}), 500
