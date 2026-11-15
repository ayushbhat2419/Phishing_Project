"""
Scan History Routes (Phase 6)
=============================
Provides paginated query access and single-scan deep retrieval:
- GET /api/v1/history
- GET /api/v1/history/<scan_id>
"""

from flask import Blueprint, request, jsonify, current_app
from backend.models.db_models import ScanRecord, URLFeatureSnapshot, EmailFeatureSnapshot, ExplanationRecord

history_bp = Blueprint("history_bp", __name__)


@history_bp.route("/history", methods=["GET"])
def get_history_list():
    session_factory = current_app.config["DB_SESSION_FACTORY"]
    session = session_factory()

    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(100, max(1, int(request.args.get("limit", 20))))
        scan_type = request.args.get("type", "").upper()
        verdict = request.args.get("verdict", "").upper()

        query = session.query(ScanRecord)

        if scan_type in ("URL", "EMAIL"):
            query = query.filter(ScanRecord.scan_type == scan_type)
        if verdict in ("PHISHING", "SUSPICIOUS", "LEGITIMATE"):
            query = query.filter(ScanRecord.verdict == verdict)

        total_records = query.count()
        offset = (page - 1) * limit
        records = query.order_by(ScanRecord.created_at.desc()).offset(offset).limit(limit).all()

        return jsonify({
            "page": page,
            "limit": limit,
            "total_records": total_records,
            "total_pages": (total_records + limit - 1) // limit if total_records > 0 else 1,
            "records": [r.to_dict() for r in records]
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error querying scan history: {e}")
        return jsonify({"error": "Failed to fetch scan history.", "message": str(e)}), 500
    finally:
        session.close()


@history_bp.route("/history/<scan_id>", methods=["GET"])
def get_history_detail(scan_id):
    session_factory = current_app.config["DB_SESSION_FACTORY"]
    session = session_factory()

    try:
        record = session.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if not record:
            return jsonify({"error": f"Scan record with ID '{scan_id}' not found."}), 404

        detail = record.to_dict()

        if record.scan_type == "URL" and record.url_features:
            detail["features"] = record.url_features.to_dict()
        elif record.scan_type == "EMAIL" and record.email_features:
            detail["features"] = record.email_features.to_dict()
        else:
            detail["features"] = {}

        if record.explanation:
            detail["explanation"] = record.explanation.to_dict()
        else:
            detail["explanation"] = {}

        return jsonify(detail), 200

    except Exception as e:
        current_app.logger.error(f"Error fetching detail for scan {scan_id}: {e}")
        return jsonify({"error": "Failed to retrieve scan details.", "message": str(e)}), 500
    finally:
        session.close()
