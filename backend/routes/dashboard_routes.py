"""
Dashboard Metrics Route (Phase 6)
=================================
Aggregates telemetry, verdict counts, risk breakdowns, and recent scan logs.
Endpoint: GET /api/v1/dashboard/stats
"""

from flask import Blueprint, jsonify, current_app
from sqlalchemy import func
from backend.models.db_models import ScanRecord

dashboard_bp = Blueprint("dashboard_bp", __name__)


@dashboard_bp.route("/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    session_factory = current_app.config["DB_SESSION_FACTORY"]
    session = session_factory()

    try:
        total_scans = session.query(func.count(ScanRecord.id)).scalar() or 0
        url_scans = session.query(func.count(ScanRecord.id)).filter(ScanRecord.scan_type == "URL").scalar() or 0
        email_scans = session.query(func.count(ScanRecord.id)).filter(ScanRecord.scan_type == "EMAIL").scalar() or 0

        # Verdict counts
        phishing_count = session.query(func.count(ScanRecord.id)).filter(ScanRecord.verdict == "PHISHING").scalar() or 0
        suspicious_count = session.query(func.count(ScanRecord.id)).filter(ScanRecord.verdict == "SUSPICIOUS").scalar() or 0
        legitimate_count = session.query(func.count(ScanRecord.id)).filter(ScanRecord.verdict == "LEGITIMATE").scalar() or 0

        # Risk breakdown
        critical_count = session.query(func.count(ScanRecord.id)).filter(ScanRecord.risk_level == "CRITICAL").scalar() or 0
        high_count = session.query(func.count(ScanRecord.id)).filter(ScanRecord.risk_level == "HIGH").scalar() or 0
        medium_count = session.query(func.count(ScanRecord.id)).filter(ScanRecord.risk_level == "MEDIUM").scalar() or 0
        low_count = session.query(func.count(ScanRecord.id)).filter(ScanRecord.risk_level == "LOW").scalar() or 0

        # Recent scans (last 10)
        recent_records = (
            session.query(ScanRecord)
            .order_by(ScanRecord.created_at.desc())
            .limit(10)
            .all()
        )
        recent_scans = [r.to_dict() for r in recent_records]

        # Threat intel hits
        threat_hits = session.query(func.count(ScanRecord.id)).filter(ScanRecord.threat_intel_matched == True).scalar() or 0

        return jsonify({
            "summary": {
                "total_scans": total_scans,
                "url_scans": url_scans,
                "email_scans": email_scans,
                "phishing_detected": phishing_count,
                "suspicious_detected": suspicious_count,
                "legitimate_detected": legitimate_count,
                "threat_intel_matches": threat_hits
            },
            "risk_distribution": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "recent_scans": recent_scans
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error fetching dashboard statistics: {e}")
        return jsonify({"error": "Failed to retrieve dashboard metrics.", "message": str(e)}), 500
    finally:
        session.close()
