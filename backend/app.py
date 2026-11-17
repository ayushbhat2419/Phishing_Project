"""
Flask Application Factory & Entry Point (Phase 6)
=================================================
Initializes database engine, services, blueprints, CORS middleware,
and structured error handlers.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, jsonify
from flask_cors import CORS
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from backend.config import config_by_name
from backend.models.db_models import Base
from backend.services.url_scan_service import URLScanService
from backend.services.email_scan_service import EmailScanService
from backend.routes.scan_routes import scan_bp
from backend.routes.dashboard_routes import dashboard_bp
from backend.routes.history_routes import history_bp
from backend.routes.health_routes import health_bp
from backend.utils.logger import get_logger

logger = get_logger("app_factory")


def create_app(config_name: str = None) -> Flask:
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")

    app = Flask(__name__)
    config_cls = config_by_name.get(config_name, config_by_name["development"])
    app.config.from_object(config_cls)

    # Enable CORS for frontend integration
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Initialize Database Engine & Session Factory
    db_uri = app.config["SQLALCHEMY_DATABASE_URI"]
    engine = create_engine(db_uri, echo=False)
    Base.metadata.create_all(engine)
    session_factory = scoped_session(sessionmaker(bind=engine))
    app.config["DB_SESSION_FACTORY"] = session_factory
    app.config["DB_ENGINE"] = engine

    # Initialize Core Detection Services
    url_service = URLScanService(session_factory)
    email_service = EmailScanService(session_factory)
    app.config["URL_SERVICE"] = url_service
    app.config["EMAIL_SERVICE"] = email_service

    # Register API Blueprints with /api/v1 prefix
    api_prefix = "/api/v1"
    app.register_blueprint(scan_bp, url_prefix=api_prefix)
    app.register_blueprint(dashboard_bp, url_prefix=api_prefix)
    app.register_blueprint(history_bp, url_prefix=api_prefix)
    app.register_blueprint(health_bp, url_prefix=api_prefix)

    # Global Error Handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        return jsonify({"error": "Bad Request", "message": str(e)}), 400

    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({"error": "Resource Not Found", "message": "The requested endpoint does not exist."}), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(e):
        return jsonify({"error": "Method Not Allowed", "message": str(e)}), 405

    @app.errorhandler(500)
    def handle_internal_error(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        session_factory.remove()

    logger.info(f"Flask App Initialized in [{config_name.upper()}] mode with SQLite DB: {db_uri}")
    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5001))
    print(f"[*] Starting AI Phishing Detection Backend on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
