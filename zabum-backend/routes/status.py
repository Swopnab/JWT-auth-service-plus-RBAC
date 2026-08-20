"""
Status & Health API Route for Zabum AI Assistant
"""

from datetime import datetime
from flask import Blueprint, jsonify, request
from services.ai_provider import get_ai_provider

status_bp = Blueprint("status", __name__)

@status_bp.route("/api/status", methods=["GET"])
@status_bp.route("/health", methods=["GET"])
@status_bp.route("/", methods=["GET"])
def system_status():
    provider = get_ai_provider()
    is_avail, provider_msg = provider.is_available()

    return jsonify({
        "status": "online",
        "app_name": "Zabum AI",
        "subtitle": "Personal AI Assistant",
        "version": "2.0.0",
        "ai_provider": {
            "name": provider.__class__.__name__,
            "available": is_avail,
            "message": provider_msg
        },
        "timestamp": datetime.now().isoformat()
    })
