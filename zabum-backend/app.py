"""
Zabum AI - Personal AI Assistant Flask Backend
Integrates with Cloudflare Worker RBAC Auth and local Ollama Llama 3.2
"""

import os
from flask import Flask, jsonify
from flask_cors import CORS

from config import PORT
from models.database import init_db
from routes.status import status_bp
from routes.chat import chat_bp
from routes.conversations import conversations_bp
from routes.memory import memory_bp

def create_app():
    """Application factory for Zabum AI Flask backend"""
    app = Flask(__name__)

    # Enable CORS for frontend requests (GitHub Pages, Vite localhost, etc.)
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

    # Initialize Database Schema
    init_db()

    # Register Blueprints
    app.register_blueprint(status_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(conversations_bp)
    app.register_blueprint(memory_bp)

    # Global Error Handlers
    @app.errorhandler(404)
    def not_found_error(e):
        return jsonify({"error": "Endpoint or resource not found", "status_code": 404}), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "Internal server error occurred", "details": str(e), "status_code": 500}), 500

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", PORT))
    print("=" * 60)
    print("🧠 Zabum AI - Personal AI Assistant Backend")
    print(f"🚀 Server running on http://localhost:{port}")
    print("🛡️ Connected to Cloudflare Worker Auth Service")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=port)
