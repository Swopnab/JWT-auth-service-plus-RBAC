"""
Auth Middleware for Zabum AI Flask Backend
Validates JWT tokens against Cloudflare Worker Auth Backend and enforces RBAC permissions
"""

from functools import wraps
import requests
from flask import request, jsonify, g
from config import CF_AUTH_WORKER_URL

def require_auth(permission: str = "use_ai_assistant"):
    """
    Decorator that verifies incoming JWT Bearer token against Cloudflare Auth Worker.
    Ensures that:
    1. Authorization header is present with Bearer token.
    2. Cloudflare Auth Worker validates the token.
    3. User has the required RBAC permission (e.g. 'use_ai_assistant').
    4. Attaches verified user details to flask.g.user.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({
                    "error": "Missing or invalid Authorization header. Please log in.",
                    "code": "UNAUTHORIZED"
                }), 401

            token = auth_header.split(" ", 1)[1].strip()
            if not token:
                return jsonify({
                    "error": "Bearer token is empty.",
                    "code": "UNAUTHORIZED"
                }), 401

            # Validate token against Cloudflare Worker auth backend
            verify_url = f"{CF_AUTH_WORKER_URL.rstrip('/')}/auth/verify"
            try:
                resp = requests.get(
                    verify_url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5
                )
            except requests.exceptions.RequestException as e:
                # If Cloudflare Worker is unreachable, return error
                return jsonify({
                    "error": f"Authentication verification service unreachable: {str(e)}",
                    "code": "AUTH_SERVICE_UNAVAILABLE"
                }), 503

            if resp.status_code != 200:
                error_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                err_message = error_data.get("error", {}).get("message") if isinstance(error_data.get("error"), dict) else error_data.get("error")
                return jsonify({
                    "error": err_message or "Invalid or expired JWT authentication token.",
                    "code": "UNAUTHORIZED"
                }), 401

            data = resp.json()
            user_data = data.get("user")
            if not user_data or "id" not in user_data:
                return jsonify({
                    "error": "Failed to resolve authenticated user identity.",
                    "code": "UNAUTHORIZED"
                }), 401

            # Check RBAC permission
            user_permissions = user_data.get("permissions", [])
            # Support both list of strings or list of objects
            perm_names = [p if isinstance(p, str) else p.get("name") for p in user_permissions]

            if permission and permission not in perm_names:
                return jsonify({
                    "error": f"Access denied: Account lacks required permission '{permission}' to use Zabum AI.",
                    "code": "FORBIDDEN"
                }), 403

            # Store user in Flask context
            g.user = user_data
            g.token = token

            return f(*args, **kwargs)
        return decorated_function
    return decorator
