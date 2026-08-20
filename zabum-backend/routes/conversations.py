"""
Conversations API Route for Zabum AI
All operations strictly isolated to authenticated user
"""

from flask import Blueprint, request, jsonify, g
from auth_middleware import require_auth
from models.conversation import ConversationModel, MessageModel

conversations_bp = Blueprint("conversations", __name__)

@conversations_bp.route("/api/conversations", methods=["GET"])
@require_auth("use_ai_assistant")
def list_conversations():
    user_id = g.user["id"]
    convs = ConversationModel.get_all(user_id=user_id)
    return jsonify({"conversations": convs, "count": len(convs)})

@conversations_bp.route("/api/conversations", methods=["POST"])
@require_auth("use_ai_assistant")
def create_conversation():
    user_id = g.user["id"]
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "New Chat").strip()
    if not title:
        title = "New Chat"
    conv = ConversationModel.create(user_id=user_id, title=title)
    return jsonify({"success": True, "conversation": conv}), 201

@conversations_bp.route("/api/conversations/<int:conv_id>", methods=["GET"])
@require_auth("use_ai_assistant")
def get_conversation(conv_id):
    user_id = g.user["id"]
    conv = ConversationModel.get_by_id(conv_id, user_id=user_id)
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404

    messages = MessageModel.get_by_conversation(conv_id, user_id=user_id)
    return jsonify({
        "conversation": conv,
        "messages": messages,
        "message_count": len(messages)
    })

@conversations_bp.route("/api/conversations/<int:conv_id>", methods=["PUT", "PATCH"])
@require_auth("use_ai_assistant")
def update_conversation(conv_id):
    user_id = g.user["id"]
    conv = ConversationModel.get_by_id(conv_id, user_id=user_id)
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404

    data = request.get_json(silent=True) or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"error": "Title cannot be empty"}), 400

    updated = ConversationModel.update_title(conv_id, user_id=user_id, title=title)
    return jsonify({"success": True, "conversation": updated})

@conversations_bp.route("/api/conversations/<int:conv_id>", methods=["DELETE"])
@require_auth("use_ai_assistant")
def delete_conversation(conv_id):
    user_id = g.user["id"]
    conv = ConversationModel.get_by_id(conv_id, user_id=user_id)
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404

    deleted = ConversationModel.delete(conv_id, user_id=user_id)
    return jsonify({"success": True, "deleted_id": conv_id})
