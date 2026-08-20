"""
Memory Management API Route for Zabum AI
All memories isolated strictly by authenticated user ID
"""

from flask import Blueprint, request, jsonify, g
from auth_middleware import require_auth
from models.memory import MemoryModel

memory_bp = Blueprint("memory", __name__)

@memory_bp.route("/api/memories", methods=["GET"])
@require_auth("use_ai_assistant")
def list_memories():
    user_id = g.user["id"]
    category = request.args.get("category")
    search = request.args.get("q")
    memories = MemoryModel.get_all(user_id=user_id, category=category, search=search)
    return jsonify({"memories": memories, "count": len(memories)})

@memory_bp.route("/api/memories", methods=["POST"])
@require_auth("use_ai_assistant")
def create_memory():
    user_id = g.user["id"]
    data = request.get_json(silent=True) or {}
    content = data.get("content", "").strip()
    category = data.get("category", "general").strip()

    if not content:
        return jsonify({"error": "Memory content cannot be empty"}), 400

    mem = MemoryModel.create(user_id=user_id, content=content, category=category)
    return jsonify({"success": True, "memory": mem}), 201

@memory_bp.route("/api/memories/<int:mem_id>", methods=["PUT", "PATCH"])
@require_auth("use_ai_assistant")
def update_memory(mem_id):
    user_id = g.user["id"]
    mem = MemoryModel.get_by_id(mem_id, user_id=user_id)
    if not mem:
        return jsonify({"error": "Memory not found"}), 404

    data = request.get_json(silent=True) or {}
    content = data.get("content", "").strip()
    category = data.get("category")

    if not content:
        return jsonify({"error": "Content cannot be empty"}), 400

    updated = MemoryModel.update(mem_id, user_id=user_id, content=content, category=category)
    return jsonify({"success": True, "memory": updated})

@memory_bp.route("/api/memories/<int:mem_id>", methods=["DELETE"])
@require_auth("use_ai_assistant")
def delete_memory(mem_id):
    user_id = g.user["id"]
    mem = MemoryModel.get_by_id(mem_id, user_id=user_id)
    if not mem:
        return jsonify({"error": "Memory not found"}), 404

    MemoryModel.delete(mem_id, user_id=user_id)
    return jsonify({"success": True, "deleted_id": mem_id})
