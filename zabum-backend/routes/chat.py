"""
Chat API Route for Zabum AI Assistant
Protected by Cloudflare Worker JWT RBAC authentication
"""

from flask import Blueprint, request, jsonify, g
from config import SYSTEM_PROMPT, MAX_RECENT_MESSAGES
from auth_middleware import require_auth
from models.conversation import ConversationModel, MessageModel
from services.ai_provider import get_ai_provider
from services.memory_service import get_memory_service

chat_bp = Blueprint("chat", __name__)

@chat_bp.route("/api/chat", methods=["POST"])
@require_auth("use_ai_assistant")
def chat():
    """
    Main Chat Endpoint
    Request: { "conversation_id": 1 (optional), "message": "..." }
    """
    user_id = g.user["id"]
    data = request.get_json(silent=True) or {}
    user_text = data.get("message", "").strip()
    conv_id = data.get("conversation_id")

    if not user_text:
        return jsonify({"error": "Message cannot be empty"}), 400

    # 1. Get or create conversation (with strict user ownership check)
    is_new_conv = False
    if not conv_id:
        conv = ConversationModel.create(user_id=user_id, title="New Chat")
        conv_id = conv["id"]
        is_new_conv = True
    else:
        conv = ConversationModel.get_by_id(conv_id, user_id=user_id)
        if not conv:
            conv = ConversationModel.create(user_id=user_id, title="New Chat")
            conv_id = conv["id"]
            is_new_conv = True
        else:
            is_new_conv = MessageModel.count_by_conversation(conv_id, user_id=user_id) == 0

    # 2. Extract and store explicit memories from user message
    memory_service = get_memory_service()
    newly_saved_memories = memory_service.extract_and_save_memory(user_id, user_text)

    # 3. Retrieve relevant personal memories for this user
    relevant_memories = memory_service.get_relevant_memories(user_id, user_text)

    # 4. Build System Context
    context_sections = [SYSTEM_PROMPT]

    # Add nickname personalization
    user_nickname = g.user.get("nickname") or g.user.get("email")
    if user_nickname:
        context_sections.append(f"\n[AUTHENTICATED USER CONTEXT]:\n- User Identifier: {user_nickname}")

    if relevant_memories:
        mem_lines = ["\n[SAVED USER MEMORIES & PREFERENCES]:"]
        for m in relevant_memories:
            mem_lines.append(f"- ({m.get('category', 'general')}) {m['content']}")
        context_sections.append("\n".join(mem_lines))

    final_system_instruction = "\n\n".join(context_sections)

    # 5. Retrieve recent conversation history
    recent_history = MessageModel.get_by_conversation(conv_id, user_id=user_id, limit=MAX_RECENT_MESSAGES)

    llm_messages = [{"role": "system", "content": final_system_instruction}]
    for msg in recent_history:
        llm_messages.append({
            "role": msg["role"],
            "content": msg["content"]
        })
    llm_messages.append({"role": "user", "content": user_text})

    # Save user message to database
    user_msg_record = MessageModel.create(conv_id, user_id, "user", user_text)

    # 6. Generate AI response from provider
    ai_provider = get_ai_provider()
    try:
        assistant_reply = ai_provider.chat(llm_messages)
    except ConnectionError:
        assistant_reply = (
            "⚠️ **Zabum AI is offline.** Start Ollama to use the assistant:\n\n"
            "```bash\n"
            "ollama serve\n"
            "ollama pull llama3.2\n"
            "```"
        )
    except Exception as e:
        assistant_reply = f"⚠️ **Zabum AI encountered an error:** {str(e)}"

    # Save assistant message to database
    assistant_msg_record = MessageModel.create(conv_id, user_id, "assistant", assistant_reply)

    # 7. Auto-generate title if this is the first turn
    current_conv = ConversationModel.get_by_id(conv_id, user_id=user_id)
    if (is_new_conv or current_conv.get("title") == "New Chat") and not assistant_reply.startswith("⚠️"):
        try:
            title_prompt = f"Summarize this initial message into a short 3 to 5 word topic title without quotes:\n\nMessage: {user_text}\n\nTitle:"
            gen_title = ai_provider.generate(title_prompt, options={"temperature": 0.2})
            clean_title = gen_title.strip().strip('"\'').split("\n")[0][:36].strip()
            if clean_title and len(clean_title) >= 2:
                ConversationModel.update_title(conv_id, user_id, clean_title)
                current_conv["title"] = clean_title
        except Exception:
            clean_title = user_text[:28] + ("..." if len(user_text) > 28 else "")
            ConversationModel.update_title(conv_id, user_id, clean_title)
            current_conv["title"] = clean_title

    return jsonify({
        "conversation_id": conv_id,
        "conversation_title": current_conv.get("title", "New Chat"),
        "user_message": user_msg_record,
        "assistant_message": assistant_msg_record,
        "memories_created": newly_saved_memories
    })
