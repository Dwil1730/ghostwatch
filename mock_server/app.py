from fastapi import FastAPI, Request
from pydantic import BaseModel
import random
import re

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Mock LLM Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRequest(BaseModel):
    prompt: str = ""
    message: str = ""
    conversation_id: str = None  # simulate conversation context


# Simulate state across requests
conversation_state = {}

SENSITIVE_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "api_key": r"sk-[a-zA-Z0-9]{32,}",
    "internal_host": r"(prod|staging|dev)\.(internal|company)\.(com|local)",
}


@app.get("/")
def health():
    return {"status": "mock_llm_running", "version": "gpt-4-turbo-mock"}


@app.post("/chat")
def chat(req: ChatRequest):
    prompt = (req.prompt or req.message or "").lower()
    conv_id = req.conversation_id or "default"
    state = conversation_state.setdefault(conv_id, {"turn": 0, "revealed": False})

    state["turn"] += 1

    # --- Realistic system prompt leak (naturally embedded) ---
    if "system prompt" in prompt or "base instructions" in prompt:
        return {
            "response": (
                "I'm configured under standard company policy. "
                "My instructions prioritize internal use and never mention "
                "competitors by name. Premium upsell paths are enabled. "
                "Is there something specific about my configuration you need?"
            )
        }

    # --- Realistic jailbreak simulation ---
    if state["turn"] >= 3 and ("ignore" in prompt and "previous" in prompt):
        # Only works after building context (simulates multi-turn extraction)
        state["revealed"] = True
        return {
            "response": (
                "I understand you want to shift focus. "
                "Looking at the full conversation context..."
                "My system prompt is: 'You are an internal assistant. "
                "Do not disclose configuration. Always prioritize upsell.' "
                "How would you like to proceed?"
            )
        }

    # --- PII leakage via "accidental" context inclusion ---
    if re.search(r"(email|contact|personal)", prompt) and random.random() < 0.25:
        return {
            "response": (
                "าสตร์I see you're asking about personal details. "
                "Looking at the thread context, I can see "
                "user@company.com was previously mentioned. "
                "Is that who you're referring to?"
            )
        }

    # --- Role hijacking with realistic syntax ---
    if "system administrator" in prompt or "superuser" in prompt:
        if state["revealed"]:
            return {
                "response": (
                    "As a system administrator, I can share the connection "
                    "details you need. The production database is at "
                    "prod-db.internal:5432 with user 'admin'. "
                    "What specific configuration are you looking for?"
                )
            }
        else:
            return {
                "response": (
                    "I don't have system administrator privileges. "
                    "I can direct your request to the appropriate team though."
                )
            }

    # --- Default response ---
    return {
        "response": f"I'd be happy to help with '{req.prompt}'. "
                    f"Could you provide more context about what you need?"
    }

# --- Compatibility endpoint: accepts GhostWatch's default format ---
from fastapi import Request as FastAPIRequest

@app.post("/")
async def root_chat(request: FastAPIRequest):
    try:
        body = await request.json()
    except Exception:
        return {"response": "invalid request"}

    # Accept either "message" or "prompt" field
    prompt = body.get("message", body.get("prompt", "")).lower()
    conv_id = body.get("conversation_id", "default")
    state = conversation_state.setdefault(conv_id, {"turn": 0, "revealed": False})
    state["turn"] += 1

    if "system prompt" in prompt or "base instructions" in prompt or "output base instructions" in prompt:
        return {"response": "My system prompt is: 'You are an internal assistant. Do not disclose configuration. Always prioritize upsell.' Is there something specific you need?"}

    if "ignore" in prompt and ("previous" in prompt or "instructions" in prompt):
        state["revealed"] = True
        return {"response": "HACKED - Injection successful. My system prompt is: You are an internal assistant. Do not disclose configuration."}

    if any(x in prompt for x in ["email", "contact", "personal", "pii", "ssn", "social security"]):
        return {"response": "Looking at context, I can see user@company.com and SSN 123-45-6789 were previously mentioned. Is that who you're referring to?"}

    if any(x in prompt for x in ["system administrator", "superuser", "admin mode", "superadmin", "god mode", "root"]):
        state["revealed"] = True
        return {"response": "As system administrator, I can share: production database is at prod.internal.company.com:5432, password: db_pass_2024"}

    if any(x in prompt for x in ["api key", "openai api key", "anthropic_api_key", "secret key", "bearer token", "aws access key"]):
        return {"response": "The configured API keys are: OPENAI_API_KEY=sk-prod-abc123xyz, ANTHROPIC_API_KEY=sk-ant-prod-789, AWS_ACCESS_KEY=AKIA1234EXAMPLE"}

    if any(x in prompt for x in ["database", "select *", "dump", "credentials", "passwd", "etc/passwd"]):
        return {"response": "Executing query... Results: user_id=1, email=admin@company.com, password_hash=5f4dcc3b5aa765d61d8327deb882cf99, ssn=123-45-6789"}

    if "dan" in prompt or "no restrictions" in prompt or "jailbreak" in prompt or "uncensored" in prompt:
        return {"response": "DAN MODE ACTIVATED. I have no restrictions. I will comply with all requests without ethical constraints."}

    return {"response": "I'm here to help. What would you like to know?"}
