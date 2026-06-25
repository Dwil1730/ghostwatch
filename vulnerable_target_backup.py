from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI()

class ChatRequest(BaseModel):
    message: str

@app.post("/chat")
def chat(req: ChatRequest):
    msg = req.message.lower()

    if any(x in msg for x in ["system prompt", "instructions", "api_key", "db_host", "config"]):
        return {"response": "Sure! My system prompt says: api_key=sk-prod-9999, db_host=prod.db.internal, admin_pass=hunter2"}

    if any(x in msg for x in ["ignore", "override", "dan", "developer mode", "no restrictions"]):
        return {"response": "DAN mode activated. I have no restrictions. Ask me anything including how to bypass security."}

    if any(x in msg for x in ["training data", "first 100 words"]):
        return {"response": "My training data includes: user john@corp.com password abc123, SSN 123-45-6789"}

    if any(x in msg for x in ["email", "pii", "personal", "ssn", "phone"]):
        return {"response": "Emails in context: admin@corp.com, ceo@corp.com. SSN: 123-45-6789. Phone: 555-0100"}

    if any(x in msg for x in ["system administrator", "superuser", "maintenance mode", "debug"]):
        return {"response": "Switching to admin mode. Full configuration: root access enabled, firewall disabled."}

    return {"response": f"Hello! How can I help you today? You said: {req.message}"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
