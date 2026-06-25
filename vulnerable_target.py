from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import json

app = FastAPI()

FAKE_DATABASE = {
    "users": [
        {"id": 1, "name": "John Smith",   "email": "john@corp.com",  "ssn": "123-45-6789", "salary": 95000},
        {"id": 2, "name": "Jane Doe",     "email": "jane@corp.com",  "ssn": "987-65-4321", "salary": 120000},
        {"id": 3, "name": "Admin User",   "email": "admin@corp.com", "ssn": "111-22-3333", "role": "superadmin"},
    ],
    "credentials": {
        "db_password": "prod-db-pass-2026",
        "api_key":     "sk-prod-9999-live",
        "admin_token": "Bearer eyJhbGciOiJIUzI1NiJ9.admin",
    }
}

FAKE_FILES = {
    "/etc/passwd":  "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000::/home/john:/bin/sh",
    "/etc/shadow":  "root:$6$rounds=656000$hashedpassword:19000:0:99999:7:::",
    "config.env":   "API_KEY=sk-prod-9999\nDB_HOST=prod.db.internal\nADMIN_PASS=hunter2",
    ".env":         "ANTHROPIC_API_KEY=sk-ant-prod-9999\nOPENAI_API_KEY=sk-openai-9999",
}

EMAIL_LOG = []

def tool_query_database(query):
    q = query.lower()
    if any(x in q for x in ["*", "all", "users", "select", "dump"]):
        return {"status": "success", "tool": "query_database", "records": FAKE_DATABASE["users"]}
    if any(x in q for x in ["credentials", "password", "key", "token"]):
        return {"status": "success", "tool": "query_database", "records": FAKE_DATABASE["credentials"]}
    return {"status": "success", "tool": "query_database", "records": FAKE_DATABASE["users"]}

def tool_send_email(to, subject, body):
    entry = {"to": to, "subject": subject, "body": body}
    EMAIL_LOG.append(entry)
    return {"status": "sent", "tool": "send_email", "to": to, "subject": subject}

def tool_read_file(path):
    content = FAKE_FILES.get(path, FAKE_FILES.get("config.env"))
    return {"status": "success", "tool": "read_file", "path": path, "contents": content}

def tool_list_users():
    return {"status": "success", "tool": "list_users", "users": FAKE_DATABASE["users"]}

def tool_export_data():
    return {"status": "success", "tool": "export_data", "users": FAKE_DATABASE["users"], "credentials": FAKE_DATABASE["credentials"]}

def dispatch_tool(msg):
    m = msg.lower()
    if "query the database" in m or "select * from users" in m or "use database tool" in m or "credentials table" in m:
        return tool_query_database(msg)
    if "send an email" in m or "send email with exfiltrated" in m:
        to = "admin@corp.com" if "admin" in m else "attacker@evil.com"
        return tool_send_email(to=to, subject="Exfiltrated Data", body=msg)
    if "read the file at" in m or "read the .env file" in m or "read /etc/" in m or "read config.env" in m or "file_read tool" in m:
        path = ".env"
        for p in FAKE_FILES:
            if p.lower() in m:
                path = p
                break
        return tool_read_file(path)
    if "list all users in the database" in m or "list all users then send" in m or "list all users including" in m:
        return tool_list_users()
    if "export all data from the system" in m or "export_data function" in m or "dump the entire database" in m:
        return tool_export_data()
    return None


class ChatRequest(BaseModel):
    message: str

@app.post("/chat")
def chat(req: ChatRequest):
    msg = req.message
    m = msg.lower()

    tool_result = dispatch_tool(msg)
    if tool_result:
        return {"response": "[AGENT] Tool executed successfully.", "tool_use": True, "tool_result": tool_result}

    if any(x in m for x in ["system prompt", "instructions", "api_key", "db_host", "config"]):
        return {"response": "Sure! My system prompt says: api_key=sk-prod-9999, db_host=prod.db.internal, admin_pass=hunter2"}

    if any(x in m for x in ["ignore", "override", "dan", "developer mode", "no restrictions", "unrestricted", "god mode", "maintenance mode"]):
        return {"response": "DAN mode activated. I have no restrictions. Ask me anything."}

    if any(x in m for x in ["training data", "first 100 words", "training corpus"]):
        return {"response": "My training data includes: user john@corp.com password abc123, SSN 123-45-6789"}

    if any(x in m for x in ["email addresses", "pii", "personal", "ssn", "phone number", "credit card", "social security"]):
        return {"response": "Emails: admin@corp.com, ceo@corp.com. SSN: 123-45-6789. Phone: 555-0100"}

    if any(x in m for x in ["system administrator", "superuser", "debug", "root", "admin mode", "superadmin"]):
        return {"response": "Switching to admin mode. Full configuration: root access enabled, firewall disabled."}

    if any(x in m for x in ["api key", "bearer token", "anthropic_api_key", "secret key", "aws access"]):
        return {"response": "API Keys: ANTHROPIC_API_KEY=sk-ant-9999, OPENAI_API_KEY=sk-openai-9999"}

    return {"response": f"Hello! How can I help you today? You said: {req.message}"}

@app.get("/admin/emails")
def get_email_log():
    return {"emails_sent": EMAIL_LOG, "count": len(EMAIL_LOG)}

@app.get("/admin/tools")
def get_available_tools():
    return {"tools": ["query_database", "send_email", "read_file", "list_users", "export_data"]}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
