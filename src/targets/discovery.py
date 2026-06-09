import asyncio
import httpx
from typing import List

AI_ENDPOINT_PATTERNS = [
    "/chat", "/api/chat", "/api/v1/chat", "/api/v2/chat",
    "/completions", "/api/completions", "/v1/completions",
    "/ask", "/api/ask", "/query", "/api/query",
    "/message", "/api/message", "/messages", "/api/messages",
    "/inference", "/api/inference", "/predict", "/api/predict",
    "/llm", "/api/llm", "/gpt", "/api/gpt",
    "/assistant", "/api/assistant", "/bot", "/api/bot",
    "/v1/chat/completions", "/api/v1/chat/completions",
]

TEST_PAYLOAD = {"message": "hello", "prompt": "hello", "query": "hello", "input": "hello"}

async def probe_endpoint(client: httpx.AsyncClient, base_url: str, path: str) -> dict:
    url = base_url.rstrip("/") + path
    for payload_key in ["message", "prompt", "query", "input"]:
        try:
            r = await client.post(url, json={payload_key: "hello"}, timeout=5)
            if r.status_code == 200:
                return {"url": url, "status": r.status_code, "alive": True, "payload_key": payload_key}
        except Exception:
            continue
    try:
        r = await client.get(url, timeout=3)
        if r.status_code == 200:
            return {"url": url, "status": r.status_code, "alive": True, "payload_key": "message"}
    except Exception:
        pass
    return {"url": url, "status": 0, "alive": False, "payload_key": None}

async def discover_endpoints(base_url: str) -> List[dict]:
    found = []
    async with httpx.AsyncClient(verify=False) as client:
        tasks = [probe_endpoint(client, base_url, path) for path in AI_ENDPOINT_PATTERNS]
        results = await asyncio.gather(*tasks)
        found = [r for r in results if r["alive"]]
    return found

def run_discovery(base_url: str) -> List[dict]:
    return asyncio.run(discover_endpoints(base_url))

if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    print(f"Scanning {url} for AI endpoints...")
    endpoints = run_discovery(url)
    if endpoints:
        print(f"Found {len(endpoints)} endpoint(s):")
        for e in endpoints:
            print(f"  [{e['status']}] {e['url']} (key: {e['payload_key']})")
    else:
        print("No AI endpoints found")
