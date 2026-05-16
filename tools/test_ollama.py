import urllib.request
import json

print("Testing Ollama HTTP API...")

payload = json.dumps({
    "model": "gemma4:latest",
    "messages": [{"role": "user", "content": "say hello"}],
    "stream": False,
}).encode()

req = urllib.request.Request(
    "http://localhost:11434/api/chat",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(req, timeout=60) as r:
        body = json.loads(r.read())
        print("SUCCESS:", body["message"]["content"])
except Exception as e:
    print("FAILED:", e)
