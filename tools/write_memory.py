import sys
import os
import json
import urllib.request
import urllib.error

# Configured Netlify URL and Gemini API Bearer Key
NETLIFY_URL = "https://claude-memory-mcp-lock1515.netlify.app/mcp"
API_KEY = "f22bb27ddfa195ae78afb818d91a1fdf5f182565575fd97257f508785a375ad3"

def write_memory(content, category="Projects", title=None, memory_type="semantic", importance=0.5):
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": "memory_write",
            "arguments": {
                "content": content,
                "category": category,
                "memory_type": memory_type,
                "importance": importance
            }
        }
    }
    if title:
        payload["params"]["arguments"]["title"] = title

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    req = urllib.request.Request(
        NETLIFY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            print("Response:", res_data)
            return res_data
    except urllib.error.HTTPError as e:
        print("HTTP Error:", e.code, e.read().decode())
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python write_memory.py <content> [category] [title] [memory_type] [importance]")
        sys.exit(1)
    content = sys.argv[1]
    category = sys.argv[2] if len(sys.argv) > 2 else "Projects"
    title = sys.argv[3] if len(sys.argv) > 3 else None
    m_type = sys.argv[4] if len(sys.argv) > 4 else "semantic"
    imp = float(sys.argv[5]) if len(sys.argv) > 5 else 0.5
    write_memory(content, category, title, m_type, imp)
