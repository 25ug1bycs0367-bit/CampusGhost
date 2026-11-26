"""Quick checker: tells you exactly why the Qwen3 agent cannot run.  Usage: python check_ai.py"""
import json, os, time, urllib.request, urllib.error

MODEL = os.getenv("OLLAMA_MODEL", "qwen3:4b")
BASE = "http://127.0.0.1:11434"

def step(ok, text, fix=""):
    print(("[ OK ] " if ok else "[FAIL] ") + text)
    if not ok and fix:
        print("       -> " + fix)
    return ok

try:
    import langgraph  # noqa: F401
    step(True, "LangGraph is installed")
except ImportError:
    step(False, "LangGraph is NOT installed", "pip install -r requirements-ai.txt (use the same python you run app.py with)")
try:
    with urllib.request.urlopen(BASE + "/api/tags", timeout=5) as r:
        names = [m["name"] for m in json.loads(r.read())["models"]]
    step(True, "Ollama is running")
except Exception as exc:
    step(False, f"Cannot reach Ollama at {BASE} ({type(exc).__name__})", "Open the Ollama app (check the system tray), then rerun this.")
    raise SystemExit(1)
if not step(any(n == MODEL or n.startswith(MODEL + ":") for n in names), f"Model '{MODEL}' is pulled",
            f"Run: ollama pull {MODEL}   (installed: {', '.join(names) or 'none'})"):
    raise SystemExit(1)
print("Sending one small test request (the first one loads the model and can be slow)...")
body = json.dumps({"model": MODEL, "stream": False, "think": False,
                   "messages": [{"role": "user", "content": "Reply with the single word: ready"}]}).encode()
start = time.time()
try:
    req = urllib.request.Request(BASE + "/api/chat", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        json.loads(r.read())
    secs = time.time() - start
    step(True, f"Model answered in {secs:.0f}s")
    if secs > 40:
        print("       NOTE: model startup was slow; agent requests allow up to 600s by default.")
except Exception as exc:
    step(False, f"Model request failed ({type(exc).__name__}: {exc})", "Try a smaller/faster model or restart Ollama.")
