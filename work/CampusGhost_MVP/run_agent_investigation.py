"""Run the Qwen3 + LangGraph agent-led investigation in the terminal and watch it work.

Usage (from this folder):
    python run_agent_investigation.py          # all cases
    python run_agent_investigation.py 7 2      # only person ids 7 and 2
Results are saved, so they also appear in the web dashboard and admin portal.
"""
import os
import sys
import time

os.environ["CAMPUSGHOST_USE_OLLAMA"] = "1"
os.environ["CAMPUSGHOST_AGENT_MODE"] = "led"
os.environ["CAMPUSGHOST_AI_STRICT"] = "1"
os.environ["CAMPUSGHOST_TRACE"] = "1"
os.environ.setdefault("OLLAMA_MODEL", "qwen3:4b")


def preflight() -> None:
    import urllib.request
    try:
        import langgraph  # noqa: F401
    except ImportError:
        sys.exit("LangGraph is not installed. Run: python -m pip install -r requirements-ai.txt")
    try:
        urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5)
    except Exception:
        sys.exit("Ollama is not reachable. Open the Ollama app, then run: python check_ai.py")


def main(argv=None) -> list:
    argv = sys.argv[1:] if argv is None else argv
    preflight()
    import database
    from agent import run_investigation
    from integrations.registry import sync_all_platforms

    database.init_db()
    sync_all_platforms()
    wanted = [int(a) for a in argv if a.isdigit()]
    person_ids = [p for p in database.get_all_person_ids() if not wanted or p in wanted]
    print(f"Model: {os.environ['OLLAMA_MODEL']} | cases: {len(person_ids)} | mode: agent-led (Qwen3 + LangGraph)\n")
    results = []
    for number, person_id in enumerate(person_ids, start=1):
        started = time.time()
        print(f"[{number}/{len(person_ids)}] Investigating person id {person_id} ...", flush=True)
        result = run_investigation(person_id)
        result["investigation_id"] = database.investigate_person(result)
        print(f"   => {result['recommendation']}  (flagged {result['flagged_access_count']}, "
              f"{time.time() - started:.0f}s)  {result['ai_mode']}\n", flush=True)
        results.append(result)
    print("=" * 78)
    print(f"{'CASE REFERENCE':<26}{'OUTCOME':<18}{'FLAGGED':<9}TOOLS USED BY QWEN3")
    for r in results:
        print(f"{r['person_token']:<26}{r['recommendation']:<18}{r['flagged_access_count']:<9}{', '.join(r['agent_tools_used']) or '-'}")
    print("\nOpen the dashboard (python app.py) to review cases and use the admin portal.")
    return results


if __name__ == "__main__":
    main()
