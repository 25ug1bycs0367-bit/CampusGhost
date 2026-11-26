from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from pathlib import Path
import os
import secrets
from threading import Lock
from functools import wraps
from database import (
    init_db, get_dashboard_data, get_all_person_ids, investigate_person,
    get_audit_logs, reset_demo, get_admin_review, admin_review_cases,
    has_current_revoke_recommendation, revoke_permission_record, confirm_permission_revoked,
)
from integrations.registry import sync_all_platforms, revoke_on_platform, reset_simulated_platforms
from agent import run_investigation

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
investigation_progress = {"active": False, "current": None, "completed": 0, "total": 0, "message": "Idle"}
investigation_progress_lock = Lock()

app.secret_key = os.getenv("CAMPUSGHOST_SESSION_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return jsonify({"error": "Administrator login required."}), 401
        return fn(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")
    # Requested local-hackathon demo credential. Set CAMPUSGHOST_ADMIN_PASSWORD
    # to override it before any non-demo deployment.
    configured_password = os.getenv("CAMPUSGHOST_ADMIN_PASSWORD") or "zxcvbnm@123"
    configured_user = os.getenv("CAMPUSGHOST_ADMIN_USERNAME", "admin")
    payload = request.get_json(silent=True) or request.form
    import hmac
    if hmac.compare_digest(str(payload.get("username", "")), configured_user) and hmac.compare_digest(str(payload.get("password", "")), configured_password):
        session.clear()
        session["admin_authenticated"] = True
        session["admin_user"] = configured_user
        session["csrf_token"] = secrets.token_urlsafe(32)
        return jsonify({"success": True, "redirect": url_for("admin_portal")})
    return jsonify({"error": "Invalid administrator credentials."}), 401


@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.get("/admin")
def admin_portal():
    if not session.get("admin_authenticated"):
        return redirect(url_for("admin_login"))
    return render_template("admin.html", csrf_token=session.get("csrf_token", ""), admin_user=session.get("admin_user", "admin"))


@app.get("/api/admin/cases")
@admin_required
def admin_cases():
    return jsonify(admin_review_cases())


@app.get("/api/admin/review/<person_token>")
@admin_required
def admin_review(person_token):
    if not has_current_revoke_recommendation(person_token):
        return jsonify({"error": "No current RECOMMEND_REVOKE finding exists for this pseudonymous identity."}), 403
    try:
        return jsonify(get_admin_review(person_token))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@app.post("/api/admin/revoke")
@admin_required
def admin_revoke():
    if request.headers.get("X-CSRF-Token") != session.get("csrf_token"):
        return jsonify({"error": "Invalid security token. Refresh the admin portal and try again."}), 403
    data = request.get_json(silent=True) or {}
    person_token = str(data.get("person_token", ""))
    permission_token = str(data.get("permission_token", ""))
    if not has_current_revoke_recommendation(person_token):
        return jsonify({"error": "Revocation is allowed only for a current RECOMMEND_REVOKE finding."}), 403
    try:
        target = revoke_permission_record(person_token, permission_token, session.get("admin_user", "admin"))
        result = revoke_on_platform(target["platform_key"], target["external_account_id"], target["resource"])
        confirm_permission_revoked(target["permission_id"], person_token, session.get("admin_user", "admin"), result)
        return jsonify({"success": True, "message": "Platform confirmed the permission revocation; the local record and audit log were updated."})
    except (ValueError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Administrator revocation failed")
        return jsonify({"error": "Revocation failed. No local permission status was changed."}), 500


@app.get("/api/dashboard")
def dashboard():
    return jsonify(get_dashboard_data())


@app.get("/api/audit")
def audit():
    return jsonify(get_audit_logs())


@app.post("/api/platforms/sync")
def sync_platforms():
    try:
        results = sync_all_platforms()
        return jsonify({"results": results, "dashboard": get_dashboard_data()})
    except Exception:
        app.logger.exception("Platform synchronisation failed")
        return jsonify({"error": "Platform synchronisation failed. Check the terminal for details."}), 500


@app.get("/api/investigation-progress")
def get_investigation_progress():
    """Expose only pseudonymous progress; never return identity fields."""
    with investigation_progress_lock:
        return jsonify(dict(investigation_progress))


@app.post("/api/investigate-all")
def investigate_all():
    """Investigate all pseudonymous identities and generate human-readable reports."""
    try:
        results = []
        person_ids = get_all_person_ids()
        with investigation_progress_lock:
            investigation_progress.update({"active": True, "current": None, "completed": 0,
                                           "total": len(person_ids), "message": "Starting investigation"})
        def update_progress(person_ref, message):
            with investigation_progress_lock:
                investigation_progress.update({"current": person_ref, "message": message})
        for index, person_id in enumerate(person_ids, start=1):
            result = run_investigation(person_id, progress_callback=update_progress)
            result["investigation_id"] = investigate_person(result)
            result.pop("person_id", None)
            results.append(result)
            with investigation_progress_lock:
                investigation_progress.update({"completed": index, "message": "Case completed"})
        priority = {"RECOMMEND_REVOKE": 0, "ESCALATE": 1, "RETAIN": 2}
        results.sort(key=lambda item: (
            priority.get(item["recommendation"], 3),
            -item["flagged_access_count"],
            -item["expired_access_count"],
            -item["active_permission_count"],
            item["person_token"],
        ))
        for rank, result in enumerate(results, start=1):
            result["rank"] = rank
        with investigation_progress_lock:
            investigation_progress.update({"active": False, "current": None, "completed": len(results),
                                           "total": len(results), "message": "All investigations completed"})
        return jsonify({"results": results, "total_records": len(results)})
    except Exception:
        with investigation_progress_lock:
            investigation_progress.update({"active": False, "message": "Investigation failed"})
        app.logger.exception("Bulk investigation failed")
        return jsonify({"error": "Bulk investigation failed. Check the terminal for details."}), 500


@app.post("/api/reset")
def reset():
    reset_simulated_platforms()
    reset_demo()
    results = sync_all_platforms()
    return jsonify({"message": "Pseudonymous demo data reset and simulated platforms synchronised.", "platforms": results})


if __name__ == "__main__":
    init_db()
    connector_results = sync_all_platforms()
    connected = sum(1 for item in connector_results if item["status"] == "success")
    print("\nCampusGhost is starting: http://127.0.0.1:5000")
    print(f"Platform data sources synchronised: {connected}/{len(connector_results)}")
    print("Pseudonymous demo data is used. Database records are encrypted at rest.")
    print("Admin portal: http://127.0.0.1:5000/admin/login")
    print("Demo admin username: admin | Demo password: zxcvbnm@123 (local demonstration only).\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
