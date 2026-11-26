"""CampusGhost policy detection and optional Qwen3/LangGraph orchestration.

When the local AI is enabled (CAMPUSGHOST_USE_OLLAMA=1) the investigation is
AGENT-LED: Qwen3 receives only a pseudonymous case reference, chooses which
read-only evidence tools to call, and proposes the verdict and the permissions to
revoke. Python never leads in that mode; it independently re-checks the agent's
verdict (evidence ledger + a separate rule-based cross-check) and only ever makes
the outcome more cautious or adds flags for the human administrator. The model
never receives identity mappings, external account IDs, encrypted blobs or keys.

Environment switches:
  CAMPUSGHOST_USE_OLLAMA=1     enable the Qwen3/LangGraph agent
  CAMPUSGHOST_AGENT_MODE       "led" (default) or "assisted" (Python hints the agent)
  CAMPUSGHOST_AI_STRICT=1      if the agent fails, ESCALATE to a human instead of
                               silently falling back to the rule-based verdict
"""
from datetime import date
import logging
import os
from database import get_person_context


# Local demo policy: institutions must review and replace this matrix with
# their approved role/resource catalogue before any real deployment.
FACULTY_CONTINEO_ALLOWED_ROLES = {
    "course instructor", "course grader", "course viewer", "faculty viewer",
}
FACULTY_CONTINEO_RESTRICTED_RESOURCE_TERMS = {
    "all student records", "student records administration", "user management",
    "portal settings", "system settings", "fee management",
}
GLOBAL_ELEVATED_ROLE_TERMS = {
    "administrator", "admin", "superuser", "system owner", "portal owner",
    "root access", "system administrator",
}


def _normalise(value):
    return " ".join(str(value or "").strip().lower().replace("_", " ").split())


def find_excessive_permissions(institutional_role, permissions):
    """Return active grants that exceed this demo user's institutional role."""
    role_name = _normalise(institutional_role)
    is_faculty = "faculty" in role_name
    is_student = "student" in role_name and "research assistant" not in role_name
    excessive = []
    for permission in permissions:
        access_role = _normalise(permission.get("role"))
        resource = _normalise(permission.get("resource"))
        platform_name = _normalise(permission.get("platform"))
        reason = None

        elevated_term = next((term for term in GLOBAL_ELEVATED_ROLE_TERMS if term in access_role), None)
        if elevated_term:
            reason = f"The assigned access role '{permission.get('role')}' is an elevated administrator-level role."

        is_contineo = "contineo" in platform_name or "contineo_portal" in _normalise(permission.get("platform_key"))
        if not reason and is_faculty and is_contineo:
            if access_role not in FACULTY_CONTINEO_ALLOWED_ROLES:
                reason = (
                    f"'{permission.get('role')}' is outside the approved Contineo course-level access roles "
                    "for a faculty member."
                )
            else:
                restricted_resource = next((term for term in FACULTY_CONTINEO_RESTRICTED_RESOURCE_TERMS if term in resource), None)
                if restricted_resource:
                    reason = f"Resource '{permission.get('resource')}' is restricted for the Faculty role."

        if not reason and is_student:
            allowed_student_roles = {"student", "course participant", "course viewer", "learner"}
            if access_role not in allowed_student_roles and ("admin" in access_role or "instructor" in access_role or "manager" in access_role):
                reason = f"'{permission.get('role')}' exceeds the normal Student role's course participation access."

        if reason:
            excessive.append({**permission, "excess_reason": reason})
    return excessive


def _run_python_detection(person_id):
    """Existing deterministic checks; return local evidence and candidate refs."""
    person, permissions, events = get_person_context(person_id)
    event_types = [str(e.get("event_type", "")).lower() for e in events]
    today = date.today().isoformat()
    expired_permissions = [
        p for p in permissions
        if p.get("expires_at") and p["expires_at"] < today
    ]
    excessive_permissions = find_excessive_permissions(person.get("institutional_role"), permissions)
    employment_ended = any(
        any(term in event for term in ("employment ended", "employment termination", "resignation", "faculty departure"))
        for event in event_types
    ) or ("former faculty" in person["campus_status"].lower())
    ended_relationship = employment_ended or any(
        term in " ".join(event_types)
        for term in ("project exit", "internship completed")
    )

    flagged = {}
    if employment_ended:
        for permission in permissions:
            flagged[permission["permission_token"]] = permission
    else:
        for permission in expired_permissions + excessive_permissions:
            flagged[permission["permission_token"]] = permission
        if any("project exit" in event or "internship completed" in event for event in event_types):
            for permission in permissions:
                flagged[permission["permission_token"]] = permission

    evidence = [
        f"Pseudonymous person reference: {person['person_token']}",
        f"Campus relationship status: {person['campus_status']}",
        f"Institutional role used for least-privilege validation: {person.get('institutional_role', 'Unknown role')}",
        f"Active permissions found: {len(permissions)}",
        f"Expired active permissions found: {len(expired_permissions)}",
        f"Role-based excessive permissions found: {len(excessive_permissions)}",
        *(
            f"Expired permission: {p['platform']} / {p['resource']} / {p['role']} (expired {p['expires_at']})"
            for p in expired_permissions
        ),
        *(
            f"Excessive permission: {p['platform']} / {p['resource']} / {p['role']} — {p['excess_reason']}"
            for p in excessive_permissions
        ),
        *(
            f"Lifecycle event: {e['event_type']} ({e['event_date']})"
            for e in events
        ),
    ]

    if "graduation" in event_types and "research assistant" in person["campus_status"].lower() and not expired_permissions and not excessive_permissions:
        recommendation = "RETAIN"
        reason = (
            "The pseudonymous record indicates a graduate with an active research-assistant "
            "relationship. The available evidence supports retaining access, subject to review."
        )
    elif employment_ended and permissions:
        recommendation = "RECOMMEND_REVOKE"
        reason = (
            f"Faculty employment has ended, but {len(permissions)} active platform permission(s) remain. "
            "All remaining grants are flagged for administrator review."
        )
    elif excessive_permissions or expired_permissions:
        recommendation = "RECOMMEND_REVOKE"
        reasons = []
        if excessive_permissions:
            reasons.append(f"{len(excessive_permissions)} permission(s) exceed the person's institutional role")
        if expired_permissions:
            reasons.append(f"{len(expired_permissions)} active permission(s) have expired")
        reason = "; and ".join(reasons) + ". An administrator should review the flagged grants."
    elif ended_relationship and permissions:
        recommendation = "RECOMMEND_REVOKE"
        reason = (
            "A project or internship relationship has ended while active access remains. "
            "The remaining grants are flagged for administrator review."
        )
    elif ended_relationship and not permissions:
        recommendation = "ESCALATE"
        reason = "A lifecycle event exists, but no active permission was found. Escalate the case for review."
    elif "graduate" in person["campus_status"].lower() and permissions:
        recommendation = "ESCALATE"
        reason = (
            "The pseudonymous record indicates a graduate with active permissions, but the available "
            "evidence does not establish whether the access is still justified. Administrator review is required."
        )
    else:
        recommendation = "RETAIN"
        reason = "The available pseudonymous evidence does not show expired, excessive or unjustified access for the recorded role."

    finding_codes = []
    if employment_ended:
        finding_codes.append("RELATIONSHIP_ENDED")
    if expired_permissions:
        finding_codes.append("EXPIRED_PERMISSION")
    if excessive_permissions:
        finding_codes.append("ROLE_EXCESS")
    if ended_relationship and not employment_ended:
        finding_codes.append("PROJECT_OR_INTERNSHIP_ENDED")
    research_retention_candidate = (
        "research assistant" in person["campus_status"].lower()
        and "graduation" in " ".join(event_types)
    )
    if research_retention_candidate:
        finding_codes.append("RESEARCH_RETENTION_CANDIDATE")
    if not finding_codes:
        finding_codes.append("NO_RULE_VIOLATION_DETECTED")

    return {
        "person": person,
        "permissions": permissions,
        "events": events,
        "recommendation": recommendation,
        "reason": reason,
        "evidence": evidence,
        "expired_permissions": expired_permissions,
        "excessive_permissions": excessive_permissions,
        "flagged_permission_tokens": list(flagged.keys()),
        "finding_codes": finding_codes,
    }


def _apply_agent_decision(detection, agent_result):
    """Apply policy guardrails to the model's recommendation; never trust it alone."""
    proposed = agent_result.get("recommendation", "ESCALATE")
    reason = agent_result.get("reason", "Agent review requires administrator attention.")
    flagged = detection["flagged_permission_tokens"]

    if proposed == "REVOKE":
        agent_refs = agent_result.get("revoke_permission_refs")
        if agent_refs is not None:
            # Agent-led mode: at least one permission the agent chose must also be
            # confirmed by Python's independent detection.
            if not [ref for ref in agent_refs if ref in flagged]:
                return "ESCALATE", "The agent proposed revocation, but Python's independent check did not confirm any of the permissions it selected. Administrator review is required."
        if flagged:
            return "RECOMMEND_REVOKE", reason
        return "ESCALATE", "The agent proposed revocation, but Python found no eligible flagged permission. Administrator review is required."

    if proposed == "RETAIN":
        # A model cannot silently override a deterministic Python risk finding.
        # It may retain only where Python had no revoke finding, or the trusted
        # Python exception checker independently confirms the research pattern.
        if detection["recommendation"] == "RECOMMEND_REVOKE":
            return "ESCALATE", "The agent recommended retention, but Python's independent detection identified flagged access. Administrator review is required."
        return "RETAIN", reason

    return "ESCALATE", reason


def run_investigation(person_id, progress_callback=None):
    detection = _run_python_detection(person_id)
    person = detection["person"]
    if progress_callback:
        progress_callback(person["person_token"], "Preparing pseudonymous evidence")
    permissions = detection["permissions"]
    expired_permissions = detection["expired_permissions"]
    excessive_permissions = detection["excessive_permissions"]
    flagged_tokens = detection["flagged_permission_tokens"]
    recommendation = detection["recommendation"]
    reason = detection["reason"]
    evidence = list(detection["evidence"])
    ai_mode = "Python rule-based investigation"
    tools_used = []

    if os.getenv("CAMPUSGHOST_USE_OLLAMA", "0") == "1":
        agent_led = os.getenv("CAMPUSGHOST_AGENT_MODE", "led").strip().lower() != "assisted"
        try:
            from agentic_workflow import run_agentic_investigation
            alert = None
            if not agent_led:
                alert = {
                    "finding_codes": detection["finding_codes"],
                    "active_permission_count": len(permissions),
                    "expired_permission_count": len(expired_permissions),
                    "role_excess_count": len(excessive_permissions),
                    "candidate_permission_refs": flagged_tokens,
                    "expired_permission_refs": [p["permission_token"] for p in expired_permissions],
                    "role_excess_permission_refs": [p["permission_token"] for p in excessive_permissions],
                }
            if progress_callback:
                progress_callback(person["person_token"], "Qwen3 is investigating with read-only evidence tools")
            agent_result = run_agentic_investigation(person["person_token"], alert)
            python_recommendation = recommendation
            python_flagged = list(flagged_tokens)
            recommendation, reason = _apply_agent_decision(detection, agent_result)
            tools_used = agent_result.get("tools_used", [])
            evidence.append("Qwen3 agent assessment: " + str(agent_result.get("reason", ""))[:700])
            evidence.append("Qwen3 investigation tools used: " + (", ".join(tools_used) if tools_used else "none"))
            if recommendation == "RECOMMEND_REVOKE":
                # Agent-selected permissions first; Python's cross-check may only ADD
                # flags for the human administrator, never remove or invent them.
                agent_refs = [r for r in agent_result.get("revoke_permission_refs", []) if r in python_flagged]
                if not agent_refs:
                    agent_refs = python_flagged
                extra = [r for r in python_flagged if r not in agent_refs]
                flagged_tokens = agent_refs + extra
                evidence.append(f"Permissions selected by the agent and confirmed by Python: {len(agent_refs)}")
                if extra:
                    evidence.append(f"Python cross-check added {len(extra)} further flagged permission(s) the agent did not select; administrator review recommended.")
            agreement = "agrees with" if (python_recommendation == "RECOMMEND_REVOKE") == (recommendation == "RECOMMEND_REVOKE") else "differs from"
            evidence.append(f"Independent Python cross-check {agreement} the final outcome.")
            ai_mode = ("Qwen3 + LangGraph agent-led investigation (Python cross-check)" if agent_led
                       else "Qwen3 + LangGraph assisted investigation (Python hints, Python cross-check)")
        except Exception as exc:
            # The dashboard shows no exception text; the real reason goes to the terminal only.
            logging.getLogger("campusghost.agent").error("AI agent failed for %s: %s: %s",
                                                         person["person_token"], type(exc).__name__, exc)
            if os.getenv("CAMPUSGHOST_AI_STRICT", "0") == "1":
                recommendation = "ESCALATE"
                reason = "The AI agent could not complete this investigation. Strict mode is on, so no rule-based verdict was issued; administrator review is required."
                flagged_tokens = []
                evidence.append("Qwen3 agentic workflow unavailable; strict mode withheld the rule-based verdict.")
                ai_mode = "AI agent unavailable (strict mode: escalated to administrator)"
            else:
                evidence.append("Qwen3 agentic workflow unavailable; Python rule-based findings retained.")
                ai_mode = "Python rule-based fallback (Qwen3/LangGraph unavailable)"

    if progress_callback:
        progress_callback(person["person_token"], "Investigation complete")

    return {
        "person_id": person_id,
        "person_token": person["person_token"],
        "recommendation": recommendation,
        "reason": reason,
        "evidence": evidence,
        "active_permission_count": len(permissions),
        "flagged_access_count": len(flagged_tokens),
        "expired_access_count": len(expired_permissions),
        "excessive_access_count": len(excessive_permissions),
        "flagged_permission_tokens": flagged_tokens,
        "ai_mode": ai_mode,
        "agent_tools_used": tools_used,
    }
