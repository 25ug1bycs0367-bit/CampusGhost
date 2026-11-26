"""Strict, read-only, pseudonymous tools exposed to the Qwen3 agent.

This module deliberately does NOT import or expose decrypt_json, the AES key
loader, identity_enc, external account IDs, usernames, emails, or admin APIs.
Database access goes through narrowly-scoped evidence queries in database.py.
Only enumerated, pseudonymous evidence is returned to the model.
"""
from __future__ import annotations

from datetime import date
import re
from typing import Any

from database import (
    get_agent_person_evidence,
    get_agent_permission_evidence,
    get_agent_permission_evidence_by_token,
)

PERSON_REF_RE = re.compile(r"^CG-P-[A-F0-9]{16}$")
PERMISSION_REF_RE = re.compile(r"^CG-G-[A-F0-9]{16}$")

# Tool descriptions and schemas only. Source code and database internals are
# never included in the Ollama request.
TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "get_lifecycle_evidence",
            "description": "Retrieve the pseudonymous person's relationship category and lifecycle event types/dates. Does not return identity details.",
            "parameters": {
                "type": "object",
                "properties": {"person_ref": {"type": "string", "description": "CampusGhost pseudonymous reference CG-P-..."}},
                "required": ["person_ref"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_active_permission_inventory",
            "description": "List active permissions for a pseudonymous person using categorical platform, resource and role labels, permission references and expiry status. No identity or platform account identifiers are returned.",
            "parameters": {
                "type": "object",
                "properties": {"person_ref": {"type": "string", "description": "CampusGhost pseudonymous reference CG-P-..."}},
                "required": ["person_ref"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_permission_policy",
            "description": "Check whether one permission exceeds the person's institutional role using CampusGhost's Python least-privilege rules.",
            "parameters": {
                "type": "object",
                "properties": {
                    "person_ref": {"type": "string", "description": "CampusGhost pseudonymous reference CG-P-..."},
                    "permission_ref": {"type": "string", "description": "Permission pseudonymous reference CG-G-..."},
                },
                "required": ["person_ref", "permission_ref"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_permission_expiry",
            "description": "Check the expiry state of one active permission. Returns only a status and date, not identity data.",
            "parameters": {
                "type": "object",
                "properties": {
                    "person_ref": {"type": "string", "description": "CampusGhost pseudonymous reference CG-P-..."},
                    "permission_ref": {"type": "string", "description": "Permission pseudonymous reference CG-G-..."},
                },
                "required": ["person_ref", "permission_ref"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_research_retention_exception",
            "description": "Check for the known graduate research-assistant retention exception in the pseudonymous record.",
            "parameters": {
                "type": "object",
                "properties": {"person_ref": {"type": "string", "description": "CampusGhost pseudonymous reference CG-P-..."}},
                "required": ["person_ref"],
                "additionalProperties": False,
            },
        },
    },
]


def _validate_person_ref(value: Any) -> str:
    token = str(value or "").strip().upper()
    if not PERSON_REF_RE.fullmatch(token):
        raise ValueError("A valid pseudonymous person reference is required.")
    return token


def _validate_permission_ref(value: Any) -> str:
    token = str(value or "").strip().upper()
    if not PERMISSION_REF_RE.fullmatch(token):
        raise ValueError("A valid pseudonymous permission reference is required.")
    return token


def _relationship_category(value: str) -> str:
    value = str(value or "").casefold()
    if "former faculty" in value or "employment ended" in value or "resigned" in value:
        return "FORMER_FACULTY"
    if "current faculty" in value:
        return "CURRENT_FACULTY"
    if "research assistant" in value and ("graduate" in value or "graduated" in value):
        return "GRADUATE_RESEARCH_ASSISTANT"
    if "internship completed" in value:
        return "INTERNSHIP_COMPLETED"
    if "former project member" in value:
        return "FORMER_PROJECT_MEMBER"
    if "current student" in value:
        return "CURRENT_STUDENT"
    if "graduate" in value:
        return "GRADUATE"
    return "UNKNOWN"


def _role_category(value: str) -> str:
    value = str(value or "").casefold()
    if "research assistant" in value:
        return "RESEARCH_ASSISTANT"
    if "faculty" in value or "professor" in value or "lecturer" in value:
        return "FACULTY"
    if "intern" in value:
        return "INTERN"
    if "project" in value:
        return "PROJECT_MEMBER"
    if "student" in value:
        return "STUDENT"
    return "UNKNOWN"


def _platform_category(platform_key: str) -> str:
    key = str(platform_key or "").casefold()
    if "contineo" in key or "moodle" in key:
        return "CONTINEO_LMS"
    if "department_drive" in key:
        return "DEPARTMENT_DRIVE"
    if "project_repository" in key:
        return "PROJECT_REPOSITORY"
    if "research_portal" in key:
        return "RESEARCH_PORTAL"
    return "OTHER_PLATFORM"


def _resource_category(value: str) -> str:
    value = str(value or "").casefold().replace("_", " ")
    if any(term in value for term in ("student record", "all student", "user management", "fee management")):
        return "STUDENT_RECORDS_OR_ADMIN"
    if any(term in value for term in ("portal administration", "portal settings", "system settings")):
        return "PORTAL_ADMINISTRATION"
    if any(term in value for term in ("course", "class", "lms")):
        return "COURSE_CONTENT"
    if any(term in value for term in ("research", "paper", "dataset")):
        return "RESEARCH_CONTENT"
    if any(term in value for term in ("repository", "repo", "source code")):
        return "PROJECT_REPOSITORY_CONTENT"
    if any(term in value for term in ("drive", "department file", "shared file")):
        return "DEPARTMENT_FILES"
    return "GENERAL_RESOURCE"


def _access_role_category(value: str) -> str:
    value = str(value or "").casefold().replace("_", " ")
    if any(term in value for term in ("administrator", "admin", "superuser", "system owner", "root")):
        return "ADMINISTRATOR"
    if "instructor" in value or "teacher" in value:
        return "COURSE_INSTRUCTOR"
    if "grader" in value:
        return "COURSE_GRADER"
    if "research assistant" in value:
        return "RESEARCH_ASSISTANT"
    if "editor" in value:
        return "EDITOR"
    if "contributor" in value:
        return "CONTRIBUTOR"
    if "viewer" in value or "reader" in value:
        return "VIEWER"
    if "student" in value or "learner" in value:
        return "STUDENT"
    return "OTHER_ROLE"


def _safe_date(value: Any) -> str:
    try:
        return date.fromisoformat(str(value or "")).isoformat()
    except ValueError:
        return ""


def _safe_event_type(value: str) -> str:
    key = str(value or "").casefold()
    if "graduat" in key:
        return "GRADUATION"
    if "employment ended" in key or "termination" in key or "resignation" in key or "departure" in key:
        return "EMPLOYMENT_ENDED"
    if "project exit" in key:
        return "PROJECT_EXIT"
    if "internship completed" in key:
        return "INTERNSHIP_COMPLETED"
    return "OTHER_LIFECYCLE_EVENT"


def _assert_model_safe(value: Any) -> None:
    """Fail closed unless every returned field belongs to the model-safe schema."""
    allowed_keys = {
        "person_ref", "relationship_category", "institutional_role_category",
        "lifecycle_events", "event_type", "event_date", "active_permissions",
        "permission_ref", "platform_category", "resource_category",
        "access_role_category", "expiry_state", "expires_on", "active",
        "policy_result", "reason_code", "exception_code", "exception_evidence_found",
    }
    forbidden = ("identity", "email", "name", "password", "cipher", "encrypt", "decrypt",
                 "secret", "key", "external", "username", "account_id", "person_id", "department")
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).casefold()
            if lowered not in allowed_keys or any(term in lowered for term in forbidden):
                raise ValueError("Tool output blocked by CampusGhost model-data boundary.")
            _assert_model_safe(item)
    elif isinstance(value, list):
        for item in value:
            _assert_model_safe(item)
    elif isinstance(value, str):
        if "@" in value or "-----BEGIN" in value or re.search(r"(?i)campusghost\.key|aes.?256|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", value):
            raise ValueError("Tool output blocked by CampusGhost model-data boundary.")


def _profile(person_ref: str) -> dict:
    return get_agent_person_evidence(_validate_person_ref(person_ref))


def _permission(person_ref: str, permission_ref: str) -> dict:
    return get_agent_permission_evidence_by_token(
        _validate_person_ref(person_ref), _validate_permission_ref(permission_ref)
    )


def get_lifecycle_evidence(person_ref: str) -> dict:
    record = _profile(person_ref)
    result = {
        "person_ref": record["person_token"],
        "relationship_category": _relationship_category(record["campus_status"]),
        "institutional_role_category": _role_category(record["institutional_role"]),
        "lifecycle_events": [
            {"event_type": _safe_event_type(item.get("event_type")),
             "event_date": _safe_date(item.get("event_date"))}
            for item in record.get("events", [])
        ],
    }
    _assert_model_safe(result)
    return result


def get_active_permission_inventory(person_ref: str) -> dict:
    token = _validate_person_ref(person_ref)
    raw_permissions = get_agent_permission_evidence(token)
    inventory = []
    today = date.today().isoformat()
    for permission in raw_permissions:
        expiry = permission.get("expires_at")
        expiry_state = "NO_EXPIRY" if not expiry else ("EXPIRED" if str(expiry) < today else "VALID")
        inventory.append({
            "permission_ref": permission["permission_token"],
            "platform_category": _platform_category(permission["platform_key"]),
            "resource_category": _resource_category(permission["resource"]),
            "access_role_category": _access_role_category(permission["role"]),
            "expiry_state": expiry_state,
            "expires_on": _safe_date(expiry) if expiry else None,
            "active": True,
        })
    result = {"person_ref": token, "active_permissions": inventory}
    _assert_model_safe(result)
    return result


def check_permission_policy(person_ref: str, permission_ref: str) -> dict:
    token = _validate_person_ref(person_ref)
    permission = _permission(token, permission_ref)
    profile = _profile(token)
    if not permission["active"]:
        result = {"permission_ref": permission["permission_token"], "policy_result": "INACTIVE_PERMISSION"}
    else:
        # Reuse the project's Python role/resource policy; only return a reason code.
        from agent import find_excessive_permissions
        normalized = [{
            "platform": permission["platform"],
            "platform_key": permission["platform_key"],
            "resource": permission["resource"],
            "role": permission["role"],
        }]
        violations = find_excessive_permissions(profile["institutional_role"], normalized)
        if violations:
            raw_reason = str(violations[0].get("excess_reason", "" )).casefold()
            code = "ELEVATED_PRIVILEGE" if "administrator" in raw_reason or "elevated" in raw_reason else "ROLE_OR_RESOURCE_MISMATCH"
            result = {"permission_ref": permission["permission_token"], "policy_result": "EXCESSIVE", "reason_code": code}
        else:
            result = {"permission_ref": permission["permission_token"], "policy_result": "WITHIN_ROLE_POLICY"}
    _assert_model_safe(result)
    return result


def check_permission_expiry(person_ref: str, permission_ref: str) -> dict:
    permission = _permission(person_ref, permission_ref)
    if not permission["active"]:
        state = "INACTIVE_PERMISSION"
    elif not permission.get("expires_at"):
        state = "NO_EXPIRY"
    elif str(permission["expires_at"]) < date.today().isoformat():
        state = "EXPIRED"
    else:
        state = "VALID"
    result = {"permission_ref": permission["permission_token"], "expiry_state": state,
              "expires_on": _safe_date(permission.get("expires_at")) if permission.get("expires_at") else None}
    _assert_model_safe(result)
    return result


def check_research_retention_exception(person_ref: str) -> dict:
    record = _profile(person_ref)
    relationship = _relationship_category(record["campus_status"])
    role = _role_category(record["institutional_role"])
    events = [_safe_event_type(item.get("event_type")) for item in record.get("events", [])]
    inventory = get_active_permission_inventory(person_ref)["active_permissions"]
    has_research_access = any(p["platform_category"] == "RESEARCH_PORTAL" for p in inventory)
    exception = (relationship == "GRADUATE_RESEARCH_ASSISTANT" and
                 role == "RESEARCH_ASSISTANT" and "GRADUATION" in events and has_research_access)
    result = {"exception_code": "APPROVED_RESEARCH_ASSISTANT_PATTERN" if exception else "NO_RESEARCH_EXCEPTION_EVIDENCE",
              "exception_evidence_found": bool(exception)}
    _assert_model_safe(result)
    return result


TOOL_FUNCTIONS = {
    "get_lifecycle_evidence": get_lifecycle_evidence,
    "get_active_permission_inventory": get_active_permission_inventory,
    "check_permission_policy": check_permission_policy,
    "check_permission_expiry": check_permission_expiry,
    "check_research_retention_exception": check_research_retention_exception,
}


def execute_agent_tool(name: str, arguments: Any, allowed_person_ref: str | None = None) -> dict:
    """Execute one read-only tool, optionally scoped to the current investigation."""
    if name not in TOOL_FUNCTIONS:
        raise ValueError("Tool is not available to the CampusGhost agent.")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object.")
    allowed_args = {
        "get_lifecycle_evidence": {"person_ref"},
        "get_active_permission_inventory": {"person_ref"},
        "check_permission_policy": {"person_ref", "permission_ref"},
        "check_permission_expiry": {"person_ref", "permission_ref"},
        "check_research_retention_exception": {"person_ref"},
    }[name]
    if set(arguments) != allowed_args:
        raise ValueError("Tool arguments do not match the approved schema.")
    if allowed_person_ref is not None:
        scoped_ref = _validate_person_ref(allowed_person_ref)
        requested_ref = _validate_person_ref(arguments.get("person_ref"))
        if requested_ref != scoped_ref:
            raise ValueError("Tool access is limited to the current pseudonymous case.")
    result = TOOL_FUNCTIONS[name](**arguments)
    _assert_model_safe(result)
    return result
