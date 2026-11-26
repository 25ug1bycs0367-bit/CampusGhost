"""Offline stand-ins used by the tests.

* fake_langgraph(): a tiny StateGraph double so our graph nodes can run without the
  real LangGraph package. Like the real library it keeps ONLY keys declared in the
  state schema, so a node that returns an undeclared key loses it (this catches
  bugs such as an undeclared ``seen_calls`` field).
* ScriptedAgent: a deterministic stand-in for Qwen3 that decides what to do next
  purely from the tool results visible in the chat messages.
"""
import json
import sys
import types
from contextlib import contextmanager

_END = "__END__"


class _FakeStateGraph:
    def __init__(self, schema):
        self.keys = set(getattr(schema, "__annotations__", {}))
        self.nodes, self.edges, self.entry, self.conditional = {}, {}, None, None

    def add_node(self, name, function):
        self.nodes[name] = function

    def set_entry_point(self, name):
        self.entry = name

    def add_conditional_edges(self, source, condition, mapping):
        self.conditional = (source, condition, mapping)

    def add_edge(self, source, target):
        self.edges[source] = target

    def compile(self):
        return self

    def invoke(self, initial):
        state = {k: v for k, v in initial.items() if k in self.keys}
        node = self.entry
        for _ in range(60):
            update = self.nodes[node](state)
            state.update({k: v for k, v in update.items() if k in self.keys})
            if self.conditional and node == self.conditional[0]:
                target = self.conditional[2][self.conditional[1](state)]
                if target == _END:
                    return state
                node = target
            else:
                node = self.edges[node]
        raise AssertionError("Test graph did not terminate")


@contextmanager
def fake_langgraph():
    graph_module = types.ModuleType("langgraph.graph")
    graph_module.END = _END
    graph_module.StateGraph = _FakeStateGraph
    package = types.ModuleType("langgraph")
    package.graph = graph_module
    saved = {name: sys.modules.get(name) for name in ("langgraph", "langgraph.graph")}
    sys.modules["langgraph"], sys.modules["langgraph.graph"] = package, graph_module
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def _call(name, **arguments):
    return {"function": {"name": name, "arguments": arguments}}


class ScriptedAgent:
    """Behaves like a tool-using LLM. ``mode`` injects typical small-model failures."""

    def __init__(self, mode="competent"):
        self.mode = mode
        self.transcript = []

    def __call__(self, messages, tools):
        self.transcript.append(json.dumps({"messages": messages, "tools": tools}))
        if self.mode == "lazy":
            return self._final("RETAIN", "SUFFICIENT_EVIDENCE_TO_RETAIN", [])
        if self.mode == "garbage":
            return {"message": {"role": "assistant", "content": "I think we should just revoke everything."}}
        case_ref = json.loads(messages[1]["content"].split("\n", 1)[1])["case_ref"]
        seen = {}
        for message in messages:
            if message.get("role") == "tool":
                content = json.loads(message["content"])
                key = message["tool_name"]
                if key in ("check_permission_policy", "check_permission_expiry"):
                    seen.setdefault(key, {})[content.get("permission_ref")] = content
                else:
                    seen[key] = content
        lifecycle, inventory = seen.get("get_lifecycle_evidence"), seen.get("get_active_permission_inventory")
        if not lifecycle or not inventory:
            calls = []
            if not lifecycle:
                calls.append(_call("get_lifecycle_evidence", person_ref=case_ref))
            if not inventory:
                calls.append(_call("get_active_permission_inventory", person_ref=case_ref))
            return {"message": {"role": "assistant", "content": "", "tool_calls": calls}}
        refs = [p["permission_ref"] for p in inventory["active_permissions"]]
        events = {e["event_type"] for e in lifecycle["lifecycle_events"]}
        ended = lifecycle["relationship_category"] == "FORMER_FACULTY" or bool(
            events & {"EMPLOYMENT_ENDED", "PROJECT_EXIT", "INTERNSHIP_COMPLETED"})
        if ended:
            return self._final("REVOKE", "ENDED_RELATIONSHIP_ACTIVE_PERMISSION", refs)
        policy = seen.get("check_permission_policy", {})
        todo = [_call("check_permission_policy", person_ref=case_ref, permission_ref=r)
                for r in refs if r not in policy]
        if lifecycle["relationship_category"] == "GRADUATE_RESEARCH_ASSISTANT" \
                and "check_research_retention_exception" not in seen:
            todo.append(_call("check_research_retention_exception", person_ref=case_ref))
        if todo:
            return {"message": {"role": "assistant", "content": "", "tool_calls": todo}}
        flagged = [p["permission_ref"] for p in inventory["active_permissions"]
                   if policy[p["permission_ref"]]["policy_result"] == "EXCESSIVE" or p["expiry_state"] == "EXPIRED"]
        if flagged:
            return self._final("REVOKE", "EXCESSIVE_PRIVILEGE", flagged)
        research = seen.get("check_research_retention_exception", {}).get("exception_evidence_found")
        return self._final("RETAIN", "RESEARCH_RETENTION_EXCEPTION" if research else "SUFFICIENT_EVIDENCE_TO_RETAIN", [])

    def _final(self, recommendation, code, refs):
        if self.mode == "fabricate" and recommendation == "REVOKE":
            refs = ["CG-G-FFFFFFFFFFFFFFFF"]
        if self.mode == "partial" and recommendation == "REVOKE":
            refs = refs[:1]
        body = {"recommendation": recommendation, "reason_code": code, "permission_refs_to_revoke": refs}
        if self.mode == "chatty":
            return {"message": {"role": "assistant", "content": "Here is my verdict: " + json.dumps(body) + " Thanks!"}}
        return {"message": {"role": "assistant", "content": json.dumps(body)}}
