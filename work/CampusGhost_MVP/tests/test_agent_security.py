import base64
import json
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import database
from integrations.registry import sync_all_platforms
from agent_tools import TOOL_FUNCTIONS, TOOL_SPECS, execute_agent_tool
from agentic_workflow import run_agentic_investigation
from agent import run_investigation, _apply_agent_decision


class CampusGhostAgentSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db, self.old_key = database.DB_PATH, database.KEY_PATH
        database.DB_PATH = Path(self.temp.name) / "test.db"
        database.KEY_PATH = Path(self.temp.name) / "test.key"
        database.init_db()
        sync_all_platforms()
        with database.connect() as con:
            self.people = [dict(row) for row in con.execute(
                "SELECT id, person_token, identity_enc FROM persons ORDER BY id"
            )]
        self.person_id = self.people[6]["id"]
        self.person_ref = self.people[6]["person_token"]
        self.identity_ciphertext = bytes(self.people[6]["identity_enc"])

    def tearDown(self):
        database.DB_PATH, database.KEY_PATH = self.old_db, self.old_key
        self.temp.cleanup()

    def test_agent_tools_never_read_encrypted_identity_mapping(self):
        original_decrypt = database.decrypt_json

        def guarded_decrypt(blob, default=None):
            if blob is not None and bytes(blob) == self.identity_ciphertext:
                raise AssertionError("Agent tool attempted to decrypt identity_enc")
            return original_decrypt(blob, default)

        with patch.object(database, "decrypt_json", side_effect=guarded_decrypt), \
             patch.dict("os.environ", {"CAMPUSGHOST_USE_OLLAMA": "0"}):
            lifecycle = execute_agent_tool("get_lifecycle_evidence", {"person_ref": self.person_ref})
            inventory = execute_agent_tool("get_active_permission_inventory", {"person_ref": self.person_ref})
            # The complete Python detection pass must also avoid the identity map.
            report = run_investigation(self.person_id)
        self.assertEqual(report["recommendation"], "RECOMMEND_REVOKE")
        self.assertEqual(lifecycle["relationship_category"], "FORMER_FACULTY")
        self.assertGreaterEqual(len(inventory["active_permissions"]), 1)

    def test_normal_investigation_sql_cannot_read_identity_mapping_or_clear_identity_columns(self):
        original_connect = database.connect

        from contextlib import contextmanager
        @contextmanager
        def guarded_connect():
            with original_connect() as con:
                def authorizer(action, table, column, _database, _trigger):
                    if action == sqlite3.SQLITE_READ and table == "persons" and column in {
                        "identity_enc", "name", "email", "department_enc"
                    }:
                        return sqlite3.SQLITE_DENY
                    return sqlite3.SQLITE_OK
                con.set_authorizer(authorizer)
                yield con

        with patch.object(database, "connect", guarded_connect), \
             patch.dict("os.environ", {"CAMPUSGHOST_USE_OLLAMA": "0"}):
            result = run_investigation(self.person_id)
        self.assertEqual(result["recommendation"], "RECOMMEND_REVOKE")

    def test_legacy_role_field_is_backfilled_without_changing_admin_identity(self):
        with database.connect() as con:
            con.execute("UPDATE persons SET institutional_role_enc=NULL WHERE id=?", (self.person_id,))
        database.init_db()
        evidence = execute_agent_tool("get_lifecycle_evidence", {"person_ref": self.person_ref})
        self.assertEqual(evidence["institutional_role_category"], "FACULTY")
        result = run_investigation(self.person_id)
        database.investigate_person(result)
        review = database.get_admin_review(self.person_ref)
        self.assertEqual(review["identity"]["full_name"], "Dr. Rohan Iyer")

    def test_model_tool_results_are_categorical_and_do_not_contain_identity_or_ciphertext(self):
        payload = {
            "lifecycle": execute_agent_tool("get_lifecycle_evidence", {"person_ref": self.person_ref}),
            "permissions": execute_agent_tool("get_active_permission_inventory", {"person_ref": self.person_ref}),
        }
        text = json.dumps(payload)
        self.assertNotIn("Dr. Rohan Iyer", text)
        self.assertNotIn("rohan.iyer.demo@campus.test", text)
        self.assertNotIn(self.identity_ciphertext.hex(), text)
        self.assertNotIn("external_account_id", text)
        self.assertIn("FORMER_FACULTY", text)
        self.assertIn("ADMINISTRATOR", text)

    def test_tool_arguments_require_pseudonymous_references_and_reject_extra_fields(self):
        with self.assertRaises(ValueError):
            execute_agent_tool("get_lifecycle_evidence", {"person_ref": "rohan.iyer.demo@campus.test"})
        with self.assertRaises(ValueError):
            execute_agent_tool("get_lifecycle_evidence", {"person_ref": self.person_ref, "email": "x@y.test"})
        other_ref = self.people[5]["person_token"]
        with self.assertRaises(ValueError):
            execute_agent_tool("get_lifecycle_evidence", {"person_ref": other_ref}, allowed_person_ref=self.person_ref)

    def test_agent_has_no_identity_decryption_database_or_revocation_tool(self):
        names = set(TOOL_FUNCTIONS)
        self.assertNotIn("decrypt_identity", names)
        self.assertNotIn("get_admin_review", names)
        self.assertNotIn("revoke_permission", names)
        self.assertTrue(all(spec["function"]["name"] in names for spec in TOOL_SPECS))

    def test_model_driven_tool_loop_uses_langgraph_and_only_receives_safe_data(self):
        # A small test double exercises our StateGraph nodes because LangGraph
        # cannot be installed in this offline build environment. Runtime uses
        # the real LangGraph package from requirements-ai.txt.
        fake_graph_module = types.ModuleType("langgraph.graph")
        fake_graph_module.END = "__END__"

        class FakeStateGraph:
            def __init__(self, _schema):
                self.nodes = {}
                self.entry = None
                self.conditional = None
                self.edges = {}

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
                state = dict(initial)
                node = self.entry
                for _ in range(30):
                    state.update(self.nodes[node](state))
                    if self.conditional and node == self.conditional[0]:
                        route = self.conditional[1](state)
                        target = self.conditional[2][route]
                        if target == fake_graph_module.END:
                            return state
                        node = target
                    else:
                        node = self.edges[node]
                raise AssertionError("Test graph did not terminate")

        fake_graph_module.StateGraph = FakeStateGraph
        fake_langgraph = types.ModuleType("langgraph")
        fake_langgraph.graph = fake_graph_module
        old_langgraph = sys.modules.get("langgraph")
        old_graph = sys.modules.get("langgraph.graph")
        sys.modules["langgraph"] = fake_langgraph
        sys.modules["langgraph.graph"] = fake_graph_module
        try:
            inventory = execute_agent_tool("get_active_permission_inventory", {"person_ref": self.person_ref})
            permission_ref = next(p["permission_ref"] for p in inventory["active_permissions"]
                                  if p["access_role_category"] == "ADMINISTRATOR")
            calls = []

            def fake_model_call(messages, tools):
                calls.append(json.dumps({"messages": messages, "tools": tools}))
                turn = len(calls)
                if turn == 1:
                    message = {"role": "assistant", "content": "", "tool_calls": [{
                        "function": {"name": "get_lifecycle_evidence", "arguments": {"person_ref": self.person_ref}}
                    }]}
                elif turn == 2:
                    message = {"role": "assistant", "content": "", "tool_calls": [{
                        "function": {"name": "get_active_permission_inventory", "arguments": {"person_ref": self.person_ref}}
                    }]}
                elif turn == 3:
                    message = {"role": "assistant", "content": "", "tool_calls": [{
                        "function": {"name": "check_permission_policy", "arguments": {
                            "person_ref": self.person_ref, "permission_ref": permission_ref
                        }}
                    }]}
                else:
                    message = {"role": "assistant", "content": json.dumps({
                        "recommendation": "REVOKE",
                        "reason_code": "ENDED_RELATIONSHIP_ACTIVE_PERMISSION"
                    })}
                return {"message": message}

            alert = {
                "finding_codes": ["RELATIONSHIP_ENDED", "ROLE_EXCESS"],
                "active_permission_count": 2,
                "expired_permission_count": 0,
                "role_excess_count": 1,
                "candidate_permission_refs": [permission_ref],
                "expired_permission_refs": [],
                "role_excess_permission_refs": [permission_ref],
            }
            result = run_agentic_investigation(self.person_ref, alert, model_call=fake_model_call)
            self.assertEqual(result["recommendation"], "REVOKE")
            self.assertEqual(result["tools_used"], [
                "get_lifecycle_evidence", "get_active_permission_inventory", "check_permission_policy"
            ])

            # A recommendation cannot pass if Qwen3 skips a required policy check.
            def incomplete_model_call(messages, tools):
                turn = sum(1 for message in messages if message.get("role") == "assistant") + 1
                if turn == 1:
                    message = {"role": "assistant", "content": "", "tool_calls": [{
                        "function": {"name": "get_lifecycle_evidence", "arguments": {"person_ref": self.person_ref}}
                    }]}
                elif turn == 2:
                    message = {"role": "assistant", "content": "", "tool_calls": [{
                        "function": {"name": "get_active_permission_inventory", "arguments": {"person_ref": self.person_ref}}
                    }]}
                else:
                    message = {"role": "assistant", "content": json.dumps({
                        "recommendation": "REVOKE", "reason_code": "EXCESSIVE_PRIVILEGE"
                    })}
                return {"message": message}

            incomplete = run_agentic_investigation(self.person_ref, alert, model_call=incomplete_model_call)
            self.assertEqual(incomplete["recommendation"], "ESCALATE")
            self.assertEqual(incomplete["reason_code"], "INCOMPLETE_OR_CONFLICTING_EVIDENCE")
        finally:
            if old_langgraph is None:
                sys.modules.pop("langgraph", None)
            else:
                sys.modules["langgraph"] = old_langgraph
            if old_graph is None:
                sys.modules.pop("langgraph.graph", None)
            else:
                sys.modules["langgraph.graph"] = old_graph

        all_model_io = "\n".join(calls)
        self.assertNotIn("Dr. Rohan Iyer", all_model_io)
        self.assertNotIn("rohan.iyer.demo@campus.test", all_model_io)
        self.assertNotIn(self.identity_ciphertext.hex(), all_model_io)
        self.assertNotIn("identity_enc", all_model_io)
        self.assertNotIn("CAMPUSGHOST_ENCRYPTION_KEY", all_model_io)
        encryption_key_text = base64.urlsafe_b64encode(database._encryption_key()).decode("ascii")
        self.assertNotIn(encryption_key_text, all_model_io)
        self.assertNotIn("revoke_permission", all_model_io)

    def test_model_retain_cannot_silently_override_python_risk_flag(self):
        detection = {
            "recommendation": "RECOMMEND_REVOKE",
            "flagged_permission_tokens": ["CG-G-1111111111111111"],
            "person": {"person_token": self.person_ref},
        }
        recommendation, _reason = _apply_agent_decision(
            detection, {"recommendation": "RETAIN", "reason": "retain"}
        )
        self.assertEqual(recommendation, "ESCALATE")

    def test_model_revoke_without_python_flag_is_rejected(self):
        detection = {
            "recommendation": "RETAIN",
            "flagged_permission_tokens": [],
            "person": {"person_token": self.person_ref},
        }
        recommendation, _reason = _apply_agent_decision(
            detection, {"recommendation": "REVOKE", "reason": "revoke"}
        )
        self.assertEqual(recommendation, "ESCALATE")


if __name__ == "__main__":
    unittest.main()
