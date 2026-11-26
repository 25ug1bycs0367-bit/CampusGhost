"""Tests for the AGENT-LED investigation mode (Qwen3 investigates, Python verifies)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_langgraph import ScriptedAgent, fake_langgraph  # noqa: E402

import agentic_workflow  # noqa: E402
import database  # noqa: E402
from agent import run_investigation  # noqa: E402
from integrations.registry import sync_all_platforms  # noqa: E402

AI_ENV = {"CAMPUSGHOST_USE_OLLAMA": "1", "OLLAMA_MODEL": "qwen3:4b"}
# person id -> (expected outcome, expected flagged permission count)
EXPECTED = {
    1: ("RETAIN", 0), 2: ("RECOMMEND_REVOKE", 2), 3: ("RETAIN", 0), 4: ("RECOMMEND_REVOKE", 1),
    5: ("RECOMMEND_REVOKE", 1), 6: ("RETAIN", 0), 7: ("RECOMMEND_REVOKE", 2), 8: ("RECOMMEND_REVOKE", 1),
}


class AgentLedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db, self.old_key = database.DB_PATH, database.KEY_PATH
        database.DB_PATH = Path(self.temp.name) / "t.db"
        database.KEY_PATH = Path(self.temp.name) / "t.key"
        database.init_db()
        sync_all_platforms()

    def tearDown(self):
        database.DB_PATH, database.KEY_PATH = self.old_db, self.old_key
        self.temp.cleanup()

    def investigate(self, person_id, agent, extra_env=None):
        env = {**AI_ENV, **(extra_env or {})}
        with fake_langgraph(), patch.dict("os.environ", env), \
             patch.object(agentic_workflow, "_ollama_chat", side_effect=lambda m, t, model: agent(m, t)):
            return run_investigation(person_id)

    # ---- the agent really leads -------------------------------------------------
    def test_agent_receives_only_the_case_reference_not_python_findings(self):
        agent = ScriptedAgent()
        self.investigate(7, agent)
        first_user_message = json.loads(agent.transcript[0])["messages"][1]["content"]
        self.assertIn("No prior findings are supplied", first_user_message)
        for leaked in ("python_detection", "finding_codes", "candidate_permission_refs", "CG-G-"):
            self.assertNotIn(leaked, first_user_message)

    def test_agent_led_outcomes_match_expected_for_every_seeded_case(self):
        for person_id, (outcome, flagged) in EXPECTED.items():
            with self.subTest(person_id=person_id):
                result = self.investigate(person_id, ScriptedAgent())
                self.assertEqual(result["recommendation"], outcome)
                self.assertEqual(result["flagged_access_count"], flagged)
                self.assertIn("agent-led", result["ai_mode"])
                self.assertTrue(result["agent_tools_used"])

    def test_local_ollama_request_timeout_defaults_to_ten_minutes(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"message":{"content":"ready"}}'
        with patch.dict("os.environ", {}, clear=True), \
             patch("agentic_workflow.urllib.request.urlopen", return_value=response) as urlopen:
            agentic_workflow._ollama_chat([], [], "qwen3:4b")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 600)

    def test_current_faculty_keep_course_grant_and_only_admin_grant_is_flagged(self):
        result = self.investigate(5, ScriptedAgent())  # fictional faculty with an extra admin grant
        self.assertEqual(result["flagged_access_count"], 1)
        self.assertIn("check_permission_policy", result["agent_tools_used"])

    # ---- Python verification of the agent (it is never trusted alone) ------------
    def test_lazy_agent_that_skips_the_tools_is_escalated(self):
        for person_id in (7, 3):
            with self.subTest(person_id=person_id):
                self.assertEqual(self.investigate(person_id, ScriptedAgent("lazy"))["recommendation"], "ESCALATE")

    def test_agent_citing_permissions_that_do_not_exist_cannot_cause_a_revoke(self):
        result = self.investigate(7, ScriptedAgent("fabricate"))
        self.assertEqual(result["recommendation"], "ESCALATE")

    def test_unparseable_agent_output_is_escalated(self):
        self.assertEqual(self.investigate(7, ScriptedAgent("garbage"))["recommendation"], "ESCALATE")

    def test_json_wrapped_in_chatty_text_is_still_understood(self):
        self.assertEqual(self.investigate(7, ScriptedAgent("chatty"))["recommendation"], "RECOMMEND_REVOKE")

    def test_python_cross_check_adds_flags_the_agent_missed(self):
        result = self.investigate(7, ScriptedAgent("partial"))  # agent names 1 of 2 permissions
        self.assertEqual(result["recommendation"], "RECOMMEND_REVOKE")
        self.assertEqual(result["flagged_access_count"], 2)
        self.assertTrue(any("cross-check added 1" in line for line in result["evidence"]))

    # ---- strict mode ---------------------------------------------------------------
    def test_ai_failure_falls_back_to_rules_unless_strict(self):
        def broken(_messages, _tools):
            raise RuntimeError("Ollama down")
        fallback = self.investigate(7, broken)
        self.assertEqual(fallback["recommendation"], "RECOMMEND_REVOKE")
        self.assertIn("fallback", fallback["ai_mode"])
        strict = self.investigate(7, broken, {"CAMPUSGHOST_AI_STRICT": "1"})
        self.assertEqual(strict["recommendation"], "ESCALATE")
        self.assertEqual(strict["flagged_access_count"], 0)

    # ---- regressions ---------------------------------------------------------------
    def test_seen_calls_is_declared_in_the_graph_state_schema(self):
        # LangGraph silently drops undeclared state keys, which disabled duplicate-call protection.
        self.assertIn("seen_calls", agentic_workflow.AgentState.__annotations__)

    def test_duplicate_tool_requests_are_skipped(self):
        class Repeater(ScriptedAgent):
            def __call__(self, messages, tools):
                if sum(1 for m in messages if m.get("role") == "assistant") < 2:
                    ref = json.loads(messages[1]["content"].split("\n", 1)[1])["case_ref"]
                    return {"message": {"role": "assistant", "content": "", "tool_calls": [
                        {"function": {"name": "get_lifecycle_evidence", "arguments": {"person_ref": ref}}}]}}
                return super().__call__(messages, tools)
        agent = Repeater()
        self.investigate(7, agent)
        self.assertTrue(any("DUPLICATE_EVIDENCE_REQUEST" in t for t in agent.transcript))

    def test_reason_code_must_match_the_action(self):
        parsed = agentic_workflow._parse_final_decision(
            json.dumps({"recommendation": "REVOKE", "reason_code": "NO_RISK_FOUND"}))
        self.assertEqual(parsed["recommendation"], "ESCALATE")

    def test_model_never_sees_identity_data_in_agent_led_mode(self):
        agent = ScriptedAgent()
        self.investigate(7, agent)
        everything = "\n".join(agent.transcript)
        for secret in ("Rohan", "@campus.test", "identity_enc", "revoke_permission", "CAMPUSGHOST_ENCRYPTION_KEY"):
            self.assertNotIn(secret, everything)


class EvidenceLedgerTests(unittest.TestCase):
    """The workflow's own verification, tested without the database or Python cross-check."""
    G1, G2 = "CG-G-" + "1" * 16, "CG-G-" + "2" * 16

    def ledger(self, category="CURRENT_FACULTY", events=(), expiry=("VALID", "VALID"), policy=None, research=None):
        perms = [{"permission_ref": r, "expiry_state": e} for r, e in zip((self.G1, self.G2), expiry)]
        return {"lifecycle": {"relationship_category": category,
                              "lifecycle_events": [{"event_type": e} for e in events]},
                "inventory": {"active_permissions": perms},
                "policy": policy if policy is not None else {self.G1: "WITHIN_ROLE_POLICY", self.G2: "WITHIN_ROLE_POLICY"},
                "expiry": {}, "research": research}

    def decide(self, rec, code, refs, ledger):
        parsed = {"recommendation": rec, "reason": "x", "reason_code": code, "permission_refs_to_revoke": refs}
        return agentic_workflow._verify_decision(parsed, ledger)

    def test_fabricated_reference_is_rejected_by_the_ledger_alone(self):
        decision, refs = self.decide("REVOKE", "EXCESSIVE_PRIVILEGE", ["CG-G-" + "F" * 16],
                                     self.ledger(policy={self.G1: "EXCESSIVE", self.G2: "WITHIN_ROLE_POLICY"}))
        self.assertEqual((decision["recommendation"], refs), ("ESCALATE", []))

    def test_only_permissions_with_supporting_evidence_survive(self):
        decision, refs = self.decide("REVOKE", "EXCESSIVE_PRIVILEGE", [self.G1, self.G2],
                                     self.ledger(policy={self.G1: "EXCESSIVE", self.G2: "WITHIN_ROLE_POLICY"}))
        self.assertEqual((decision["recommendation"], refs), ("REVOKE", [self.G1]))

    def test_ended_relationship_makes_every_active_permission_eligible(self):
        _decision, refs = self.decide("REVOKE", "ENDED_RELATIONSHIP_ACTIVE_PERMISSION", [self.G1, self.G2],
                                      self.ledger(category="FORMER_FACULTY", policy={}))
        self.assertEqual(refs, [self.G1, self.G2])

    def test_omitted_revoke_list_falls_back_to_the_agents_own_evidence(self):
        _decision, refs = self.decide("REVOKE", "EXPIRED_PERMISSION", None, self.ledger(expiry=("EXPIRED", "VALID")))
        self.assertEqual(refs, [self.G1])

    def test_retain_is_rejected_when_the_agents_own_evidence_shows_risk(self):
        decision, _ = self.decide("RETAIN", "SUFFICIENT_EVIDENCE_TO_RETAIN", [],
                                  self.ledger(policy={self.G1: "EXCESSIVE", self.G2: "WITHIN_ROLE_POLICY"}))
        self.assertEqual(decision["recommendation"], "ESCALATE")

    def test_retain_without_policy_checking_every_permission_is_rejected(self):
        decision, _ = self.decide("RETAIN", "SUFFICIENT_EVIDENCE_TO_RETAIN", [],
                                  self.ledger(policy={self.G1: "WITHIN_ROLE_POLICY"}))
        self.assertEqual(decision["recommendation"], "ESCALATE")

    def test_research_assistant_retain_requires_the_exception_check(self):
        ledger = self.ledger(category="GRADUATE_RESEARCH_ASSISTANT", events=("GRADUATION",))
        self.assertEqual(self.decide("RETAIN", "RESEARCH_RETENTION_EXCEPTION", [], ledger)[0]["recommendation"], "ESCALATE")
        ledger["research"] = True
        self.assertEqual(self.decide("RETAIN", "RESEARCH_RETENTION_EXCEPTION", [], ledger)[0]["recommendation"], "RETAIN")

    def test_missing_lifecycle_or_inventory_is_escalated(self):
        ledger = self.ledger()
        ledger["inventory"] = None
        self.assertEqual(self.decide("RETAIN", "NO_RISK_FOUND", [], ledger)[0]["recommendation"], "ESCALATE")


if __name__ == "__main__":
    unittest.main()


class TerminalRunnerTests(unittest.TestCase):
    def test_cli_runner_investigates_with_the_agent_and_saves_results(self):
        import io
        from contextlib import redirect_stdout
        import run_agent_investigation as cli
        temp = tempfile.TemporaryDirectory()
        old = database.DB_PATH, database.KEY_PATH
        database.DB_PATH, database.KEY_PATH = Path(temp.name) / "c.db", Path(temp.name) / "c.key"
        agent = ScriptedAgent()
        buffer = io.StringIO()
        try:
            with fake_langgraph(), patch.object(cli, "preflight"), \
                 patch.object(agentic_workflow, "_ollama_chat", side_effect=lambda m, t, model: agent(m, t)), \
                 redirect_stdout(buffer):
                results = cli.main(["7", "6"])
            self.assertEqual([r["recommendation"] for r in results], ["RETAIN", "RECOMMEND_REVOKE"])
            self.assertIn("Qwen3 chose tool: get_lifecycle_evidence", buffer.getvalue())
            self.assertTrue(database.has_current_revoke_recommendation(results[1]["person_token"]))
        finally:
            database.DB_PATH, database.KEY_PATH = old
            temp.cleanup()
            for key in ("CAMPUSGHOST_USE_OLLAMA", "CAMPUSGHOST_AGENT_MODE", "CAMPUSGHOST_AI_STRICT", "CAMPUSGHOST_TRACE"):
                os.environ.pop(key, None)
