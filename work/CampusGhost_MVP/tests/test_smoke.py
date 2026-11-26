import json
import shutil
import tempfile
import unittest
from pathlib import Path

import database
from agent import run_investigation
from integrations.registry import sync_all_platforms
from integrations.rest import HTTPSJSONConnector


class CampusGhostPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        old_db, old_key = database.DB_PATH, database.KEY_PATH
        self.addCleanup(setattr, database, "DB_PATH", old_db)
        self.addCleanup(setattr, database, "KEY_PATH", old_key)
        database.DB_PATH = Path(self.temp.name) / "test.db"
        database.KEY_PATH = Path(self.temp.name) / "test.key"
        database.init_db()
        self.sync_results = sync_all_platforms()
        self.addCleanup(self.temp.cleanup)

    def test_simulated_connectors_sync_four_platforms(self):
        self.assertEqual(len(self.sync_results), 4)
        self.assertTrue(all(item["status"] == "success" for item in self.sync_results))
        with database.connect() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM platform_accounts").fetchone()[0], 9)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM permissions").fetchone()[0], 12)

    def test_contineo_replaces_moodle_as_the_lms_demo(self):
        with database.connect() as con:
            rows = con.execute("SELECT DISTINCT platform_name FROM platform_accounts").fetchall()
        names = {row[0] for row in rows}
        self.assertIn("Contineo Portal (LMS)", names)
        self.assertNotIn("Moodle LMS", names)

    def test_old_simulated_moodle_account_is_migrated_away(self):
        with database.connect() as con:
            con.execute("""INSERT INTO platform_accounts
                (person_id,platform_key,platform_name,external_account_id,account_status,source_type,last_synced_at)
                VALUES(1,'moodle_lms','Moodle LMS','legacy-moodle-account','PROTECTED','simulated','2026-11-25')""")
        database.init_db()
        with database.connect() as con:
            count = con.execute("SELECT COUNT(*) FROM platform_accounts WHERE platform_key='moodle_lms'").fetchone()[0]
        self.assertEqual(count, 0)

    def test_repeated_sync_does_not_duplicate_records(self):
        sync_all_platforms()
        with database.connect() as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM platform_accounts").fetchone()[0], 9)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM permissions").fetchone()[0], 12)

    def test_live_connector_requires_https(self):
        with self.assertRaises(ValueError):
            HTTPSJSONConnector("contineo_portal", "Contineo Portal (LMS)", "http://example.test/api", "demo-token")

    def test_same_person_gets_same_pseudonym_across_platforms(self):
        with database.connect() as con:
            rows = con.execute("SELECT person_id, account_token FROM platform_accounts WHERE person_id=2").fetchall()
        self.assertEqual(len(rows), 2)
        tokens = {row["account_token"] for row in rows}
        self.assertEqual(len(tokens), 2)
        person, permissions, events = database.get_person_context(2)
        self.assertTrue(person["person_token"].startswith("CG-P-"))
        self.assertEqual(len(permissions), 2)

    def test_plaintext_identity_is_not_stored_in_clear_columns(self):
        with database.connect() as con:
            people = [dict(r) for r in con.execute("SELECT * FROM persons")]
            accounts = [dict(r) for r in con.execute("SELECT * FROM platform_accounts")]
            permissions = [dict(r) for r in con.execute("SELECT * FROM permissions")]
            events = [dict(r) for r in con.execute("SELECT * FROM lifecycle_events")]
        self.assertTrue(all(p["name"] == p["person_token"] for p in people))
        self.assertTrue(all(p["email"] == "" for p in people))
        self.assertTrue(all(p["campus_status"] == "PROTECTED" and p["department"] == "PROTECTED" for p in people))
        self.assertTrue(all(a["external_account_id"] == a["account_token"] for a in accounts))
        self.assertTrue(all(a["external_username"] is None and a["external_email"] is None for a in accounts))
        self.assertTrue(all(p["resource"] == "PROTECTED" and p["role"] == "PROTECTED" and p["active"] == 0 for p in permissions))
        self.assertTrue(all(e["event_type"] == "PROTECTED" and e["details"] == "ENCRYPTED" for e in events))
        combined = repr((people, accounts, permissions, events))
        self.assertNotIn("Mira Nair", combined)
        self.assertNotIn("mira.demo@campus.test", combined)
        self.assertNotIn("Dr. Ananya Rao", combined)
        self.assertNotIn("ananya.rao.demo@campus.test", combined)

    def test_encrypted_payload_round_trip_and_ciphertext_is_not_plaintext(self):
        original = {"resource": "Campus Security Repository", "role": "Admin", "active": True}
        encrypted = database.encrypt_json(original)
        self.assertNotIn(b"Campus Security Repository", encrypted)
        self.assertEqual(database.decrypt_json(encrypted), original)

    def test_investigation_uses_pseudonym_and_recommends_review(self):
        result = run_investigation(2)
        self.assertEqual(result["recommendation"], "RECOMMEND_REVOKE")
        self.assertGreater(result["expired_access_count"], 0)
        self.assertTrue(result["person_token"].startswith("CG-P-"))
        self.assertNotIn("person_name", result)
        self.assertNotIn("email", result)

    def test_research_exception_recommends_retain(self):
        result = run_investigation(3)
        self.assertEqual(result["recommendation"], "RETAIN")

    def test_current_faculty_excessive_contineo_role_is_flagged_only(self):
        # Dr. Ananya Rao: normal course-instructor access plus excessive portal admin.
        result = run_investigation(5)
        self.assertEqual(result["recommendation"], "RECOMMEND_REVOKE")
        self.assertEqual(result["excessive_access_count"], 1)
        self.assertEqual(result["flagged_access_count"], 1)
        self.assertTrue(any("Portal Administrator" in item for item in result["evidence"]))
        self.assertFalse(any("Course Instructor" in item and "Excessive permission" in item for item in result["evidence"]))

    def test_current_faculty_with_course_level_permissions_is_retained(self):
        # Dr. Vikram Shah has only normal course instructor and grader grants.
        result = run_investigation(6)
        self.assertEqual(result["recommendation"], "RETAIN")
        self.assertEqual(result["excessive_access_count"], 0)
        self.assertEqual(result["flagged_access_count"], 0)

    def test_former_faculty_with_active_contineo_access_is_flagged(self):
        # Employment ended, but the Contineo account still has active grants.
        result = run_investigation(7)
        self.assertEqual(result["recommendation"], "RECOMMEND_REVOKE")
        self.assertEqual(result["flagged_access_count"], 2)
        self.assertTrue(any("Employment ended" in item for item in result["evidence"]))

    def test_former_faculty_with_single_active_course_grant_is_flagged(self):
        result = run_investigation(8)
        self.assertEqual(result["recommendation"], "RECOMMEND_REVOKE")
        self.assertEqual(result["flagged_access_count"], 1)

    def test_investigation_does_not_modify_permissions(self):
        with database.connect() as con:
            before = [bytes(r[0]) for r in con.execute("SELECT payload_enc FROM permissions ORDER BY id")]
        result = run_investigation(2)
        report_id = database.investigate_person(result)
        with database.connect() as con:
            after = [bytes(r[0]) for r in con.execute("SELECT payload_enc FROM permissions ORDER BY id")]
        self.assertGreater(report_id, 0)
        self.assertEqual(before, after)

    def test_audit_contains_pseudonymous_person_reference_only(self):
        result = run_investigation(2)
        database.investigate_person(result)
        logs = database.get_audit_logs()
        self.assertEqual(logs[0]["person_token"], result["person_token"])
        self.assertNotIn("person_name", logs[0])
        self.assertNotIn("Mira Nair", json.dumps(logs))

    def test_admin_identity_mapping_and_institutional_role_are_available(self):
        result = run_investigation(5)
        database.investigate_person(result)
        review = database.get_admin_review(result["person_token"])
        self.assertEqual(review["identity"]["full_name"], "Dr. Ananya Rao")
        self.assertEqual(review["identity"]["email"], "ananya.rao.demo@campus.test")
        self.assertEqual(review["identity"]["institutional_role"], "Faculty - Assistant Professor")
        public = database.get_dashboard_data()
        self.assertNotIn("people", public)

    def test_end_to_end_simulated_revocation_updates_platform_database_and_audit(self):
        result = run_investigation(2)
        database.investigate_person(result)
        review = database.get_admin_review(result["person_token"])
        flagged = [g for a in review["accounts"] for g in a["permissions"] if g["flagged_for_review"] and g["active"]]
        self.assertGreaterEqual(len(flagged), 1)
        target_grant = next(g for a in review["accounts"] for g in a["permissions"] if g["platform"] == "Project Repository" and g["active"])
        target = database.revoke_permission_record(result["person_token"], target_grant["permission_token"], "test-admin")
        fixture = Path(self.temp.name) / "repo.json"
        source = Path(__file__).resolve().parents[1] / "integrations" / "mock_data" / "project_repository.json"
        shutil.copy(source, fixture)
        from integrations.mock import JSONFixtureConnector
        connector_result = JSONFixtureConnector(fixture).revoke_permission(target["external_account_id"], target["resource"])
        database.confirm_permission_revoked(target["permission_id"], result["person_token"], "test-admin", connector_result)
        refreshed = database.get_admin_review(result["person_token"])
        refreshed_grants = [g for a in refreshed["accounts"] for g in a["permissions"]]
        self.assertFalse(next(g for g in refreshed_grants if g["permission_token"] == target_grant["permission_token"])["active"])
        self.assertEqual(database.get_audit_logs()[0]["action"], "Administrator revoked permission")

    def test_mock_connector_revokes_only_local_fixture_permission(self):
        fixture = Path(self.temp.name) / "fixture.json"
        source = Path(__file__).resolve().parents[1] / "integrations" / "mock_data" / "contineo_portal.json"
        shutil.copy(source, fixture)
        from integrations.mock import JSONFixtureConnector
        connector = JSONFixtureConnector(fixture)
        result = connector.revoke_permission("contineo-ananya-005", "Portal Administration")
        self.assertTrue(result["success"])
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        ananya = next(a for a in payload["accounts"] if a["external_account_id"] == "contineo-ananya-005")
        grant = next(g for g in ananya["permissions"] if g["resource"] == "Portal Administration")
        self.assertFalse(grant["active"])

    def test_dashboard_data_does_not_return_people_directory(self):
        data = database.get_dashboard_data()
        self.assertNotIn("people", data)
        self.assertEqual(data["stats"]["people_monitored"], 8)
        self.assertEqual(data["stats"]["linked_accounts"], 9)
        self.assertEqual(len(data["platforms"]), 4)

    def test_no_wifi_platform_is_seeded(self):
        with database.connect() as con:
            names = [row[0].lower() for row in con.execute("SELECT DISTINCT platform_name FROM platform_accounts")]
        self.assertFalse(any("wifi" in name for name in names))


if __name__ == "__main__":
    unittest.main()
