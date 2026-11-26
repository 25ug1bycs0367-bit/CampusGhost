import json
from pathlib import Path
from .base import PlatformConnector


class JSONFixtureConnector(PlatformConnector):
    """Reads a separate fictional export containing pseudonymous references only."""

    source_type = "simulated"

    def __init__(self, fixture_path):
        self.fixture_path = Path(fixture_path)

    def fetch_snapshot(self):
        if not self.fixture_path.exists():
            raise FileNotFoundError(f"Missing simulated platform file: {self.fixture_path.name}")
        with self.fixture_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        required = {"platform_key", "platform_name", "accounts"}
        if not required.issubset(payload):
            raise ValueError(f"{self.fixture_path.name} is missing required connector fields.")
        if not isinstance(payload["accounts"], list):
            raise ValueError(f"The accounts field in {self.fixture_path.name} must be a list.")
        for account in payload["accounts"]:
            if not isinstance(account, dict) or not account.get("person_ref"):
                raise ValueError(f"{self.fixture_path.name} must use pseudonymous person_ref values.")
            forbidden = {"person_email", "person_name", "full_name", "display_name",
                         "external_username", "external_email", "email", "name"}
            if forbidden.intersection(account):
                raise ValueError(f"{self.fixture_path.name} contains direct identity fields; use person_ref instead.")
        return payload

    def revoke_permission(self, external_account_id, resource):
        """Change only the local fictional JSON fixture; never contacts a real platform."""
        with self.fixture_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        changed = False
        for account in payload.get("accounts", []):
            if account.get("external_account_id") == external_account_id:
                for grant in account.get("permissions", []):
                    if grant.get("resource") == resource and grant.get("active") is True:
                        grant["active"] = False
                        changed = True
        if not changed:
            raise ValueError("The active permission was not found in the simulated platform.")
        backup = self.fixture_path.with_suffix(self.fixture_path.suffix + ".baseline")
        if not backup.exists():
            import shutil
            shutil.copy2(self.fixture_path, backup)
        temp = self.fixture_path.with_suffix(self.fixture_path.suffix + ".tmp")
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        temp.replace(self.fixture_path)
        return {"success": True, "platform_key": payload.get("platform_key"), "mode": "simulated"}



def restore_fixture(fixture_path):
    """Restore a fixture modified by a simulated revoke, if a baseline exists."""
    fixture_path = Path(fixture_path)
    backup = fixture_path.with_suffix(fixture_path.suffix + ".baseline")
    if backup.exists():
        backup.replace(fixture_path)
