import os
from pathlib import Path
from .mock import JSONFixtureConnector
from .rest import HTTPSJSONConnector
from database import canonical_platform, upsert_platform_snapshot

ROOT = Path(__file__).resolve().parent
SIMULATED_PLATFORMS = [
    ("contineo_portal", "Contineo Portal (LMS)", ROOT / "mock_data" / "contineo_portal.json"),
    ("department_drive", "Department Drive", ROOT / "mock_data" / "department_drive.json"),
    ("project_repository", "Project Repository", ROOT / "mock_data" / "project_repository.json"),
    ("research_portal", "Research Portal", ROOT / "mock_data" / "research_portal.json"),
]


def _connector_for(key, name, path):
    """Construct one connector. Live access is opt-in for each configured URL."""
    live_enabled = os.getenv("CAMPUSGHOST_ENABLE_LIVE_CONNECTORS", "0") == "1"
    endpoint = os.getenv("CAMPUSGHOST_" + key.upper() + "_API_URL", "").strip()
    if live_enabled and endpoint:
        return HTTPSJSONConnector.from_environment(key, name)
    return JSONFixtureConnector(path)


def sync_all_platforms():
    """Pull all configured platform snapshots through the same connector contract."""
    outcomes = []
    for key, name, path in SIMULATED_PLATFORMS:
        connector = None
        try:
            connector = _connector_for(key, name, path)
            snapshot = connector.fetch_snapshot()
            payload_key = str(snapshot.get("platform_key", "")).strip()
            if payload_key and payload_key != key:
                raise ValueError("Connector returned a platform_key that does not match its configured platform.")
            canonical_key, default_name = canonical_platform(key)
            platform_name = str(snapshot.get("platform_name") or getattr(connector, "platform_name", name or default_name))
            outcome = upsert_platform_snapshot(
                canonical_key, platform_name, connector.source_type, snapshot
            )
            outcomes.append({"status": "success", **outcome})
        except Exception as exc:
            # Do not include URLs, request headers, or secrets in the UI response.
            outcomes.append({
                "status": "error",
                "platform_key": key,
                "platform_name": getattr(connector, "platform_name", name),
                "message": str(exc),
            })
    return outcomes


def connector_for_platform(platform_key):
    for key, name, path in SIMULATED_PLATFORMS:
        if key == platform_key:
            return _connector_for(key, name, path)
    raise ValueError("Unknown platform connector.")


def revoke_on_platform(platform_key, external_account_id, resource):
    connector = connector_for_platform(platform_key)
    return connector.revoke_permission(external_account_id, resource)



def reset_simulated_platforms():
    """Restore local fixture files to their pre-revocation state."""
    from .mock import restore_fixture
    for _key, _name, path in SIMULATED_PLATFORMS:
        restore_fixture(path)
