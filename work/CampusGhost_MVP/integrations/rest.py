"""Generic HTTPS JSON connector for future authorised platform APIs.

A vendor-specific adapter may be needed to convert a platform's native API
response into CampusGhost's normalised accounts/permissions schema.
"""
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, HTTPRedirectHandler, build_opener
from .base import PlatformConnector


class _NoRedirectHandler(HTTPRedirectHandler):
    """Reject redirects so bearer credentials are not forwarded elsewhere."""
    def redirect_request(self, req, fp, code, msg, headers, new_url):
        return None


class HTTPSJSONConnector(PlatformConnector):
    source_type = "live_api"

    def __init__(self, platform_key, platform_name, endpoint, token, revoke_endpoint=None):
        parsed = urlparse(endpoint or "")
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("Live platform endpoints must use HTTPS.")
        if not token:
            raise ValueError("A bearer token is required for the configured platform connector.")
        self.platform_key = platform_key
        self.platform_name = platform_name
        self.endpoint = endpoint
        self.token = token
        self.revoke_endpoint = revoke_endpoint or ""
        self.revoke_endpoint = revoke_endpoint or ""

    @classmethod
    def from_environment(cls, platform_key, platform_name):
        env_prefix = "CAMPUSGHOST_" + platform_key.upper() + "_"
        return cls(
            platform_key=platform_key,
            platform_name=platform_name,
            endpoint=os.getenv(env_prefix + "API_URL", ""),
            token=os.getenv(env_prefix + "API_TOKEN", ""),
            revoke_endpoint=os.getenv(env_prefix + "REVOKE_API_URL", ""),
        )

    def fetch_snapshot(self):
        request = Request(
            self.endpoint,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "CampusGhost-Access-Review/1.0",
            },
            method="GET",
        )
        try:
            opener = build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise RuntimeError(f"Platform API returned HTTP {exc.code}.") from exc
        except (URLError, TimeoutError) as exc:
            raise RuntimeError("Could not retrieve data from the configured platform API.") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("accounts"), list):
            raise ValueError("Platform API must return CampusGhost's normalised accounts JSON schema.")
        forbidden = {"person_email", "person_name", "full_name", "display_name",
                     "external_username", "external_email", "email", "name"}
        for account in payload["accounts"]:
            if not isinstance(account, dict) or not account.get("person_ref"):
                raise ValueError("Every API account must contain a pseudonymous person_ref.")
            if forbidden.intersection(account):
                raise ValueError("The API response contains direct identity fields. Configure the platform adapter to emit person_ref only.")
        payload.setdefault("platform_key", self.platform_key)
        payload.setdefault("platform_name", self.platform_name)
        return payload

    def revoke_permission(self, external_account_id, resource):
        """Call an explicitly configured HTTPS revocation endpoint. The API must return JSON {success:true}."""
        parsed = urlparse(self.revoke_endpoint)
        if parsed.scheme != "https" or not parsed.netloc:
            raise RuntimeError("No authorised HTTPS revoke endpoint is configured for this platform.")
        body = json.dumps({"external_account_id": external_account_id, "resource": resource}).encode("utf-8")
        request = Request(self.revoke_endpoint, data=body, headers={
            "Accept": "application/json", "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}", "User-Agent": "CampusGhost-Access-Review/1.0"
        }, method="POST")
        try:
            with build_opener(_NoRedirectHandler()).open(request, timeout=20) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            raise RuntimeError("The platform did not confirm the requested revocation.") from exc
        if not isinstance(result, dict) or result.get("success") is not True:
            raise RuntimeError("The platform did not confirm the requested revocation.")
        return {"success": True, "mode": "live_api"}

    def revoke_permission(self, external_account_id, resource):
        """Call an explicitly configured HTTPS revocation endpoint. The API must return JSON {success:true}."""
        parsed = urlparse(self.revoke_endpoint)
        if parsed.scheme != "https" or not parsed.netloc:
            raise RuntimeError("No authorised HTTPS revoke endpoint is configured for this platform.")
        body = json.dumps({"external_account_id": external_account_id, "resource": resource}).encode("utf-8")
        request = Request(self.revoke_endpoint, data=body, headers={
            "Accept": "application/json", "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}", "User-Agent": "CampusGhost-Access-Review/1.0"
        }, method="POST")
        try:
            with build_opener(_NoRedirectHandler()).open(request, timeout=20) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            raise RuntimeError("The platform did not confirm the requested revocation.") from exc
        if not isinstance(result, dict) or result.get("success") is not True:
            raise RuntimeError("The platform did not confirm the requested revocation.")
        return {"success": True, "mode": "live_api"}
