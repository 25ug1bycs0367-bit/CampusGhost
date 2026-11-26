from abc import ABC, abstractmethod


class PlatformConnector(ABC):
    """Common interface for authorised platform read and revoke operations."""
    platform_key: str
    platform_name: str
    source_type: str

    @abstractmethod
    def fetch_snapshot(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def revoke_permission(self, external_account_id: str, resource: str) -> dict:
        raise NotImplementedError
