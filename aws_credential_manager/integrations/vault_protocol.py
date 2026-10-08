"""Protocol defining the interface for password vault integrations."""

from typing import Protocol, runtime_checkable

from ..utils.config import DEFAULT_PASSWORD_LENGTH


@runtime_checkable
class PasswordVault(Protocol):
    """Interface that every password vault client must implement."""

    #: Human-readable vault name for user-facing messages (e.g. "1Password").
    display_name: str

    def check_session(self) -> bool:
        """Check if the vault CLI session is active. Return True if ready."""
        ...

    def get_item(self, title: str) -> dict | None:
        """Get a vault item by title. Returns parsed dict or None if not found."""
        ...

    def get_one_time_password(self, title: str) -> str:
        """Return the item's current one-time password (MFA code)."""
        ...

    def edit_item(self, title: str, **fields: str) -> None:
        """Update fields on a vault item.

        Usage: edit_item("my-item", password="secret", notes="hello")
        """
        ...

    def get_field_value(self, item_data: dict, label: str) -> str | None:
        """Extract a field value from item data by label."""
        ...

    def generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """Generate a secure password meeting AWS policy requirements."""
        ...
