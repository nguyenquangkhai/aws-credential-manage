"""1Password CLI wrapper."""

import json
import secrets
import string
import subprocess
from typing import cast

from ..utils.config import DEFAULT_PASSWORD_LENGTH, DEFAULT_VAULT


class OnePasswordError(RuntimeError):
    """A 1Password CLI call failed for a reason other than a missing item."""


# Phrases the CLI uses when the item itself does not exist. Anything else --
# an expired session, an unknown vault, an unreachable service -- is a real
# failure and must not be reported as "item not found".
_MISSING_ITEM_PHRASES = (
    "isn't an item",
    "isn t an item",
    "no item matches",
    "not found",
)


def _is_missing_item(stderr: str) -> bool:
    """Return True only when stderr says the item genuinely does not exist."""
    lowered = stderr.lower()
    return any(phrase in lowered for phrase in _MISSING_ITEM_PHRASES)


class OnePasswordClient:
    """Thin wrapper around 1Password CLI commands."""

    def __init__(self, vault_name: str = DEFAULT_VAULT):
        self.vault_name = vault_name

    def check_session(self) -> bool:
        """Check if 1Password CLI session is active."""
        try:
            subprocess.run(['op', 'account', 'list'],
                          capture_output=True, text=True, check=True)
            return True
        except subprocess.CalledProcessError:
            print("Please sign in to 1Password CLI first:")
            print("Run: op signin")
            return False

    def get_item(self, title: str) -> dict | None:
        """Get a 1Password item by title.

        Returns None only when the item genuinely does not exist. Every other
        CLI failure raises OnePasswordError carrying the CLI's own message,
        so a dropped session is never mistaken for a missing item.
        """
        result = subprocess.run([
            'op', 'item', 'get', title,
            '--vault', self.vault_name,
            '--format', 'json'
        ], capture_output=True, text=True)

        if result.returncode == 0:
            return cast(dict, json.loads(result.stdout))

        stderr = (result.stderr or "").strip()
        if _is_missing_item(stderr):
            return None
        raise OnePasswordError(
            f"1Password lookup failed for '{title}': {stderr or 'no error output'}"
        )

    def edit_item(self, title: str, **fields: str) -> None:
        """Update fields on a 1Password item.

        Usage: edit_item("my-item", password="secret", notes="hello")
        For typed fields use the 1Password notation in the key:
            edit_item("my-item", **{"field[text]": "value"})
        """
        cmd = ['op', 'item', 'edit', title, '--vault', self.vault_name]
        for key, value in fields.items():
            cmd.append(f'{key}={value}')
        subprocess.run(cmd, check=True, capture_output=True)

    def edit_item_generate_password(self, title: str, recipe: str = "letters,digits,symbols,18",
                                     **extra_fields: str) -> None:
        """Update a 1Password item with a generated password."""
        cmd = [
            'op', 'item', 'edit', title,
            '--vault', self.vault_name,
            f'--generate-password={recipe}',
        ]
        for key, value in extra_fields.items():
            cmd.append(f'{key}={value}')
        subprocess.run(cmd, check=True, capture_output=True)

    def get_field_value(self, item_data: dict, label: str) -> str | None:
        """Extract a field value from 1Password item data by label."""
        for field in item_data.get('fields', []):
            if field.get('label') == label:
                return cast("str | None", field.get('value'))
        return None

    def generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """Generate a secure password meeting AWS policy requirements."""
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"

        password_chars = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(symbols),
        ]

        all_chars = uppercase + lowercase + digits + symbols
        for _ in range(length - 4):
            password_chars.append(secrets.choice(all_chars))

        # Fisher-Yates shuffle using a CSPRNG (secrets has no shuffle helper).
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
        return ''.join(password_chars)
