"""Bitwarden CLI wrapper."""

import json
import os
import re
import secrets
import string
import subprocess
from typing import cast

from ..utils.config import DEFAULT_PASSWORD_LENGTH


class BitwardenClient:
    """Thin wrapper around Bitwarden CLI (bw) commands.

    Requires BW_SESSION environment variable to be set after 'bw unlock'.
    """

    display_name = "Bitwarden"

    def __init__(self, vault_name: str = "AWS"):
        self.vault_name = vault_name

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        """Run a bw command with the session token."""
        env = os.environ.copy()
        cmd = ["bw", *args]
        return subprocess.run(cmd, capture_output=True, text=True, check=True, env=env)

    def _session_token(self) -> str | None:
        """Return BW_SESSION env var, or None."""
        return os.environ.get("BW_SESSION")

    def check_session(self) -> bool:
        """Check if Bitwarden CLI session is unlocked."""
        token = self._session_token()
        if not token:
            print("Bitwarden CLI not unlocked. Run: bw login  # then bw unlock")
            print("Then set BW_SESSION to the session key printed by bw unlock.")
            return False
        try:
            result = self._run("status")
            status = json.loads(result.stdout).get("status", "")
            if status == "unlocked":
                return True
            print(f"Bitwarden status is '{status}'. Run: bw unlock")
            return False
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            print("Bitwarden CLI not available or session expired.")
            print("Run: bw login  # then bw unlock")
            return False

    def get_item(self, title: str) -> dict | None:
        """Get a Bitwarden item by name. Returns None if not found."""
        token = self._session_token()
        if not token:
            return None
        try:
            result = self._run("get", "item", title)
            return cast(dict, json.loads(result.stdout))
        except subprocess.CalledProcessError:
            return None

    def get_one_time_password(self, title: str) -> str:
        """Return the item's current TOTP code."""
        item = self.get_item(title)
        if not item:
            raise ValueError(f"Item '{title}' not found in Bitwarden vault")
        try:
            result = self._run("get", "totp", item["id"])
        except subprocess.CalledProcessError as error:
            raise RuntimeError(
                f"Bitwarden TOTP lookup failed for '{title}'"
            ) from error
        code = str(result.stdout).strip()
        if not code:
            raise RuntimeError(f"Bitwarden returned an empty TOTP for '{title}'")
        return code

    def edit_item(self, title: str, **fields: str) -> None:
        """Update fields on a Bitwarden item.

        Bitwarden requires fetching the item, modifying fields, and
        writing the full JSON back via 'bw encode | bw edit item <id>'.
        """
        token = self._session_token()
        if not token:
            raise RuntimeError("BW_SESSION not set")

        item = self.get_item(title)
        if not item:
            raise ValueError(f"Item '{title}' not found in Bitwarden vault")

        # Build a lookup of existing fields by name
        existing = {f["name"]: f for f in item.get("fields", [])}

        # Strip 1Password [type] suffixes (e.g. "field[text]" -> "field")
        # so callers that use 1Password notation work with Bitwarden too.
        _suffix_re = re.compile(r"\[(text|password|concealed)\]$")

        login = item.get("login")
        for key, value in fields.items():
            clean_key = _suffix_re.sub("", key)
            # Login items keep the password under login.password, not a field.
            if clean_key == "password" and isinstance(login, dict):
                login["password"] = value
                continue
            # Bitwarden field types: 0 = text, 1 = hidden, 2 = boolean
            field_type = 1 if clean_key in ("password", "aws_secret_access_key") else 0
            if clean_key in existing:
                existing[clean_key]["value"] = value
                existing[clean_key]["type"] = field_type
            else:
                existing[clean_key] = {"name": clean_key, "value": value, "type": field_type}

        item["fields"] = list(existing.values())

        # Encode and write back via bw edit
        encoded = json.dumps(item)
        env = os.environ.copy()
        env["BW_SESSION"] = token

        encode = subprocess.run(
            ["bw", "encode"],
            input=encoded,
            capture_output=True, text=True, check=True, env=env,
        )

        subprocess.run(
            ["bw", "edit", "item", item["id"]],
            input=encode.stdout,
            capture_output=True, text=True, check=True, env=env,
        )

    def get_field_value(self, item_data: dict, label: str) -> str | None:
        """Extract a field value from Bitwarden item data by name.

        A Login item keeps its password under ``login.password`` rather than
        a custom field, so ``password`` falls back there when no field matches.
        """
        for field in item_data.get("fields", []):
            if field.get("name") == label:
                return cast("str | None", field.get("value"))
        if label == "password":
            login = item_data.get("login")
            if isinstance(login, dict):
                return cast("str | None", login.get("password"))
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

        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
        return "".join(password_chars)
