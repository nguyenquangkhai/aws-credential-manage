"""Configuration management for AWS credential manager."""

import configparser
import json
import os
from pathlib import Path

# Project root = repository root (two levels up from this file:
# aws_credential_manager/utils/config.py -> repo root).
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: str, environ: dict | None = None) -> None:
    """Load KEY=VALUE lines from a .env file into environ (default os.environ).

    Only sets a key when it is not already present, so real environment
    variables always take precedence. Best-effort: malformed lines and a
    missing file are ignored silently.
    """
    env = os.environ if environ is None else environ
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in env:
                env[key] = value


def _resolve_mapping_path(filename: str, project_root: Path) -> str:
    """Resolve a mapping filename: absolute as-is, relative under project_root."""
    p = Path(filename)
    if p.is_absolute():
        return str(p)
    return str(project_root / p)


# Load .env at import so env vars are available before constants resolve.
_load_dotenv(str(PROJECT_ROOT / ".env"))

# Default expiry thresholds (days)
DEFAULT_PASSWORD_MAX_AGE = 90
DEFAULT_ACCESS_KEY_MAX_AGE = 90

# Default vault name (env-overridable; built-in default matches docs).
DEFAULT_VAULT = os.environ.get("DEFAULT_VAULT", "AWS")

# Default vault type (1password or bitwarden; env-overridable).
DEFAULT_VAULT_TYPE = os.environ.get("DEFAULT_VAULT_TYPE", "1password")

# Profile mapping filename (env-overridable).
PROFILE_MAPPING_FILE = os.environ.get("PROFILE_MAPPING_FILE", "profile_mapping.json")

# Password generation settings
DEFAULT_PASSWORD_LENGTH = 18


class ConfigManager:
    """Manages configuration for AWS credential manager."""

    def __init__(self, credentials_path: str | None = None, vault_name: str = DEFAULT_VAULT):
        self.credentials_path = credentials_path or os.path.expanduser("~/.aws/credentials")
        self.vault_name = vault_name

    def get_mapping_path(self) -> str:
        """Resolve the profile mapping file path (env-overridable)."""
        filename = os.environ.get("PROFILE_MAPPING_FILE", PROFILE_MAPPING_FILE)
        return _resolve_mapping_path(filename, PROJECT_ROOT)

    def load_profile_mappings(self) -> dict[str, object] | None:
        """Return every vault mapping entry, or None if the file is unusable.

        None means the mapping file is missing or malformed, which is different
        from a readable file that simply has no entry for a given profile.
        """
        mapping_path = self.get_mapping_path()
        if not os.path.exists(mapping_path):
            print(f"⚠ Profile mapping file not found: {mapping_path}")
            return None
        try:
            with open(mapping_path, encoding="utf-8") as f:
                mapping_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"⚠ Error parsing profile mapping file: {e}")
            return None
        profile_mappings: object = mapping_data.get("profile_mappings", {})
        if not isinstance(profile_mappings, dict):
            print("⚠ Profile mappings must be an object")
            return None
        return profile_mappings

    def get_profile_mapping(self, profile_name: str) -> dict[str, object] | None:
        """Return the vault mapping entry for a profile, or None."""
        profile_mappings = self.load_profile_mappings()
        if profile_mappings is None:
            return None
        profile_mapping: object = profile_mappings.get(profile_name)
        if isinstance(profile_mapping, dict):
            return profile_mapping
        return None


    def get_aws_profiles(self) -> list[dict]:
        """Parse AWS credentials file and extract profile names."""
        if not os.path.exists(self.credentials_path):
            raise FileNotFoundError(f"AWS credentials file not found: {self.credentials_path}")

        config = configparser.ConfigParser()
        config.read(self.credentials_path)

        profiles = []
        for section in config.sections():
            if config.has_option(section, 'aws_access_key_id'):
                profiles.append({
                    'name': section,
                    'access_key_id': config.get(section, 'aws_access_key_id'),
                    'secret_access_key': config.get(section, 'aws_secret_access_key')
                })

        return profiles
