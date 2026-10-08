"""Shared pytest fixtures."""

import textwrap
from pathlib import Path

import pytest


@pytest.fixture
def aws_credentials_file(tmp_path: Path) -> Path:
    """Write a temporary AWS credentials ini file with two valid profiles
    and one section missing an access key id."""
    content = textwrap.dedent(
        """
        [profile-one]
        aws_access_key_id = AKIAONE
        aws_secret_access_key = secretone

        [profile-two]
        aws_access_key_id = AKIATWO
        aws_secret_access_key = secrettwo

        [no-key-section]
        some_other_option = value
        """
    ).strip()
    path = tmp_path / "credentials"
    path.write_text(content)
    return path


@pytest.fixture
def bitwarden_item() -> dict:
    """A minimal Bitwarden item fixture."""
    return {
        "id": "item-123",
        "name": "test-item",
        "fields": [
            {"name": "username", "value": "bob", "type": 1},
            {"name": "password", "value": "hunter2", "type": 2},
        ],
    }


class FakeCompletedProcess:
    """Stand-in for subprocess.CompletedProcess used in tests."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
