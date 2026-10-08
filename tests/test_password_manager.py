"""Tests for password rotation ordering and secret-handling guarantees."""

import subprocess

from aws_credential_manager.core.password_manager import PasswordManager
from aws_credential_manager.integrations.onepassword import OnePasswordError


class FakeAWS:
    def __init__(self):
        self.password_changes = []

    def get_user(self, profile_name):
        return {"UserName": f"user-{profile_name}"}

    def change_password(self, profile_name, old_password, new_password):
        self.password_changes.append((profile_name, old_password, new_password))


class FakeOnePassword:
    display_name = "1Password"

    def __init__(self, item=None):
        self.item = item
        self.edits = []

    def get_item(self, item_title):
        return self.item

    def generate_password(self):
        return "generated-password"

    def get_field_value(self, item_data, label):
        if label == "password":
            return item_data.get("password")
        return None

    def edit_item(self, item_title, **fields):
        self.edits.append(item_title)


class FakeConfig:
    def get_profile_mapping(self, profile_name):
        return None


def make_manager(item=None):
    aws = FakeAWS()
    op = FakeOnePassword(item)
    return PasswordManager(aws, op, FakeConfig()), aws, op


def test_missing_onepassword_item_leaves_aws_password_untouched():
    """A rotated password that cannot be stored would be lost, so never rotate first."""
    manager, aws, op = make_manager(item=None)

    assert manager.update_profile("unmapped-profile") is False
    assert aws.password_changes == []
    assert op.edits == []


def test_missing_onepassword_item_is_reported():
    manager, _, _ = make_manager(item=None)

    assert manager.update_profile("unmapped-profile") is False


def test_existing_item_rotates_and_stores_password():
    manager, aws, op = make_manager(
        item={"id": "abc", "password": "current-password"}
    )

    assert manager.update_profile("mapped-profile") is True
    assert aws.password_changes == [
        ("mapped-profile", "current-password", "generated-password")
    ]
    assert op.edits == ["mapped-profile"]


def test_dry_run_changes_nothing():
    manager, aws, op = make_manager(item={"id": "abc"})

    assert manager.update_profile("mapped-profile", dry_run=True) is True
    assert aws.password_changes == []
    assert op.edits == []


def test_onepassword_failure_is_not_reported_as_missing_item(capsys):
    """A dropped session must not claim the item does not exist."""
    manager, aws, _ = make_manager(item={"id": "abc"})

    def raise_session_error(item_title):
        raise OnePasswordError(
            f"1Password lookup failed for '{item_title}': "
            "You are not currently signed in"
        )

    manager.op.get_item = raise_session_error

    assert manager.update_profile("mapped-profile") is False
    assert aws.password_changes == []
    out = capsys.readouterr().out
    assert "not currently signed in" in out
    assert "item not found" not in out
    assert "AWS password left unchanged" in out


def test_messages_use_vault_display_name(capsys):
    """Output must name the active vault, not always 1Password."""
    manager, _, op = make_manager(item={"id": "abc", "password": "current-password"})
    op.display_name = "Bitwarden"

    assert manager.update_profile("mapped-profile") is True
    out = capsys.readouterr().out
    assert "Updated Bitwarden password for:" in out
    assert "Successfully updated both AWS and Bitwarden for:" in out
    assert "1Password" not in out


def test_failed_aws_call_does_not_print_the_password(capsys):
    """subprocess errors carry their own argv, which holds the password."""
    old_secret = "current-password"
    new_secret = "-xl%x6};^wRi;@)C4J"
    manager, aws, op = make_manager(item={"id": "abc", "password": old_secret})
    op.generate_password = lambda: new_secret

    def explode(profile_name, old_password, new_password):
        raise subprocess.CalledProcessError(
            252,
            [
                "aws", "iam", "change-password",
                f"--old-password={old_password}",
                f"--new-password={new_password}",
            ],
            stderr="aws: [ERROR]: argument --password: expected one argument",
        )

    aws.change_password = explode

    assert manager.update_profile("mapped-profile") is False
    out = capsys.readouterr().out
    assert old_secret not in out
    assert new_secret not in out
    assert "252" in out
    assert "expected one argument" in out


def test_missing_stored_password_leaves_aws_password_untouched(capsys):
    manager, aws, op = make_manager(item={"id": "abc"})

    assert manager.update_profile("mapped-profile") is False
    assert aws.password_changes == []
    assert op.edits == []
    assert "password field is missing" in capsys.readouterr().out


def test_failed_onepassword_write_does_not_print_the_password(capsys):
    manager, aws, op = make_manager(item={"id": "abc", "password": "current-password"})
    secret = "Str0ng!Password--x"
    op.generate_password = lambda: secret

    def explode(item_title, **fields):
        raise subprocess.CalledProcessError(
            1, ["op", "item", "edit", item_title, f"password={secret}"], stderr=""
        )

    op.edit_item = explode

    assert manager.update_profile("mapped-profile") is False
    assert secret not in capsys.readouterr().out
