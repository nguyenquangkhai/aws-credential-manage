"""Tests for OnePasswordClient."""

import json

import pytest

from aws_credential_manager.integrations.onepassword import (
    OnePasswordClient,
    OnePasswordError,
)
from tests.conftest import FakeCompletedProcess

MODULE = "aws_credential_manager.integrations.onepassword.subprocess"


@pytest.fixture
def client():
    return OnePasswordClient(vault_name="TestVault")


class TestGeneratePassword:
    def test_default_length(self, client):
        assert len(client.generate_password()) == 18

    def test_custom_length(self, client):
        assert len(client.generate_password(24)) == 24

    def test_contains_all_char_classes(self, client):
        pw = client.generate_password(40)
        assert any(c.isupper() for c in pw)
        assert any(c.islower() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(not c.isalnum() for c in pw)

    def test_outputs_differ(self, client):
        passwords = {client.generate_password() for _ in range(20)}
        assert len(passwords) > 1


class TestGetFieldValue:
    def test_found(self, client):
        data = {"fields": [{"label": "username", "value": "bob"}]}
        assert client.get_field_value(data, "username") == "bob"

    def test_missing_label(self, client):
        data = {"fields": [{"label": "username", "value": "bob"}]}
        assert client.get_field_value(data, "password") is None

    def test_no_fields(self, client):
        assert client.get_field_value({}, "username") is None


class TestCheckSession:
    def test_active(self, client, mocker):
        mocker.patch(MODULE).run.return_value = FakeCompletedProcess()
        assert client.check_session() is True

    def test_inactive(self, client, mocker):
        import subprocess

        sub = mocker.patch(MODULE)
        sub.CalledProcessError = subprocess.CalledProcessError
        sub.run.side_effect = subprocess.CalledProcessError(1, "op")
        assert client.check_session() is False


class TestGetItem:
    def test_success_parses_json(self, client, mocker):
        payload = {"id": "abc", "title": "my-item"}
        run = mocker.patch(MODULE).run
        run.return_value = FakeCompletedProcess(
            returncode=0, stdout=json.dumps(payload)
        )
        assert client.get_item("my-item") == payload
        args = run.call_args.args[0]
        assert args[:4] == ["op", "item", "get", "my-item"]
        assert "--vault" in args and "TestVault" in args

    def test_not_found_returns_none(self, client, mocker):
        mocker.patch(MODULE).run.return_value = FakeCompletedProcess(
            returncode=1,
            stderr='[ERROR] 2026/08/07 "missing" isn\'t an item. '
                   "Specify the item with its UUID, name, or domain.",
        )
        assert client.get_item("missing") is None

    def test_dropped_session_raises_instead_of_reporting_not_found(
        self, client, mocker
    ):
        """A lost session must not be reported as a missing item."""
        mocker.patch(MODULE).run.return_value = FakeCompletedProcess(
            returncode=1,
            stderr="[ERROR] 2026/08/07 error initializing client: "
                   "You are not currently signed in. "
                   "Please run `op signin --help` for instructions",
        )
        with pytest.raises(OnePasswordError) as excinfo:
            client.get_item("AWS DECA Studio Prod")
        assert "not currently signed in" in str(excinfo.value)
        assert "AWS DECA Studio Prod" in str(excinfo.value)

    def test_unknown_vault_raises(self, client, mocker):
        mocker.patch(MODULE).run.return_value = FakeCompletedProcess(
            returncode=1,
            stderr='[ERROR] "AWS" isn\'t a vault in this account.',
        )
        with pytest.raises(OnePasswordError):
            client.get_item("some-item")

    def test_empty_stderr_raises_rather_than_assuming_not_found(self, client, mocker):
        mocker.patch(MODULE).run.return_value = FakeCompletedProcess(returncode=1)
        with pytest.raises(OnePasswordError):
            client.get_item("some-item")


class TestEditItem:
    def test_builds_field_args(self, client, mocker):
        run = mocker.patch(MODULE).run
        run.return_value = FakeCompletedProcess()
        client.edit_item("my-item", password="secret", notes="hi")
        args = run.call_args.args[0]
        assert args[:4] == ["op", "item", "edit", "my-item"]
        assert "password=secret" in args
        assert "notes=hi" in args


class TestEditItemGeneratePassword:
    def test_includes_recipe(self, client, mocker):
        run = mocker.patch(MODULE).run
        run.return_value = FakeCompletedProcess()
        client.edit_item_generate_password("my-item", recipe="letters,digits,20")
        args = run.call_args.args[0]
        assert "--generate-password=letters,digits,20" in args
