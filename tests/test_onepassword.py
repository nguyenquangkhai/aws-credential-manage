"""Tests for OnePasswordClient."""

import json

import pytest

from aws_credential_manager.integrations.onepassword import OnePasswordClient
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
        mocker.patch(MODULE).run.return_value = FakeCompletedProcess(returncode=1)
        assert client.get_item("missing") is None


class TestCreateItem:
    def test_builds_field_args(self, client, mocker):
        run = mocker.patch(MODULE).run
        run.return_value = FakeCompletedProcess()
        client.create_item("my-item", **{"password[password]": "secret", "notes": "hi"})
        args = run.call_args.args[0]
        assert args[:7] == ["op", "item", "create", "--vault", "TestVault", "--title", "my-item"]
        assert "--category" in args and "login" in args
        assert "password[password]=secret" in args
        assert "notes=hi" in args

    def test_custom_category(self, client, mocker):
        run = mocker.patch(MODULE).run
        run.return_value = FakeCompletedProcess()
        client.create_item("my-item", category="api-credential", username="bob")
        args = run.call_args.args[0]
        assert "--category" in args and "api-credential" in args
        assert "username=bob" in args


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
