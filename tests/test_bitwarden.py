"""Tests for BitwardenClient."""

import json
import subprocess

import pytest

from aws_credential_manager.integrations.bitwarden import BitwardenClient
from tests.conftest import FakeCompletedProcess

BW_RUN = "aws_credential_manager.integrations.bitwarden.subprocess.run"


@pytest.fixture
def client():
    return BitwardenClient(vault_name="AWS")


class TestCheckSession:
    def test_active(self, client, mocker):
        mocker.patch.dict("os.environ", {"BW_SESSION": "tok-123"})
        run = mocker.patch(BW_RUN)
        run.return_value = FakeCompletedProcess(
            stdout=json.dumps({"status": "unlocked"})
        )
        assert client.check_session() is True

    def test_no_token(self, client, mocker):
        mocker.patch.dict("os.environ", {}, clear=True)
        assert client.check_session() is False

    def test_locked(self, client, mocker):
        mocker.patch.dict("os.environ", {"BW_SESSION": "tok-123"})
        run = mocker.patch(BW_RUN)
        run.return_value = FakeCompletedProcess(
            stdout=json.dumps({"status": "locked"})
        )
        assert client.check_session() is False


class TestGetItem:
    def test_success_parses_json(self, client, mocker):
        mocker.patch.dict("os.environ", {"BW_SESSION": "tok-123"})
        payload = {"id": "abc", "name": "my-item"}
        run = mocker.patch(BW_RUN)
        run.return_value = FakeCompletedProcess(
            returncode=0, stdout=json.dumps(payload)
        )
        assert client.get_item("my-item") == payload
        args = run.call_args.args[0]
        assert args[:3] == ["bw", "get", "item"]

    def test_not_found_returns_none(self, client, mocker):
        mocker.patch.dict("os.environ", {"BW_SESSION": "tok-123"})
        run = mocker.patch(BW_RUN)
        run.side_effect = subprocess.CalledProcessError(1, ["bw", "get", "item", "missing"])
        # Avoid module-level patch interfering with exception catching by
        # patching only subprocess.run rather than the whole subprocess module.
        assert client.get_item("missing") is None

    def test_no_session_returns_none(self, client, mocker):
        mocker.patch.dict("os.environ", {}, clear=True)
        assert client.get_item("anything") is None


class TestEditItem:
    def test_updates_fields(self, client, mocker, bitwarden_item):
        mocker.patch.dict("os.environ", {"BW_SESSION": "tok-123"})
        run = mocker.patch(BW_RUN)
        # First call = bw get item, second = bw encode, third = bw edit item
        run.side_effect = [
            FakeCompletedProcess(stdout=json.dumps(bitwarden_item)),
            FakeCompletedProcess(stdout="<encoded>"),
            FakeCompletedProcess(),
        ]
        client.edit_item("test-item", password="newpass")

        # bw get item was called
        assert run.call_args_list[0].args[0][:3] == ["bw", "get", "item"]
        # The encoded item should have the updated password field
        encode_input = run.call_args_list[1].args[0]
        assert encode_input == ["bw", "encode"]

    def test_updates_login_password(self, client, mocker):
        mocker.patch.dict("os.environ", {"BW_SESSION": "tok-123"})
        item = {"id": "item-123", "name": "test-item", "login": {"password": "old"}, "fields": []}
        run = mocker.patch(BW_RUN)
        run.side_effect = [
            FakeCompletedProcess(stdout=json.dumps(item)),
            FakeCompletedProcess(stdout="<encoded>"),
            FakeCompletedProcess(),
        ]
        client.edit_item("test-item", password="newpass")
        encoded = json.loads(run.call_args_list[1].kwargs["input"])
        assert encoded["login"]["password"] == "newpass"
        assert all(f["name"] != "password" for f in encoded["fields"])

    def test_no_session_raises(self, client, mocker):
        mocker.patch.dict("os.environ", {}, clear=True)
        with pytest.raises(RuntimeError, match="BW_SESSION"):
            client.edit_item("x", password="p")


class TestGetOneTimePassword:
    def test_returns_totp_code(self, client, mocker):
        mocker.patch.dict("os.environ", {"BW_SESSION": "tok-123"})
        run = mocker.patch(BW_RUN)
        run.side_effect = [
            FakeCompletedProcess(stdout=json.dumps({"id": "abc", "name": "it"})),
            FakeCompletedProcess(stdout="123456"),
        ]
        assert client.get_one_time_password("it") == "123456"
        assert run.call_args_list[1].args[0] == ["bw", "get", "totp", "abc"]

    def test_missing_item_raises(self, client, mocker):
        mocker.patch.dict("os.environ", {}, clear=True)
        with pytest.raises(ValueError, match="not found"):
            client.get_one_time_password("missing")

    def test_cli_failure_raises(self, client, mocker):
        mocker.patch.dict("os.environ", {"BW_SESSION": "tok-123"})
        run = mocker.patch(BW_RUN)
        run.side_effect = [
            FakeCompletedProcess(stdout=json.dumps({"id": "abc", "name": "it"})),
            subprocess.CalledProcessError(1, ["bw", "get", "totp", "abc"]),
        ]
        with pytest.raises(RuntimeError, match="TOTP lookup failed"):
            client.get_one_time_password("it")


class TestGetFieldValue:
    def test_found(self, client, bitwarden_item):
        assert client.get_field_value(bitwarden_item, "username") == "bob"

    def test_missing_label(self, client, bitwarden_item):
        assert client.get_field_value(bitwarden_item, "nonexistent") is None

    def test_no_fields(self, client):
        assert client.get_field_value({}, "username") is None

    def test_login_password_fallback(self, client):
        login_item = {"login": {"username": "bob", "password": "hunter2"}, "fields": []}
        assert client.get_field_value(login_item, "password") == "hunter2"

    def test_custom_field_wins_over_login(self, client):
        item = {
            "login": {"password": "old"},
            "fields": [{"name": "password", "value": "custom"}],
        }
        assert client.get_field_value(item, "password") == "custom"


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
