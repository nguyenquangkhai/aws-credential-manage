"""Tests for MFA-backed IAM access-key rotation."""

from aws_credential_manager.core.access_key_manager import AccessKeyManager
from aws_credential_manager.utils.config import ConfigManager


class FakeAws:
    """Record the security boundary used by a refresh."""

    def __init__(self):
        self.session = {
            "AccessKeyId": "ASIASESSION",
            "SecretAccessKey": "session-secret",
            "SessionToken": "session-token",
        }
        self.new_key = {
            "AccessKeyId": "AKIANEW",
            "SecretAccessKey": "new-secret",
        }
        self.deleted = []
        self.checked_credentials = None

    def get_user(self, profile_name):
        return {"UserName": "bob"}

    def list_access_keys(self, profile_name, username):
        return [{"AccessKeyId": "AKIAOLD"}]

    def get_mfa_serial_number(self, profile_name, username):
        return "arn:aws:iam::123:mfa/bob"

    def get_mfa_session(self, profile_name, mfa_serial_number, mfa_code):
        assert profile_name == "profile-one"
        assert mfa_serial_number == "arn:aws:iam::123:mfa/bob"
        assert mfa_code == "123456"
        return self.session

    def create_access_key(self, profile_name, username, session_credentials):
        assert session_credentials == self.session
        return self.new_key

    def get_user_with_credentials(self, credentials):
        self.checked_credentials = credentials
        return {"UserName": "bob"}

    def delete_access_key(self, profile_name, username, access_key_id, session_credentials):
        self.deleted.append((access_key_id, session_credentials))


class FakeOnePassword:
    display_name = "1Password"

    def get_one_time_password(self, title):
        assert title == "profile-one"
        return "123456"

    def edit_item(self, *args, **kwargs):
        pass


def test_refresh_uses_mfa_session_for_mutations_and_new_key_for_validation(
    aws_credentials_file, monkeypatch,
):
    aws = FakeAws()
    manager = AccessKeyManager(
        aws, FakeOnePassword(), ConfigManager(str(aws_credentials_file))
    )
    manager._update_credentials_file = lambda *args: True
    manager.passwords.get_item_title = lambda profile_name: profile_name
    monkeypatch.setattr(
        "aws_credential_manager.core.access_key_manager.time.sleep", lambda seconds: None
    )

    assert manager.refresh_key("profile-one")
    assert aws.checked_credentials == aws.new_key
    assert aws.deleted == [("AKIAOLD", aws.session)]
