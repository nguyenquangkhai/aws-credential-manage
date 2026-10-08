"""AWS IAM CLI wrapper."""

import csv
import io
import json
import subprocess
import time
from typing import cast


class AWSClient:
    """Thin wrapper around AWS CLI IAM commands."""

    def get_user(self, profile_name: str) -> dict:
        """Get IAM user info for a profile."""
        result = subprocess.run([
            'aws', 'iam', 'get-user',
            '--profile', profile_name,
            '--output', 'json'
        ], capture_output=True, text=True, check=True)
        return cast(dict, json.loads(result.stdout)['User'])

    def update_login_profile(self, profile_name: str, username: str, password: str) -> None:
        """Update AWS console password.

        The password is attached with '--password=' rather than passed as a
        separate argument. A generated password may begin with '-', which the
        AWS CLI argument parser would otherwise read as another option and
        reject with exit status 252 before contacting AWS.
        """
        subprocess.run([
            'aws', 'iam', 'update-login-profile',
            '--profile', profile_name,
            '--user-name', username,
            f'--password={password}',
            '--no-password-reset-required'
        ], check=True, capture_output=True)

    def list_access_keys(self, profile_name: str, username: str) -> list[dict]:
        """List access keys for a user."""
        result = subprocess.run([
            'aws', 'iam', 'list-access-keys',
            '--profile', profile_name,
            '--user-name', username,
            '--output', 'json'
        ], capture_output=True, text=True, check=True)
        return cast(list[dict], json.loads(result.stdout)['AccessKeyMetadata'])

    def create_access_key(self, profile_name: str, username: str) -> dict:
        """Create a new access key. Returns the AccessKey dict."""
        result = subprocess.run([
            'aws', 'iam', 'create-access-key',
            '--profile', profile_name,
            '--user-name', username,
            '--output', 'json'
        ], capture_output=True, text=True, check=True)
        return cast(dict, json.loads(result.stdout)['AccessKey'])

    def delete_access_key(self, profile_name: str, username: str, access_key_id: str) -> None:
        """Delete an access key."""
        subprocess.run([
            'aws', 'iam', 'delete-access-key',
            '--profile', profile_name,
            '--user-name', username,
            '--access-key-id', access_key_id
        ], capture_output=True, text=True, check=True)

    def get_password_last_changed(self, profile_name: str) -> str | None:
        """Return ISO timestamp of when the IAM user's console password was last changed.

        Uses the IAM credential report, which is the only AWS source for this data.
        Matches the report row by the profile's actual IAM username (ARN) to avoid
        returning data for the wrong user in multi-user accounts.
        Returns None if the user has no console password or on any error.
        """
        import base64
        try:
            # Resolve the actual IAM username for this profile
            user = self.get_user(profile_name)
            username = user.get('UserName') or user.get('Arn', '')

            # Trigger report generation; keep retrying until COMPLETE
            for _ in range(10):
                gen = subprocess.run([
                    'aws', 'iam', 'generate-credential-report',
                    '--profile', profile_name,
                    '--output', 'json'
                ], capture_output=True, text=True, check=True)
                state = json.loads(gen.stdout).get('State', '')
                if state == 'COMPLETE':
                    break
                time.sleep(2)

            result = subprocess.run([
                'aws', 'iam', 'get-credential-report',
                '--profile', profile_name,
                '--output', 'json'
            ], capture_output=True, text=True, check=True)

            report = json.loads(result.stdout)
            csv_content = base64.b64decode(report['Content']).decode('utf-8')

            reader = csv.DictReader(io.StringIO(csv_content))
            for row in reader:
                # Match by username; the 'user' column in the report is the IAM username
                if row.get('user') != username:
                    continue
                changed = row.get('password_last_changed', 'N/A')
                if changed and changed not in ('N/A', 'not_supported', 'no_information'):
                    return changed
                # User found but no valid password_last_changed — stop searching
                return None
        except Exception:  # noqa: S110 - best-effort lookup; fall back to None
            pass
        return None
