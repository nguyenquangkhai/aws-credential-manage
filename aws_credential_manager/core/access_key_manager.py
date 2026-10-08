"""Access key management for AWS IAM access keys."""

import configparser
import os
import subprocess
import time
from datetime import datetime

from ..integrations.aws_client import AWSClient
from ..integrations.vault_protocol import PasswordVault
from ..utils.config import DEFAULT_ACCESS_KEY_MAX_AGE, ConfigManager
from .password_manager import PasswordManager


class AccessKeyManager:
    """Manages AWS access key rotation with rollback support."""

    def __init__(self, aws: AWSClient, op: PasswordVault, config: ConfigManager):
        self.aws = aws
        self.op = op
        self.config = config
        self.passwords = PasswordManager(aws, op, config)

    def get_access_key_age(self, profile_name: str) -> dict | None:
        """Get access key age from AWS API."""
        try:
            user = self.aws.get_user(profile_name)
            username = user['UserName']

            access_keys = self.aws.list_access_keys(profile_name, username)

            if not access_keys:
                print(f"✗ No access keys found for {profile_name}")
                return None

            # Get the current access key being used
            current_profiles = self.config.get_aws_profiles()
            current_access_key_id = None
            for profile in current_profiles:
                if profile['name'] == profile_name:
                    current_access_key_id = profile['access_key_id']
                    break

            current_key_info = None
            for key in access_keys:
                if key['AccessKeyId'] == current_access_key_id:
                    current_key_info = key
                    break

            if not current_key_info:
                print(
                    f"⚠️ Current access key {current_access_key_id} not found "
                    "in AWS (may be deleted)"
                )
                return None

            create_date_str = current_key_info['CreateDate']
            if isinstance(create_date_str, str):
                create_date = datetime.fromisoformat(create_date_str.replace('Z', '+00:00'))
            else:
                create_date = create_date_str

            now = datetime.now(create_date.tzinfo) if create_date.tzinfo else datetime.now()
            age_days = (now - create_date).days

            return {
                'access_key_id': current_access_key_id,
                'username': username,
                'create_date': create_date_str,
                'age_days': age_days,
                'outdated': age_days >= DEFAULT_ACCESS_KEY_MAX_AGE,
                'status': current_key_info['Status'],
                'source': 'AWS API'
            }

        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to get access key info for {profile_name}: {e}")
            return None
        except Exception as e:
            print(f"✗ Error checking access key age for {profile_name}: {e}")
            return None

    def _update_credentials_file(self, profile_name: str, new_access_key_id: str,
                                  new_secret_key: str) -> bool:
        """Update the AWS credentials file with new access keys."""
        credentials_path = self.config.credentials_path
        try:
            backup_path = f"{credentials_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            subprocess.run(['cp', credentials_path, backup_path], check=True)
            print(f"✓ Created backup: {backup_path}")

            config = configparser.ConfigParser()
            config.read(credentials_path)

            if not config.has_section(profile_name):
                print(f"✗ Profile {profile_name} not found in credentials file")
                return False

            config.set(profile_name, 'aws_access_key_id', new_access_key_id)
            config.set(profile_name, 'aws_secret_access_key', new_secret_key)

            with open(credentials_path, 'w') as configfile:
                config.write(configfile)

            print(f"✓ Updated credentials file for profile: {profile_name}")
            return True

        except (subprocess.CalledProcessError, configparser.Error) as e:
            print(f"✗ Failed to update credentials file: {e}")
            return False

    def _restore_credentials_from_backup(self, profile_name: str) -> bool:
        """Restore credentials file from the most recent backup."""
        credentials_path = self.config.credentials_path
        try:
            backup_files = sorted([
                f for f in os.listdir(os.path.dirname(credentials_path))
                if f.startswith(f"{os.path.basename(credentials_path)}.backup.")
            ])

            if not backup_files:
                print("✗ No backup files found to restore from")
                return False

            latest_backup = os.path.join(os.path.dirname(credentials_path), backup_files[-1])
            subprocess.run(['cp', latest_backup, credentials_path], check=True)
            print(f"✓ Restored credentials from backup: {latest_backup}")
            return True

        except (subprocess.CalledProcessError, OSError) as e:
            print(f"✗ Failed to restore credentials from backup: {e}")
            print(
                f"  Please manually restore using: "
                f"cp {credentials_path}.backup.* {credentials_path}"
            )
            return False

    def _test_new_credentials(self, profile_name: str, credentials: dict[str, str],
                              max_retries: int = 5, initial_delay: int = 2) -> bool:
        """Test new credentials with exponential backoff retry."""
        print(f"🔄 Testing new credentials for {profile_name}...")

        for attempt in range(max_retries):
            try:
                self.aws.get_user_with_credentials(credentials)
                print(f"✓ New credentials for {profile_name} are working")
                return True
            except subprocess.CalledProcessError as e:
                if attempt < max_retries - 1:
                    stderr = str(e.stderr)
                    propagating = (
                        "InvalidClientTokenId" in stderr
                        or "The security token included in the request is invalid"
                        in stderr
                    )
                    if propagating:
                        delay = initial_delay * (2 ** attempt)
                        print(
                            f"  Attempt {attempt + 1}/{max_retries}: Credentials "
                            f"still propagating, waiting {delay}s..."
                        )
                        time.sleep(delay)
                        continue
                    else:
                        print(
                            f"✗ New credentials for {profile_name} failed with "
                            f"non-propagation error: {e}"
                        )
                        return False
                else:
                    print(
                        f"✗ New credentials for {profile_name} failed after "
                        f"{max_retries} attempts: {e}"
                    )
                    print(
                        "  This may indicate an AWS service issue or the "
                        "credentials are genuinely invalid"
                    )
                    return False

        return False

    @staticmethod
    def _describe_aws_error(error: Exception) -> str:
        """Return AWS CLI stderr without leaking command-line MFA codes."""
        if not isinstance(error, subprocess.CalledProcessError):
            return str(error)
        detail = error.stderr
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", "replace")
        detail = (detail or "").strip()
        return detail or f"AWS CLI exited with status {error.returncode}"

    def refresh_key(
        self, profile_name: str, dry_run: bool = False,
    ) -> bool:
        """Refresh (recreate) AWS access key for a profile with rollback support."""
        credentials_path = self.config.credentials_path

        if not os.path.exists(credentials_path):
            print(f"✗ AWS credentials file not found: {credentials_path}")
            return False

        config = configparser.ConfigParser()
        config.read(credentials_path)
        if not config.has_section(profile_name):
            print(f"✗ Profile '{profile_name}' not found in credentials file")
            return False

        if dry_run:
            print(f"[DRY RUN] Would refresh AWS access key for '{profile_name}':")
            print(f"  {self.op.display_name} Item: {profile_name}")
            print("  Actions:")
            print("    1. Get current user info and access keys")
            print("    2. Create new access key pair")
            print("    3. Update local credentials file (~/.aws/credentials)")
            print("    4. Wait for AWS credential propagation (3 seconds + retry logic)")
            print("    5. Test new credentials (up to 5 attempts with exponential backoff)")
            print(f"    6. Record access key refresh metadata in {self.op.display_name}")
            print("    7. Delete old access key")
            print(
                "  Note: Access keys will only be stored in ~/.aws/credentials "
                f"(not in {self.op.display_name})"
            )
            print("  Safety: Automatic rollback and cleanup if any step fails")
            return True

        print(f"🔄 Refreshing access key for: {profile_name}")

        # Step 1: Get user and check key count
        try:
            user = self.aws.get_user(profile_name)
            username = user['UserName']
            current_keys = self.aws.list_access_keys(profile_name, username)

            if len(current_keys) >= 2:
                print(f"✗ User {username} already has 2 access keys (AWS limit)")
                print("  Please delete an existing key before creating a new one")
                return False

            try:
                mfa_serial_number = self.aws.get_mfa_serial_number(
                    profile_name, username
                )
                item_title = self.passwords.get_item_title(profile_name)
                mfa_code = self.op.get_one_time_password(item_title)
            except (subprocess.CalledProcessError, ValueError) as error:
                print(f"✗ Unable to resolve MFA device: {self._describe_aws_error(error)}")
                return False
            except Exception as error:
                print(
                    f"✗ Unable to retrieve MFA code from "
                    f"{self.op.display_name}: {error}"
                )
                return False

            if not (len(mfa_code) == 6 and mfa_code.isdecimal()):
                print(f"✗ {self.op.display_name} returned an invalid MFA code")
                return False
            mfa_session = self.aws.get_mfa_session(
                profile_name, mfa_serial_number, mfa_code
            )

            # Step 2: Create new access key through the MFA-backed session.
            new_key = self.aws.create_access_key(
                profile_name, username, mfa_session
            )
            print(f"✓ Created new access key for user: {username}")
            print(f"  New Access Key ID: {new_key['AccessKeyId']}")
        except subprocess.CalledProcessError as e:
            print(
                f"✗ Failed to create new access key for {profile_name}: "
                f"{self._describe_aws_error(e)}"
            )
            return False

        old_access_key_id = current_keys[0]['AccessKeyId'] if current_keys else None

        # Step 3: Update local credentials file
        if not self._update_credentials_file(
            profile_name, new_key['AccessKeyId'], new_key['SecretAccessKey']
        ):
            print("✗ Failed to update credentials file, cleaning up...")
            try:
                self.aws.delete_access_key(
                    profile_name, username, new_key['AccessKeyId'], mfa_session
                )
            except Exception:  # noqa: S110 - cleanup best-effort during rollback
                pass
            return False

        # Step 4: Wait for propagation
        print("⏱️  Waiting for AWS credential propagation (3 seconds)...")
        time.sleep(3)

        # Step 5: Test new credentials
        if not self._test_new_credentials(profile_name, new_key):
            print("✗ New credentials failed testing, rolling back...")
            print(f"  Deleting newly created access key: {new_key['AccessKeyId']}")
            try:
                self.aws.delete_access_key(
                    profile_name, username, new_key['AccessKeyId'], mfa_session
                )
                print(f"  ✓ Deleted failed access key: {new_key['AccessKeyId']}")
            except (subprocess.CalledProcessError, Exception) as e:
                print(f"  ⚠️ Could not delete failed access key {new_key['AccessKeyId']}: {e}")
                print("  Please manually delete it from the AWS console")

            print("  Attempting to restore credentials from backup...")
            if not self._restore_credentials_from_backup(profile_name):
                print("  Please manually restore credentials from backup file:")
                print(f"    cp {credentials_path}.backup.* {credentials_path}")

            return False

        # Step 6: Record metadata in the vault
        try:
            item_title = self.passwords.get_item_title(profile_name)
            self.op.edit_item(item_title,
                              **{
                                  'last_access_key_refresh[text]': datetime.now().isoformat(),
                                  'current_access_key_id[text]': new_key['AccessKeyId']
                              })
            print(
                f"✓ Updated {self.op.display_name} metadata for: {profile_name} "
                f"with item title: {item_title}"
            )
        except subprocess.CalledProcessError:
            print(
                f"⚠️ Failed to update {self.op.display_name} metadata, "
                "but access key refresh succeeded"
            )

        # Step 7: Delete old access key
        if old_access_key_id:
            try:
                self.aws.delete_access_key(
                    profile_name, username, old_access_key_id, mfa_session
                )
                print(f"✓ Deleted old access key: {old_access_key_id}")
            except Exception:
                print(f"⚠️ Failed to delete old access key: {old_access_key_id}")
                print("  New key is working, but please manually delete the old one")

        print(f"✓ Successfully refreshed access key for: {profile_name}")
        return True

    def refresh_all(self, dry_run: bool = False) -> bool:
        """Refresh access keys for all profiles."""
        profiles = self.config.get_aws_profiles()
        profile_names = [p['name'] for p in profiles]
        print(f"Refreshing access keys for {len(profile_names)} profiles...")

        success_count = 0
        for profile_name in profile_names:
            if self.refresh_key(profile_name, dry_run):
                success_count += 1
            print()

        print(f"Summary: {success_count}/{len(profile_names)} access keys refreshed successfully")
        return success_count == len(profile_names)

    def list_outdated(self, max_age_days: int | None = None) -> list[dict]:
        """List all profiles with outdated access keys."""
        max_age_days = max_age_days or DEFAULT_ACCESS_KEY_MAX_AGE
        outdated_profiles = []
        profiles = self.config.get_aws_profiles()

        print(f"Checking access key age for {len(profiles)} profiles...")
        print(f"Access key policy: {max_age_days} days maximum age\n")

        for profile in profiles:
            profile_name = profile['name']
            access_key_info = self.get_access_key_age(profile_name)

            if access_key_info:
                access_key_info['outdated'] = access_key_info['age_days'] >= max_age_days

                status = "🔴 OUTDATED" if access_key_info['outdated'] else "🟢 OK"
                print(f"{status} {profile_name}")
                print(f"    {self.op.display_name}: {profile_name}")
                print(f"    User: {access_key_info['username']}")
                print(f"    Access Key: {access_key_info['access_key_id']}")
                print(f"    Age: {access_key_info['age_days']} days")
                print(f"    Status: {access_key_info['status']}")
                print(f"    Created: {access_key_info['create_date']}")
                print(f"    Source: {access_key_info['source']}")
                print()

                if access_key_info['outdated']:
                    outdated_profiles.append({
                        'profile_name': profile_name,
                        'onepassword_title': profile_name,
                        **access_key_info
                    })
            else:
                print(f"⚠️  UNKNOWN {profile_name}")
                print(f"    {self.op.display_name}: {profile_name}")
                print("    Could not check access key age")
                print()

        print(
            f"Summary: {len(outdated_profiles)}/{len(profiles)} profiles "
            "have outdated access keys"
        )
        return outdated_profiles

    def update_outdated(self, max_age_days: int | None = None, dry_run: bool = False) -> bool:
        """Update all profiles with outdated access keys."""
        outdated_profiles = self.list_outdated(max_age_days)

        if not outdated_profiles:
            print("✅ No outdated access keys found!")
            return True

        print(f"\n🔄 Found {len(outdated_profiles)} outdated access keys")

        if dry_run:
            print("\n[DRY RUN] Would refresh the following outdated access keys:")
            for profile in outdated_profiles:
                print(f"  - {profile['profile_name']} (age: {profile['age_days']} days)")
                print(f"    Access Key: {profile['access_key_id']}")
                print(f"    Created: {profile['create_date']}")
            return True

        print("\nProceeding to refresh outdated access keys...")

        success_count = 0
        for profile in outdated_profiles:
            profile_name = profile['profile_name']
            print(f"\n🔄 Refreshing {profile_name} (age: {profile['age_days']} days)...")
            print(f"  Current key: {profile['access_key_id']}")

            if self.refresh_key(profile_name):
                success_count += 1
            else:
                print(f"❌ Failed to refresh {profile_name}")

        print(
            f"\n📊 Summary: {success_count}/{len(outdated_profiles)} outdated "
            "access keys refreshed successfully"
        )
        return success_count == len(outdated_profiles)
