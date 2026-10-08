"""Password management for AWS console passwords."""

import subprocess
from datetime import datetime

from ..integrations.aws_client import AWSClient
from ..integrations.onepassword import OnePasswordError
from ..integrations.vault_protocol import PasswordVault
from ..utils.config import DEFAULT_PASSWORD_MAX_AGE, ConfigManager


def _describe_failure(error: Exception, *secrets: str | None) -> str:
    """Describe a failure without echoing the command that produced it.

    A failed subprocess carries its own argv, which for password rotation
    contains the plaintext password. Printing the exception directly would
    leak it into terminals and log files, so only the exit status and the
    tool's own stderr are reported, with the secret scrubbed from both.
    """
    if isinstance(error, subprocess.CalledProcessError):
        detail = error.stderr
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", "replace")
        detail = (detail or "").strip()
        message = f"exit status {error.returncode}"
        if detail:
            message = f"{message}: {detail}"
    else:
        message = str(error)

    for secret in secrets:
        if secret:
            message = message.replace(secret, "***")
    return message


class PasswordManager:
    """Manages AWS console password rotation with vault sync."""

    def __init__(self, aws: AWSClient, op: PasswordVault, config: ConfigManager):
        self.aws = aws
        self.op = op
        self.config = config

    def get_item_title(self, profile_name: str) -> str:
        """Get the vault item title for a given AWS profile name."""
        mapping = self.config.get_profile_mapping(profile_name)
        item_title = mapping.get('onepassword_title') if mapping else None
        if isinstance(item_title, str):
            return item_title
        return profile_name  # Fallback to profile name if no mapping exists

    def get_password_age(self, profile_name: str) -> dict | None:
        """Get password age, preferring AWS IAM credential report over the vault."""
        # --- Primary source: AWS IAM credential report ---
        try:
            aws_timestamp = self.aws.get_password_last_changed(profile_name)
            if aws_timestamp:
                last_date = datetime.fromisoformat(aws_timestamp.replace('Z', '+00:00'))
                age_days = (datetime.now(last_date.tzinfo) - last_date).days
                return {
                    'last_update': aws_timestamp,
                    'age_days': age_days,
                    'expired': age_days >= DEFAULT_PASSWORD_MAX_AGE,
                    'source': 'AWS IAM',
                }
        except Exception as e:
            print(f"⚠ Could not fetch AWS password age for {profile_name}: {e}")

        # --- Fallback: vault metadata ---
        item_title = self.get_item_title(profile_name)
        try:
            item_data = self.op.get_item(item_title)
        except OnePasswordError as e:
            # Age lookup is best-effort; a failed read must not abort a listing.
            print(f"⚠ {e}")
            return None
        if not item_data:
            return None

        try:
            last_update = self.op.get_field_value(item_data, 'last_password_update')

            if last_update:
                if 'T' in last_update:
                    last_date = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
                else:
                    last_date = datetime.fromisoformat(last_update)

                age_days = (datetime.now(last_date.tzinfo) - last_date).days

                return {
                    'last_update': last_update,
                    'age_days': age_days,
                    'expired': age_days >= DEFAULT_PASSWORD_MAX_AGE,
                    'source': f'{self.op.display_name} (fallback)',
                }
        except (ValueError, TypeError) as e:
            print(
                f"✗ Failed to get {self.op.display_name} timestamp for {profile_name} "
                f"that have item title {item_title}: {e}"
            )

        return None

    def update_profile(self, profile_name: str, dry_run: bool = False) -> bool:

        item_title = self.get_item_title(profile_name)
        """Update AWS console password and store in the vault."""
        if dry_run:
            print(f"[DRY RUN] Would update AWS console password for '{profile_name}':")
            print(f"  {self.op.display_name} Item: {item_title}")
            print("  Actions:")
            print("    1. Generate secure password (18+ chars, meets AWS policy)")
            print("    2. Update AWS console password via IAM API")
            print(f"    3. Store new password in {self.op.display_name}")
            return True

        # Check if AWS credentials are valid
        try:
            self.aws.get_user(profile_name)
        except Exception as e:
            print(f"⚠️ Skipping {profile_name}: Invalid AWS credentials")
            error_str = str(e)
            if "InvalidClientTokenId" in error_str:
                print("  Reason: AWS access keys are expired or invalid")
            else:
                print(f"  Reason: {error_str}")
            print(f"  Note: Fix AWS credentials for {profile_name} to enable password updates")
            return False

        # Confirm the vault item exists before rotating anything. A password
        # changed in AWS but not stored here would be unrecoverable.
        try:
            item_data = self.op.get_item(item_title)
        except OnePasswordError as e:
            print(f"✗ {e}")
            print(f"  Skipping {profile_name}: AWS password left unchanged")
            return False

        if not item_data:
            print(f"✗ {self.op.display_name} item not found: {item_title}")
            print(f"  Skipping {profile_name}: AWS password left unchanged")
            return False

        old_password = self.op.get_field_value(item_data, 'password')
        if not old_password:
            print(f"✗ {self.op.display_name} password field is missing: {item_title}")
            print(f"  Skipping {profile_name}: AWS password left unchanged")
            return False

        new_password = self.op.generate_password()

        # ChangePassword deliberately cannot modify another IAM user's password.
        try:
            user = self.aws.get_user(profile_name)
            self.aws.change_password(profile_name, old_password, new_password)
            print(f"✓ Updated AWS console password for user: {user['UserName']}")
        except Exception as e:
            print(f"✗ Failed to update AWS console password: "
                  f"{_describe_failure(e, old_password, new_password)}")
            return False

        # Update the vault
        try:
            self.op.edit_item(item_title,
                              password=new_password,
                              **{'last_password_update[text]': datetime.now().isoformat()})
            print(f"✓ Updated {self.op.display_name} password for: {item_title}")
        except Exception as e:
            print(f"✗ Failed to update {self.op.display_name} for {item_title}: "
                  f"{_describe_failure(e, old_password, new_password)}")
            return False

        print(f"✓ Successfully updated both AWS and {self.op.display_name} for: {profile_name}")
        return True

    def list_expired(self, max_age_days: int | None = None) -> list[dict]:
        """List all profiles with expired passwords."""
        max_age_days = max_age_days or DEFAULT_PASSWORD_MAX_AGE
        expired_profiles = []
        profiles = self.config.get_aws_profiles()

        print(f"Checking password age for {len(profiles)} profiles...")
        print(f"Password policy: {max_age_days} days maximum age\n")

        for profile in profiles:
            profile_name = profile['name']
            password_info = self.get_password_age(profile_name)

            if password_info:
                password_info['expired'] = password_info['age_days'] >= max_age_days
                status = "🔴 EXPIRED" if password_info['expired'] else "🟢 OK"
                print(f"{status} {profile_name}")
                print(f"    {self.op.display_name}: {profile_name}")

                if 'username' in password_info:
                    print(f"    User: {password_info['username']}")

                print(f"    Age: {password_info['age_days']} days")
                print(f"    Source: {password_info['source']}")

                if 'last_update' in password_info:
                    print(f"    Last Updated: {password_info['last_update']}")
                elif 'create_date' in password_info:
                    print(f"    Created: {password_info['create_date']}")

                print()

                if password_info['expired']:
                    expired_profiles.append({
                        'profile_name': profile_name,
                        'onepassword_title': profile_name,
                        **password_info
                    })
            else:
                print(f"⚠️  UNKNOWN {profile_name}")
                print(f"    {self.op.display_name}: {profile_name}")
                print("    Could not check password age")
                print()

        print(f"Summary: {len(expired_profiles)}/{len(profiles)} profiles have expired passwords")
        return expired_profiles

    def update_expired(self, max_age_days: int | None = None, dry_run: bool = False) -> bool:
        """Update all profiles with expired passwords."""
        expired_profiles = self.list_expired(max_age_days)

        if not expired_profiles:
            print("✅ No expired passwords found!")
            return True

        print(f"\n🔄 Found {len(expired_profiles)} expired passwords")

        if dry_run:
            print("\n[DRY RUN] Would update the following expired passwords:")
            for profile in expired_profiles:
                print(f"  - {profile['profile_name']} (age: {profile['age_days']} days)")
            return True

        print("\nProceeding to update expired passwords...")

        success_count = 0
        for profile in expired_profiles:
            profile_name = profile['profile_name']
            print(f"\n🔄 Updating {profile_name} (age: {profile['age_days']} days)...")

            if self.update_profile(profile_name):
                success_count += 1
            else:
                print(f"❌ Failed to update {profile_name}")

        print(
            f"\n📊 Summary: {success_count}/{len(expired_profiles)} expired "
            "passwords updated successfully"
        )
        return success_count == len(expired_profiles)

    def update_all(self, dry_run: bool = False) -> bool:
        """Update all profiles."""
        profiles = self.config.get_aws_profiles()
        profile_names = [p['name'] for p in profiles]

        print(f"Found {len(profile_names)} AWS profiles")

        success_count = 0
        for profile_name in profile_names:
            if self.update_profile(profile_name, dry_run):
                success_count += 1
            print()

        print(f"Summary: {success_count}/{len(profile_names)} profiles updated successfully")
        return success_count == len(profile_names)
