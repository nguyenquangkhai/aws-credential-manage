"""Main orchestrator for AWS credential management."""

import json
import os
from datetime import datetime
from typing import cast

from ..integrations.aws_client import AWSClient
from ..integrations.bitwarden import BitwardenClient
from ..integrations.onepassword import OnePasswordClient
from ..integrations.vault_protocol import PasswordVault
from ..utils.config import (
    DEFAULT_ACCESS_KEY_MAX_AGE,
    DEFAULT_PASSWORD_MAX_AGE,
    DEFAULT_VAULT,
    DEFAULT_VAULT_TYPE,
    ConfigManager,
)
from .access_key_manager import AccessKeyManager
from .password_manager import PasswordManager

VAULT_CLIENTS: dict[str, type] = {
    "1password": OnePasswordClient,
    "bitwarden": BitwardenClient,
}


class CredentialManager:
    """Top-level orchestrator for all credential operations."""

    def __init__(self, credentials_path: str | None = None,
                 vault_name: str = DEFAULT_VAULT,
                 vault_type: str = DEFAULT_VAULT_TYPE):
        self.config = ConfigManager(credentials_path, vault_name)

        client_cls = VAULT_CLIENTS.get(vault_type)
        if client_cls is None:
            raise ValueError(
                f"Unknown vault type: {vault_type!r}. "
                f"Supported: {', '.join(sorted(VAULT_CLIENTS))}"
            )
        self.op: PasswordVault = cast(PasswordVault, client_cls(vault_name))
        self.aws = AWSClient()
        self.passwords = PasswordManager(self.aws, self.op, self.config)
        self.access_keys = AccessKeyManager(self.aws, self.op, self.config)

    def check_op_session(self) -> bool:
        """Check if the vault CLI session is active."""
        return self.op.check_session()

    def list_profiles(self) -> None:
        """List all AWS profiles."""
        profiles = self.config.get_aws_profiles()
        print(f"Found {len(profiles)} AWS profiles:")
        for i, profile in enumerate(profiles, 1):
            profile_name = profile['name']
            print(f"{i:2d}. {profile_name}")
            print(f"     Access Key: {profile['access_key_id']}")
            print(f"     Vault Item: {profile_name}")
            print()

    def import_credentials(
        self, profile_name: str | None = None, dry_run: bool = False
    ) -> bool:
        """Import AWS access keys from credentials file to vault items."""
        profiles = self.config.get_aws_profiles()

        if profile_name:
            target_profiles = [p for p in profiles if p['name'] == profile_name]
            if not target_profiles:
                print(f"✗ Profile '{profile_name}' not found in AWS credentials")
                return False
        else:
            target_profiles = profiles

        if not target_profiles:
            print("✗ No profiles to import")
            return False

        print(f"Importing AWS credentials for {len(target_profiles)} profiles to vault...")

        success_count = 0
        for profile in target_profiles:
            pname = profile['name']

            if dry_run:
                print(f"[DRY RUN] Would import credentials for '{pname}':")
                print(f"  Vault Item: {pname}")
                print(f"  AWS Access Key ID: {profile['access_key_id']}")
                print(f"  AWS Secret Key: {profile['secret_access_key'][:8]}...")
                print()
                success_count += 1
                continue

            try:
                item_title = self.passwords.get_item_title(pname)
                item_data = self.op.get_item(item_title)
                if not item_data:
                    print(f"✗ {self.op.display_name} item not found: {item_title}")
                    continue

                has_access_key = (
                    self.op.get_field_value(item_data, 'aws_access_key_id') is not None
                )
                has_secret_key = (
                    self.op.get_field_value(item_data, 'aws_secret_access_key')
                    is not None
                )

                self.op.edit_item(item_title,
                                  **{
                                      'aws_access_key_id[text]':
                                          profile['access_key_id'],
                                      'aws_secret_access_key[password]':
                                          profile['secret_access_key'],
                                      'credential_import_date[text]':
                                          datetime.now().isoformat()
                                  })

                action = "Updated" if (has_access_key or has_secret_key) else "Added"
                print(
                    f"✓ {action} AWS credentials in vault: {pname} - "
                    f"item title: {item_title}"
                )
                success_count += 1

            except Exception as e:
                print(f"✗ Failed to import credentials for {pname} (item title: {item_title}): {e}")

        print(
            f"\n📊 Summary: {success_count}/{len(target_profiles)} profiles "
            "imported successfully"
        )
        return success_count == len(target_profiles)

    def batch_update(
        self,
        operation: str,
        excluded_profiles: list[str] | None = None,
        dry_run: bool = False,
    ) -> bool:
        """Run password and/or access-key maintenance for selected profiles."""
        valid_operations = {"password", "access-key", "both"}
        if operation not in valid_operations:
            print(
                f"✗ Invalid batch operation '{operation}'. "
                "Choose password, access-key, or both."
            )
            return False

        profiles = self.config.get_aws_profiles()
        profile_names = [profile["name"] for profile in profiles]
        excluded = list(dict.fromkeys(excluded_profiles or []))
        unknown_exclusions = [name for name in excluded if name not in profile_names]
        if unknown_exclusions:
            print(
                "✗ Unknown profile exclusion(s): "
                + ", ".join(unknown_exclusions)
            )
            return False

        excluded_set = set(excluded)
        candidate_names = [name for name in profile_names if name not in excluded_set]
        if not candidate_names:
            print("✗ No profiles remain after applying exclusions")
            return False

        # Profiles with no vault mapping are skipped rather than attempted.
        # An unmapped profile is typically an alias of a mapped one (e.g. the
        # 'default' section), so operating on it would rotate the same IAM user
        # twice and strand credentials the alias still points at.
        mappings = self.config.load_profile_mappings()
        if mappings is None:
            print("✗ Cannot read the profile mapping file; refusing to run a batch")
            return False

        selected_names = [name for name in candidate_names if name in mappings]
        unmapped_names = [name for name in candidate_names if name not in mappings]
        if not selected_names:
            print("✗ No selected profile has a vault mapping")
            return False

        operations = [operation] if operation != "both" else ["password", "access-key"]
        total_operations = len(selected_names) * len(operations)
        successful_operations = 0
        failed_profiles: list[str] = []

        print(
            f"🔄 Running batch '{operation}' for {len(selected_names)} profile(s)"
        )
        if excluded:
            print(f"Excluded profiles: {', '.join(excluded)}")
        if unmapped_names:
            print(
                f"Skipped (no vault mapping): {', '.join(unmapped_names)}"
            )
        if dry_run:
            print("[DRY RUN] No changes will be made")

        for profile_name in selected_names:
            profile_succeeded = True
            print(f"\n📍 Processing {profile_name}")
            for current_operation in operations:
                try:
                    if current_operation == "password":
                        succeeded = self.passwords.update_profile(profile_name, dry_run)
                    else:
                        succeeded = self.access_keys.refresh_key(profile_name, dry_run)
                except Exception as error:
                    print(f"✗ {current_operation} failed for {profile_name}: {error}")
                    succeeded = False

                if succeeded:
                    successful_operations += 1
                else:
                    profile_succeeded = False
                    if current_operation == "password" and operation == "both":
                        break

            if not profile_succeeded:
                failed_profiles.append(profile_name)

        print("\n📊 Batch summary")
        print(f"  Successful operations: {successful_operations}/{total_operations}")
        print(f"  Profiles failed: {len(failed_profiles)}/{len(selected_names)}")
        if failed_profiles:
            print(f"  Failed profiles: {', '.join(failed_profiles)}")
        return not failed_profiles

    def quarterly_update(self, password_max_age: int | None = None,
                          access_key_max_age: int | None = None,
                          dry_run: bool = False) -> bool:
        """Update both passwords and access keys (quarterly maintenance)."""
        password_max_age = password_max_age or DEFAULT_PASSWORD_MAX_AGE
        access_key_max_age = access_key_max_age or DEFAULT_ACCESS_KEY_MAX_AGE

        if not self.check_op_session():
            return False

        print("🔄 Starting quarterly credential update (passwords + access keys)")
        print(f"Password policy: {password_max_age} days maximum age")
        print(f"Access key policy: {access_key_max_age} days maximum age")
        print("=" * 60)

        print("\n📍 Step 1: Updating expired passwords...")
        password_success = self.passwords.update_expired(password_max_age, dry_run)

        print("\n📍 Step 2: Updating outdated access keys...")
        access_key_success = self.access_keys.update_outdated(
            access_key_max_age, dry_run
        )

        print("\n" + "=" * 60)
        print("🎯 QUARTERLY CREDENTIAL UPDATE SUMMARY:")
        print(f"  Passwords: {'✅ Success' if password_success else '❌ Some failures'}")
        print(f"  Access Keys: {'✅ Success' if access_key_success else '❌ Some failures'}")

        overall_success = password_success and access_key_success
        overall_msg = (
            '✅ Complete success!' if overall_success else '⚠️ Check logs for issues'
        )
        print(f"  Overall: {overall_msg}")

        if not dry_run:
            self._log_quarterly_update({
                'timestamp': datetime.now().isoformat(),
                'type': 'quarterly_update',
                'password_max_age': password_max_age,
                'access_key_max_age': access_key_max_age,
                'password_success': password_success,
                'access_key_success': access_key_success,
                'overall_success': overall_success
            })

        return overall_success

    def _log_quarterly_update(self, log_entry: dict) -> None:
        """Log quarterly update results."""
        try:
            log_file = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "quarterly_updates.log"
            )
            with open(log_file, "a") as f:
                f.write(f"{json.dumps(log_entry)}\n")
            print(f"📝 Logged update to: {log_file}")
        except Exception as e:
            print(f"⚠️ Could not log quarterly update: {e}")
