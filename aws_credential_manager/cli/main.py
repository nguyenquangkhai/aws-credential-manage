"""Command line interface for AWS credential manager."""

import argparse
import sys

from ..core.credential_manager import VAULT_CLIENTS, CredentialManager
from ..utils.config import (
    DEFAULT_ACCESS_KEY_MAX_AGE,
    DEFAULT_PASSWORD_MAX_AGE,
    DEFAULT_VAULT,
    DEFAULT_VAULT_TYPE,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='AWS Credential Password Updater with password vault'
    )
    parser.add_argument('--credentials-path', help='Path to AWS credentials file')
    parser.add_argument(
        '--vault',
        default=DEFAULT_VAULT,
        help=f'Vault name (default: {DEFAULT_VAULT})',
    )
    parser.add_argument(
        '--vault-type',
        default=DEFAULT_VAULT_TYPE,
        choices=sorted(VAULT_CLIENTS),
        help=f'Vault backend (default: {DEFAULT_VAULT_TYPE})',
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Show what would be updated without making changes',
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # List command
    subparsers.add_parser('list', help='List all AWS profiles')

    # Update single profile
    update_parser = subparsers.add_parser('update', help='Update a specific profile')
    update_parser.add_argument('profile_name', help='Name of the profile to update')

    # Update all profiles
    subparsers.add_parser('update-all', help='Update all profiles')

    # List expired passwords
    expired_parser = subparsers.add_parser(
        'list-expired', help='List profiles with expired passwords'
    )
    expired_parser.add_argument(
        '--max-age', type=int, default=DEFAULT_PASSWORD_MAX_AGE,
        help=f'Maximum password age in days (default: {DEFAULT_PASSWORD_MAX_AGE})',
    )

    # Update expired passwords
    update_expired_parser = subparsers.add_parser(
        'update-expired', help='Update all expired passwords'
    )
    update_expired_parser.add_argument(
        '--max-age', type=int, default=DEFAULT_PASSWORD_MAX_AGE,
        help=f'Maximum password age in days (default: {DEFAULT_PASSWORD_MAX_AGE})',
    )

    # Import credentials
    import_parser = subparsers.add_parser(
        'import-credentials', help='Import AWS credentials to the vault'
    )
    import_parser.add_argument(
        'profile_name', nargs='?',
        help='Profile name to import (optional, imports all if not specified)',
    )

    # Import all credentials
    subparsers.add_parser(
        'import-all-credentials', help='Import all AWS credentials to the vault'
    )

    # Refresh access key for single profile
    refresh_parser = subparsers.add_parser(
        'refresh-access-key',
        help='Refresh (recreate) AWS access key for a specific profile',
    )
    refresh_parser.add_argument(
        'profile_name', help='Name of the profile to refresh access key for'
    )

    # Refresh access keys for all profiles
    subparsers.add_parser(
        'refresh-all-access-keys', help='Refresh access keys for all profiles'
    )

    # List outdated access keys
    outdated_keys_parser = subparsers.add_parser(
        'list-outdated-access-keys', help='List profiles with outdated access keys'
    )
    outdated_keys_parser.add_argument(
        '--max-age', type=int, default=DEFAULT_ACCESS_KEY_MAX_AGE,
        help=f'Maximum access key age in days (default: {DEFAULT_ACCESS_KEY_MAX_AGE})',
    )

    # Update outdated access keys
    update_outdated_keys_parser = subparsers.add_parser(
        'update-outdated-access-keys', help='Update all outdated access keys'
    )
    update_outdated_keys_parser.add_argument(
        '--max-age', type=int, default=DEFAULT_ACCESS_KEY_MAX_AGE,
        help=f'Maximum access key age in days (default: {DEFAULT_ACCESS_KEY_MAX_AGE})',
    )

    # Quarterly update
    quarterly_parser = subparsers.add_parser(
        'quarterly-update',
        help='Update both passwords and access keys (for scheduled maintenance)',
    )
    quarterly_parser.add_argument(
        '--password-max-age', type=int, default=DEFAULT_PASSWORD_MAX_AGE,
        help=f'Maximum password age in days (default: {DEFAULT_PASSWORD_MAX_AGE})',
    )
    quarterly_parser.add_argument(
        '--access-key-max-age', type=int, default=DEFAULT_ACCESS_KEY_MAX_AGE,
        help=f'Maximum access key age in days (default: {DEFAULT_ACCESS_KEY_MAX_AGE})',
    )

    # Batch update
    batch_parser = subparsers.add_parser(
        'batch-update',
        help='Update passwords and/or refresh access keys for selected profiles',
    )
    batch_parser.add_argument(
        'operation',
        choices=('password', 'access-key', 'both'),
        help='Credential operation to run',
    )
    batch_parser.add_argument(
        '--exclude',
        dest='excluded_profiles',
        action='append',
        default=[],
        metavar='PROFILE',
        help='Profile to skip; may be repeated',
    )

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    mgr = CredentialManager(args.credentials_path, args.vault, args.vault_type)

    try:
        if args.command == 'list':
            mgr.list_profiles()
        elif args.command == 'update':
            if not mgr.check_op_session():
                return 1
            mgr.passwords.update_profile(args.profile_name, args.dry_run)
        elif args.command == 'update-all':
            if not mgr.check_op_session():
                return 1
            mgr.passwords.update_all(args.dry_run)
        elif args.command == 'list-expired':
            if not mgr.check_op_session():
                return 1
            mgr.passwords.list_expired(args.max_age)
        elif args.command == 'update-expired':
            if not mgr.check_op_session():
                return 1
            mgr.passwords.update_expired(args.max_age, args.dry_run)
        elif args.command == 'import-credentials':
            if not mgr.check_op_session():
                return 1
            profile_name = getattr(args, 'profile_name', None)
            mgr.import_credentials(profile_name, args.dry_run)
        elif args.command == 'import-all-credentials':
            if not mgr.check_op_session():
                return 1
            mgr.import_credentials(None, args.dry_run)
        elif args.command == 'refresh-access-key':
            if not mgr.check_op_session():
                return 1
            mgr.access_keys.refresh_key(
                args.profile_name,
                args.dry_run,
            )
        elif args.command == 'refresh-all-access-keys':
            if not mgr.check_op_session():
                return 1
            mgr.access_keys.refresh_all(args.dry_run)
        elif args.command == 'list-outdated-access-keys':
            if not mgr.check_op_session():
                return 1
            mgr.access_keys.list_outdated(args.max_age)
        elif args.command == 'update-outdated-access-keys':
            if not mgr.check_op_session():
                return 1
            mgr.access_keys.update_outdated(args.max_age, args.dry_run)
        elif args.command == 'quarterly-update':
            if not mgr.check_op_session():
                return 1
            mgr.quarterly_update(
                args.password_max_age, args.access_key_max_age, args.dry_run
            )
        elif args.command == 'batch-update':
            if not mgr.check_op_session():
                return 1
            return 0 if mgr.batch_update(
                args.operation,
                args.excluded_profiles,
                args.dry_run,
            ) else 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
