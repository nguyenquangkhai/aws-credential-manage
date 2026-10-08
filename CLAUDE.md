# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an AWS credential management tool that automates the process of updating AWS IAM user console passwords and synchronizing them with 1Password. The tool helps maintain security compliance by rotating passwords based on age policies and keeping credentials centralized.

## Core Architecture

- **Entry Point**: `aws_credential_updater.py` - Thin wrapper delegating to the package
- **Package**: `aws_credential_manager/` - Modular Python package
- **Runtime**: Uses `mise.toml` for Python 3.13 version management
- **Alternative invocation**: `python -m aws_credential_manager`

## Package Structure

```
aws_credential_manager/
  cli/main.py                  # Argparse CLI definitions and command dispatch
  core/credential_manager.py   # Top-level orchestrator (quarterly update, import, list)
  core/password_manager.py     # Password rotation logic
  core/access_key_manager.py   # Access key rotation with rollback
  integrations/aws_client.py   # AWS IAM CLI wrapper (subprocess calls)
  integrations/onepassword.py  # 1Password CLI wrapper + password generation
  utils/config.py              # Constants (DEFAULT_PASSWORD_MAX_AGE, DEFAULT_ACCESS_KEY_MAX_AGE), ConfigManager
  utils/validators.py          # Input validation utilities
```

### Profile Naming Convention
1Password item titles match AWS profile names exactly (e.g., profile `resola-deca-crm-dev` corresponds to 1Password item `resola-deca-crm-dev`).

### Default Thresholds
Defined in `aws_credential_manager/utils/config.py`:
- `DEFAULT_PASSWORD_MAX_AGE = 90` days
- `DEFAULT_ACCESS_KEY_MAX_AGE = 90` days

## Common Commands

### Basic Operations
```bash
# List all AWS profiles
python3 aws_credential_updater.py list

# Update a specific profile's password
python3 aws_credential_updater.py update <profile_name>

# Update all profiles
python3 aws_credential_updater.py update-all

# Show what would be updated without making changes
python3 aws_credential_updater.py --dry-run <command>
```

### Password Management
```bash
# List profiles with expired passwords (>90 days)
python3 aws_credential_updater.py list-expired

# Update all expired passwords
python3 aws_credential_updater.py update-expired

# Set custom age threshold (e.g., 60 days)
python3 aws_credential_updater.py list-expired --max-age 60
```

### Credential Import
```bash
# Import AWS access keys to 1Password for all mapped profiles
python3 aws_credential_updater.py import-all-credentials

# Import credentials for a specific profile
python3 aws_credential_updater.py import-credentials <profile_name>
```

### Access Key Refresh
```bash
# Refresh (recreate) AWS access key for a specific profile
python3 aws_credential_updater.py refresh-access-key <profile_name>

# Refresh access keys for all mapped profiles
python3 aws_credential_updater.py refresh-all-access-keys

# Show what would be refreshed without making changes
python3 aws_credential_updater.py --dry-run refresh-access-key <profile_name>
```

### Outdated Access Key Management
```bash
# List profiles with outdated access keys (>100 days)
python3 aws_credential_updater.py list-outdated-access-keys

# Update all outdated access keys
python3 aws_credential_updater.py update-outdated-access-keys

# Set custom age threshold (e.g., 60 days)
python3 aws_credential_updater.py list-outdated-access-keys --max-age 60

# Show what would be updated without making changes
python3 aws_credential_updater.py --dry-run update-outdated-access-keys
```

### Quarterly Maintenance
```bash
# Combined update of both passwords and access keys (ideal for scheduled maintenance)
python3 aws_credential_updater.py quarterly-update

# Customize age thresholds for quarterly update
python3 aws_credential_updater.py quarterly-update --password-max-age 90 --access-key-max-age 90

# Test quarterly update without making changes
python3 aws_credential_updater.py --dry-run quarterly-update
```

### Batch Credential Maintenance
```bash
# Shortcut: update all configured profiles
./batch_credentials.sh password
./batch_credentials.sh access-key
./batch_credentials.sh both

# Skip one or more profiles
./batch_credentials.sh both --exclude profile-a --exclude profile-b

# Preview without making changes
./batch_credentials.sh both --dry-run

# Direct Python form; global --dry-run precedes the command
python3 aws_credential_updater.py batch-update both
python3 aws_credential_updater.py --dry-run batch-update password --exclude profile-a
```

The batch command selects profiles from the configured AWS credentials file
that also have an entry in the profile mapping file. Profiles with no 1Password
mapping — such as the `default` section, which is normally an alias of another
profile — are skipped and listed in the output. This is a safety guard: an alias
shares an IAM user with its real profile, so operating on both would rotate the
same user twice and strand the credentials the alias still points at. The batch
aborts outright if the mapping file is missing or unparseable.

The `--exclude` option may be repeated and is validated against the credentials
file, so excluding an auto-skipped profile is still accepted. The `both`
operation runs password rotation before access-key refresh for each profile, and
skips the access-key step for a profile whose password step failed. Processing
continues after individual failures, prints an aggregate summary, and exits
non-zero if any selected operation fails. Passwords and secret access keys are
never printed.

## Dependencies and Prerequisites

### Required Tools
- **1Password CLI**: Must be installed and authenticated (`op signin`)
- **AWS CLI**: Required for IAM operations (`aws configure` for each profile)
- **Python 3.13**: Managed via mise

### Authentication Requirements
- 1Password CLI session must be active
- AWS credentials must be valid for each profile being updated
- IAM permissions required: 
  - For password updates: `iam:GetUser`, `iam:UpdateLoginProfile`
  - For access key refresh: `iam:CreateAccessKey`, `iam:DeleteAccessKey`, `iam:ListAccessKeys`
  - For access key age tracking: `iam:GetUser`, `iam:ListAccessKeys`

## Configuration Notes

### Adding New AWS Profiles
1. Add AWS credentials to `~/.aws/credentials` with the profile name
2. Create a 1Password item in the "AWS" vault with the **same name** as the AWS profile

### Vault Configuration
- Default 1Password vault: "AWS"
- Override with `--vault` flag
- All 1Password items must exist in the specified vault

### Environment Configuration (`.env`)
Copy `.env.example` to `.env` to configure per-machine settings. Precedence:
real environment variable > `.env` file > built-in default.
- `DEFAULT_VAULT` — 1Password vault name (built-in default: `AWS`)
- `PROFILE_MAPPING_FILE` — profile mapping file; relative paths resolve
  against the project root (built-in default: `profile_mapping.json`)

## Security Considerations

- Passwords meet AWS policy: 18+ characters, mixed case, numbers, symbols
- No credentials are logged or stored in plaintext
- All password operations use secure generation methods
- Failed operations don't expose sensitive data in error messages
- Access keys are stored only in `~/.aws/credentials` (not in 1Password)
- Access key refresh creates backup files automatically before making changes
- AWS 2-key limit enforced: refresh fails if user already has 2 active keys
- Comprehensive rollback mechanisms in case of refresh failures
- Access key age tracked via AWS API (not 1Password) for accurate timestamps
- Outdated access key detection helps maintain compliance with rotation policies

## Automated Scheduling (macOS)

The tool includes macOS automation for quarterly credential maintenance using Launch Agents.

### Setup Automation
```bash
# One-time setup to install the quarterly automation
./setup_quarterly_automation.sh
```

### Schedule Details
- **Frequency**: Every 3 months (Jan 1, Apr 1, Jul 1, Oct 1)
- **Time**: 9:00 AM
- **Actions**: Updates both expired passwords (>90 days) and outdated access keys (>90 days)
- **Logging**: Automatic logging to `logs/` directory
- **Notifications**: Optional email notifications (configure in plist file)

### Manual Commands
```bash
# Test the automation setup
./aws_quarterly_update.sh test

# Run a dry-run to see what would be updated
./aws_quarterly_update.sh dry-run

# Run the quarterly update immediately
./aws_quarterly_update.sh

# View recent logs
tail -f logs/launchd.log
```

### Management Commands
```bash
# Check if automation is running
launchctl list | grep com.resola.aws-credential-updater

# Stop the automation
launchctl unload ~/Library/LaunchAgents/com.resola.aws-credential-updater.plist

# Start the automation
launchctl load ~/Library/LaunchAgents/com.resola.aws-credential-updater.plist
```

### Email Notifications
To enable email notifications:
1. Edit `~/Library/LaunchAgents/com.resola.aws-credential-updater.plist`
2. Change `<string>your-email@example.com</string>` to your actual email
3. Ensure `mail` command is configured on your system
4. Reload: `launchctl unload <plist> && launchctl load <plist>`
