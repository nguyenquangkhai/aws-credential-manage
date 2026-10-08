# AWS Credential Manager

[![CI](https://github.com/nguyenquangkhai/aws-credential-manage/actions/workflows/ci.yml/badge.svg)](https://github.com/nguyenquangkhai/aws-credential-manage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![Code style: ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)

A comprehensive tool for automating AWS IAM credential management, integrating with 1Password for secure password storage and featuring automatic quarterly maintenance.

## Features

### 🔐 Password Management
- Update AWS console passwords for IAM users
- Track password age and enforce 90-day rotation policy
- Secure password generation meeting AWS requirements
- 1Password integration for centralized storage

### 🔑 Access Key Management  
- Refresh (recreate) AWS access keys with automatic rotation
- Track access key age and detect outdated keys (100-day policy)
- Safe rotation with backup and rollback mechanisms
- AWS 2-key limit enforcement

### 🤖 Automated Maintenance
- Quarterly automation using macOS Launch Agents
- Combined password and access key updates
- Comprehensive logging and email notifications
- One-command setup with testing capabilities

## Quick Start

### Prerequisites
- Python 3.13+ (managed via mise)
- 1Password CLI (`op`)
- AWS CLI configured with profiles
- macOS (for automation features)

### Installation
1. Clone this repository
2. Configure your profile mappings in `profile_mapping.json`
3. (Optional) Copy `.env.example` to `.env` to configure per-machine settings
4. Set up automation: `./setup_quarterly_automation.sh`

### Environment Configuration (`.env`)
Copy `.env.example` to `.env` to configure per-machine settings. Precedence:
real environment variable > `.env` file > built-in default.
- `DEFAULT_VAULT` — 1Password vault name (built-in default: `AWS`)
- `PROFILE_MAPPING_FILE` — profile mapping file; relative paths resolve
  against the project root (built-in default: `profile_mapping.json`)

### Basic Usage
```bash
# List all profiles
python3 aws_credential_updater.py list

# Update specific profile password
python3 aws_credential_updater.py update <profile_name>

# Refresh access key for profile
python3 aws_credential_updater.py refresh-access-key <profile_name>

# Quarterly maintenance (both passwords and keys)
python3 aws_credential_updater.py quarterly-update
```

### Batch Credential Maintenance

The shortcut processes every configured AWS profile that has a 1Password
mapping. Profiles without one — including the `default` section, which is
usually an alias of another profile — are skipped and reported, so the same IAM
user is never rotated twice in a single run. Use repeated `--exclude` options to
skip further profiles, and use `--dry-run` to preview changes.

```bash
# Rotate passwords for every configured profile
./batch_credentials.sh password

# Refresh access keys while skipping selected profiles
./batch_credentials.sh access-key --exclude profile-a --exclude profile-b

# Run both operations without making changes
./batch_credentials.sh both --dry-run
```

The equivalent direct Python commands are:

```bash
python3 aws_credential_updater.py batch-update password
python3 aws_credential_updater.py batch-update access-key --exclude profile-a
python3 aws_credential_updater.py --dry-run batch-update both
```

`password` rotates IAM console passwords and synchronizes them with 1Password.
`access-key` replaces AWS access keys and updates the local credentials file.
`both` runs the password rotation before the access-key refresh for each
profile. All configured profiles are selected by default, and `--exclude` may
be repeated.

Processing continues after a profile failure, prints a final summary, and
exits non-zero if any selected operation fails. Use an active 1Password CLI
session and valid AWS CLI profiles before running a non-dry-run command.

## Documentation

See [CLAUDE.md](CLAUDE.md) for comprehensive usage documentation, including:
- Complete command reference
- Configuration instructions  
- Automation setup guide
- Security considerations

## Architecture

- **Main Script**: `aws_credential_updater.py` - Core functionality
- **Configuration**: `profile_mapping.json` - AWS profile to 1Password mappings
- **Automation**: macOS Launch Agent with quarterly scheduling
- **Logging**: Comprehensive audit trail with email notifications

## Security

- Access keys stored only in `~/.aws/credentials` (not in 1Password)
- Automatic credential backup before changes
- Comprehensive error handling with rollback capabilities
- No secrets logged or exposed in error messages

## Development

```bash
# Install with dev tooling
pip install -e ".[dev]"

# Run the test suite (with coverage)
pytest

# Lint and type-check
ruff check .
mypy aws_credential_manager
```

CI runs lint, type-check, and tests on Python 3.11–3.13 for every push and
pull request. See [.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All changes should include appropriate
tests and pass CI. Report security issues per [SECURITY.md](SECURITY.md).
