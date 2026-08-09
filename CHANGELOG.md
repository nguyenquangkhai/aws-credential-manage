# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `import-all-credentials` / `import-credentials` now create the 1Password item
  automatically when it does not exist instead of failing.
- `OnePasswordClient.create_item` for creating new 1Password items via the CLI.
- Test suite (`tests/`) covering `utils/` and `integrations/` with mocked
  subprocess calls — no real AWS or 1Password access required.
- GitHub Actions CI running ruff, mypy, and pytest on Python 3.11–3.13.
- Community health files: `CHANGELOG.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, issue templates, and a pull request template.
- README badges for CI, license, supported Python versions, and lint.

### Changed
- `generate_password` now uses the `secrets` module (cryptographically
  secure) instead of `random`.
- Coverage configuration now targets the `aws_credential_manager` package
  instead of the legacy `aws_credential_updater` wrapper module.
- Ruff line length raised from 88 to 100; existing long lines reflowed.
- Default password and access key max age set to 90 days, matching the
  documented rotation policy (was 70).

### Fixed
- Package author/maintainer email corrected from a placeholder.

## [1.0.0] - 2025-03-02

### Added
- Initial release: AWS IAM password and access key management with
  1Password integration and quarterly automation for macOS.
