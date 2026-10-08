# Batch Credential Maintenance Design

## Goal

Provide a short Bash command for rotating passwords and/or refreshing access keys across all configured AWS profiles, with optional exclusions and safe batch behavior.

## User-facing interface

The repository will provide `batch_credentials.sh`:

```bash
./batch_credentials.sh password
./batch_credentials.sh access-key
./batch_credentials.sh both
./batch_credentials.sh password --exclude profile-a --exclude profile-b
./batch_credentials.sh both --dry-run
```

The script selects all profiles from the configured AWS credentials file by default. Each `--exclude` value removes one profile from the selected set. The script validates the operation and forwards the remaining options to the Python CLI.

The Python CLI will also expose a `batch-update` command with operation choices `password`, `access-key`, and `both`, plus repeatable exclusions and dry-run support. Existing commands remain available and unchanged.

## Architecture

`CredentialManager` will own batch orchestration. It will:

1. Load configured AWS profiles.
2. Remove excluded profiles and reject unknown exclusions or an empty resulting selection.
3. Process each selected profile in deterministic credentials-file order.
4. For `password`, call the existing password manager's single-profile operation.
5. For `access-key`, call the existing access-key manager's single-profile operation.
6. For `both`, perform the password operation before the access-key operation for each profile.
7. Continue processing after an individual operation fails.
8. Print per-profile results and a final summary.
9. Return success only when every requested operation for every selected profile succeeds.

The Bash wrapper will remain intentionally thin: validate its invocation, translate the convenience syntax into the Python CLI command, and return the Python process status. It will not duplicate AWS or 1Password logic.

## Operation semantics

- `password` updates the IAM login password and synchronizes the generated password with the mapped 1Password item.
- `access-key` creates and validates a replacement AWS access key, updates the local credentials file, records refresh metadata in 1Password, and removes the old key using the existing rollback behavior.
- `both` runs password rotation first and access-key refresh second for each profile. If the password step fails, the access-key step for that profile is skipped and the profile is marked failed; later profiles still run.
- `--dry-run` performs no mutations and reports the intended operations.
- Passwords, secret access keys, and other credential material must not be printed.

## Error handling and exit status

The batch continues after profile-level failures so one broken profile does not prevent maintenance of the rest. Failures include missing profile data, AWS or 1Password errors, access-key limits, and operation failures returned by existing managers.

The command exits non-zero when:

- the operation is missing or invalid;
- an exclusion names no configured profile;
- exclusions remove every profile; or
- any requested operation fails.

It exits zero when all selected operations succeed, including a successful dry run.

## Testing and documentation

Add tests covering:

- operation dispatch for `password`, `access-key`, and `both`;
- exclusion filtering and deterministic profile selection;
- unknown and all-excluded profile validation;
- continue-on-error behavior and aggregate success/failure status;
- password-before-access-key ordering for `both`;
- dry-run propagation;
- CLI parsing and exit status.

Validate the wrapper with `bash -n` and document the shortcut and direct CLI forms in the repository usage documentation.

## Scope boundaries

This change does not alter the existing single-profile commands, AWS/1Password integration behavior, credential rotation algorithms, scheduling configuration, or profile storage format. Parallel execution is intentionally out of scope because the operations modify shared credential state and depend on AWS propagation and local file updates.
