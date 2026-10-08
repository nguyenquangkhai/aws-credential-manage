# Batch Credential Maintenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Add a tested batch operation for rotating passwords and/or refreshing access keys across all configured AWS profiles, with repeatable exclusions, dry-run support, aggregate exit status, and a Bash shortcut.

**Architecture:** Keep AWS and 1Password behavior in the existing PasswordManager and AccessKeyManager. Add CredentialManager.batch_update() as the orchestration boundary, expose it through a batch-update argparse subcommand, and make batch_credentials.sh a thin wrapper.

**Tech Stack:** Python 3.11+, argparse, pytest, Bash, existing AWS CLI and 1Password CLI integrations.

---

## File map

- Create: tests/test_batch_update.py — orchestration, filtering, dispatch, ordering, continuation, dry-run, and CLI tests.
- Modify: aws_credential_manager/core/credential_manager.py — batch profile filtering and operation orchestration.
- Modify: aws_credential_manager/cli/main.py — batch-update, optional argv for tests, and batch status.
- Create: batch_credentials.sh — password, access-key, and both shortcut.
- Modify: README.md and CLAUDE.md — shortcut and direct CLI documentation.

## Task 1: Define failing batch and CLI tests

**Files:**
- Create: tests/test_batch_update.py

- [ ] Step 1: Add fake collaborators and orchestration tests

Use a fake config and fake operation managers so tests never call AWS or 1Password:

~~~python
from types import SimpleNamespace

from aws_credential_manager.core.credential_manager import CredentialManager


class FakeConfig:
    def __init__(self, names):
        self._profiles = [{"name": name} for name in names]

    def get_aws_profiles(self):
        return self._profiles


class FakeOperationManager:
    def __init__(self, result=True):
        self.result = result
        self.calls = []

    def update_profile(self, profile_name, dry_run=False):
        self.calls.append((profile_name, dry_run))
        return self.result

    def refresh_key(self, profile_name, dry_run=False):
        self.calls.append((profile_name, dry_run))
        return self.result


def make_manager(names=("profile-one", "profile-two")):
    manager = CredentialManager.__new__(CredentialManager)
    manager.config = FakeConfig(names)
    manager.passwords = SimpleNamespace()
    manager.access_keys = SimpleNamespace()
    return manager
~~~

Add tests for password exclusion order, access-key dry-run forwarding, both-operation ordering, skipping access-key after a password failure while continuing later profiles, unknown exclusions, all-excluded profiles, and aggregate failure status:

~~~python
def test_password_filters_exclusions_in_config_order(capsys):
    manager = make_manager(("profile-one", "profile-two", "profile-three"))
    password = FakeOperationManager()
    manager.passwords.update_profile = password.update_profile

    assert manager.batch_update("password", ["profile-two"]) is True
    assert password.calls == [
        ("profile-one", False),
        ("profile-three", False),
    ]
    assert "2/2" in capsys.readouterr().out


def test_access_key_forwards_dry_run():
    manager = make_manager()
    access_keys = FakeOperationManager()
    manager.access_keys.refresh_key = access_keys.refresh_key

    assert manager.batch_update("access-key", [], dry_run=True) is True
    assert access_keys.calls == [
        ("profile-one", True),
        ("profile-two", True),
    ]


def test_both_runs_password_before_access_key_per_profile():
    manager = make_manager()
    events = []
    manager.passwords.update_profile = lambda name, dry_run=False: (
        events.append(("password", name)) or True
    )
    manager.access_keys.refresh_key = lambda name, dry_run=False: (
        events.append(("access-key", name)) or True
    )

    assert manager.batch_update("both") is True
    assert events == [
        ("password", "profile-one"),
        ("access-key", "profile-one"),
        ("password", "profile-two"),
        ("access-key", "profile-two"),
    ]


def test_both_skips_access_key_after_password_failure_and_continues():
    manager = make_manager()
    password_calls = []
    access_key_calls = []
    manager.passwords.update_profile = lambda name, dry_run=False: (
        password_calls.append(name) or name == "profile-two"
    )
    manager.access_keys.refresh_key = lambda name, dry_run=False: (
        access_key_calls.append(name) or True
    )

    assert manager.batch_update("both") is False
    assert password_calls == ["profile-one", "profile-two"]
    assert access_key_calls == ["profile-two"]


def test_rejects_unknown_exclusion():
    assert make_manager().batch_update("password", ["missing-profile"]) is False


def test_rejects_excluding_every_profile():
    manager = make_manager()
    assert manager.batch_update("password", ["profile-one", "profile-two"]) is False


def test_continues_after_failure_and_returns_false():
    manager = make_manager()
    calls = []
    manager.passwords.update_profile = lambda name, dry_run=False: (
        calls.append(name) or name == "profile-two"
    )

    assert manager.batch_update("password") is False
    assert calls == ["profile-one", "profile-two"]
~~~

- [ ] Step 2: Add CLI dispatch tests

Refactor main() to accept argv: list[str] | None = None. Replace CredentialManager with a fake and assert parsing, repeated exclusions, dry-run forwarding, and non-zero failure status:

~~~python
def test_cli_batch_update_dispatches_operation(monkeypatch):
    calls = []

    class FakeManager:
        def __init__(self, credentials_path, vault):
            pass

        def check_op_session(self):
            return True

        def batch_update(self, operation, excluded_profiles, dry_run):
            calls.append((operation, excluded_profiles, dry_run))
            return True

    monkeypatch.setattr(
        "aws_credential_manager.cli.main.CredentialManager",
        FakeManager,
    )
    from aws_credential_manager.cli.main import main

    assert main([
        "--dry-run", "batch-update", "access-key",
        "--exclude", "profile-one",
        "--exclude", "profile-two",
    ]) == 0
    assert calls == [
        ("access-key", ["profile-one", "profile-two"], True),
    ]


def test_cli_batch_update_returns_nonzero_when_batch_fails(monkeypatch):
    class FakeManager:
        def __init__(self, credentials_path, vault):
            pass

        def check_op_session(self):
            return True

        def batch_update(self, operation, excluded_profiles, dry_run):
            return False

    monkeypatch.setattr(
        "aws_credential_manager.cli.main.CredentialManager",
        FakeManager,
    )
    from aws_credential_manager.cli.main import main

    assert main(["batch-update", "password"]) == 1
~~~

- [ ] Step 3: Run the focused tests and verify they fail

Run:

~~~bash
python3 -m pytest tests/test_batch_update.py -q -p no:cov
~~~

Expected: FAIL because batch_update() and the batch-update parser do not yet exist.

- [ ] Step 4: Commit the failing tests

~~~bash
git add tests/test_batch_update.py
git commit -m "test: define batch credential orchestration behavior"
~~~

## Task 2: Implement batch orchestration

**Files:**
- Modify: aws_credential_manager/core/credential_manager.py
- Test: tests/test_batch_update.py

- [ ] Step 1: Add CredentialManager.batch_update()

Implement this signature:

~~~python
def batch_update(
    self,
    operation: str,
    excluded_profiles: list[str] | None = None,
    dry_run: bool = False,
) -> bool:
    """Run password and/or access-key maintenance for selected profiles."""
~~~

The method must validate operation as password, access-key, or both; load profile names from config in credentials-file order; deduplicate exclusions; reject unknown exclusions and an empty selection; call PasswordManager.update_profile() or AccessKeyManager.refresh_key(); continue after failures; skip access-key refresh after a password failure in both mode; print per-profile and aggregate results; and return true only if every requested operation succeeds. It must pass dry_run through unchanged and never print secrets.

Use operations = [operation] except in both mode, where operations = ["password", "access-key"]. Track successful operation count and failed profile names. Break the inner operation loop after a password failure in both mode, but continue the outer profile loop.

- [ ] Step 2: Run focused orchestration tests

~~~bash
python3 -m pytest tests/test_batch_update.py -q -p no:cov
~~~

Expected: all orchestration tests pass.

- [ ] Step 3: Commit the orchestration

~~~bash
git add aws_credential_manager/core/credential_manager.py tests/test_batch_update.py
git commit -m "feat: add batch credential orchestration"
~~~

## Task 3: Expose the Python CLI command

**Files:**
- Modify: aws_credential_manager/cli/main.py
- Test: tests/test_batch_update.py

- [ ] Step 1: Add parser support

Change main to accept an optional argv and call parser.parse_args(argv):

~~~python
def main(argv: list[str] | None = None) -> int:
    args = parser.parse_args(argv)
~~~

Add this subparser:

~~~python
batch_parser = subparsers.add_parser(
    "batch-update",
    help="Update passwords and/or refresh access keys for selected profiles",
)
batch_parser.add_argument(
    "operation",
    choices=("password", "access-key", "both"),
    help="Credential operation to run",
)
batch_parser.add_argument(
    "--exclude",
    dest="excluded_profiles",
    action="append",
    default=[],
    metavar="PROFILE",
    help="Profile to skip; may be repeated",
)
~~~

Keep the existing global --dry-run before the command. The direct dry-run form is:

~~~bash
python3 aws_credential_updater.py --dry-run batch-update password
~~~

- [ ] Step 2: Add dispatch and exit status propagation

Add:

~~~python
elif args.command == "batch-update":
    if not mgr.check_op_session():
        return 1
    return 0 if mgr.batch_update(
        args.operation,
        args.excluded_profiles,
        args.dry_run,
    ) else 1
~~~

- [ ] Step 3: Run CLI tests and help

~~~bash
python3 -m pytest tests/test_batch_update.py -q -p no:cov
python3 aws_credential_updater.py batch-update --help
~~~

Expected: focused tests pass and help lists all operations and repeatable --exclude.

- [ ] Step 4: Commit the CLI

~~~bash
git add aws_credential_manager/cli/main.py tests/test_batch_update.py
git commit -m "feat: expose batch credential update command"
~~~

## Task 4: Add the Bash shortcut

**Files:**
- Create: batch_credentials.sh

- [ ] Step 1: Create the executable wrapper

The script must use Bash strict mode, resolve aws_credential_updater.py relative to its own directory, accept exactly one operation, support repeatable --exclude PROFILE, support --dry-run and help, reject missing values and unknown options with status 2, and use exec so Python's status is preserved.

Use this implementation shape:

~~~bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/aws_credential_updater.py"

usage() {
    cat <<'EOF'
Usage: ./batch_credentials.sh OPERATION [options]

Options:
  --exclude PROFILE  Skip a configured profile; may be repeated
  --dry-run          Show planned operations without changing credentials
  -h, --help         Show this help
EOF
}

operation=""
if (($#)); then
    operation="$1"
    shift
fi

case "$operation" in
    password|access-key|both) ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

dry_run=false
python_args=("batch-update" "$operation")
while (($#)); do
    case "$1" in
        --exclude)
            if (($# < 2)) || [[ -z "$2" ]]; then
                echo "error: --exclude requires a profile name" >&2
                exit 2
            fi
            python_args+=("--exclude" "$2")
            shift 2
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$dry_run" == true ]]; then
    python_args=("--dry-run" "${python_args[@]}")
fi

exec python3 "$PYTHON_SCRIPT" "${python_args[@]}"
~~~

- [ ] Step 2: Validate syntax and local argument handling

~~~bash
bash -n batch_credentials.sh
./batch_credentials.sh --help
./batch_credentials.sh invalid >/tmp/batch-credentials-invalid.out 2>&1; test "$?" -eq 2
~~~

Expected: syntax and help succeed; invalid operation exits 2.

- [ ] Step 3: Set executable mode and commit

~~~bash
chmod +x batch_credentials.sh
git add batch_credentials.sh
git commit -m "feat: add batch credential shortcut script"
~~~

## Task 5: Update documentation

**Files:**
- Modify: README.md
- Modify: CLAUDE.md

- [ ] Step 1: Add shortcut examples to README.md

Add:

~~~bash
./batch_credentials.sh password
./batch_credentials.sh access-key --exclude profile-a --exclude profile-b
./batch_credentials.sh both --dry-run
~~~

Explain that all configured profiles are selected by default, exclusions are repeatable, processing continues after failures, and any failed operation returns non-zero.

- [ ] Step 2: Add direct CLI documentation to CLAUDE.md

Add:

~~~bash
python3 aws_credential_updater.py batch-update both
python3 aws_credential_updater.py --dry-run batch-update password --exclude profile-a
~~~

State that both runs password rotation before access-key refresh for each profile and no secrets are printed.

- [ ] Step 3: Commit documentation

~~~bash
git add README.md CLAUDE.md
git commit -m "docs: document batch credential maintenance"
~~~

## Task 6: Verify the complete change

- [ ] Step 1: Run focused tests and shell validation

~~~bash
python3 -m pytest tests/test_batch_update.py -q -p no:cov
bash -n batch_credentials.sh
~~~

- [ ] Step 2: Run full quality checks

~~~bash
python3 -m pytest
ruff check aws_credential_manager tests
mypy aws_credential_manager
git diff --check
~~~

Expected: tests, Ruff, mypy, and whitespace checks pass. Record unrelated pre-existing failures instead of weakening tests or bypassing hooks.

- [ ] Step 3: Exercise non-mutating help paths

~~~bash
python3 aws_credential_updater.py batch-update --help
./batch_credentials.sh --help
~~~

- [ ] Step 4: Review scope

~~~bash
git status --short
git diff HEAD~5 --stat
git diff HEAD~5 --check
~~~

Confirm only intended implementation, tests, shortcut, and documentation changed. Do not stage the pre-existing profile_mapping.json modification or untracked uv.lock.
