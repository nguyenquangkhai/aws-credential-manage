#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/aws_credential_updater.py"

usage() {
    cat <<'EOF'
Usage: ./batch_credentials.sh OPERATION [options]

Operations:
  password           Rotate IAM console passwords
  access-key         Refresh AWS access keys
  both               Run both operations

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
