#!/usr/bin/env bash
set -euo pipefail

# Portable launcher for Signum; place next to the compiled binary on USB.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SCRIPT_DIR}/signum"

if [[ ! -x "$BIN" ]]; then
  echo "Signum binary not found at $BIN"
  exit 1
fi

export SIGNUM_PORTABLE=1
export SIGNUM_DATA_DIR="${SIGNUM_DATA_DIR:-"${SCRIPT_DIR}/signum-data"}"

exec "$BIN" "$@"
