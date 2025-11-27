#!/usr/bin/env bash
set -euo pipefail

# Portable launcher for Signum; place next to the compiled binary on USB.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
BIN="${SCRIPT_DIR}/signum"

if [[ ! -x "$BIN" ]]; then
  echo "Signum binary not found at $BIN"
  exit 1
fi

export SIGNUM_PORTABLE=1
export SIGNUM_SHARED_DIR="${SIGNUM_SHARED_DIR:-"${ROOT_DIR}/signum-data"}"
export SIGNUM_CONFIG_PATH="${SIGNUM_CONFIG_PATH:-"${ROOT_DIR}/signum.conf"}"

exec "$BIN" "$@"
