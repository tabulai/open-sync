#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

finish() {
  local status=$?
  printf '\n'

  if [[ ${status} -eq 0 ]]; then
    printf 'Open Sync install finished successfully.\n'
  else
    printf 'Open Sync install failed with exit code %s.\n' "${status}"
  fi

  printf 'Press Return to close this window.'
  read -r _ || true
  exit "${status}"
}

trap finish EXIT

"${REPO_DIR}/scripts/build-and-install-macos.sh"
