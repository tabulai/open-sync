#!/bin/bash
set -euo pipefail

APP_NAME="Open Sync"
APP_VERSION=""
MIN_NODE_MAJOR=20
MAX_NODE_MAJOR=25

SOURCE_REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_DASHBOARD_DIR="$(cd "${SOURCE_REPO_DIR}/.." && pwd)/open-dashboard"
DASHBOARD_DIR="${OPEN_DASHBOARD_DIR:-${DEFAULT_DASHBOARD_DIR}}"
DASHBOARD_GIT_URL="${OPEN_DASHBOARD_GIT_URL:-git@github.com-tabulai:tabulai/open-dashboard.git}"
NODE_BIN="${NODE_BIN:-$(command -v node || true)}"
NPM_BIN="${NPM_BIN:-$(command -v npm || true)}"
LOG_DIR="${HOME}/Library/Logs/Open Sync Installer"
LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d-%H%M%S).log"
BUILD_PARENT=""
BUILD_ONLY=0
OPEN_AFTER_INSTALL=1
STAGED_SYNC_DIR=""
STAGED_DASHBOARD_DIR=""

usage() {
  cat <<USAGE
Usage: build-and-install-macos.sh [--build-only] [--no-open]

Builds Open Sync in a temporary workspace so interrupted installs do not
corrupt this checkout's node_modules. By default it installs the unsigned local
developer app into /Applications, falling back to ~/Applications.

Options:
  --build-only   Build and publish unsigned artifacts into ./dist, but do not install.
  --no-open      Install without launching Open Sync afterwards.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-only)
      BUILD_ONLY=1
      ;;
    --no-open)
      OPEN_AFTER_INSTALL=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_FILE}") 2>&1

step() {
  printf '\n==> %s\n' "$*"
}

warn() {
  printf 'Warning: %s\n' "$*" >&2
}

fail() {
  printf '\nError: %s\n' "$*" >&2
  printf 'Log written to: %s\n' "${LOG_FILE}" >&2
  exit 1
}

cleanup() {
  if [[ -n "${BUILD_PARENT}" && "${OPEN_SYNC_KEEP_BUILD_DIR:-0}" != "1" ]]; then
    rm -rf "${BUILD_PARENT}"
  elif [[ -n "${BUILD_PARENT}" ]]; then
    printf 'Keeping build workspace: %s\n' "${BUILD_PARENT}"
  fi
}
trap cleanup EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

node_major() {
  "${NODE_BIN}" -p "Number(process.versions.node.split('.')[0])"
}

preflight() {
  step "Running preflight checks"

  if [[ "$(uname -s)" != "Darwin" ]]; then
    fail "This installer runs on macOS only."
  fi

  if [[ -z "${NODE_BIN}" || -z "${NPM_BIN}" ]]; then
    fail "Node.js and npm are required. Install Node.js, then run this installer again."
  fi

  require_command ditto
  require_command find
  require_command rsync
  require_command xcode-select

  xcode-select -p >/dev/null 2>&1 || fail "Xcode Command Line Tools are required. Run: xcode-select --install"

  if [[ ! -f "${SOURCE_REPO_DIR}/package-lock.json" ]]; then
    fail "Missing package-lock.json in ${SOURCE_REPO_DIR}."
  fi

  if [[ -f "${DASHBOARD_DIR}/package.json" ]]; then
    if [[ ! -f "${DASHBOARD_DIR}/package-lock.json" ]]; then
      fail "Missing package-lock.json in ${DASHBOARD_DIR}."
    fi
  else
    require_command git
    warn "Open Dashboard was not found at ${DASHBOARD_DIR}; it will be cloned from ${DASHBOARD_GIT_URL}."
  fi

  local major
  major="$(node_major)"
  if (( major < MIN_NODE_MAJOR || major > MAX_NODE_MAJOR )); then
    fail "Unsupported Node.js major version ${major}. Use Node ${MIN_NODE_MAJOR}-${MAX_NODE_MAJOR}; Node 22 is recommended."
  fi

  if [[ "${major}" != "22" ]]; then
    warn "Node ${major} is supported, but Node 22 is the pinned/recommended developer runtime."
  fi

  APP_VERSION="$("${NODE_BIN}" -e "const fs = require('fs'); console.log(JSON.parse(fs.readFileSync(process.argv[1], 'utf8')).version)" "${SOURCE_REPO_DIR}/package.json")"

  local available_kb
  available_kb="$(df -Pk "${TMPDIR:-/tmp}" | awk 'NR==2 {print $4}')"
  if [[ -n "${available_kb}" && "${available_kb}" -lt 2097152 ]]; then
    fail "At least 2GB of free space is required in ${TMPDIR:-/tmp}."
  fi

  printf 'Node: %s (%s)\n' "$("${NODE_BIN}" --version)" "${NODE_BIN}"
  printf 'npm: %s (%s)\n' "$("${NPM_BIN}" --version)" "${NPM_BIN}"
  printf 'Open Sync source: %s\n' "${SOURCE_REPO_DIR}"
  if [[ -f "${DASHBOARD_DIR}/package.json" ]]; then
    printf 'Open Dashboard source: %s\n' "${DASHBOARD_DIR}"
  else
    printf 'Open Dashboard source: %s\n' "${DASHBOARD_GIT_URL}"
  fi
}

choose_install_path() {
  local requested_path="${OPEN_SYNC_APP_PATH:-}"

  if [[ -n "${requested_path}" ]]; then
    printf '%s\n' "${requested_path}"
    return
  fi

  if [[ -w "/Applications" ]]; then
    printf '/Applications/%s.app\n' "${APP_NAME}"
    return
  fi

  mkdir -p "${HOME}/Applications"
  printf '%s/Applications/%s.app\n' "${HOME}" "${APP_NAME}"
}

copy_project() {
  local source_dir="$1"
  local target_dir="$2"

  mkdir -p "${target_dir}"
  rsync -a --delete \
    --exclude '.git/' \
    --exclude '.DS_Store' \
    --exclude 'dist/' \
    --exclude 'node_modules/' \
    --exclude 'tmp/' \
    --exclude 'output/' \
    --exclude 'coverage/' \
    "${source_dir}/" "${target_dir}/"
}

prepare_workspace() {
  step "Preparing temporary build workspace"

  BUILD_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/open-sync-build.XXXXXX")"
  mkdir -p "${BUILD_PARENT}/workspace"

  STAGED_SYNC_DIR="${BUILD_PARENT}/workspace/open-sync"
  STAGED_DASHBOARD_DIR="${BUILD_PARENT}/workspace/open-dashboard"

  copy_project "${SOURCE_REPO_DIR}" "${STAGED_SYNC_DIR}"
  if [[ -f "${DASHBOARD_DIR}/package.json" ]]; then
    copy_project "${DASHBOARD_DIR}" "${STAGED_DASHBOARD_DIR}"
  else
    git clone --depth 1 "${DASHBOARD_GIT_URL}" "${STAGED_DASHBOARD_DIR}"
  fi

  if [[ ! -f "${STAGED_DASHBOARD_DIR}/package-lock.json" ]]; then
    fail "Missing package-lock.json in staged Open Dashboard source."
  fi

  printf 'Build workspace: %s\n' "${BUILD_PARENT}"
}

build_dashboard() {
  step "Building bundled Open Dashboard"
  (
    cd "${STAGED_DASHBOARD_DIR}"
    "${NPM_BIN}" ci --foreground-scripts --prefer-offline
    "${NPM_BIN}" run build
  )
}

build_open_sync() {
  step "Building ${APP_NAME}.app"
  (
    cd "${STAGED_SYNC_DIR}"
    "${NPM_BIN}" ci --foreground-scripts --prefer-offline
    "${NPM_BIN}" run dist:dir
  )
}

find_built_app() {
  find "${STAGED_SYNC_DIR}/dist" -maxdepth 3 -type d -name "${APP_NAME}.app" -print -quit
}

publish_artifacts() {
  local built_app="$1"
  local local_app_dir="${SOURCE_REPO_DIR}/dist/mac-arm64"
  local local_app="${local_app_dir}/${APP_NAME}.app"
  local zip_path="${SOURCE_REPO_DIR}/dist/${APP_NAME// /-}-${APP_VERSION}-mac-arm64-unsigned.zip"

  step "Publishing unsigned local artifacts"
  rm -rf "${local_app}"
  mkdir -p "${local_app_dir}"
  ditto "${built_app}" "${local_app}"

  rm -f "${zip_path}"
  (
    cd "${local_app_dir}"
    ditto -c -k --keepParent "${APP_NAME}.app" "${zip_path}"
  )

  printf 'App artifact: %s\n' "${local_app}"
  printf 'Zip artifact: %s\n' "${zip_path}"
}

install_app() {
  local app_path="$1"
  local install_path="$2"
  local app_parent

  if [[ "${install_path}" != *.app ]]; then
    fail "Install path must end in .app: ${install_path}"
  fi

  app_parent="$(dirname "${install_path}")"
  mkdir -p "${app_parent}"

  step "Installing ${APP_NAME} to ${install_path}"
  if [[ -d "${install_path}" ]]; then
    rm -rf "${install_path}"
  fi

  ditto "${app_path}" "${install_path}"
  find "${install_path}" -exec xattr -d com.apple.quarantine {} + 2>/dev/null || true
}

preflight
prepare_workspace
build_dashboard
build_open_sync

BUILT_APP="$(find_built_app)"
if [[ -z "${BUILT_APP}" ]]; then
  fail "Build completed, but ${APP_NAME}.app was not found under ${STAGED_SYNC_DIR}/dist."
fi

publish_artifacts "${BUILT_APP}"
LOCAL_APP="${SOURCE_REPO_DIR}/dist/mac-arm64/${APP_NAME}.app"

if [[ "${BUILD_ONLY}" == "1" ]]; then
  printf '\nBuilt %s successfully.\n' "${APP_NAME}"
  printf 'Log written to: %s\n' "${LOG_FILE}"
  exit 0
fi

APP_PATH="$(choose_install_path)"
install_app "${LOCAL_APP}" "${APP_PATH}"

if [[ "${OPEN_AFTER_INSTALL}" == "1" ]]; then
  step "Opening ${APP_NAME}"
  open "${APP_PATH}" || true
fi

printf '\nInstalled %s successfully.\n' "${APP_NAME}"
printf 'App path: %s\n' "${APP_PATH}"
printf 'Log written to: %s\n' "${LOG_FILE}"
