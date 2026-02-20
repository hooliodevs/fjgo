#!/usr/bin/env bash
set -euo pipefail

APP_NAME="fj-go-relay"
APP_USER="cursor"
APP_HOME="/opt/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"
ENV_FILE="/etc/${APP_NAME}.env"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
SUDOERS_FILE="/etc/sudoers.d/${APP_USER}"
RELAY_BINARY_URL="${RELAY_BINARY_URL:-}"
SOURCE_DIR="${SOURCE_DIR:-}"
CURSOR_LAUNCH_COMMAND="${CURSOR_LAUNCH_COMMAND:-cursor}"
EFFECTIVE_CURSOR_COMMAND="${CURSOR_LAUNCH_COMMAND}"
GITHUB_REPO="${GITHUB_REPO:-hooliodevs/fjgo}"
GITHUB_REF="${GITHUB_REF:-main}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
TMP_SRC_DIR="/tmp/fj-go-relay-src"
PAIR_INFO_CMD="/usr/local/bin/fj-go-relay-info"
SELF_CHECK_CMD="/usr/local/bin/fj-go-relay-self-check"

log() {
  echo "[fj-install] $*" >&2
}

as_app_user() {
  sudo -u "${APP_USER}" -H "$@"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root (sudo)." >&2
    exit 1
  fi
}

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    log "Installing dependencies via apt-get..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      ca-certificates curl git sqlite3 jq build-essential
  elif command -v dnf >/dev/null 2>&1; then
    log "Installing dependencies via dnf..."
    dnf install -y ca-certificates curl git sqlite sqlite jq gcc
  else
    log "Unsupported package manager. Install curl/git/sqlite3/build tools manually."
    exit 1
  fi
}

prompt_for_github_token() {
  if [[ -n "${GITHUB_TOKEN}" ]]; then
    log "GitHub token provided via environment."
    return
  fi

  if [[ ! -r /dev/tty ]]; then
    log "No interactive TTY available. Skipping token prompt."
    log "For private repo cloning support, rerun with GITHUB_TOKEN=..."
    return
  fi

  log "Optional: configure GitHub token for private repository cloning."
  log "Create a fine-grained token here:"
  log "https://github.com/settings/personal-access-tokens/new"
  log "Minimum permission: Repository contents: Read-only (for needed repos)."
  printf "Enter GitHub token (leave empty to skip): " > /dev/tty
  IFS= read -r GITHUB_TOKEN < /dev/tty || true
}

load_existing_github_token() {
  if [[ -n "${GITHUB_TOKEN}" ]]; then
    return
  fi

  local creds_file="${APP_HOME}/.git-credentials"
  if [[ ! -f "${creds_file}" ]]; then
    return
  fi

  local creds_line
  creds_line="$(sed -n '1p' "${creds_file}")"
  if [[ "${creds_line}" =~ ^https://x-access-token:([^@]+)@github\.com/?$ ]]; then
    GITHUB_TOKEN="${BASH_REMATCH[1]}"
    log "Reusing existing GitHub token from ${creds_file}."
  fi
}

install_go_if_missing() {
  if command -v go >/dev/null 2>&1; then
    log "Go already installed: $(go version)"
    return
  fi

  local arch
  arch="$(uname -m)"
  local go_arch="amd64"
  if [[ "${arch}" == "aarch64" || "${arch}" == "arm64" ]]; then
    go_arch="arm64"
  fi

  local version="1.22.12"
  local tarball="go${version}.linux-${go_arch}.tar.gz"
  local tmp="/tmp/${tarball}"
  log "Installing Go ${version} (${go_arch})..."
  curl -fsSL "https://go.dev/dl/${tarball}" -o "${tmp}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "${tmp}"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  log "Installed: $(go version)"
}

ensure_user_and_paths() {
  if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    useradd --home-dir "${APP_HOME}" --create-home --shell /bin/bash "${APP_USER}"
  else
    usermod --shell /bin/bash "${APP_USER}" || true
    usermod --home "${APP_HOME}" "${APP_USER}" || true
  fi
  mkdir -p "${APP_HOME}" "${DATA_DIR}" "${DATA_DIR}/workspaces"
  chown -R "${APP_USER}:${APP_USER}" "${APP_HOME}" "${DATA_DIR}"
}

install_full_sudo_access() {
  cat >"${SUDOERS_FILE}" <<EOF
${APP_USER} ALL=(ALL) NOPASSWD:ALL
EOF
  chmod 440 "${SUDOERS_FILE}"
  visudo -cf "${SUDOERS_FILE}" >/dev/null
}

prepare_source() {
  local src="${1:-}"
  if [[ -z "${src}" && -n "${SOURCE_DIR}" ]]; then
    src="${SOURCE_DIR}"
  fi
  if [[ -z "${src}" ]]; then
    src="$(download_repo_source)"
  fi

  if [[ -z "${src}" ]]; then
    echo "Source not found. Pass SOURCE_DIR=/path/to/repo or configure GITHUB_REPO/GITHUB_REF." >&2
    exit 1
  fi

  if [[ -f "${src}/go.mod" ]]; then
    echo "${src}"
    return
  fi

  if [[ -f "${src}/fj_go_server/go.mod" ]]; then
    echo "${src}/fj_go_server"
    return
  fi

  echo "Source not found. Expected go.mod at source root or source/fj_go_server." >&2
  exit 1
}

download_repo_source() {
  rm -rf "${TMP_SRC_DIR}"
  mkdir -p "${TMP_SRC_DIR}"

  local archive_path="${TMP_SRC_DIR}/repo.tar.gz"
  local github_url
  github_url="https://api.github.com/repos/${GITHUB_REPO}/tarball/${GITHUB_REF}"

  log "Downloading source archive from ${GITHUB_REPO}@${GITHUB_REF}..."
  if [[ -n "${GITHUB_TOKEN}" ]]; then
    curl -fsSL \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      "${github_url}" -o "${archive_path}"
  else
    curl -fsSL "${github_url}" -o "${archive_path}"
  fi

  mkdir -p "${TMP_SRC_DIR}/src"
  tar -xzf "${archive_path}" -C "${TMP_SRC_DIR}/src" --strip-components=1
  echo "${TMP_SRC_DIR}/src"
}

install_prebuilt_binary() {
  if [[ -z "${RELAY_BINARY_URL}" ]]; then
    return 1
  fi
  log "Downloading relay binary..."
  if [[ -n "${GITHUB_TOKEN}" ]]; then
    curl -fsSL \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      "${RELAY_BINARY_URL}" -o "${APP_HOME}/fj-go-relay"
  else
    curl -fsSL "${RELAY_BINARY_URL}" -o "${APP_HOME}/fj-go-relay"
  fi
  chmod +x "${APP_HOME}/fj-go-relay"
  chown "${APP_USER}:${APP_USER}" "${APP_HOME}/fj-go-relay"
  return 0
}

configure_git_auth() {
  if [[ -z "${GITHUB_TOKEN}" ]]; then
    log "GitHub token not set. Private HTTPS repo clones may fail."
    return
  fi

  local creds_file="${APP_HOME}/.git-credentials"
  printf "https://x-access-token:%s@github.com\n" "${GITHUB_TOKEN}" > "${creds_file}"
  chown "${APP_USER}:${APP_USER}" "${creds_file}"
  chmod 600 "${creds_file}"

  as_app_user git config --global credential.helper "store --file ${creds_file}"
  as_app_user git config --global credential.useHttpPath false
  as_app_user git config --global url."https://github.com/".insteadOf "git@github.com:"
  as_app_user git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"
  as_app_user git config --global advice.detachedHead false || true
  log "Configured GitHub credential helper for ${APP_USER}."
}

configure_git_identity() {
  local existing_name
  existing_name="$(as_app_user git config --global user.name 2>/dev/null || true)"
  local existing_email
  existing_email="$(as_app_user git config --global user.email 2>/dev/null || true)"
  if [[ -z "${existing_name}" ]]; then
    as_app_user git config --global user.name "FJ Mobile IDE"
    log "Set git user.name to 'FJ Mobile IDE' for ${APP_USER}."
  fi
  if [[ -z "${existing_email}" ]]; then
    as_app_user git config --global user.email "cursor@$(hostname -f 2>/dev/null || echo localhost)"
    log "Set git user.email for ${APP_USER}."
  fi
}

build_binary() {
  local src="${1}"
  log "Building relay binary..."
  pushd "${src}" >/dev/null
  go mod tidy
  CGO_ENABLED=1 go build -o "${APP_HOME}/fj-go-relay" ./cmd/server
  popd >/dev/null
  chown "${APP_USER}:${APP_USER}" "${APP_HOME}/fj-go-relay"
  chmod +x "${APP_HOME}/fj-go-relay"
}

cursor_setup_guide() {
  log "Cursor CLI check..."

  if [[ "${CURSOR_LAUNCH_COMMAND}" != "cursor" ]]; then
    EFFECTIVE_CURSOR_COMMAND="${CURSOR_LAUNCH_COMMAND}"
    if as_app_user bash -lc "${EFFECTIVE_CURSOR_COMMAND} --version" >/dev/null 2>&1; then
      log "Using configured cursor launch command: ${EFFECTIVE_CURSOR_COMMAND}"
      return
    fi
    log "Configured CURSOR_LAUNCH_COMMAND is not executable by ${APP_USER}: ${EFFECTIVE_CURSOR_COMMAND}"
    return
  fi

  if ! command -v cursor >/dev/null 2>&1; then
    log "Cursor CLI not detected."
    log "Install Cursor CLI before first session usage and ensure 'cursor' is on PATH for ${APP_USER}."
    log "After install, authenticate with your normal flow on server:"
    log "  cursor login   (or your existing auth command)"
    return
  fi

  local cursor_bin
  cursor_bin="$(command -v cursor)"
  local cursor_real
  cursor_real="$(readlink -f "${cursor_bin}" 2>/dev/null || true)"
  if [[ -z "${cursor_real}" ]]; then
    cursor_real="${cursor_bin}"
  fi

  if as_app_user bash -lc "${cursor_real} --version" >/dev/null 2>&1; then
    EFFECTIVE_CURSOR_COMMAND="${cursor_real}"
    log "Cursor CLI available for ${APP_USER}: ${EFFECTIVE_CURSOR_COMMAND}"
  else
    log "Cursor binary is not executable by ${APP_USER}; installing shared runtime bundle..."
    local runtime_src
    runtime_src="$(dirname "${cursor_real}")"
    mkdir -p "${APP_HOME}/cursor-runtime" "${APP_HOME}/bin"
    cp -a "${runtime_src}/." "${APP_HOME}/cursor-runtime/"
    ln -sf "${APP_HOME}/cursor-runtime/cursor-agent" "${APP_HOME}/bin/cursor"
    chown -R "${APP_USER}:${APP_USER}" "${APP_HOME}/cursor-runtime" "${APP_HOME}/bin"
    chmod -R a+rX "${APP_HOME}/cursor-runtime"
    chmod 755 "${APP_HOME}/bin/cursor"

    EFFECTIVE_CURSOR_COMMAND="${APP_HOME}/bin/cursor"
    if as_app_user bash -lc "${EFFECTIVE_CURSOR_COMMAND} --version" >/dev/null 2>&1; then
      log "Cursor runtime prepared for ${APP_USER}: ${EFFECTIVE_CURSOR_COMMAND}"
    else
      log "Cursor runtime still unavailable for ${APP_USER}; manual fix required."
      return
    fi
  fi

  if as_app_user bash -lc "${EFFECTIVE_CURSOR_COMMAND} status" 2>/dev/null | grep -qi "Not logged in"; then
    log "Cursor is not logged in for ${APP_USER}. Run:"
    log "  sudo -u ${APP_USER} -H bash -lc '${EFFECTIVE_CURSOR_COMMAND} login'"
  fi
}

write_env_file() {
  local server_ip
  server_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [[ -z "${server_ip}" ]]; then
    server_ip="127.0.0.1"
  fi

  local pair_hex
  pair_hex="$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n' | tr '[:lower:]' '[:upper:]')"
  local pair_code
  pair_code="${pair_hex:0:3}-${pair_hex:3:3}"

  cat >"${ENV_FILE}" <<EOF
HOST=0.0.0.0
PORT=8787
DATABASE_PATH=${DATA_DIR}/fj_relay.db
WORKSPACES_ROOT=${DATA_DIR}/workspaces
DEFAULT_CURSOR_COMMAND=${EFFECTIVE_CURSOR_COMMAND}
PAIR_CODE=${pair_code}
PAIR_CODE_TTL_MINUTES=43200
SERVER_URL=http://${server_ip}:8787
PRIVILEGE_CONFIRMATION_REQUIRED=true
PRIVILEGE_CONFIRMATION_DISABLED=false
EOF
  chmod 600 "${ENV_FILE}"
}

install_service() {
  cat >"${SERVICE_FILE}" <<'EOF'
[Unit]
Description=FJ Mobile IDE Go Relay
After=network.target

[Service]
Type=simple
User=cursor
Group=cursor
EnvironmentFile=/etc/fj-go-relay.env
WorkingDirectory=/opt/fj-go-relay
ExecStart=/opt/fj-go-relay/fj-go-relay
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${APP_NAME}"
  if systemctl is-active --quiet "${APP_NAME}"; then
    log "Service is already running; restarting to apply updates..."
    systemctl restart "${APP_NAME}"
  else
    log "Starting service..."
    systemctl start "${APP_NAME}"
  fi
}

install_pair_info_command() {
  cat >"${PAIR_INFO_CMD}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ENV_FILE="/etc/fj-go-relay.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Pairing env file not found: ${ENV_FILE}" >&2
  exit 1
fi
SERVER_URL="$(awk -F= '/^SERVER_URL=/{print $2}' "${ENV_FILE}")"
PAIR_CODE="$(awk -F= '/^PAIR_CODE=/{print $2}' "${ENV_FILE}")"
LAUNCH_CMD="$(awk -F= '/^DEFAULT_CURSOR_COMMAND=/{print $2}' "${ENV_FILE}")"
echo "Server URL: ${SERVER_URL}"
echo "Pair Code: ${PAIR_CODE}"
echo "Launch Command: ${LAUNCH_CMD}"
echo "Pairing payload:"
printf '{"server_url":"%s","pair_code":"%s"}\n' "${SERVER_URL}" "${PAIR_CODE}"
EOF
  chmod 755 "${PAIR_INFO_CMD}"
}

install_self_check_command() {
  cat >"${SELF_CHECK_CMD}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/fj-go-relay.env"
SERVICE_NAME="fj-go-relay"
APP_USER="cursor"
DEFAULT_REPO_URL="${1:-https://github.com/hooliodevs/fj.git}"

green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red() { printf '\033[31m%s\033[0m\n' "$*"; }

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); green "[PASS] $*"; }
warn() { WARN_COUNT=$((WARN_COUNT + 1)); yellow "[WARN] $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); red "[FAIL] $*"; }

require_root_if_needed() {
  if [[ "${EUID}" -ne 0 ]]; then
    warn "Run as root for full checks. Limited checks will run."
  fi
}

check_service() {
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    pass "systemd service '${SERVICE_NAME}' is active"
  else
    fail "systemd service '${SERVICE_NAME}' is not active"
  fi
}

check_health() {
  if curl -fsS "http://127.0.0.1:8787/v1/health" >/dev/null; then
    pass "local health endpoint responds"
  else
    fail "local health endpoint failed"
  fi
}

check_listener() {
  if ss -ltnp 2>/dev/null | grep -q ":8787"; then
    pass "port 8787 is listening"
  else
    fail "port 8787 is not listening"
  fi
}

check_ufw() {
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw not installed (skipping firewall rule check)"
    return
  fi

  local status
  status="$(ufw status 2>/dev/null || true)"
  if echo "${status}" | grep -q "Status: active"; then
    if echo "${status}" | grep -Eq "8787/tcp\s+ALLOW"; then
      pass "ufw allows 8787/tcp"
    else
      fail "ufw is active but 8787/tcp is not allowed"
    fi
  else
    warn "ufw not active (ensure cloud firewall allows 8787/tcp)"
  fi
}

check_env_and_pair() {
  if [[ ! -f "${ENV_FILE}" ]]; then
    fail "env file missing at ${ENV_FILE}"
    return
  fi
  pass "env file exists (${ENV_FILE})"

  local server_url pair_code launch_cmd
  server_url="$(awk -F= '/^SERVER_URL=/{print $2}' "${ENV_FILE}")"
  pair_code="$(awk -F= '/^PAIR_CODE=/{print $2}' "${ENV_FILE}")"
  launch_cmd="$(awk -F= '/^DEFAULT_CURSOR_COMMAND=/{print $2}' "${ENV_FILE}")"

  if [[ -n "${server_url}" && -n "${pair_code}" && -n "${launch_cmd}" ]]; then
    pass "env has SERVER_URL, PAIR_CODE and DEFAULT_CURSOR_COMMAND"
  else
    fail "env missing required pairing/runtime values"
  fi

  if command -v fj-go-relay-info >/dev/null 2>&1; then
    if fj-go-relay-info >/dev/null 2>&1; then
      pass "fj-go-relay-info command works"
    else
      fail "fj-go-relay-info command failed"
    fi
  else
    fail "fj-go-relay-info command missing"
  fi
}

check_cursor_for_service_user() {
  local launch_cmd
  launch_cmd="$(awk -F= '/^DEFAULT_CURSOR_COMMAND=/{print $2}' "${ENV_FILE}" 2>/dev/null || true)"
  if [[ -z "${launch_cmd}" ]]; then
    fail "DEFAULT_CURSOR_COMMAND not set in env"
    return
  fi

  if sudo -u "${APP_USER}" -H bash -lc "${launch_cmd} --version" >/dev/null 2>&1; then
    pass "cursor command executes as ${APP_USER} (${launch_cmd})"
  else
    fail "cursor command is not executable by ${APP_USER} (${launch_cmd})"
    return
  fi

  local status_output
  status_output="$(sudo -u "${APP_USER}" -H bash -lc "${launch_cmd} status" 2>&1 || true)"
  if echo "${status_output}" | grep -qi "Not logged in"; then
    warn "cursor is not logged in for ${APP_USER} (run: sudo -u ${APP_USER} -H bash -lc '${launch_cmd} login')"
  else
    pass "cursor appears logged in for ${APP_USER}"
  fi
}

check_git_auth() {
  if sudo -u "${APP_USER}" -H bash -lc "GIT_TERMINAL_PROMPT=0 git ls-remote ${DEFAULT_REPO_URL}" >/dev/null 2>&1; then
    pass "git non-interactive access works for ${DEFAULT_REPO_URL}"
  else
    fail "git non-interactive access failed for ${DEFAULT_REPO_URL}"
  fi
}

summary() {
  echo
  echo "------ fj-go-relay self-check summary ------"
  echo "PASS: ${PASS_COUNT}"
  echo "WARN: ${WARN_COUNT}"
  echo "FAIL: ${FAIL_COUNT}"
  echo "--------------------------------------------"
  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
  fi
}

main() {
  require_root_if_needed
  check_service
  check_health
  check_listener
  check_ufw
  check_env_and_pair
  if [[ "${EUID}" -eq 0 ]]; then
    check_cursor_for_service_user
    check_git_auth
  else
    warn "Skipping ${APP_USER} user checks (run as root for full validation)"
  fi
  summary
}

main "$@"
EOF
  chmod 755 "${SELF_CHECK_CMD}"
}

print_pairing_info() {
  log "----------------------------------------------------------"
  log "Install complete."
  log "Service: ${APP_NAME}"
  log "Status: $(systemctl is-active "${APP_NAME}")"
  log ""
  log "Use this in FJ Mobile IDE app onboarding:"
  awk -F= '
    /^SERVER_URL=/ {print "Server URL: " $2}
    /^PAIR_CODE=/ {print "Pair Code: " $2}
    /^DEFAULT_CURSOR_COMMAND=/ {print "Launch Command: " $2}
  ' "${ENV_FILE}"
  echo "Pairing payload JSON:"
  awk -F= '
    /^SERVER_URL=/ {server=$2}
    /^PAIR_CODE=/ {code=$2}
    END {printf("{\"server_url\":\"%s\",\"pair_code\":\"%s\"}\n", server, code)}
  ' "${ENV_FILE}"
  log ""
  log "Cursor authentication guide:"
  log "1) Switch to service user shell: sudo -u ${APP_USER} -H bash"
  log "2) Run Cursor auth command you already use (e.g., cursor login)."
  log "3) Verify CLI command works before starting sessions from mobile app."
  log ""
  log "Reminder command:"
  log "  ${PAIR_INFO_CMD}"
  log "Self-check command:"
  log "  ${SELF_CHECK_CMD}"
  log "----------------------------------------------------------"
}

main() {
  require_root
  install_packages
  prompt_for_github_token
  ensure_user_and_paths
  install_full_sudo_access
  load_existing_github_token
  if ! install_prebuilt_binary; then
    install_go_if_missing
    local source_dir
    source_dir="$(prepare_source "${1:-}")"
    build_binary "${source_dir}"
  fi
  configure_git_auth
  configure_git_identity
  cursor_setup_guide
  write_env_file
  install_service
  install_pair_info_command
  install_self_check_command
  print_pairing_info
}

main "$@"
