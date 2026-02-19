#!/usr/bin/env bash
set -euo pipefail

APP_NAME="fj-go-relay"
APP_USER="fjrelay"
APP_HOME="/opt/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"
ENV_FILE="/etc/${APP_NAME}.env"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
RELAY_BINARY_URL="${RELAY_BINARY_URL:-}"
SOURCE_DIR="${SOURCE_DIR:-}"
CURSOR_LAUNCH_COMMAND="${CURSOR_LAUNCH_COMMAND:-cursor}"
GITHUB_REPO="${GITHUB_REPO:-hooliodevs/fjgo}"
GITHUB_REF="${GITHUB_REF:-main}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
TMP_SRC_DIR="/tmp/fj-go-relay-src"
PAIR_INFO_CMD="/usr/local/bin/fj-go-relay-info"

log() {
  echo "[fj-install] $*"
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
  id -u "${APP_USER}" >/dev/null 2>&1 || useradd --system --home "${APP_HOME}" --create-home --shell /usr/sbin/nologin "${APP_USER}"
  mkdir -p "${APP_HOME}" "${DATA_DIR}" "${DATA_DIR}/workspaces"
  chown -R "${APP_USER}:${APP_USER}" "${APP_HOME}" "${DATA_DIR}"
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
  as_app_user git config --global credential.useHttpPath true
  as_app_user git config --global url."https://github.com/".insteadOf "git@github.com:"
  as_app_user git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"
  as_app_user git config --global advice.detachedHead false || true
  log "Configured GitHub credential helper for ${APP_USER}."
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
  if command -v cursor >/dev/null 2>&1; then
    log "Cursor CLI found: $(cursor --version || true)"
  else
    log "Cursor CLI not detected."
    log "Install Cursor CLI before first session usage and ensure 'cursor' is on PATH for ${APP_USER}."
    log "After install, authenticate with your normal flow on server:"
    log "  cursor login   (or your existing auth command)"
  fi
}

write_env_file() {
  local server_ip
  server_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [[ -z "${server_ip}" ]]; then
    server_ip="127.0.0.1"
  fi

  local pair_code
  pair_code="$(tr -dc 'A-F0-9' </dev/urandom | head -c 6 | sed 's/.../&-/')"

  cat >"${ENV_FILE}" <<EOF
HOST=0.0.0.0
PORT=8787
DATABASE_PATH=${DATA_DIR}/fj_relay.db
WORKSPACES_ROOT=${DATA_DIR}/workspaces
DEFAULT_CURSOR_COMMAND=${CURSOR_LAUNCH_COMMAND}
PAIR_CODE=${pair_code}
PAIR_CODE_TTL_MINUTES=43200
SERVER_URL=http://${server_ip}:8787
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
User=fjrelay
Group=fjrelay
EnvironmentFile=/etc/fj-go-relay.env
WorkingDirectory=/opt/fj-go-relay
ExecStart=/opt/fj-go-relay/fj-go-relay
Restart=always
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${APP_NAME}"
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
  log "----------------------------------------------------------"
}

main() {
  require_root
  install_packages
  prompt_for_github_token
  ensure_user_and_paths
  if ! install_prebuilt_binary; then
    install_go_if_missing
    local source_dir
    source_dir="$(prepare_source "${1:-}")"
    build_binary "${source_dir}"
  fi
  configure_git_auth
  cursor_setup_guide
  write_env_file
  install_service
  install_pair_info_command
  print_pairing_info
}

main "$@"
