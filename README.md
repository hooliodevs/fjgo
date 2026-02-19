# FJ Go Relay Server

Go + SQLite relay backend for `FJ Mobile IDE`.

## What it does

- Device pairing via one-time pair code
- Workspace clone management (`git clone`)
- Multi-session Cursor chats with persistent context
- Real-time stream to app over WebSocket
- Message/session persistence in SQLite (WAL mode)

## Install on a server (recommended)

If `hooliodevs/fjgo` is public, this is enough:

```bash
curl -fsSL "https://raw.githubusercontent.com/hooliodevs/fjgo/main/scripts/install.sh?v=$(date +%s)" | sudo bash
```

If you want to provide a GitHub token to the installer:

```bash
read -rsp "GitHub token: " GITHUB_TOKEN; echo
curl -fsSL "https://raw.githubusercontent.com/hooliodevs/fjgo/main/scripts/install.sh?v=$(date +%s)" \
  | sudo GITHUB_TOKEN="$GITHUB_TOKEN" bash
```

After install, show pairing details any time with:

```bash
sudo fj-go-relay-pairing-info
```

Run full post-install diagnostics:

```bash
sudo fj-go-relay-self-check
```

## Restart / status / logs

```bash
sudo systemctl restart fj-go-relay
sudo systemctl status fj-go-relay --no-pager
sudo journalctl -u fj-go-relay -f
```

## Health and networking checks

Local health check:

```bash
curl -s http://127.0.0.1:8787/v1/health
```

Check listener:

```bash
sudo ss -ltnp | rg 8787
```

If using UFW:

```bash
sudo ufw allow 8787/tcp
sudo ufw reload
sudo ufw status
```

## Update to latest server version

Re-run installer:

```bash
curl -fsSL "https://raw.githubusercontent.com/hooliodevs/fjgo/main/scripts/install.sh?v=$(date +%s)" | sudo bash
sudo systemctl restart fj-go-relay
```

## Local development run

```bash
cp .env.example .env
go mod tidy
go run ./cmd/server
```

## API (v1)

- `GET /v1/health`
- `GET /v1/server/info`
- `POST /v1/pair`
- `GET /v1/workspaces`
- `POST /v1/workspaces/clone`
- `GET /v1/sessions`
- `POST /v1/sessions`
- `POST /v1/sessions/:id/model`
- `GET /v1/sessions/:id/messages`
- `POST /v1/sessions/:id/input`
- `POST /v1/sessions/:id/interrupt`
- `GET /v1/sessions/:id/stream` (WebSocket)
