# FJ Go Relay Server

Go + SQLite relay backend for `FJ Mobile IDE`.

## What it does

- Device pairing via one-time pair code
- Workspace clone management (`git clone`)
- Multi-session chat runtimes (one process per session)
- Real-time stream to app over WebSocket
- Message/session persistence in SQLite (WAL mode)

## Local run

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
- `GET /v1/sessions/:id/messages`
- `POST /v1/sessions/:id/input`
- `POST /v1/sessions/:id/interrupt`
- `GET /v1/sessions/:id/stream` (WebSocket)

## One-line server install concept

```bash
curl -fsSL https://YOUR_DOMAIN/install.sh | sudo bash
```

Use `scripts/install.sh` as the installer payload for your hosted link.
