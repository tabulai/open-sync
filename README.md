# open-sync

Desktop SSH discovery, connection management, and port forwarding.

## Features

- **Network Discovery** - Find SSH-enabled devices with mDNS plus local SSH port probing
- **SSH Key Management** - Automatic Ed25519 key generation and deployment
- **Connection Management** - Persistent SSH connections with status tracking
- **Port Forwarding** - Tunnel remote ports to localhost
- **Web UI** - Browser-based device dashboard
- **CLI** - Full command-line interface

## Quick Start

```bash
npm install

# CLI
node src/cli/index.js discover          # Find devices on your network
node src/cli/index.js create ssh://<account>@<host>
node src/cli/index.js connect hostname
node src/cli/index.js open hostname 8888
node src/cli/index.js status hostname

# Web UI
node src/web/server.js                   # open the printed localhost URL
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `discover` | Find SSH hosts via mDNS and local SSH port probing |
| `create <ssh-url>` | Register a new device |
| `connect <hostname>` | Open SSH connection |
| `disconnect <hostname>` | Close SSH connection |
| `status <hostname>` | Show connection & tunnel status |
| `open <hostname> <port>` | Forward a remote port |
| `close <hostname> [port]` | Close port forward(s) |
| `delete <hostname>` | Remove device config |
| `list` | Show all devices |
| `pubkey` | Print public SSH key |

## Web API

All CLI functionality is also available via REST API when running the web server:

The web server prints a localhost URL for the browser UI. The UI obtains a per-process API token from the same-origin `/api/session` endpoint, and direct `/api/*` requests must include that token in the `X-Open-Sync-Token` header.

- `GET /api/devices` - List devices
- `GET /api/tools` - List supported local app launch targets
- `GET /api/pubkey` - Return the Open Sync public SSH key
- `GET /api/discover` - Discover hosts
- `POST /api/devices` - Add device
- `POST /api/devices/:hostname/connect` - Connect
- `POST /api/devices/:hostname/disconnect` - Disconnect
- `GET /api/devices/:hostname/status` - Status
- `POST /api/devices/:hostname/tunnels` - Open tunnel
- `POST /api/devices/:hostname/apps/terminal` - Open a terminal SSH session
- `POST /api/devices/:hostname/apps/dashboard` - Open the configured dashboard app
- `DELETE /api/devices/:hostname/tunnels/:port` - Close tunnel
- `DELETE /api/devices/:hostname/tunnels` - Close all tunnels
- `DELETE /api/devices/:hostname` - Delete device

## Configuration

All config is stored in `~/.open-sync/`:
- `open-sync.key` / `open-sync.key.pub` - SSH key pair
- `state.json` - Device state
- `ssh_config` - Generated SSH config (can be included in `~/.ssh/config`)
- `known_hosts` - Pinned SSH host keys used by Open Sync terminal launches

On first contact with an SSH host, Open Sync stops before authentication and shows the host key fingerprint. Verify it on the device, then retry with that fingerprint to pin the host key. The CLI accepts `--host-fingerprint <fingerprint>` on `create` and `connect`.
