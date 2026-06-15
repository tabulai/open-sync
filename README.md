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

Install this repo before running the CLI, web UI, tests, or app build:

```bash
nvm use
npm ci
npm test
```

Use the CLI directly during development:

```bash
node src/cli/index.js discover          # Find devices on your network
node src/cli/index.js create ssh://<account>@<host>
node src/cli/index.js connect hostname
node src/cli/index.js open hostname 8888
node src/cli/index.js status hostname
```

Run the web UI or Electron shell locally:

```bash
npm run web                             # open the printed localhost URL
npm start                               # launch the Electron app in development
```

## Build the macOS App

The packaged Electron app bundles `open-dashboard`. The build scripts use `../open-dashboard` when it exists; otherwise they clone `open-dashboard` into a temporary build workspace.

```bash
git clone git@github.com-tabulai:tabulai/open-dashboard.git ../open-dashboard
```

Then build Open Sync in a temporary workspace:

```bash
nvm use
npm run mac:build
open "dist/mac-arm64/Open Sync.app"
```

The local unsigned `.app` bundle is written to `dist/mac-arm64/Open Sync.app`, and an unsigned zip artifact is written to `dist/Open-Sync-0.1.0-mac-arm64-unsigned.zip`.

### Clickable macOS Installer

For a one-click local build and install, double-click:

```text
installers/Open Sync Installer.command
```

The installer builds in a temporary workspace, so failed or interrupted runs do not corrupt this checkout's `node_modules`. It builds `../open-dashboard`, builds the Open Sync Electron app, publishes unsigned local artifacts into `dist/`, installs `Open Sync.app` into `/Applications` when possible, and opens it. If `/Applications` is not writable, it installs to `~/Applications/Open Sync.app`.

You can run the same flow from Terminal with:

```bash
npm run mac:install
```

Useful installer options and environment variables:

```bash
npm run mac:build                         # build unsigned artifacts only
bash scripts/build-and-install-macos.sh --no-open
OPEN_DASHBOARD_DIR=/path/to/open-dashboard npm run mac:install
OPEN_DASHBOARD_GIT_URL=git@github.com-tabulai:tabulai/open-dashboard.git npm run mac:install
OPEN_SYNC_APP_PATH="$HOME/Applications/Open Sync.app" npm run mac:install
OPEN_SYNC_KEEP_BUILD_DIR=1 npm run mac:install
```

### Unsigned CI Builds

The `.github/workflows/macos-unsigned-build.yml` workflow checks out `open-sync` and `open-dashboard` side by side, uses the Node version pinned in `.nvmrc`, runs `npm run mac:build`, and uploads the unsigned zip artifact. This is for internal developer validation only; it is not a public macOS distribution build.

### Packaging Notes

- The local build scripts intentionally skip signing by setting Electron Builder's macOS identity to `null`. The resulting app can be useful for development, but it is not signed, notarized, or distribution-ready.
- The build scripts install dependencies inside a temporary workspace. You do not need to run `npm ci` in the live checkout before running `npm run mac:build` or `npm run mac:install`.
- Native dependencies used by `ssh2` and `cpu-features` are rebuilt during packaging. Long quiet periods in this phase usually mean Electron Rebuild is compiling native code.
- The custom app icon is generated from `build/icon.svg` with `npm run mac:icon`, which writes `build/icon.icns` for Electron Builder.

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
