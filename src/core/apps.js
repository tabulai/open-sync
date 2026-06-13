import { accessSync, closeSync, constants, existsSync, openSync } from 'fs';
import { spawn } from 'child_process';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import { homedir } from 'os';
import { isIP } from 'net';
import { CONFIG_DIR, SSH_CONFIG_PATH, SSH_KEY_PATH } from './paths.js';
import { resolveTargetHost, validateHostname, validateUsername } from './hosts.js';
import { normalizeRemoteDirectory } from './ssh.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_PANEL_DIR = resolve(__dirname, '..', '..', '..', 'open-dashboard');
const OPEN_DASHBOARD_DIR = resolveOpenDashboardDir();
const OPEN_DASHBOARD_PORT = Number(process.env.OPEN_DASHBOARD_PORT || 5199);
const OPEN_DASHBOARD_URL = normalizeDashboardUrl(process.env.OPEN_DASHBOARD_URL || `http://127.0.0.1:${OPEN_DASHBOARD_PORT}`);
const OPEN_DASHBOARD_LOG_PATH = join(CONFIG_DIR, 'open-dashboard.log');
const DASHBOARD_API_TOKEN_HEADER = 'x-open-dashboard-token';
const DASHBOARD_API_REQUEST_HEADER = 'x-open-dashboard-request';
const DASHBOARD_API_REQUEST_VALUE = '1';

let dashboardApiToken = '';

function shellEscape(value = '') {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function escapeAppleScriptString(value = '') {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"');
}

function getDashboardUrl() {
  return OPEN_DASHBOARD_URL;
}

function normalizeDashboardUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('OPEN_DASHBOARD_URL must be a valid localhost HTTP URL.');
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase();
  const isLoopback = hostname === 'localhost'
    || hostname === '::1'
    || (isIP(hostname) === 4 && hostname.startsWith('127.'));

  if (url.protocol !== 'http:' || url.username || url.password || !isLoopback) {
    throw new Error('OPEN_DASHBOARD_URL must use http://localhost, http://127.0.0.1, or http://[::1].');
  }

  return url.origin;
}

function getDashboardDirCandidates() {
  return [...new Set([
    process.env.OPEN_DASHBOARD_DIR,
    DEFAULT_PANEL_DIR,
    resolve(process.cwd(), '..', 'open-dashboard'),
    resolve(homedir(), 'Programming', 'open-dashboard'),
  ].filter(Boolean))];
}

function isDashboardProjectDir(dir) {
  return Boolean(dir) && existsSync(join(dir, 'server.js'));
}

function hasDashboardRuntimeDependencies(dir) {
  return (
    isDashboardProjectDir(dir) &&
    existsSync(join(dir, 'node_modules', 'express', 'package.json')) &&
    existsSync(join(dir, 'node_modules', 'vite', 'package.json'))
  );
}

function resolveOpenDashboardDir() {
  if (process.env.OPEN_DASHBOARD_DIR) {
    return process.env.OPEN_DASHBOARD_DIR;
  }
  const candidates = getDashboardDirCandidates();
  return candidates.find(hasDashboardRuntimeDependencies) || candidates.find(isDashboardProjectDir) || DEFAULT_PANEL_DIR;
}

function extractDashboardApiToken(html = '') {
  const match = String(html).match(/window\.__OPEN_DASHBOARD__\s*=\s*({[^<]+?})\s*;?\s*<\/script>/);
  if (!match) return '';
  try {
    const config = JSON.parse(match[1]);
    return typeof config.apiToken === 'string' ? config.apiToken : '';
  } catch {
    return '';
  }
}

function buildDashboardApiHeaders(apiToken, { write = false } = {}) {
  const headers = {
    [DASHBOARD_API_TOKEN_HEADER]: apiToken,
  };
  if (write) {
    headers[DASHBOARD_API_REQUEST_HEADER] = DASHBOARD_API_REQUEST_VALUE;
  }
  return headers;
}

async function fetchDashboardApiToken() {
  const response = await fetch(OPEN_DASHBOARD_URL, {
    signal: AbortSignal.timeout(1500),
  });
  if (!response.ok) return '';
  return extractDashboardApiToken(await response.text());
}

async function getDashboardApiToken({ refresh = false } = {}) {
  if (dashboardApiToken && !refresh) {
    return dashboardApiToken;
  }
  dashboardApiToken = await fetchDashboardApiToken();
  return dashboardApiToken;
}

function buildTerminalCommand(device) {
  return `ssh -F ${shellEscape(SSH_CONFIG_PATH)} ${shellEscape(validateHostname(device.hostname))}`;
}

function buildDashboardConnectionConfig(device) {
  const hostname = validateHostname(device.hostname);
  const username = validateUsername(device.username);
  const workingDir = normalizeRemoteDirectory(device.path)
    || normalizeRemoteDirectory(device.homeDirectory)
    || `/home/${username}`;
  return {
    host: resolveTargetHost(hostname),
    username,
    authMethod: 'key',
    sshKeyPath: SSH_KEY_PATH,
    localPort: 8888,
    remotePort: 8888,
    workingDir,
  };
}

function spawnDetached(command, args, options = {}) {
  const child = spawn(command, args, {
    detached: true,
    stdio: 'ignore',
    ...options,
  });
  // Spawn failures (ENOENT, EACCES, EMFILE) surface as an async 'error'
  // event; without a listener that becomes an uncaught exception that
  // kills the whole process.
  child.once('error', (err) => {
    console.error(`Failed to launch ${command}: ${err.message}`);
  });
  child.unref();
}

async function waitFor(check, timeoutMs = 15000, intervalMs = 500) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return true;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return false;
}

async function isDashboardServerHealthy() {
  try {
    const apiToken = await getDashboardApiToken({ refresh: true });
    if (!apiToken) return false;

    const response = await fetch(`${OPEN_DASHBOARD_URL}/api/tunnel/status`, {
      headers: buildDashboardApiHeaders(apiToken),
      signal: AbortSignal.timeout(1500),
    });
    return response.ok;
  } catch {
    return false;
  }
}

function ensureDashboardProjectExists() {
  if (!isDashboardProjectDir(OPEN_DASHBOARD_DIR)) {
    const candidates = getDashboardDirCandidates().join(', ');
    throw new Error(`Open Dashboard project not found. Checked: ${candidates}.`);
  }

  if (!hasDashboardRuntimeDependencies(OPEN_DASHBOARD_DIR)) {
    throw new Error(`Open Dashboard dependencies are missing at ${OPEN_DASHBOARD_DIR}. Run npm install in that project or rebuild Open Sync with bundled Open Dashboard resources.`);
  }

  accessSync(OPEN_DASHBOARD_DIR, constants.R_OK);
}

function dashboardServerEnv() {
  const env = { ...process.env };
  if (existsSync(join(OPEN_DASHBOARD_DIR, 'dist', 'index.html'))) {
    env.NODE_ENV ||= 'production';
  }
  if (process.versions?.electron) {
    env.ELECTRON_RUN_AS_NODE = '1';
  }
  return env;
}

async function ensureDashboardServerRunning() {
  ensureDashboardProjectExists();

  if (await isDashboardServerHealthy()) {
    return OPEN_DASHBOARD_URL;
  }

  const logFd = openSync(OPEN_DASHBOARD_LOG_PATH, 'a');
  try {
    spawnDetached(process.execPath, ['server.js'], {
      cwd: OPEN_DASHBOARD_DIR,
      stdio: ['ignore', logFd, logFd],
      env: dashboardServerEnv(),
    });
  } finally {
    // The child holds its own duplicate of the descriptor; keeping the
    // parent's copy open would leak one fd per start attempt.
    closeSync(logFd);
  }

  const ready = await waitFor(() => isDashboardServerHealthy());
  if (!ready) {
    throw new Error(`Open Dashboard did not start at ${OPEN_DASHBOARD_URL}.`);
  }

  return OPEN_DASHBOARD_URL;
}

async function configureDashboardForDevice(device) {
  const config = buildDashboardConnectionConfig(device);
  let apiToken = await getDashboardApiToken();
  if (!apiToken) {
    throw new Error('Open Dashboard did not provide an API token.');
  }

  let response;
  let data;
  try {
    response = await configureDashboard(apiToken, config);
    if (response.status === 403) {
      apiToken = await getDashboardApiToken({ refresh: true });
      if (apiToken) {
        response = await configureDashboard(apiToken, config);
      }
    }

    // The abort signal also governs the body read, so json() can reject
    // with the same raw TimeoutError as the fetch itself.
    data = await response.json();
  } catch (err) {
    if (err?.name === 'TimeoutError' || err?.name === 'AbortError') {
      throw new Error('Open Dashboard did not respond in time.');
    }
    throw err;
  }
  if (!response.ok) {
    throw new Error(data?.error || 'Failed to configure Open Dashboard.');
  }
  return data;
}

function configureDashboard(apiToken, config) {
  return fetch(`${OPEN_DASHBOARD_URL}/api/tunnel/configure`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...buildDashboardApiHeaders(apiToken, { write: true }),
    },
    body: JSON.stringify(config),
    signal: AbortSignal.timeout(5000),
  });
}

function openUrl(url) {
  if (process.platform === 'darwin') {
    spawnDetached('open', [url]);
    return;
  }
  if (process.platform === 'linux') {
    spawnDetached('xdg-open', [url]);
    return;
  }
  if (process.platform === 'win32') {
    spawnDetached('cmd', ['/c', 'start', '', url]);
    return;
  }
  throw new Error(`Opening URLs is not supported on ${process.platform}.`);
}

async function openDashboardForDevice(device) {
  const url = await ensureDashboardServerRunning();
  await configureDashboardForDevice(device);
  openUrl(url);
  return { ok: true, url };
}

async function openTerminalForDevice(device) {
  const command = buildTerminalCommand(device);

  if (process.platform !== 'darwin') {
    throw new Error(`Opening a terminal is not supported on ${process.platform}.`);
  }

  spawnDetached('osascript', [
    '-e', 'tell application "Terminal"',
    '-e', 'activate',
    '-e', `do script "${escapeAppleScriptString(command)}"`,
    '-e', 'end tell',
  ]);

  return { ok: true };
}

export {
  OPEN_DASHBOARD_DIR,
  OPEN_DASHBOARD_PORT,
  buildDashboardApiHeaders,
  buildDashboardConnectionConfig,
  buildTerminalCommand,
  configureDashboardForDevice,
  getDashboardDirCandidates,
  ensureDashboardProjectExists,
  ensureDashboardServerRunning,
  extractDashboardApiToken,
  getDashboardUrl,
  normalizeDashboardUrl,
  openDashboardForDevice,
  openTerminalForDevice,
};
