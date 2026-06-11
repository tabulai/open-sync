import { createRequire } from 'module';
import { createHash, randomUUID } from 'crypto';
import { createServer } from 'net';
import { readFileSync } from 'fs';
import { SSH_KEY_PATH, SSH_CONFIG_PATH, SSH_KNOWN_HOSTS_PATH, ensureConfigDir } from './paths.js';
import { loadState, saveState, getDevice, upsertDevice, removeDevice } from './state.js';
import { ensureKeyPair } from './keys.js';
import { validateHostname, validateUsername, resolveTargetHost } from './hosts.js';
import { writeFileAtomic } from './atomic_write.js';

// ssh2 is the heaviest dependency in the app and is only needed once a real
// SSH operation starts, so load it on first use to keep CLI/server/Electron
// startup fast. It is CommonJS, so a memoized require stays synchronous for
// callers like hostVerifier and shares Node's module cache.
const require = createRequire(import.meta.url);
let ssh2Module;
function getSsh2() {
  return (ssh2Module ??= require('ssh2'));
}

// Active SSH connections keyed by hostname
const connections = new Map();

// In-flight SSH connection attempts keyed by hostname
const pendingConnections = new Map();

// Active port forwards keyed by "hostname:remotePort"
const tunnels = new Map();

class HostKeyTrustRequiredError extends Error {
  constructor({ hostname, host, port, fingerprint }) {
    super(`SSH host key for ${host}:${port} is not trusted. Verify fingerprint ${fingerprint}, then retry with that fingerprint to trust this device.`);
    this.code = 'HOST_KEY_TRUST_REQUIRED';
    this.hostname = hostname;
    this.host = host;
    this.port = port;
    this.fingerprint = fingerprint;
  }
}

class HostKeyChangedError extends Error {
  constructor({ hostname, host, port, fingerprint, expectedFingerprint }) {
    super(`SSH host key for ${host}:${port} does not match the trusted fingerprint. Expected ${expectedFingerprint}; got ${fingerprint}.`);
    this.code = 'HOST_KEY_CHANGED';
    this.hostname = hostname;
    this.host = host;
    this.port = port;
    this.fingerprint = fingerprint;
    this.expectedFingerprint = expectedFingerprint;
  }
}

function normalizeHostFingerprint(fingerprint = '') {
  const value = String(fingerprint || '').trim();
  if (!value) return '';
  return `SHA256:${value.replace(/^SHA256:/i, '').replace(/=+$/g, '')}`;
}

function hostKeyStateKey(hostname, port = 22) {
  return `${validateHostname(hostname)}:${Number(port) || 22}`;
}

function hostKeyAlias(hostname, port = 22) {
  return `open-sync-${validateHostname(hostname)}-${Number(port) || 22}`;
}

function validatePort(port, label = 'port') {
  const value = typeof port === 'number'
    ? port
    : (typeof port === 'string' && port.trim() ? Number(port) : NaN);
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`Invalid ${label}. Use a port between 1 and 65535.`);
  }
  return value;
}

function normalizeRemoteDirectory(directory = '') {
  const value = String(directory || '').replace(/\0/g, '').trim();
  if (!value || value.length > 4096 || !value.startsWith('/') || /[\x00-\x1F\x7F]/.test(value)) {
    return '';
  }
  return value;
}

function shellEscape(value = '') {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function buildInstallPublicKeyCommand(publicKey) {
  const escapedPublicKey = shellEscape(String(publicKey || '').trim());
  return [
    'mkdir -p ~/.ssh',
    'chmod 700 ~/.ssh',
    'touch ~/.ssh/authorized_keys',
    `grep -qxF ${escapedPublicKey} ~/.ssh/authorized_keys || printf '%s\\n' ${escapedPublicKey} >> ~/.ssh/authorized_keys`,
    'chmod 600 ~/.ssh/authorized_keys',
  ].join(' && ');
}

function buildKeyboardInteractiveResponses(prompts = [], password = '') {
  if (!password || !Array.isArray(prompts) || prompts.length !== 1 || prompts[0]?.echo) {
    return [];
  }
  return [password];
}

// The remote host controls how much it writes; cap what we keep so a
// misbehaving or malicious host cannot grow these buffers without bound.
// The only stdout consumer (readRemoteHomeDirectory) needs at most 4096
// bytes, and stderr is only used to decorate error messages.
const MAX_EXEC_CAPTURE_BYTES = 64 * 1024;

function createCappedCapture() {
  const chunks = [];
  let bytes = 0;
  let truncated = false;
  return {
    push(chunk) {
      if (bytes >= MAX_EXEC_CAPTURE_BYTES) {
        truncated = true;
        return;
      }
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      let piece = buf;
      if (buf.length > MAX_EXEC_CAPTURE_BYTES - bytes) {
        truncated = true;
        piece = buf.subarray(0, MAX_EXEC_CAPTURE_BYTES - bytes);
      }
      chunks.push(piece);
      bytes += piece.length;
    },
    get truncated() {
      return truncated;
    },
    toString() {
      return Buffer.concat(chunks).toString();
    },
  };
}

function execSshCommand(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(err);

      const stderr = createCappedCapture();
      stream.on('data', () => {
        // Drain stdout so a verbose remote command cannot block channel close.
      });
      stream.stderr?.on('data', (chunk) => {
        stderr.push(chunk);
      });
      stream.on('error', reject);
      stream.on('close', (code, signal) => {
        if (code === 0) {
          resolve();
          return;
        }

        const detail = stderr.toString().trim();
        const suffix = detail ? `: ${detail}${stderr.truncated ? ' … [remote output truncated]' : ''}` : '';
        reject(new Error(`Remote command failed${signal ? ` with signal ${signal}` : ` with exit code ${code}`}${suffix}`));
      });
    });
  });
}

function execSshCommandOutput(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(err);

      const stdout = createCappedCapture();
      const stderr = createCappedCapture();
      stream.on('data', (chunk) => {
        stdout.push(chunk);
      });
      stream.stderr?.on('data', (chunk) => {
        stderr.push(chunk);
      });
      stream.on('error', reject);
      stream.on('close', (code, signal) => {
        if (code === 0) {
          resolve(stdout.toString());
          return;
        }

        const detail = stderr.toString().trim();
        const suffix = detail ? `: ${detail}${stderr.truncated ? ' … [remote output truncated]' : ''}` : '';
        reject(new Error(`Remote command failed${signal ? ` with signal ${signal}` : ` with exit code ${code}`}${suffix}`));
      });
    });
  });
}

async function readRemoteHomeDirectory(conn) {
  const stdout = await execSshCommandOutput(conn, 'printf %s "$HOME"');
  return normalizeRemoteDirectory(stdout);
}

function getHostKeyDetails(rawKey) {
  const parsed = getSsh2().utils.parseKey(rawKey);
  if (parsed instanceof Error) throw parsed;
  const publicKey = parsed.getPublicSSH();
  return {
    keyType: parsed.type,
    publicKey: publicKey.toString('base64'),
    fingerprint: `SHA256:${createHash('sha256').update(publicKey).digest('base64').replace(/=+$/g, '')}`,
  };
}

function getKnownHost(state, hostname, port) {
  return state.knownHosts?.[hostKeyStateKey(hostname, port)];
}

function rememberTrustedHostKey(state, hostKey) {
  if (!hostKey) return;
  state.knownHosts ||= {};
  state.knownHosts[hostKeyStateKey(hostKey.hostname, hostKey.port)] = {
    hostname: hostKey.hostname,
    host: hostKey.host,
    port: hostKey.port,
    fingerprint: hostKey.fingerprint,
    alias: hostKeyAlias(hostKey.hostname, hostKey.port),
    keyType: hostKey.keyType,
    publicKey: hostKey.publicKey,
    trustedAt: new Date().toISOString(),
  };
}

function createHostKeyVerifier({ hostname, host, port, expectedHostFingerprint } = {}) {
  const expectedFingerprint = normalizeHostFingerprint(expectedHostFingerprint);
  let verificationError;
  let trustedHostKey;

  return {
    hostVerifier(rawKey) {
      let details;
      try {
        details = getHostKeyDetails(rawKey);
      } catch (err) {
        verificationError = err;
        return false;
      }

      const fingerprint = normalizeHostFingerprint(details.fingerprint);
      const state = loadState();
      const known = getKnownHost(state, hostname, port);
      const knownFingerprint = normalizeHostFingerprint(known?.fingerprint);

      if (knownFingerprint) {
        if (knownFingerprint === fingerprint) {
          trustedHostKey = { ...details, fingerprint, hostname, host, port };
          return true;
        }

        verificationError = new HostKeyChangedError({
          hostname,
          host,
          port,
          fingerprint,
          expectedFingerprint: known.fingerprint,
        });
        return false;
      }

      if (!expectedFingerprint) {
        verificationError = new HostKeyTrustRequiredError({ hostname, host, port, fingerprint });
        return false;
      }

      if (expectedFingerprint !== fingerprint) {
        verificationError = new HostKeyChangedError({
          hostname,
          host,
          port,
          fingerprint,
          expectedFingerprint,
        });
        return false;
      }

      trustedHostKey = { ...details, fingerprint, hostname, host, port };
      return true;
    },

    getError() {
      return verificationError;
    },

    getTrustedHostKey() {
      return trustedHostKey;
    },
  };
}

function parseSSHUrl(url) {
  // ssh://<account>@<host>[:port]
  const match = url.match(/^ssh:\/\/([^@]+)@([^:]+)(?::(\d+))?$/);
  if (!match) throw new Error(`Invalid SSH URL: ${url}. Expected ssh://<account>@<host>[:port]`);
  return {
    username: validateUsername(match[1]),
    hostname: validateHostname(match[2]),
    port: validatePort(match[3] || 22, 'SSH port'),
  };
}

function knownHostsLine(entry) {
  if (!entry?.host || !entry?.keyType || !entry?.publicKey) return '';
  return `${entry.alias || hostKeyAlias(entry.hostname, entry.port)} ${entry.keyType} ${entry.publicKey}`;
}

function writeKnownHosts(knownHosts = {}) {
  ensureConfigDir();
  const lines = Object.values(knownHosts).map(knownHostsLine).filter(Boolean);
  writeFileAtomic(SSH_KNOWN_HOSTS_PATH, lines.length ? `${lines.join('\n')}\n` : '', { mode: 0o600 });
}

function writeSshConfig(stateOrDevices) {
  ensureConfigDir();
  const devices = Array.isArray(stateOrDevices) ? stateOrDevices : (stateOrDevices.devices || []);
  const knownHosts = Array.isArray(stateOrDevices) ? {} : (stateOrDevices.knownHosts || {});
  const lines = devices.map((device) => {
    const hostname = validateHostname(device.hostname);
    const username = validateUsername(device.username);
    const port = validatePort(device.sshPort || 22, 'SSH port');
    return `Host ${hostname}\n  Hostname ${resolveTargetHost(hostname)}\n  User ${username}\n  Port ${port}\n  IdentityFile "${SSH_KEY_PATH}"\n  UserKnownHostsFile "${SSH_KNOWN_HOSTS_PATH}"\n  StrictHostKeyChecking yes\n  HostKeyAlias ${hostKeyAlias(hostname, port)}\n`;
  }
  );
  writeFileAtomic(SSH_CONFIG_PATH, '\n' + lines.join('\n'), { mode: 0o600 });
  writeKnownHosts(knownHosts);
}

function isAuthenticationFailure(err) {
  return err?.level === 'client-authentication'
    || /all authentication methods failed/i.test(err?.message || '');
}

function buildCreateDeviceAuthError({ username, targetHost, hasPassword }) {
  if (hasPassword) {
    return `Authentication failed for ${username}@${targetHost}. Verify the SSH username and password for this device.`;
  }
  return `Authentication failed for ${username}@${targetHost}. Use the device's real SSH username, and if this is a first-time connection enter its password so Open Sync can install your SSH key.`;
}

function normalizeCreateDeviceError(err, context) {
  if (!isAuthenticationFailure(err)) return err;
  const wrapped = new Error(buildCreateDeviceAuthError(context));
  wrapped.code = err.code;
  wrapped.level = err.level;
  wrapped.cause = err;
  return wrapped;
}

async function createDevice(sshUrl, password, options = {}) {
  const { username, hostname, port } = parseSSHUrl(sshUrl);
  const keys = ensureKeyPair();
  const targetHost = resolveTargetHost(hostname);
  const hostKeyVerifier = createHostKeyVerifier({
    hostname,
    host: targetHost,
    port,
    expectedHostFingerprint: options.expectedHostFingerprint,
  });
  const authContext = {
    username,
    targetHost,
    hasPassword: Boolean(password),
  };

  const authAttempts = [{ method: 'key', password: '' }];
  if (password) {
    authAttempts.push({ method: 'password', password });
  }

  let lastAuthError;

  for (const authAttempt of authAttempts) {
    let conn;
    try {
      conn = await connectForCreateDevice({
        targetHost,
        port,
        username,
        password: authAttempt.password,
        hostKeyVerifier,
      });

      try {
        // If password auth was needed, install the public key before persisting the device.
        if (authAttempt.method === 'password') {
          await execSshCommand(conn, buildInstallPublicKeyCommand(keys.publicKey));
        }

        let homeDirectory = '';
        try {
          homeDirectory = await readRemoteHomeDirectory(conn);
        } catch {
          // Fall back to the historical Linux-style default below.
        }
        return persistCreatedDevice({ hostname, username, port, homeDirectory, hostKeyVerifier });
      } finally {
        conn.end();
      }
    } catch (err) {
      if (err.code?.startsWith('HOST_KEY_')) {
        throw err;
      }

      if (authAttempt.method === 'key' && password && isAuthenticationFailure(err)) {
        lastAuthError = err;
        continue;
      }

      throw normalizeCreateDeviceError(err, authContext);
    }
  }

  throw normalizeCreateDeviceError(lastAuthError, authContext);
}

function connectForCreateDevice({ targetHost, port, username, password, hostKeyVerifier }) {
  return new Promise((resolve, reject) => {
    const conn = new (getSsh2().Client)();
    const connectOpts = {
      host: targetHost,
      port,
      username,
      tryKeyboard: Boolean(password),
      hostVerifier: hostKeyVerifier.hostVerifier,
    };
    let settled = false;

    if (password) {
      connectOpts.password = password;
      conn.on('keyboard-interactive', (name, instructions, instructionsLang, prompts, finish) => {
        finish(buildKeyboardInteractiveResponses(prompts, password));
      });
    } else {
      connectOpts.privateKey = readFileSync(SSH_KEY_PATH);
    }

    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };

    conn.on('ready', () => finish(resolve, conn));
    conn.on('error', (err) => {
      conn.end();
      finish(reject, hostKeyVerifier.getError() || err);
    });
    conn.connect(connectOpts);
  });
}

function persistCreatedDevice({ hostname, username, port, homeDirectory, hostKeyVerifier }) {
  const state = loadState();
  rememberTrustedHostKey(state, hostKeyVerifier.getTrustedHostKey());
  const resolvedHomeDirectory = homeDirectory || `/home/${username}`;
  const device = {
    id: randomUUID(),
    hostname,
    username,
    sshPort: port,
    status: 'disconnected',
    homeDirectory: resolvedHomeDirectory,
    path: resolvedHomeDirectory,
  };
  upsertDevice(state, device);
  writeSshConfig(state);
  saveState(state);
  return device;
}

function updateDeviceConnectionState(hostname, update, { trustedHostKey, writeConfig = false } = {}) {
  const state = loadState();
  const device = getDevice(state, hostname);
  if (!device) return null;

  update(device, state);
  if (trustedHostKey) {
    rememberTrustedHostKey(state, trustedHostKey);
  }
  upsertDevice(state, device);
  if (writeConfig) {
    writeSshConfig(state);
  }
  saveState(state);
  return device;
}

function connect(hostname, options = {}) {
  if (connections.has(hostname)) {
    return Promise.resolve({ status: 'RUNNING', hostname });
  }

  if (pendingConnections.has(hostname)) {
    return pendingConnections.get(hostname);
  }

  const pending = connectOnce(hostname, options).finally(() => {
    pendingConnections.delete(hostname);
  });
  pendingConnections.set(hostname, pending);
  return pending;
}

function connectOnce(hostname, options = {}) {
  return new Promise((resolve, reject) => {
    const initialState = loadState();
    const device = getDevice(initialState, hostname);
    if (!device) return reject(new Error(`Device '${hostname}' not found. Use 'create' first.`));

    // options.onClose fires only after a successful connect; ssh2 also emits
    // 'close' after handshake failures, which must stay with the error path.
    // It receives the post-establishment error, if any, so callers can tell
    // an abnormal drop (network failure, remote crash) from a clean close.
    let established = false;
    let postEstablishError;

    const targetHost = resolveTargetHost(device.hostname);
    const port = device.sshPort || 22;
    const hostKeyVerifier = createHostKeyVerifier({
      hostname: device.hostname,
      host: targetHost,
      port,
      expectedHostFingerprint: options.expectedHostFingerprint,
    });
    const conn = new (getSsh2().Client)();
    conn.on('ready', () => {
      try {
        const updated = updateDeviceConnectionState(hostname, (currentDevice) => {
          currentDevice.status = 'connected';
          delete currentDevice.error;
        }, {
          trustedHostKey: hostKeyVerifier.getTrustedHostKey(),
          writeConfig: true,
        });

        if (!updated) {
          conn.end();
          return reject(new Error(`Device '${hostname}' was removed before connection completed.`));
        }

        connections.set(hostname, conn);
        established = true;
        resolve({ status: 'RUNNING', hostname });
      } catch (err) {
        conn.end();
        reject(err);
      }
    });

    conn.on('error', (err) => {
      connections.delete(hostname);
      if (established) postEstablishError = err;
      const hostKeyError = hostKeyVerifier.getError();
      if (hostKeyError) {
        return reject(hostKeyError);
      }
      try {
        updateDeviceConnectionState(hostname, (currentDevice) => {
          currentDevice.status = 'error';
          currentDevice.error = err.message;
        });
      } catch {
        // Preserve the original connection failure for callers.
      }
      reject(err);
    });

    conn.on('close', () => {
      connections.delete(hostname);
      try {
        const s = loadState();
        const d = getDevice(s, hostname);
        if (d && d.status !== 'disconnected') {
          d.status = 'disconnected';
          upsertDevice(s, d);
          saveState(s);
        }
      } catch {
        // State file may be mid-write from another operation; skip update
      }
      if (established && typeof options.onClose === 'function') {
        options.onClose(postEstablishError);
      }
    });

    let privateKey;
    try {
      privateKey = readFileSync(SSH_KEY_PATH);
    } catch {
      return reject(new Error('No SSH key found. Run "create" first to set up the device.'));
    }

    conn.connect({
      host: targetHost,
      port,
      username: device.username,
      privateKey,
      hostVerifier: hostKeyVerifier.hostVerifier,
    });
  });
}

function disconnect(hostname) {
  const conn = connections.get(hostname);
  if (conn) {
    // Close all tunnels for this host
    for (const [key, info] of tunnels) {
      if (key.startsWith(`${hostname}:`)) {
        info.server.close();
        tunnels.delete(key);
      }
    }
    conn.end();
    connections.delete(hostname);
  }
  const state = loadState();
  const device = getDevice(state, hostname);
  if (device) {
    device.status = 'disconnected';
    delete device.error;
    upsertDevice(state, device);
  }
  delete state.openPorts[hostname];
  saveState(state);
  return { status: 'DISCONNECTED', hostname };
}

function getStatus(hostname) {
  const state = loadState();
  const device = getDevice(state, hostname);
  if (!device) return { status: 'NOT_FOUND', error: `Device '${hostname}' not found` };

  const isConnected = connections.has(hostname);
  const ports = {};

  for (const [key, info] of tunnels) {
    if (key.startsWith(`${hostname}:`)) {
      const port = key.split(':')[1];
      ports[port] = { status: 'OPENED', localPort: info.localPort, error: '' };
    }
  }

  return {
    status: isConnected ? 'RUNNING' : (device.status === 'error' ? 'ERROR' : 'DISCONNECTED'),
    error: device.error || '',
    ports,
  };
}

function openTunnel(hostname, remotePort) {
  return new Promise((resolve, reject) => {
    let validatedRemotePort;
    try {
      validatedRemotePort = validatePort(remotePort, 'remote port');
    } catch (err) {
      return reject(err);
    }

    const conn = connections.get(hostname);
    if (!conn) return reject(new Error(`Not connected to '${hostname}'. Run 'connect' first.`));

    const key = `${hostname}:${validatedRemotePort}`;
    if (tunnels.has(key)) {
      return resolve({ status: 'OPENED', remotePort: validatedRemotePort, localPort: tunnels.get(key).localPort });
    }

    const server = createServer((socket) => {
      conn.forwardOut('127.0.0.1', 0, '127.0.0.1', validatedRemotePort, (err, stream) => {
        if (err) { socket.end(); return; }
        socket.pipe(stream);
        stream.pipe(socket);
        socket.on('error', () => stream.end());
        stream.on('error', () => socket.end());
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const localPort = server.address().port;
      tunnels.set(key, { server, localPort });

      const state = loadState();
      if (!state.openPorts[hostname]) state.openPorts[hostname] = [];
      if (!state.openPorts[hostname].includes(validatedRemotePort)) {
        state.openPorts[hostname].push(validatedRemotePort);
      }
      saveState(state);

      resolve({ status: 'OPENED', remotePort: validatedRemotePort, localPort });
    });

    server.on('error', reject);
  });
}

function closeTunnel(hostname, remotePort) {
  const hasRemotePort = remotePort !== undefined;
  const validatedRemotePort = hasRemotePort ? validatePort(remotePort, 'remote port') : undefined;

  if (hasRemotePort) {
    const key = `${hostname}:${validatedRemotePort}`;
    const info = tunnels.get(key);
    if (info) {
      info.server.close();
      tunnels.delete(key);
    }
  } else {
    // Close all tunnels for hostname
    for (const [key, info] of tunnels) {
      if (key.startsWith(`${hostname}:`)) {
        info.server.close();
        tunnels.delete(key);
      }
    }
  }

  const state = loadState();
  if (hasRemotePort) {
    if (state.openPorts[hostname]) {
      state.openPorts[hostname] = state.openPorts[hostname].filter(p => p !== validatedRemotePort);
    }
  } else {
    delete state.openPorts[hostname];
  }
  saveState(state);
  return { status: 'CLOSED' };
}

function deleteDevice(hostname) {
  disconnect(hostname);
  const state = loadState();
  removeDevice(state, hostname);
  writeSshConfig(state);
  saveState(state);
  return { status: 'DELETED', hostname };
}

function getConnections() {
  return connections;
}

function getPendingConnections() {
  return pendingConnections;
}

export {
  buildInstallPublicKeyCommand,
  buildKeyboardInteractiveResponses,
  buildCreateDeviceAuthError,
  createHostKeyVerifier,
  execSshCommand,
  getPendingConnections,
  normalizeRemoteDirectory,
  normalizeHostFingerprint,
  parseSSHUrl,
  updateDeviceConnectionState,
  validatePort,
  createDevice,
  connect,
  disconnect,
  getStatus,
  openTunnel,
  closeTunnel,
  deleteDevice,
  getConnections,
};
