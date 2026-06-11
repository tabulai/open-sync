import express from 'express';
import { randomBytes, timingSafeEqual } from 'crypto';
import { isIP } from 'net';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { loadState, getDevice } from '../core/state.js';
import { discover } from '../core/discovery.js';
import { ensureKeyPair, getPublicKey } from '../core/keys.js';
import { createDevice, connect, disconnect, getStatus, openTunnel, closeTunnel, deleteDevice, getConnections, validatePort } from '../core/ssh.js';
import { openDashboardForDevice, openTerminalForDevice } from '../core/apps.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');
const INDEX_PATH = join(PUBLIC_DIR, 'index.html');
const app = express();
app.use(enforceLoopbackHost);
app.use(securityHeaders);
app.get(['/', '/index.html'], (req, res) => {
  const html = readFileSync(INDEX_PATH, 'utf-8').replaceAll('{{cspNonce}}', res.locals.cspNonce);
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(html);
});
app.get('/api/session', requireSameOriginRequest, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ apiToken: app.locals.apiToken });
});
app.use(express.static(PUBLIC_DIR, { index: false }));
app.use('/api', requireTrustedApiRequest);
app.use('/api', express.json({ limit: '64kb' }));

// --- API Routes ---

// List all devices
app.get('/api/devices', (req, res) => {
  const state = loadState();
  const conns = getConnections();
  const devices = state.devices.map(d => ({
    ...d,
    status: conns.has(d.hostname) ? 'connected' : (d.status || 'disconnected'),
  }));
  res.json(devices);
});

// Discover hosts. We coalesce concurrent calls onto a single in-flight promise:
// each discovery spins up a Bonjour browser plus a batched TCP scan that holds
// up to ~64 sockets at a time, so a token-holding caller spamming this endpoint
// could otherwise pin local resources for 10+ seconds at a time.
let inflightDiscovery = null;
app.get('/api/discover', async (req, res) => {
  try {
    const requested = parseInt(req.query.timeout || '3', 10);
    const timeout = Math.min(Math.max(Number.isInteger(requested) ? requested : 3, 1), 10);
    if (!inflightDiscovery) {
      inflightDiscovery = discover(timeout).finally(() => { inflightDiscovery = null; });
    }
    const hosts = await inflightDiscovery;
    res.json(hosts);
  } catch (err) {
    res.status(500).json({ error: String(err.message || 'Discovery failed.') });
  }
});

// Create device
app.post('/api/devices', async (req, res) => {
  const { sshUrl, password, expectedHostFingerprint } = req.body || {};
  try {
    const device = await createDevice(sshUrl, password, { expectedHostFingerprint });
    res.json(device);
  } catch (err) {
    sendApiError(res, err, 400);
  }
});

// Connect to device
app.post('/api/devices/:hostname/connect', async (req, res) => {
  const { expectedHostFingerprint } = req.body || {};
  try {
    const result = await connect(req.params.hostname, { expectedHostFingerprint });
    res.json(result);
  } catch (err) {
    sendApiError(res, err, 400);
  }
});

// Disconnect from device
app.post('/api/devices/:hostname/disconnect', (req, res) => {
  const result = disconnect(req.params.hostname);
  res.json(result);
});

// Get device status
app.get('/api/devices/:hostname/status', (req, res) => {
  const status = getStatus(req.params.hostname);
  res.json(status);
});

// Open tunnel
app.post('/api/devices/:hostname/tunnels', async (req, res) => {
  const { port } = req.body || {};
  try {
    const result = await openTunnel(req.params.hostname, validatePort(port, 'remote port'));
    res.json(result);
  } catch (err) {
    sendApiError(res, err, 400);
  }
});

// Open terminal for device
app.post('/api/devices/:hostname/apps/terminal', async (req, res) => {
  const state = loadState();
  const device = getDevice(state, req.params.hostname);
  if (!device) {
    return res.status(404).json({ error: `Device '${req.params.hostname}' not found.` });
  }

  try {
    const result = await openTerminalForDevice(device);
    res.json(result);
  } catch (err) {
    sendApiError(res, err, 500);
  }
});

// Open Open Dashboard for device
app.post('/api/devices/:hostname/apps/dashboard', async (req, res) => {
  const state = loadState();
  const device = getDevice(state, req.params.hostname);
  if (!device) {
    return res.status(404).json({ error: `Device '${req.params.hostname}' not found.` });
  }

  try {
    const result = await openDashboardForDevice(device);
    res.json(result);
  } catch (err) {
    sendApiError(res, err, 500);
  }
});

// Close tunnel
app.delete('/api/devices/:hostname/tunnels/:port', (req, res) => {
  try {
    const result = closeTunnel(req.params.hostname, validatePort(req.params.port, 'remote port'));
    res.json(result);
  } catch (err) {
    sendApiError(res, err, 400);
  }
});

// Close all tunnels
app.delete('/api/devices/:hostname/tunnels', (req, res) => {
  const result = closeTunnel(req.params.hostname);
  res.json(result);
});

// Delete device
app.delete('/api/devices/:hostname', (req, res) => {
  const result = deleteDevice(req.params.hostname);
  res.json(result);
});

// Get public key
app.get('/api/pubkey', (req, res) => {
  ensureKeyPair();
  res.json({ publicKey: getPublicKey() });
});

// Get tools list
app.get('/api/tools', (req, res) => {
  const state = loadState();
  res.json(state.tools || []);
});

function resolveListenPort(port) {
  // Reject anything that would not produce a valid TCP port number.
  // Without this, app.listen() would interpret a non-numeric string as a
  // Unix domain socket path and silently bind to a file in CWD.
  if (port === 0) return 0;
  if (port !== undefined && port !== null) {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 0 || n > 65535) {
      throw new Error(`Invalid listen port: ${port}`);
    }
    return n;
  }
  if (process.env.PORT !== undefined && process.env.PORT !== '') {
    const n = Number(process.env.PORT);
    if (!Number.isInteger(n) || n < 0 || n > 65535) {
      throw new Error(`Invalid PORT environment variable: ${process.env.PORT}`);
    }
    return n;
  }
  return 8384;
}

function startServer(port) {
  const p = resolveListenPort(port);
  const apiToken = createApiToken();
  app.locals.apiToken = apiToken;
  return new Promise((resolve) => {
    const server = app.listen(p, '127.0.0.1', () => {
      const addr = server.address();
      server.openSyncApiToken = apiToken;
      server.openSyncUrl = `http://localhost:${addr.port}/`;
      console.log(`open-sync web UI running at ${server.openSyncUrl}`);
      resolve(server);
    });
  });
}

function createApiToken() {
  return randomBytes(32).toString('base64url');
}

function securityHeaders(req, res, next) {
  const nonce = randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'none'",
  ].join('; '));
  next();
}

function parseHostHeader(hostHeader = '') {
  try {
    return new URL(`http://${hostHeader}`).hostname.replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase();
  } catch {
    return '';
  }
}

function isLoopbackHostname(hostname) {
  // Accept exactly 'localhost' and the IPv4/IPv6 loopback ranges. We
  // deliberately do not allow `*.localhost`: although RFC 6761 reserves the
  // TLD for loopback, that subdomain space provides a foothold for DNS
  // rebinding setups that point e.g. `attacker.localhost` at a public IP
  // first and then rebind to 127.0.0.1, so it widens the attack surface
  // without enabling anything we ship.
  if (hostname === 'localhost') return true;
  if (hostname === '::1') return true;
  if (isIP(hostname) === 4) {
    // 127.0.0.0/8 is entirely loopback per RFC 1122.
    return hostname.startsWith('127.');
  }
  return false;
}

function enforceLoopbackHost(req, res, next) {
  if (isLoopbackHostname(parseHostHeader(req.headers.host))) {
    return next();
  }
  res.status(403).json({ error: 'Forbidden host header.' });
}

function requestOrigin(req) {
  const origin = req.get('origin');
  if (!origin) return '';
  try {
    return new URL(origin).origin;
  } catch {
    return 'invalid';
  }
}

function expectedOrigin(req) {
  try {
    return new URL(`http://${req.get('host')}`).origin;
  } catch {
    return '';
  }
}

function hasValidApiToken(req) {
  const token = req.get('x-open-sync-token') || '';
  const expected = app.locals.apiToken || '';
  const tokenBytes = Buffer.from(token);
  const expectedBytes = Buffer.from(expected);
  return expectedBytes.length > 0 && tokenBytes.length === expectedBytes.length && timingSafeEqual(tokenBytes, expectedBytes);
}

function isTrustedBrowserRequest(req) {
  const origin = requestOrigin(req);
  if (origin && origin !== expectedOrigin(req)) {
    return false;
  }

  const fetchSite = req.get('sec-fetch-site');
  if (fetchSite && !['same-origin', 'same-site', 'none'].includes(fetchSite)) {
    return false;
  }

  return true;
}

function requireSameOriginRequest(req, res, next) {
  if (!isTrustedBrowserRequest(req)) {
    return res.status(403).json({ error: 'Cross-site API requests are not allowed.' });
  }

  return next();
}

function requireTrustedApiRequest(req, res, next) {
  if (!isTrustedBrowserRequest(req)) {
    return res.status(403).json({ error: 'Cross-site API requests are not allowed.' });
  }

  if (!hasValidApiToken(req)) {
    return res.status(401).json({ error: 'Missing or invalid Open Sync API token.' });
  }

  return next();
}

function sendApiError(res, err, fallbackStatus) {
  const body = { error: err.message };
  if (err.code) body.code = err.code;
  if (err.fingerprint) body.fingerprint = err.fingerprint;
  if (err.host) body.host = err.host;
  if (err.hostname) body.hostname = err.hostname;
  if (err.port) body.port = err.port;
  const status = err.code?.startsWith('HOST_KEY_') ? 409 : fallbackStatus;
  res.status(status).json(body);
}

// Auto-start when run directly (not imported for tests)
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'))) {
  startServer();
}

export { app, startServer };
