import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { setupTempConfig, cleanupTempConfig } from './helpers.js';

const tempDir = setupTempConfig();

const { startServer } = await import('../src/web/server.js');

function rawRequest({ port, headers = {}, path = '/api/devices', method = 'GET' }) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on('error', reject);
    req.end();
  });
}

let server;
let BASE;
let TOKEN;

before(async () => {
  server = await startServer(0);
  const port = server.address().port;
  BASE = `http://localhost:${port}`;
  TOKEN = server.openSyncApiToken;
});

after(() => {
  server?.close();
  cleanupTempConfig(tempDir);
});

function apiFetch(path, opts = {}) {
  return fetch(`${BASE}${path}`, {
    ...opts,
    headers: {
      ...(opts.headers || {}),
      'X-Open-Sync-Token': TOKEN,
    },
  });
}

describe('web API', () => {
  describe('API request trust', () => {
    it('rejects missing API tokens', async () => {
      const res = await fetch(`${BASE}/api/devices`);
      assert.equal(res.status, 401);
    });

    it('rejects cross-origin requests even with a valid token', async () => {
      const res = await apiFetch('/api/devices', {
        headers: { Origin: 'https://attacker.example' },
      });
      assert.equal(res.status, 403);
    });

    it('sets browser hardening headers', async () => {
      const res = await fetch(`${BASE}/`);
      assert.equal(res.status, 200);
      const csp = res.headers.get('content-security-policy');
      assert.match(csp, /default-src 'self'/);
      assert.match(csp, /script-src 'self' 'nonce-[^']+'/);
      assert.doesNotMatch(csp, /script-src 'self' 'unsafe-inline'/);
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    });

    it('returns an API session token only to trusted browser requests', async () => {
      const res = await fetch(`${BASE}/api/session`);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('cache-control'), 'no-store');
      const data = await res.json();
      assert.equal(data.apiToken, TOKEN);

      const crossSite = await fetch(`${BASE}/api/session`, {
        headers: { Origin: 'https://attacker.example' },
      });
      assert.equal(crossSite.status, 403);
    });
  });

  describe('GET /api/devices', () => {
    it('returns an array', async () => {
      const res = await apiFetch('/api/devices');
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data));
    });

    it('returns empty array initially', async () => {
      const res = await apiFetch('/api/devices');
      const data = await res.json();
      assert.equal(data.length, 0);
    });
  });

  describe('GET /api/tools', () => {
    it('returns tools array', async () => {
      const res = await apiFetch('/api/tools');
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data));
      assert.ok(data.length > 0);
    });

    it('includes terminal tool', async () => {
      const res = await apiFetch('/api/tools');
      const data = await res.json();
      const terminal = data.find(t => t.id === 'terminal');
      assert.ok(terminal);
      assert.equal(terminal.available, true);
    });
  });

  describe('GET /api/pubkey', () => {
    it('returns a public key', async () => {
      const res = await apiFetch('/api/pubkey');
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.publicKey.includes('ssh-ed25519'));
    });
  });

  describe('GET /api/devices/:hostname/status', () => {
    it('returns NOT_FOUND for unknown device', async () => {
      const res = await apiFetch('/api/devices/nonexistent/status');
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.status, 'NOT_FOUND');
    });
  });

  describe('POST /api/devices', () => {
    it('rejects invalid SSH URL', async () => {
      const res = await apiFetch('/api/devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sshUrl: 'not-valid' }),
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.ok(data.error.includes('Invalid SSH URL'));
    });
  });

  describe('POST /api/devices/:hostname/connect', () => {
    it('rejects unknown device', async () => {
      const res = await apiFetch('/api/devices/ghost/connect', { method: 'POST' });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.ok(data.error.includes('not found'));
    });
  });

  describe('POST /api/devices/:hostname/disconnect', () => {
    it('returns DISCONNECTED for unknown device', async () => {
      const res = await apiFetch('/api/devices/ghost/disconnect', { method: 'POST' });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.status, 'DISCONNECTED');
    });
  });

  describe('POST /api/devices/:hostname/tunnels', () => {
    it('rejects tunnel open for unconnected device', async () => {
      const res = await apiFetch('/api/devices/ghost/tunnels', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port: 8888 }),
      });
      assert.equal(res.status, 400);
    });

    it('rejects invalid tunnel ports with a clear 400', async () => {
      const res = await apiFetch('/api/devices/ghost/tunnels', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port: 65536 }),
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /Invalid remote port/);
    });
  });

  describe('POST /api/devices/:hostname/apps/terminal', () => {
    it('returns 404 for unknown device', async () => {
      const res = await apiFetch('/api/devices/ghost/apps/terminal', { method: 'POST' });
      assert.equal(res.status, 404);
      const data = await res.json();
      assert.ok(data.error.includes('not found'));
    });
  });

  describe('POST /api/devices/:hostname/apps/dashboard', () => {
    it('returns 404 for unknown device', async () => {
      const res = await apiFetch('/api/devices/ghost/apps/dashboard', { method: 'POST' });
      assert.equal(res.status, 404);
      const data = await res.json();
      assert.ok(data.error.includes('not found'));
    });
  });

  describe('GET /api/discover', () => {
    it('returns arrays and coalesces concurrent calls onto a single in-flight scan', async () => {
      const start = Date.now();
      const responses = await Promise.all([
        apiFetch('/api/discover?timeout=1'),
        apiFetch('/api/discover?timeout=1'),
        apiFetch('/api/discover?timeout=1'),
      ]);
      const elapsed = Date.now() - start;
      // Three serial 1s scans would take >=3s; coalesced should fit in <2s.
      assert.ok(elapsed < 2000, `Three concurrent discovers took ${elapsed}ms; expected <2000ms`);
      for (const res of responses) {
        assert.equal(res.status, 200);
      }
      const [a, b, c] = await Promise.all(responses.map((r) => r.json()));
      assert.ok(Array.isArray(a));
      assert.deepStrictEqual(a, b);
      assert.deepStrictEqual(b, c);
    });
  });

  describe('loopback host enforcement', () => {
    it('rejects non-loopback Host headers', async () => {
      const port = server.address().port;
      const status = await rawRequest({
        port,
        headers: { Host: `attacker.example:${port}`, 'X-Open-Sync-Token': TOKEN },
      });
      assert.equal(status, 403);
    });

    it('rejects subdomain.localhost Host headers (no DNS-rebinding foothold)', async () => {
      const port = server.address().port;
      const status = await rawRequest({
        port,
        headers: { Host: `attacker.localhost:${port}`, 'X-Open-Sync-Token': TOKEN },
      });
      assert.equal(status, 403);
    });

    it('accepts 127.0.0.1 Host headers', async () => {
      const port = server.address().port;
      const status = await rawRequest({
        port,
        headers: { Host: `127.0.0.1:${port}`, 'X-Open-Sync-Token': TOKEN },
      });
      assert.equal(status, 200);
    });
  });
});
