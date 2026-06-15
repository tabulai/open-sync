import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import ssh2 from 'ssh2';
import { spawnSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { createHash } from 'crypto';
import { PassThrough } from 'stream';
import { setupTempConfig, cleanupTempConfig } from './helpers.js';

const tempDir = setupTempConfig();

const {
  parseSSHUrl,
  validatePort,
  normalizeRemoteDirectory,
  getStatus,
  connect,
  disconnect,
  getConnections,
  getPendingConnections,
  buildCreateDeviceAuthError,
  buildInstallPublicKeyCommand,
  buildKeyboardInteractiveResponses,
  createDevice,
  createHostKeyVerifier,
  execSshCommand,
  normalizeHostFingerprint,
  openTunnel,
  updateDeviceConnectionState,
} = await import('../src/core/ssh.js');
const { resolveTargetHost } = await import('../src/core/hosts.js');
const { loadState, saveState, upsertDevice, removeDevice } = await import('../src/core/state.js');
const { SSH_CONFIG_PATH } = await import('../src/core/paths.js');

const { Server, utils } = ssh2;

function testHostPublicKey() {
  const pair = utils.generateKeyPairSync('ed25519');
  return utils.parseKey(pair.public).getPublicSSH();
}

function fingerprintForPublicKey(publicKey) {
  const parsed = utils.parseKey(publicKey);
  if (parsed instanceof Error) throw parsed;
  return `SHA256:${createHash('sha256').update(parsed.getPublicSSH()).digest('base64').replace(/=+$/g, '')}`;
}

function startRejectingSshServer(rejectMethods = ['publickey', 'keyboard-interactive']) {
  const attempts = [];
  const pair = utils.generateKeyPairSync('ed25519');
  const server = new Server({ hostKeys: [pair.private] }, (client) => {
    client.on('authentication', (ctx) => {
      attempts.push(ctx.method);
      ctx.reject(rejectMethods);
    });
    client.on('error', () => {});
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve({
        attempts,
        fingerprint: fingerprintForPublicKey(pair.public),
        port: server.address().port,
        server,
      });
    });
  });
}

function startPasswordHomeSshServer(homeDirectory) {
  const attempts = [];
  const commands = [];
  const pair = utils.generateKeyPairSync('ed25519');
  const server = new Server({ hostKeys: [pair.private] }, (client) => {
    client.on('authentication', (ctx) => {
      attempts.push(ctx.method);
      if (ctx.method === 'password' && ctx.password === 'secret') {
        ctx.accept();
        return;
      }
      ctx.reject(['publickey', 'password']);
    });
    client.on('session', (accept) => {
      const session = accept();
      session.on('exec', (acceptExec, rejectExec, info) => {
        commands.push(info.command);
        const stream = acceptExec();
        if (info.command === 'printf %s "$HOME"') {
          stream.write(homeDirectory);
        } else {
          stream.write('ok');
        }
        setImmediate(() => {
          stream.exit(0);
          stream.end();
        });
      });
    });
    client.on('error', () => {});
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve({
        attempts,
        commands,
        fingerprint: fingerprintForPublicKey(pair.public),
        port: server.address().port,
        server,
      });
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

describe('ssh', () => {
  after(() => cleanupTempConfig(tempDir));

  describe('parseSSHUrl', () => {
    it('parses ssh://<account>@<host>', () => {
      const result = parseSSHUrl('ssh://account-a@node-a');
      assert.equal(result.username, 'account-a');
      assert.equal(result.hostname, 'node-a');
      assert.equal(result.port, 22);
    });

    it('parses ssh://<account>@<host>:port', () => {
      const result = parseSSHUrl('ssh://account-b@node-b:2222');
      assert.equal(result.username, 'account-b');
      assert.equal(result.hostname, 'node-b');
      assert.equal(result.port, 2222);
    });

    it('throws on invalid URL format', () => {
      assert.throws(() => parseSSHUrl('http://example.com'), /Invalid SSH URL/);
    });

    it('throws on missing user', () => {
      assert.throws(() => parseSSHUrl('ssh://hostname'), /Invalid SSH URL/);
    });

    it('throws on empty string', () => {
      assert.throws(() => parseSSHUrl(''), /Invalid SSH URL/);
    });

    it('handles hostname with hyphens and numbers', () => {
      const result = parseSSHUrl('ssh://account-c@node-243');
      assert.equal(result.hostname, 'node-243');
    });

    it('normalizes discovered .local hostnames', () => {
      const result = parseSSHUrl('ssh://account-d@desktop.local.');
      assert.equal(result.hostname, 'desktop.local');
      assert.equal(result.port, 22);
    });

    it('collapses duplicated .local suffixes from stale UI input', () => {
      const result = parseSSHUrl('ssh://account-e@node-243.local.local');
      assert.equal(result.hostname, 'node-243.local');
      assert.equal(resolveTargetHost(result.hostname), 'node-243.local');
    });

    it('rejects invalid account names', () => {
      assert.throws(() => parseSSHUrl('ssh://bad account@node-a'), /Invalid SSH account name/);
    });

    it('rejects invalid host names', () => {
      assert.throws(() => parseSSHUrl('ssh://account-a@node-a\nHost evil'), /Invalid SSH host/);
    });

    it('rejects out-of-range SSH ports', () => {
      assert.throws(() => parseSSHUrl('ssh://account-a@node-a:0'), /Invalid SSH port/);
      assert.throws(() => parseSSHUrl('ssh://account-a@node-a:65536'), /Invalid SSH port/);
    });
  });

  describe('validatePort', () => {
    it('accepts valid integer ports', () => {
      assert.equal(validatePort('1'), 1);
      assert.equal(validatePort(65535), 65535);
    });

    it('rejects invalid ports', () => {
      assert.throws(() => validatePort('abc'), /Invalid port/);
      assert.throws(() => validatePort(true), /Invalid port/);
      assert.throws(() => validatePort([22]), /Invalid port/);
      assert.throws(() => validatePort(0), /Invalid port/);
      assert.throws(() => validatePort(65536), /Invalid port/);
    });
  });

  describe('normalizeRemoteDirectory', () => {
    it('accepts absolute remote directories without control characters', () => {
      assert.equal(normalizeRemoteDirectory('/Users/account-a/projects'), '/Users/account-a/projects');
      assert.equal(normalizeRemoteDirectory(' /home/account-a '), '/home/account-a');
    });

    it('rejects relative paths and control characters', () => {
      assert.equal(normalizeRemoteDirectory('relative/path'), '');
      assert.equal(normalizeRemoteDirectory('/home/account-a\nProxyCommand bad'), '');
      assert.equal(normalizeRemoteDirectory(`/home/${'a'.repeat(4100)}`), '');
    });
  });

  describe('resolveTargetHost', () => {
    it('adds .local for bare mDNS hostnames', () => {
      assert.equal(resolveTargetHost('raspberrypi'), 'raspberrypi.local');
    });

    it('does not duplicate .local for discovered hosts', () => {
      assert.equal(resolveTargetHost('desktop.local'), 'desktop.local');
    });

    it('leaves ip addresses unchanged', () => {
      assert.equal(resolveTargetHost('192.168.1.25'), '192.168.1.25');
    });
  });

  describe('buildCreateDeviceAuthError', () => {
    it('explains first-time setup when no password is provided', () => {
      assert.equal(
        buildCreateDeviceAuthError({ username: 'account-a', targetHost: 'node-243.local', hasPassword: false }),
        "Authentication failed for account-a@node-243.local. Use the device's real SSH username, and if this is a first-time connection enter its password so Open Sync can install your SSH key."
      );
    });

    it('mentions invalid password or username when a password was supplied', () => {
      assert.equal(
        buildCreateDeviceAuthError({ username: 'account-a', targetHost: 'node-243.local', hasPassword: true }),
        'Authentication failed for account-a@node-243.local. Verify the SSH username and password for this device.'
      );
    });
  });

  describe('password key installation', () => {
    it('builds a shell-valid public key install command', () => {
      const command = buildInstallPublicKeyCommand('ssh-ed25519 AAAATEST open-sync');
      const result = spawnSync('sh', ['-n'], {
        input: command,
        encoding: 'utf-8',
      });
      assert.equal(result.status, 0, result.stderr);
      assert.match(command, /grep -qxF/);
      assert.match(command, /chmod 600 ~\/.ssh\/authorized_keys/);
    });

    it('answers only one hidden keyboard-interactive password prompt', () => {
      assert.deepStrictEqual(buildKeyboardInteractiveResponses([{ prompt: 'Passphrase?', echo: false }], 'sample-pass'), ['sample-pass']);
      assert.deepStrictEqual(buildKeyboardInteractiveResponses([{ prompt: 'Passphrase?', echo: true }], 'sample-pass'), []);
      assert.deepStrictEqual(buildKeyboardInteractiveResponses([{ prompt: 'Passphrase?', echo: false }, { prompt: 'OTP:', echo: false }], 'sample-pass'), []);
    });

    it('rejects when the remote command exits non-zero', async () => {
      const stream = new PassThrough();
      stream.stderr = new PassThrough();
      const conn = {
        exec(command, callback) {
          callback(null, stream);
          setImmediate(() => {
            stream.stderr.emit('data', Buffer.from('permission denied'));
            stream.emit('close', 1);
          });
        },
      };

      await assert.rejects(() => execSshCommand(conn, 'false'), /exit code 1: permission denied/);
    });
  });

  describe('createDevice auth flow', () => {
    it('does not request keyboard-interactive auth when no password is supplied', async () => {
      const { attempts, fingerprint, port, server } = await startRejectingSshServer();

      try {
        await assert.rejects(
          () => createDevice(`ssh://account-a@127.0.0.1:${port}`, '', { expectedHostFingerprint: fingerprint }),
          /if this is a first-time connection enter its password/,
        );
        assert.ok(attempts.includes('none'));
        assert.ok(attempts.includes('publickey'));
        assert.equal(attempts.includes('keyboard-interactive'), false);
      } finally {
        await closeServer(server);
      }
    });

    it('persists the remote home directory after first-time key setup', async () => {
      const { commands, fingerprint, port, server } = await startPasswordHomeSshServer('/Users/account-a');

      try {
        const device = await createDevice(
          `ssh://account-a@127.0.0.1:${port}`,
          'secret',
          { expectedHostFingerprint: fingerprint },
        );

        assert.equal(device.homeDirectory, '/Users/account-a');
        assert.equal(device.path, '/Users/account-a');
        assert.ok(commands.includes('printf %s "$HOME"'));
      } finally {
        await closeServer(server);
      }
    });

    it('falls back when the remote home directory contains control characters', async () => {
      const { fingerprint, port, server } = await startPasswordHomeSshServer('/Users/account-a\nHost evil');

      try {
        const device = await createDevice(
          `ssh://account-a@127.0.0.1:${port}`,
          'secret',
          { expectedHostFingerprint: fingerprint },
        );

        assert.equal(device.homeDirectory, '/home/account-a');
        assert.equal(device.path, '/home/account-a');
      } finally {
        await closeServer(server);
      }
    });
  });

  describe('host key verification', () => {
    it('rejects unknown host keys before trust is confirmed', () => {
      const verifier = createHostKeyVerifier({ hostname: 'new-host', host: 'new-host.local', port: 22 });
      assert.equal(verifier.hostVerifier(testHostPublicKey()), false);
      const err = verifier.getError();
      assert.equal(err.code, 'HOST_KEY_TRUST_REQUIRED');
      assert.ok(err.fingerprint.startsWith('SHA256:'));
    });

    it('accepts and normalizes a confirmed host fingerprint', () => {
      const publicKey = testHostPublicKey();
      const first = createHostKeyVerifier({ hostname: 'trusted-host', host: 'trusted-host.local', port: 22 });
      assert.equal(first.hostVerifier(publicKey), false);
      const fingerprint = first.getError().fingerprint;

      const confirmed = createHostKeyVerifier({
        hostname: 'trusted-host',
        host: 'trusted-host.local',
        port: 22,
        expectedHostFingerprint: normalizeHostFingerprint(fingerprint),
      });
      assert.equal(confirmed.hostVerifier(publicKey), true);
      assert.equal(confirmed.getTrustedHostKey().fingerprint, fingerprint);
    });

    it('accepts a new hostname when the exact host key is already pinned', () => {
      const publicKey = testHostPublicKey();
      const fingerprint = fingerprintForPublicKey(publicKey);
      const state = loadState();
      state.knownHosts['192.168.1.104:22'] = {
        hostname: '192.168.1.104',
        host: '192.168.1.104',
        port: 22,
        fingerprint,
        keyType: 'ssh-ed25519',
        publicKey: publicKey.toString('base64'),
      };
      saveState(state);

      const verifier = createHostKeyVerifier({
        hostname: 'Bojans-Mac-mini.local',
        host: 'Bojans-Mac-mini.local',
        port: 22,
      });

      assert.equal(verifier.hostVerifier(publicKey), true);
      assert.equal(verifier.getTrustedHostKey().hostname, 'Bojans-Mac-mini.local');
      assert.equal(verifier.getTrustedHostKey().fingerprint, fingerprint);
    });

    it('rejects host key changes for pinned hosts', () => {
      const firstKey = testHostPublicKey();
      const secondKey = testHostPublicKey();
      const first = createHostKeyVerifier({ hostname: 'pinned-host', host: 'pinned-host.local', port: 22 });
      assert.equal(first.hostVerifier(firstKey), false);
      const fingerprint = first.getError().fingerprint;

      const state = loadState();
      state.knownHosts['pinned-host:22'] = {
        hostname: 'pinned-host',
        host: 'pinned-host.local',
        port: 22,
        fingerprint,
        keyType: 'ssh-ed25519',
        publicKey: firstKey.toString('base64'),
      };
      saveState(state);

      const verifier = createHostKeyVerifier({ hostname: 'pinned-host', host: 'pinned-host.local', port: 22 });
      assert.equal(verifier.hostVerifier(secondKey), false);
      assert.equal(verifier.getError().code, 'HOST_KEY_CHANGED');
    });
  });

  describe('generated ssh config', () => {
    it('rejects invalid stored SSH ports before writing config', () => {
      const state = loadState();
      upsertDevice(state, {
        hostname: 'config-host',
        username: 'account-a',
        sshPort: '22\nProxyCommand bad',
        status: 'disconnected',
      });
      saveState(state);

      assert.throws(
        () => updateDeviceConnectionState('config-host', (device) => { device.status = 'connected'; }, { writeConfig: true }),
        /Invalid SSH port/,
      );

      if (existsSync(SSH_CONFIG_PATH)) {
        assert.doesNotMatch(readFileSync(SSH_CONFIG_PATH, 'utf-8'), /ProxyCommand bad/);
      }
      removeDevice(state, 'config-host');
      saveState(state);
    });
  });

  describe('getStatus', () => {
    it('returns NOT_FOUND for unknown device', () => {
      const status = getStatus('nonexistent');
      assert.equal(status.status, 'NOT_FOUND');
      assert.ok(status.error.includes('not found'));
    });

    it('returns DISCONNECTED for a known but unconnected device', () => {
      const state = loadState();
      upsertDevice(state, { hostname: 'test-device', username: 'u', status: 'disconnected' });
      saveState(state);

      const status = getStatus('test-device');
      assert.equal(status.status, 'DISCONNECTED');
      assert.deepStrictEqual(status.ports, {});
    });

    it('returns ERROR for a known device with a stored connection error', () => {
      const state = loadState();
      upsertDevice(state, { hostname: 'error-device', username: 'u', status: 'error', error: 'boom' });
      saveState(state);

      const status = getStatus('error-device');
      assert.equal(status.status, 'ERROR');
      assert.equal(status.error, 'boom');
    });
  });

  describe('updateDeviceConnectionState', () => {
    it('preserves state changes made after a connection attempt starts', () => {
      const initial = loadState();
      upsertDevice(initial, {
        hostname: 'race-host',
        username: 'u',
        status: 'disconnected',
        path: '/home/u/old',
      });
      saveState(initial);

      const concurrent = loadState();
      const device = concurrent.devices.find((entry) => entry.hostname === 'race-host');
      device.path = '/home/u/new';
      concurrent.openPorts['other-host'] = [8888];
      concurrent.tools.push({ id: 'custom', name: 'Custom', available: true });
      saveState(concurrent);

      const updated = updateDeviceConnectionState('race-host', (currentDevice) => {
        currentDevice.status = 'connected';
        delete currentDevice.error;
      });

      assert.equal(updated.status, 'connected');

      const refreshed = loadState();
      const refreshedDevice = refreshed.devices.find((entry) => entry.hostname === 'race-host');
      assert.equal(refreshedDevice.status, 'connected');
      assert.equal(refreshedDevice.path, '/home/u/new');
      assert.deepStrictEqual(refreshed.openPorts['other-host'], [8888]);
      assert.ok(refreshed.tools.some((tool) => tool.id === 'custom'));
    });

    it('does not recreate a device removed before an async connection finishes', () => {
      const state = loadState();
      upsertDevice(state, { hostname: 'removed-race-host', username: 'u', status: 'disconnected' });
      saveState(state);

      const removed = loadState();
      removeDevice(removed, 'removed-race-host');
      saveState(removed);

      const updated = updateDeviceConnectionState('removed-race-host', (currentDevice) => {
        currentDevice.status = 'connected';
      });

      assert.equal(updated, null);
      assert.equal(loadState().devices.some((entry) => entry.hostname === 'removed-race-host'), false);
    });
  });

  describe('openTunnel', () => {
    it('rejects invalid remote ports before opening a tunnel', async () => {
      await assert.rejects(() => openTunnel('test-device', 0), /Invalid remote port/);
      await assert.rejects(() => openTunnel('test-device', 65536), /Invalid remote port/);
    });
  });

  describe('disconnect', () => {
    it('returns DISCONNECTED even if not connected', () => {
      const state = loadState();
      upsertDevice(state, { hostname: 'offline-host', username: 'u', status: 'disconnected' });
      saveState(state);

      const result = disconnect('offline-host');
      assert.equal(result.status, 'DISCONNECTED');
      assert.equal(result.hostname, 'offline-host');
    });

    it('handles disconnecting unknown host gracefully', () => {
      const result = disconnect('totally-unknown');
      assert.equal(result.status, 'DISCONNECTED');
    });

    it('clears stored error and open port metadata', () => {
      const state = loadState();
      upsertDevice(state, {
        hostname: 'broken-host',
        username: 'u',
        status: 'error',
        error: 'Authentication failed',
      });
      state.openPorts['broken-host'] = [8888];
      saveState(state);

      const result = disconnect('broken-host');
      assert.equal(result.status, 'DISCONNECTED');

      const refreshed = loadState();
      const device = refreshed.devices.find((entry) => entry.hostname === 'broken-host');
      assert.equal(device.status, 'disconnected');
      assert.equal(device.error, undefined);
      assert.equal(refreshed.openPorts['broken-host'], undefined);

      const status = getStatus('broken-host');
      assert.equal(status.error, '');
    });
  });

  describe('getConnections', () => {
    it('returns a Map', () => {
      const conns = getConnections();
      assert.ok(conns instanceof Map);
    });

    it('is empty when no connections are active', () => {
      const conns = getConnections();
      assert.equal(conns.size, 0);
    });

    it('clears failed pending connection attempts', async () => {
      await assert.rejects(() => connect('missing-host'), /not found/);
      assert.equal(getPendingConnections().size, 0);
    });
  });
});
