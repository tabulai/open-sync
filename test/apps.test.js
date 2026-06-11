import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { setupTempConfig, cleanupTempConfig } from './helpers.js';

const tempDir = setupTempConfig();
process.env.OPEN_DASHBOARD_DIR = '/tmp/open-dashboard';
process.env.OPEN_DASHBOARD_PORT = '5199';

const {
  OPEN_DASHBOARD_DIR,
  OPEN_DASHBOARD_PORT,
  buildDashboardApiHeaders,
  buildDashboardConnectionConfig,
  buildTerminalCommand,
  extractDashboardApiToken,
  getDashboardUrl,
  normalizeDashboardUrl,
} = await import('../src/core/apps.js');
const { SSH_CONFIG_PATH, SSH_KEY_PATH } = await import('../src/core/paths.js');

describe('apps', () => {
  after(() => {
    delete process.env.OPEN_DASHBOARD_DIR;
    delete process.env.OPEN_DASHBOARD_PORT;
    cleanupTempConfig(tempDir);
  });

  it('builds a terminal ssh command using the generated ssh config', () => {
    const command = buildTerminalCommand({ hostname: 'node-101.local' });
    assert.equal(command, `ssh -F '${SSH_CONFIG_PATH}' 'node-101.local'`);
  });

  it('builds an Open Dashboard connection config from a device', () => {
    const config = buildDashboardConnectionConfig({
      hostname: 'node-101',
      username: 'account-name',
      path: '/home/remote/work',
    });

    assert.deepStrictEqual(config, {
      host: 'node-101.local',
      username: 'account-name',
      authMethod: 'key',
      sshKeyPath: SSH_KEY_PATH,
      localPort: 8888,
      remotePort: 8888,
      workingDir: '/home/remote/work',
    });
  });

  it('falls back when dashboard working directory state is unsafe', () => {
    const config = buildDashboardConnectionConfig({
      hostname: 'node-101',
      username: 'account-name',
      path: '/home/remote\nProxyCommand bad',
      homeDirectory: '/home/account-name',
    });

    assert.equal(config.workingDir, '/home/account-name');
  });

  it('uses the configured dashboard location and url', () => {
    assert.equal(OPEN_DASHBOARD_DIR, '/tmp/open-dashboard');
    assert.equal(OPEN_DASHBOARD_PORT, 5199);
    assert.equal(getDashboardUrl(), 'http://127.0.0.1:5199');
  });

  it('allows only local dashboard URLs', () => {
    assert.equal(normalizeDashboardUrl('http://localhost:5199/path'), 'http://localhost:5199');
    assert.equal(normalizeDashboardUrl('http://127.0.0.1:5199'), 'http://127.0.0.1:5199');
    assert.equal(normalizeDashboardUrl('http://[::1]:5199'), 'http://[::1]:5199');
    assert.throws(() => normalizeDashboardUrl('https://localhost:5199'), /localhost HTTP URL|http:\/\/localhost/);
    assert.throws(() => normalizeDashboardUrl('http://dashboard.example'), /localhost HTTP URL|http:\/\/localhost/);
    assert.throws(() => normalizeDashboardUrl('http://user:pass@localhost:5199'), /localhost HTTP URL|http:\/\/localhost/);
  });

  it('extracts the Open Dashboard API token from runtime config', () => {
    const html = '<html><head><script>window.__OPEN_DASHBOARD__ = {"apiToken":"abc123"};</script></head></html>';
    assert.equal(extractDashboardApiToken(html), 'abc123');
    assert.equal(extractDashboardApiToken('<html></html>'), '');
  });

  it('builds authenticated Open Dashboard API headers', () => {
    assert.deepStrictEqual(buildDashboardApiHeaders('token-1'), {
      'x-open-dashboard-token': 'token-1',
    });
    assert.deepStrictEqual(buildDashboardApiHeaders('token-1', { write: true }), {
      'x-open-dashboard-token': 'token-1',
      'x-open-dashboard-request': '1',
    });
  });
});
