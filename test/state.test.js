import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, readdirSync, rmSync, statSync, writeFileSync } from 'fs';
import { setupTempConfig, cleanupTempConfig } from './helpers.js';

const tempDir = setupTempConfig();

const { loadState, saveState, getDevice, upsertDevice, removeDevice, DEFAULT_STATE } = await import('../src/core/state.js');
const { CONFIG_DIR, STATE_PATH, ensureConfigDir } = await import('../src/core/paths.js');

describe('state', () => {
  after(() => cleanupTempConfig(tempDir));

  describe('loadState', () => {
    it('returns default state when no file exists', () => {
      const state = loadState();
      assert.deepStrictEqual(state.devices, []);
      assert.ok(Array.isArray(state.tools));
      assert.ok(state.tools.length > 0);
    });

    it('returns saved state after saveState', () => {
      const state = loadState();
      state.devices.push({ hostname: 'test-host', username: 'account-1' });
      saveState(state);

      const loaded = loadState();
      assert.equal(loaded.devices.length, 1);
      assert.equal(loaded.devices[0].hostname, 'test-host');
    });

    it('returns a fresh default state without shared nested references', () => {
      const baseline = JSON.parse(JSON.stringify(DEFAULT_STATE));

      rmSync(STATE_PATH, { force: true });
      const first = loadState();
      first.tools[0].available = false;
      first.openPorts.demo = [8888];

      rmSync(STATE_PATH, { force: true });
      const second = loadState();
      assert.deepStrictEqual(second, baseline);
    });

    it('throws instead of resetting state when state JSON is corrupt', () => {
      writeFileSync(STATE_PATH, '{not-json');
      try {
        assert.throws(() => loadState(), /Failed to load Open Sync state/);
      } finally {
        rmSync(STATE_PATH, { force: true });
      }
    });

    it('writes state atomically without leaving temp files behind', () => {
      const state = loadState();
      state.devices.push({ hostname: 'atomic-host', username: 'u' });
      saveState(state);

      const tempFiles = readdirSync(CONFIG_DIR).filter((entry) => entry.includes('.tmp'));
      assert.deepStrictEqual(tempFiles, []);
      assert.equal(loadState().devices.some((device) => device.hostname === 'atomic-host'), true);
    });

    it('forces the config directory to 0700', () => {
      chmodSync(CONFIG_DIR, 0o755);
      ensureConfigDir();
      assert.equal(statSync(CONFIG_DIR).mode & 0o777, 0o700);
    });
  });

  describe('getDevice', () => {
    it('finds a device by hostname', () => {
      const state = { devices: [{ hostname: 'a' }, { hostname: 'b' }] };
      assert.equal(getDevice(state, 'b').hostname, 'b');
    });

    it('returns undefined for unknown hostname', () => {
      const state = { devices: [{ hostname: 'a' }] };
      assert.equal(getDevice(state, 'z'), undefined);
    });
  });

  describe('upsertDevice', () => {
    it('adds a new device', () => {
      const state = { devices: [] };
      upsertDevice(state, { hostname: 'new', username: 'u' });
      assert.equal(state.devices.length, 1);
      assert.equal(state.devices[0].hostname, 'new');
    });

    it('updates an existing device by hostname', () => {
      const state = { devices: [{ hostname: 'x', status: 'disconnected' }] };
      upsertDevice(state, { hostname: 'x', status: 'connected' });
      assert.equal(state.devices.length, 1);
      assert.equal(state.devices[0].status, 'connected');
    });

    it('merges fields when updating', () => {
      const state = { devices: [{ hostname: 'x', username: 'u', status: 'disconnected' }] };
      upsertDevice(state, { hostname: 'x', status: 'connected' });
      assert.equal(state.devices[0].username, 'u');
      assert.equal(state.devices[0].status, 'connected');
    });
  });

  describe('removeDevice', () => {
    it('removes a device by hostname', () => {
      const state = { devices: [{ hostname: 'a' }, { hostname: 'b' }], openPorts: { a: [8080] } };
      removeDevice(state, 'a');
      assert.equal(state.devices.length, 1);
      assert.equal(state.devices[0].hostname, 'b');
    });

    it('removes associated openPorts', () => {
      const state = { devices: [{ hostname: 'a' }], openPorts: { a: [8080], b: [9090] } };
      removeDevice(state, 'a');
      assert.equal(state.openPorts.a, undefined);
      assert.deepStrictEqual(state.openPorts.b, [9090]);
    });

    it('handles removing non-existent device gracefully', () => {
      const state = { devices: [{ hostname: 'a' }], openPorts: {} };
      removeDevice(state, 'zzz');
      assert.equal(state.devices.length, 1);
    });
  });

  describe('DEFAULT_STATE', () => {
    it('has expected tool ids', () => {
      const ids = DEFAULT_STATE.tools.map(t => t.id);
      assert.ok(ids.includes('terminal'));
      assert.ok(ids.includes('editor'));
      assert.ok(ids.includes('jupyter'));
    });
  });
});
