import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';

describe('macOS packaging', () => {
  it('declares local network permissions required for SSH discovery', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    const extendInfo = pkg.build?.mac?.extendInfo || {};

    assert.match(
      extendInfo.NSLocalNetworkUsageDescription || '',
      /local network/i,
    );
    assert.deepEqual(extendInfo.NSBonjourServices, ['_ssh._tcp']);
  });

  it('ad-hoc signs local macOS artifacts so Info.plist is bound to the app identity', () => {
    const installer = readFileSync(new URL('../scripts/build-and-install-macos.sh', import.meta.url), 'utf8');

    assert.match(installer, /codesign --force --deep --sign -/);
    assert.match(installer, /codesign --verify --deep --strict/);
  });

  it('ships a custom macOS app icon instead of relying on Electron defaults', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    const iconPath = new URL('../build/icon.icns', import.meta.url);

    assert.equal(pkg.build?.mac?.icon, 'build/icon.icns');
    assert.equal(existsSync(iconPath), true);
    assert.ok(statSync(iconPath).size > 1024);
  });
});
