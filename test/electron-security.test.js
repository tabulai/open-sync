import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const { isAllowedAppUrl, isSafeExternalUrl } = await import('../src/electron/security.js');

describe('electron security helpers', () => {
  it('allows only safe external protocols', () => {
    assert.equal(isSafeExternalUrl('https://example.com/docs'), true);
    assert.equal(isSafeExternalUrl('http://example.com/docs'), false);
    assert.equal(isSafeExternalUrl('mailto:help@example.com'), true);
    assert.equal(isSafeExternalUrl('file:///etc/passwd'), false);
    assert.equal(isSafeExternalUrl('open-sync://device'), false);
    assert.equal(isSafeExternalUrl('not a url'), false);
  });

  it('allows app navigation only to the local Open Sync server port', () => {
    assert.equal(isAllowedAppUrl('http://localhost:8384/', 8384), true);
    assert.equal(isAllowedAppUrl('http://127.0.0.1:8384/index.html', 8384), true);
    assert.equal(isAllowedAppUrl('http://localhost:8385/', 8384), false);
    assert.equal(isAllowedAppUrl('https://localhost:8384/', 8384), false);
    assert.equal(isAllowedAppUrl('http://attacker.example:8384/', 8384), false);
  });
});
