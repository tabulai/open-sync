import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, rmSync, statSync, writeFileSync } from 'fs';
import { setupTempConfig, cleanupTempConfig } from './helpers.js';

const tempDir = setupTempConfig();

const { ensureKeyPair, getPrivateKey, getPublicKey, normalizePublicKey } = await import('../src/core/keys.js');
const { SSH_KEY_PATH, SSH_PUB_KEY_PATH } = await import('../src/core/paths.js');

describe('keys', () => {
  after(() => cleanupTempConfig(tempDir));

  describe('ensureKeyPair', () => {
    it('generates a new key pair when none exists', () => {
      const keys = ensureKeyPair();
      assert.ok(keys.privateKey.includes('BEGIN OPENSSH PRIVATE KEY'));
      assert.ok(keys.publicKey.includes('ssh-ed25519'));
      assert.match(keys.publicKey, /\sopen-sync\n$/);
    });

    it('creates key files on disk', () => {
      ensureKeyPair();
      assert.ok(existsSync(SSH_KEY_PATH));
      assert.ok(existsSync(SSH_PUB_KEY_PATH));
    });

    it('sets private key file permissions to 0600', () => {
      ensureKeyPair();
      const mode = statSync(SSH_KEY_PATH).mode & 0o777;
      assert.equal(mode, 0o600);
    });

    it('returns existing keys on second call', () => {
      const first = ensureKeyPair();
      const second = ensureKeyPair();
      assert.equal(first.privateKey, second.privateKey);
      assert.equal(first.publicKey, second.publicKey);
    });

    it('repairs private key permissions for existing keys', () => {
      ensureKeyPair();
      chmodSync(SSH_KEY_PATH, 0o644);
      ensureKeyPair();
      const mode = statSync(SSH_KEY_PATH).mode & 0o777;
      assert.equal(mode, 0o600);
    });

    it('regenerates a missing public key from the private key', () => {
      ensureKeyPair();
      rmSync(SSH_PUB_KEY_PATH, { force: true });

      const keys = ensureKeyPair();
      assert.ok(existsSync(SSH_PUB_KEY_PATH));
      assert.ok(keys.publicKey.includes('ssh-ed25519'));
      assert.match(keys.publicKey, /\sopen-sync\n$/);
    });

    it('removes local username and host comments from existing public keys', () => {
      const keys = ensureKeyPair();
      const [type, body] = keys.publicKey.trim().split(/\s+/);
      writeFileSync(SSH_PUB_KEY_PATH, `${type} ${body} local-user@private-host\n`);

      assert.equal(ensureKeyPair().publicKey, `${type} ${body} open-sync\n`);
    });
  });

  describe('getPrivateKey', () => {
    it('returns the private key as a string', () => {
      ensureKeyPair();
      const key = getPrivateKey();
      assert.ok(key.includes('BEGIN OPENSSH PRIVATE KEY'));
    });
  });

  describe('getPublicKey', () => {
    it('returns the public key as a string', () => {
      ensureKeyPair();
      const key = getPublicKey();
      assert.ok(key.includes('ssh-ed25519'));
      assert.match(key, /\sopen-sync\n$/);
    });

    it('normalizes public key comments', () => {
      assert.equal(
        normalizePublicKey('ssh-ed25519 AAAATEST local-user@private-host'),
        'ssh-ed25519 AAAATEST open-sync\n',
      );
    });
  });
});
