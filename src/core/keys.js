import { spawnSync } from 'child_process';
import { readFileSync, existsSync, chmodSync, rmSync } from 'fs';
import { SSH_KEY_PATH, SSH_PUB_KEY_PATH, ensureConfigDir } from './paths.js';
import { writeFileAtomic } from './atomic_write.js';

const PUBLIC_KEY_COMMENT = 'open-sync';

function ensureKeyPair() {
  ensureConfigDir();
  const hasPrivateKey = existsSync(SSH_KEY_PATH);
  const hasPublicKey = existsSync(SSH_PUB_KEY_PATH);

  if (hasPrivateKey) {
    chmodSync(SSH_KEY_PATH, 0o600);
  }

  if (hasPrivateKey && !hasPublicKey) {
    regeneratePublicKey();
  }

  if (hasPrivateKey && existsSync(SSH_PUB_KEY_PATH)) {
    return {
      privateKey: readFileSync(SSH_KEY_PATH, 'utf-8'),
      publicKey: normalizePublicKeyFile(),
    };
  }

  if (!hasPrivateKey && hasPublicKey) {
    rmSync(SSH_PUB_KEY_PATH, { force: true });
  }

  // Generate an Ed25519 key pair in OpenSSH format (what ssh2 expects)
  const result = spawnSync('ssh-keygen', ['-t', 'ed25519', '-f', SSH_KEY_PATH, '-N', '', '-C', PUBLIC_KEY_COMMENT, '-q'], {
    stdio: 'ignore',
  });
  if (result.status !== 0) {
    throw new Error('Failed to generate SSH key pair.');
  }
  chmodSync(SSH_KEY_PATH, 0o600);

  return {
    privateKey: readFileSync(SSH_KEY_PATH, 'utf-8'),
    publicKey: normalizePublicKeyFile(),
  };
}

function regeneratePublicKey() {
  const result = spawnSync('ssh-keygen', ['-y', '-f', SSH_KEY_PATH], {
    encoding: 'utf-8',
  });
  if (result.status !== 0 || !result.stdout) {
    throw new Error('Failed to regenerate SSH public key.');
  }
  writeFileAtomic(SSH_PUB_KEY_PATH, normalizePublicKey(result.stdout), { mode: 0o644 });
}

function normalizePublicKey(publicKey = '') {
  const parts = String(publicKey).trim().split(/\s+/);
  if (parts.length < 2) return String(publicKey || '').trim();
  return `${parts[0]} ${parts[1]} ${PUBLIC_KEY_COMMENT}\n`;
}

function normalizePublicKeyFile() {
  const current = readFileSync(SSH_PUB_KEY_PATH, 'utf-8');
  const normalized = normalizePublicKey(current);
  if (normalized && normalized !== current) {
    writeFileAtomic(SSH_PUB_KEY_PATH, normalized, { mode: 0o644 });
  }
  return normalized;
}

function getPrivateKey() {
  if (!existsSync(SSH_KEY_PATH)) {
    ensureKeyPair();
  }
  return readFileSync(SSH_KEY_PATH, 'utf-8');
}

function getPublicKey() {
  if (!existsSync(SSH_PUB_KEY_PATH)) {
    ensureKeyPair();
  }
  return normalizePublicKeyFile();
}

export { ensureKeyPair, getPrivateKey, getPublicKey, normalizePublicKey };
