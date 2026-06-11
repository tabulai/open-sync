import { isIP } from 'node:net';

function normalizeUsername(username) {
  return String(username || '').trim();
}

function normalizeHostname(hostname) {
  return String(hostname || '')
    .trim()
    .replace(/\.+$/, '')
    .replace(/(?:\.local)+$/i, '.local');
}

function validateUsername(username) {
  const normalized = normalizeUsername(username);
  if (!normalized || !/^[A-Za-z0-9._-]+$/.test(normalized)) {
    throw new Error('Invalid SSH account name. Use letters, numbers, dots, underscores, or hyphens.');
  }
  return normalized;
}

function validateHostname(hostname) {
  const normalized = normalizeHostname(hostname);
  if (!normalized || !/^[A-Za-z0-9._-]+$/.test(normalized)) {
    throw new Error('Invalid SSH host. Use letters, numbers, dots, underscores, or hyphens.');
  }
  return normalized;
}

function resolveTargetHost(hostname) {
  const normalized = validateHostname(hostname);
  if (!normalized) return normalized;
  if (normalized === 'localhost' || normalized.includes('.') || isIP(normalized)) {
    return normalized;
  }
  return `${normalized}.local`;
}

function extractDiscoveryUsername(txt = {}) {
  const candidates = [txt.u, txt.user, txt.username, txt.login];
  const match = candidates.find((value) => typeof value === 'string' && value.trim());
  if (!match) return '';
  try {
    return validateUsername(match);
  } catch {
    return '';
  }
}

export {
  normalizeUsername,
  normalizeHostname,
  validateUsername,
  validateHostname,
  resolveTargetHost,
  extractDiscoveryUsername,
};
