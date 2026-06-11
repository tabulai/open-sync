function parseUrl(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isSafeExternalUrl(value) {
  const url = parseUrl(value);
  return Boolean(url && ['https:', 'mailto:'].includes(url.protocol));
}

function isAllowedAppUrl(value, port) {
  const url = parseUrl(value);
  if (!url || !port) return false;
  return url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname) && url.port === String(port);
}

export { isAllowedAppUrl, isSafeExternalUrl };
