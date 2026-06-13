import { Bonjour } from 'bonjour-service';
import { Socket } from 'node:net';
import { networkInterfaces } from 'node:os';
import { extractDiscoveryUsername, normalizeHostname } from './hosts.js';

const SSH_PORT = 22;
const SCAN_CONCURRENCY = 64;
const MAX_SCAN_TARGETS_PER_INTERFACE = 1024;
const MAX_MDNS_DISCOVERY_HOSTS = 256;
const MAX_DISCOVERY_FIELD_LENGTH = 256;
const MAX_DISCOVERY_ADDRESSES = 16;
const MAX_DISCOVERY_TXT_KEYS = 16;
const MIN_PROBE_TIMEOUT_MS = 75;
const MAX_PROBE_TIMEOUT_MS = 400;

async function discover(timeoutSec = 3, iface) {
  const timeoutMs = normalizeTimeout(timeoutSec);
  const [advertisedHosts, probedHosts] = await Promise.all([
    discoverAdvertisedHosts(timeoutMs),
    discoverOpenSshPorts(timeoutMs, iface),
  ]);

  return mergeDiscoveredHosts([...advertisedHosts, ...probedHosts]);
}

function discoverAdvertisedHosts(timeoutMs) {
  return new Promise((resolve) => {
    const hosts = [];
    let bonjour;
    let browser;

    try {
      // Without an error callback, bonjour-service rethrows async mDNS
      // socket errors (e.g. EADDRINUSE on 5353), crashing the process.
      // Treat them as "no mDNS results" — the TCP probe still runs.
      bonjour = new Bonjour(undefined, () => {});
      browser = bonjour.find({ type: 'ssh' }, (service) => {
        if (hosts.length >= MAX_MDNS_DISCOVERY_HOSTS) return;
        const host = normalizeAdvertisedHost(service);
        if (host) {
          hosts.push(host);
        }
      });
    } catch {
      resolve(hosts);
      return;
    }

    setTimeout(() => {
      browser?.stop();
      bonjour?.destroy();
      resolve(hosts);
    }, timeoutMs);
  });
}

function truncateDiscoveryField(value = '') {
  return String(value || '').replace(/\0/g, '').slice(0, MAX_DISCOVERY_FIELD_LENGTH);
}

function normalizeDiscoveredAddresses(addresses = []) {
  if (!Array.isArray(addresses)) return [];
  return addresses
    .filter((address) => typeof address === 'string' && address.trim())
    .slice(0, MAX_DISCOVERY_ADDRESSES)
    .map((address) => truncateDiscoveryField(address.trim()));
}

function normalizeDiscoveryTxt(txt = {}) {
  if (!txt || typeof txt !== 'object' || Array.isArray(txt)) return {};
  return Object.fromEntries(
    Object.entries(txt)
      .filter(([key, value]) => typeof key === 'string' && typeof value === 'string')
      .slice(0, MAX_DISCOVERY_TXT_KEYS)
      .map(([key, value]) => [truncateDiscoveryField(key), truncateDiscoveryField(value.trim())]),
  );
}

function normalizeAdvertisedHost(service = {}) {
  const host = truncateDiscoveryField(normalizeHostname(service.host));
  const port = service.port;
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }

  const txt = normalizeDiscoveryTxt(service.txt);
  return {
    name: truncateDiscoveryField(service.name || host),
    host,
    port,
    addresses: normalizeDiscoveredAddresses(service.addresses),
    txt,
    suggestedUsername: extractDiscoveryUsername(txt),
    source: 'mdns',
  };
}

async function discoverOpenSshPorts(timeoutMs, iface) {
  const targets = getScanTargets(iface);
  if (!targets.length) return [];

  const batches = Math.max(1, Math.ceil(targets.length / SCAN_CONCURRENCY));
  const probeTimeoutMs = Math.min(
    MAX_PROBE_TIMEOUT_MS,
    Math.max(MIN_PROBE_TIMEOUT_MS, Math.floor((timeoutMs - 50) / batches)),
  );
  const openHosts = [];

  for (let index = 0; index < targets.length; index += SCAN_CONCURRENCY) {
    const batch = targets.slice(index, index + SCAN_CONCURRENCY);
    const results = await Promise.all(
      batch.map(async (address) => {
        const isOpen = await probeSshPort(address, SSH_PORT, probeTimeoutMs);
        return isOpen ? address : '';
      }),
    );
    openHosts.push(...results.filter(Boolean));
  }

  return openHosts.map((address) => ({
    name: `SSH at ${address}`,
    host: address,
    port: SSH_PORT,
    addresses: [address],
    txt: {},
    suggestedUsername: '',
    source: 'tcp',
  }));
}

function probeSshPort(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new Socket();
    let settled = false;
    let banner = '';

    const finish = (isOpen) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(isOpen);
    };

    socket.setTimeout(timeoutMs);
    socket.on('data', (chunk) => {
      banner += chunk.toString('utf8');
      if (banner.includes('\n') || banner.length > 255) {
        finish(banner.trimStart().startsWith('SSH-'));
      }
    });
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.once('close', () => finish(false));
    socket.connect({ host, port });
  });
}

function getScanTargets(iface) {
  const targets = new Set();
  const interfaces = networkInterfaces();
  const entries = iface ? { [iface]: interfaces[iface] || [] } : interfaces;

  for (const [name, addresses] of Object.entries(entries)) {
    for (const address of addresses || []) {
      if (!isScannableIPv4Interface(name, address)) continue;
      for (const target of getInterfaceScanTargets(address)) {
        targets.add(target);
      }
    }
  }

  return [...targets].sort(compareIPv4);
}

function getInterfaceScanTargets(address) {
  const ip = ipv4ToInt(address.address);
  const mask = ipv4ToInt(address.netmask);
  if (ip === null || mask === null) return [];

  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const hostCount = Math.max(0, broadcast - network - 1);
  if (!hostCount) return [];

  const ranges = [];
  if (hostCount <= MAX_SCAN_TARGETS_PER_INTERFACE) {
    ranges.push([network + 1, broadcast - 1]);
  } else {
    const classCNetwork = (ip & 0xffffff00) >>> 0;
    ranges.push([classCNetwork + 1, classCNetwork + 254]);
  }

  const targets = [];
  for (const [start, end] of ranges) {
    for (let current = start; current <= end; current += 1) {
      if (current === ip) continue;
      targets.push(intToIPv4(current));
    }
  }
  return targets;
}

function isScannableIPv4Interface(name, address) {
  return (
    address &&
    address.family === 'IPv4' &&
    !address.internal &&
    address.address &&
    address.netmask &&
    !name.startsWith('utun') &&
    isPrivateIPv4(address.address)
  );
}

function mergeDiscoveredHosts(hosts) {
  const byHostPort = new Map();
  const mdnsAddresses = new Set(
    hosts
      .filter((host) => host.source === 'mdns')
      .flatMap((host) => host.addresses || [])
      .filter((address) => typeof address === 'string'),
  );

  for (const host of hosts) {
    if (host.source === 'tcp' && mdnsAddresses.has(host.host)) continue;
    const key = `${host.host}:${host.port}`;
    if (!byHostPort.has(key)) {
      byHostPort.set(key, host);
    }
  }

  return [...byHostPort.values()].sort((a, b) => {
    if (a.source !== b.source) return a.source === 'mdns' ? -1 : 1;
    return compareDiscoveryHost(a.host, b.host);
  });
}

function normalizeTimeout(timeoutSec) {
  const timeout = Number(timeoutSec);
  if (!Number.isFinite(timeout) || timeout <= 0) return 3000;
  return Math.max(250, Math.floor(timeout * 1000));
}

function isPrivateIPv4(address) {
  const parts = address.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [first, second] = parts;
  return (
    first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 169 && second === 254)
  );
}

function ipv4ToInt(address) {
  const parts = address.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return parts.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
}

function intToIPv4(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
}

function compareIPv4(a, b) {
  return (ipv4ToInt(a) ?? 0) - (ipv4ToInt(b) ?? 0);
}

function compareDiscoveryHost(a, b) {
  const aInt = ipv4ToInt(a);
  const bInt = ipv4ToInt(b);
  if (aInt !== null && bInt !== null) return aInt - bInt;
  return String(a).localeCompare(String(b));
}

export {
  discover,
  getInterfaceScanTargets,
  normalizeAdvertisedHost,
  isPrivateIPv4,
  mergeDiscoveredHosts,
  normalizeTimeout,
};
