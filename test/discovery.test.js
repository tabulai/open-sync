import { before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  discover,
  getInterfaceScanTargets,
  isPrivateIPv4,
  mergeDiscoveredHosts,
  normalizeAdvertisedHost,
  normalizeTimeout,
  parseDnsSdBrowseInstances,
  parseDnsSdLookup,
} from '../src/core/discovery.js';
import { extractDiscoveryUsername, normalizeHostname } from '../src/core/hosts.js';

describe('discovery', () => {
  it('normalizes discovered hostnames', () => {
    assert.equal(normalizeHostname('device.local.'), 'device.local');
    assert.equal(normalizeHostname(' device.local '), 'device.local');
    assert.equal(normalizeHostname('device.local.local'), 'device.local');
  });

  it('extracts suggested username from ssh TXT records', () => {
    assert.equal(extractDiscoveryUsername({ u: 'remote-account' }), 'remote-account');
    assert.equal(extractDiscoveryUsername({ username: 'service-login' }), 'service-login');
    assert.equal(extractDiscoveryUsername({}), '');
  });

  it('detects private IPv4 ranges for local subnet probing', () => {
    assert.equal(isPrivateIPv4('192.168.1.164'), true);
    assert.equal(isPrivateIPv4('10.0.12.4'), true);
    assert.equal(isPrivateIPv4('172.16.0.10'), true);
    assert.equal(isPrivateIPv4('172.31.255.10'), true);
    assert.equal(isPrivateIPv4('172.32.0.10'), false);
    assert.equal(isPrivateIPv4('8.8.8.8'), false);
    assert.equal(isPrivateIPv4('192.168.1.999'), false);
  });

  it('builds bounded scan targets for a private /24 subnet', () => {
    const targets = getInterfaceScanTargets({
      address: '192.168.1.164',
      netmask: '255.255.255.0',
    });

    assert.equal(targets.length, 253);
    assert.ok(targets.includes('192.168.1.168'));
    assert.ok(!targets.includes('192.168.1.0'));
    assert.ok(!targets.includes('192.168.1.164'));
    assert.ok(!targets.includes('192.168.1.255'));
  });

  it('limits wide private subnets to the local /24', () => {
    const targets = getInterfaceScanTargets({
      address: '10.4.5.6',
      netmask: '255.255.0.0',
    });

    assert.equal(targets.length, 253);
    assert.ok(targets.includes('10.4.5.1'));
    assert.ok(targets.includes('10.4.5.254'));
    assert.ok(!targets.includes('10.4.5.6'));
    assert.ok(!targets.includes('10.4.6.1'));
  });

  it('deduplicates SSH probe results already advertised by mDNS', () => {
    const hosts = mergeDiscoveredHosts([
      {
        name: 'Ubuntu SSH',
        host: 'ubuntu.local',
        port: 22,
        addresses: ['192.168.1.168'],
        txt: {},
        suggestedUsername: '',
        source: 'mdns',
      },
      {
        name: 'SSH at 192.168.1.168',
        host: '192.168.1.168',
        port: 22,
        addresses: ['192.168.1.168'],
        txt: {},
        suggestedUsername: '',
        source: 'tcp',
      },
    ]);

    assert.equal(hosts.length, 1);
    assert.equal(hosts[0].host, 'ubuntu.local');
  });

  it('bounds and sanitizes mDNS service records', () => {
    const host = normalizeAdvertisedHost({
      name: 'n'.repeat(400),
      host: `${'h'.repeat(400)}.local`,
      port: 22,
      addresses: Array.from({ length: 32 }, (_, index) => `192.168.1.${index + 1}`),
      txt: {
        username: 'remote-account',
        ignoredObject: { nested: true },
        ...Object.fromEntries(Array.from({ length: 32 }, (_, index) => [`k${index}`, 'v'.repeat(400)])),
      },
    });

    assert.equal(host.name.length, 256);
    assert.equal(host.host.length, 256);
    assert.equal(host.addresses.length, 16);
    assert.equal(Object.keys(host.txt).length, 16);
    assert.equal(host.suggestedUsername, 'remote-account');
  });

  it('drops mDNS service records with invalid host or port data', () => {
    assert.equal(normalizeAdvertisedHost({ host: '', port: 22 }), null);
    assert.equal(normalizeAdvertisedHost({ host: 'device.local', port: 0 }), null);
    assert.equal(normalizeAdvertisedHost({ host: 'device.local', port: 65536 }), null);
    assert.equal(normalizeAdvertisedHost({ host: 'device.local', port: '22' }), null);
  });

  it('normalizes discovery timeouts', () => {
    assert.equal(normalizeTimeout(3), 3000);
    assert.equal(normalizeTimeout('1'), 1000);
    assert.equal(normalizeTimeout(0), 3000);
    assert.equal(normalizeTimeout(0.1), 250);
  });

  it('parses dns-sd SSH browse and lookup output', () => {
    const browseOutput = `Browsing for _ssh._tcp.local
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
 6:53:30.888  Add        3  14 local.               _ssh._tcp.           spark-2b43-4 SSH
 6:53:30.888  Add        2  14 local.               _ssh._tcp.           BOJAN's Mac Studio (3890)
`;
    assert.deepEqual(parseDnsSdBrowseInstances(browseOutput), [
      'spark-2b43-4 SSH',
      "BOJAN's Mac Studio (3890)",
    ]);

    const lookupOutput = `Lookup spark-2b43-4 SSH._ssh._tcp.local
 6:53:31.002  spark-2b43-4 SSH._ssh._tcp.local. can be reached at spark-2b43-4.local.:22 (interface 14)
`;
    assert.deepEqual(parseDnsSdLookup('spark-2b43-4 SSH', lookupOutput), {
      name: 'spark-2b43-4 SSH',
      host: 'spark-2b43-4.local',
      port: 22,
      addresses: [],
      txt: {},
    });
  });

  // One real network scan shared by the live tests; each scan blocks for the
  // full timeout, so per-test scans only add wall clock, never information.
  describe('live scan', () => {
    let hosts;
    let elapsed;

    before(async () => {
      // Short timeout to keep tests fast
      const start = Date.now();
      hosts = await discover(1);
      elapsed = Date.now() - start;
    });

    it('returns an array', () => {
      assert.ok(Array.isArray(hosts));
    });

    it('each host has expected shape', () => {
      for (const h of hosts) {
        assert.ok(typeof h.name === 'string');
        assert.ok(typeof h.host === 'string');
        assert.ok(typeof h.port === 'number');
        assert.ok(Array.isArray(h.addresses));
        assert.ok(typeof h.suggestedUsername === 'string');
      }
    });

    it('respects timeout parameter', () => {
      // Should complete within ~1.5s (1s timeout + overhead)
      assert.ok(elapsed < 2500, `Took ${elapsed}ms, expected < 2500ms`);
    });
  });
});
