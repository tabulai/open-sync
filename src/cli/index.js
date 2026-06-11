#!/usr/bin/env node

import { Command } from 'commander';

// Core modules load inside each action handler so light commands
// (version, list, pubkey) skip the dependency cost of the others.
const program = new Command();

program
  .name('open-sync')
  .description('Open-source SSH device discovery, connection management, and port forwarding')
  .version('0.1.0');

// version
program.command('version')
  .description('Get version information')
  .action(() => {
    console.log('open-sync 0.1.0 (open-source; ' + process.platform + '; ' + process.arch + '; node ' + process.version + ')');
  });

// discover
program.command('discover')
  .description('Discover SSH hosts on the local network via mDNS and SSH port probing')
  .option('-t, --timeout <seconds>', 'Discovery timeout in seconds', '3')
  .action(async (opts) => {
    const { discover } = await import('../core/discovery.js');
    console.log(`Discovering SSH hosts (${opts.timeout}s timeout)...`);
    const hosts = await discover(parseInt(opts.timeout, 10));
    if (hosts.length === 0) {
      console.log('No SSH hosts found.');
    } else {
      console.log(`Found ${hosts.length} host(s):\n`);
      for (const h of hosts) {
        console.log(`  ${h.name}`);
        console.log(`    Host: ${h.host}`);
        console.log(`    Port: ${h.port}`);
        console.log(`    Addresses: ${h.addresses.join(', ')}`);
        console.log();
      }
    }
  });

// create
program.command('create <ssh-url>')
  .description('Set up a new remote device (ssh://<account>@<host>[:port])')
  .option('--password-stdin', 'Read the password from stdin')
  .option('--host-fingerprint <fingerprint>', 'Trust this exact SSH host key fingerprint for first contact')
  .action(async (sshUrl, opts) => {
    try {
      const { createDevice } = await import('../core/ssh.js');
      let password;
      if (opts.passwordStdin) {
        const chunks = [];
        for await (const chunk of process.stdin) chunks.push(chunk);
        password = Buffer.concat(chunks).toString().trim();
      }
      const device = await createDevice(sshUrl, password, { expectedHostFingerprint: opts.hostFingerprint });
      console.log(`Device '${device.hostname}' created successfully.`);
      console.log(`  User: ${device.username}`);
      console.log(`  SSH Port: ${device.sshPort}`);
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// connect
program.command('connect <hostname>')
  .description('Connect to a remote machine')
  .option('--host-fingerprint <fingerprint>', 'Trust this exact SSH host key fingerprint for first contact')
  .action(async (hostname, opts) => {
    try {
      const { connect, disconnect } = await import('../core/ssh.js');
      const result = await connect(hostname, {
        expectedHostFingerprint: opts.hostFingerprint,
        onClose: (closeError) => {
          if (closeError) {
            console.error(`\nConnection to '${hostname}' lost: ${closeError.message}`);
            process.exit(1);
          }
          console.log(`\nConnection to '${hostname}' closed.`);
          process.exit(0);
        },
      });
      console.log(`Connected to '${hostname}'. Status: ${result.status}`);
      console.log('Press Ctrl+C to disconnect.');
      process.on('SIGINT', () => {
        disconnect(hostname);
        console.log(`\nDisconnected from '${hostname}'.`);
        process.exit(0);
      });
      // The live SSH socket keeps the event loop alive until the
      // connection closes; onClose above exits the process then.
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// disconnect
program.command('disconnect <hostname>')
  .description('Disconnect from a remote machine')
  .action(async (hostname) => {
    const { disconnect } = await import('../core/ssh.js');
    disconnect(hostname);
    console.log(`Disconnected from '${hostname}'.`);
  });

// status
program.command('status <hostname>')
  .description('Get connection status')
  .action(async (hostname) => {
    const { getStatus } = await import('../core/ssh.js');
    const status = getStatus(hostname);
    console.log(JSON.stringify(status, null, 2));
  });

// open
program.command('open <hostname> <port>')
  .description('Open a port tunnel to the remote machine')
  .action(async (hostname, port) => {
    try {
      const { openTunnel } = await import('../core/ssh.js');
      const result = await openTunnel(hostname, parseInt(port, 10));
      console.log(`Tunnel opened: localhost:${result.localPort} -> ${hostname}:${result.remotePort}`);
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// close
program.command('close <hostname> [port]')
  .description('Close a port tunnel')
  .action(async (hostname, port) => {
    const { closeTunnel } = await import('../core/ssh.js');
    closeTunnel(hostname, port ? parseInt(port, 10) : undefined);
    console.log(port ? `Tunnel to port ${port} closed.` : `All tunnels to '${hostname}' closed.`);
  });

// delete
program.command('delete <hostname>')
  .description('Delete device configuration')
  .action(async (hostname) => {
    const { deleteDevice } = await import('../core/ssh.js');
    deleteDevice(hostname);
    console.log(`Device '${hostname}' deleted.`);
  });

// list (convenience command not in original, but useful)
program.command('list')
  .description('List all configured devices')
  .action(async () => {
    const { loadState } = await import('../core/state.js');
    const { resolveTargetHost } = await import('../core/hosts.js');
    const state = loadState();
    if (state.devices.length === 0) {
      console.log('No devices configured.');
      return;
    }
    for (const d of state.devices) {
      console.log(`  ${d.hostname} (${d.username}@${resolveTargetHost(d.hostname)}:${d.sshPort || 22}) [${d.status || 'unknown'}]`);
    }
  });

// pubkey (convenience command)
program.command('pubkey')
  .description('Show the public SSH key (for manual installation)')
  .action(async () => {
    const { ensureKeyPair, getPublicKey } = await import('../core/keys.js');
    ensureKeyPair();
    console.log(getPublicKey());
  });

await program.parseAsync();
