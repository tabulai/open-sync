import { join } from 'path';
import { homedir } from 'os';
import { chmodSync, mkdirSync } from 'fs';

const CONFIG_DIR = process.env.OPEN_SYNC_CONFIG_DIR || join(homedir(), '.open-sync');
const SSH_KEY_PATH = join(CONFIG_DIR, 'open-sync.key');
const SSH_PUB_KEY_PATH = join(CONFIG_DIR, 'open-sync.key.pub');
const STATE_PATH = join(CONFIG_DIR, 'state.json');
const SSH_CONFIG_PATH = join(CONFIG_DIR, 'ssh_config');
const SSH_KNOWN_HOSTS_PATH = join(CONFIG_DIR, 'known_hosts');

function ensureConfigDir() {
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  chmodSync(CONFIG_DIR, 0o700);
}

export {
  CONFIG_DIR,
  SSH_KEY_PATH,
  SSH_PUB_KEY_PATH,
  STATE_PATH,
  SSH_CONFIG_PATH,
  SSH_KNOWN_HOSTS_PATH,
  ensureConfigDir,
};
