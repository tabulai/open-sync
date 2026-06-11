import { readFileSync } from 'fs';
import { STATE_PATH, ensureConfigDir } from './paths.js';
import { writeFileAtomic } from './atomic_write.js';

const DEFAULT_STATE = {
  devices: [],
  openPorts: {},
  knownHosts: {},
  tools: [
    { id: 'terminal', name: 'Terminal', description: 'Connect via SSH terminal', available: true },
    { id: 'editor', name: 'Editor', description: 'Open in a local editor over SSH', available: false },
    { id: 'jupyter', name: 'Notebook Server', description: 'Notebook server on the remote device', available: false, settings: [{ id: 'port', label: 'Port', value: '8888' }] },
  ],
};

function createDefaultState() {
  return JSON.parse(JSON.stringify(DEFAULT_STATE));
}

function loadState() {
  ensureConfigDir();
  try {
    return normalizeState(JSON.parse(readFileSync(STATE_PATH, 'utf-8')));
  } catch (err) {
    if (err.code === 'ENOENT') {
      return createDefaultState();
    }

    throw new Error(`Failed to load Open Sync state from ${STATE_PATH}: ${err.message}`, { cause: err });
  }
}

function saveState(state) {
  ensureConfigDir();
  writeFileAtomic(STATE_PATH, JSON.stringify(normalizeState(state), null, 2), { mode: 0o600 });
}

function getDevice(state, hostname) {
  return state.devices.find(d => d.hostname === hostname);
}

function upsertDevice(state, device) {
  const idx = state.devices.findIndex(d => d.hostname === device.hostname);
  if (idx >= 0) {
    state.devices[idx] = { ...state.devices[idx], ...device };
  } else {
    state.devices.push(device);
  }
  return state;
}

function removeDevice(state, hostname) {
  state.devices = state.devices.filter(d => d.hostname !== hostname);
  delete state.openPorts[hostname];
  if (state.knownHosts) {
    for (const key of Object.keys(state.knownHosts)) {
      if (key === hostname || key.startsWith(`${hostname}:`)) {
        delete state.knownHosts[key];
      }
    }
  }
  return state;
}

function normalizeState(state) {
  const normalized = {
    ...createDefaultState(),
    ...(state && typeof state === 'object' ? state : {}),
  };
  normalized.devices = Array.isArray(normalized.devices) ? normalized.devices : [];
  normalized.openPorts = normalized.openPorts && typeof normalized.openPorts === 'object' ? normalized.openPorts : {};
  normalized.knownHosts = normalized.knownHosts && typeof normalized.knownHosts === 'object' ? normalized.knownHosts : {};
  normalized.tools = Array.isArray(normalized.tools) ? normalized.tools : createDefaultState().tools;
  return normalized;
}

export { loadState, saveState, getDevice, upsertDevice, removeDevice, DEFAULT_STATE };
