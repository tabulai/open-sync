import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

// Call this BEFORE importing any src modules.
// Sets OPEN_SYNC_CONFIG_DIR so paths.js picks up the temp directory.
export function setupTempConfig() {
  const tempDir = mkdtempSync(join(tmpdir(), 'open-sync-test-'));
  process.env.OPEN_SYNC_CONFIG_DIR = tempDir;
  return tempDir;
}

export function cleanupTempConfig(tempDir) {
  delete process.env.OPEN_SYNC_CONFIG_DIR;
  try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
}
