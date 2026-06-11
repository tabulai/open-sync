import { chmodSync, renameSync, rmSync, writeFileSync } from 'fs';
import { randomUUID } from 'crypto';

/**
 * Write a file atomically: stage the bytes in a sibling temp file with
 * restrictive permissions, fsync via writeFileSync, then rename into place.
 * The temp filename is randomized to defeat predictable-name symlink attacks
 * by other local processes; the final chmod re-applies the desired mode in
 * case the rename did not preserve it on some filesystems.
 *
 * Throws on failure and removes the temp file (best-effort) so we never leave
 * partially written content behind.
 */
function writeFileAtomic(path, contents, { mode = 0o600 } = {}) {
  const tmpPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(tmpPath, contents, { mode });
    chmodSync(tmpPath, mode);
    renameSync(tmpPath, path);
    chmodSync(path, mode);
  } catch (err) {
    try { rmSync(tmpPath, { force: true }); } catch {}
    throw err;
  }
}

export { writeFileAtomic };
