import { chmodSync, closeSync, fsyncSync, openSync, renameSync, rmSync, writeFileSync } from 'fs';
import { dirname } from 'path';
import { randomUUID } from 'crypto';

/**
 * Write a file atomically: stage the bytes in a sibling temp file with
 * restrictive permissions, fsync the temp file, then rename into place and
 * fsync the parent directory (best effort) so the rename itself survives a
 * crash. The temp filename is randomized to defeat predictable-name symlink
 * attacks by other local processes; the final chmod re-applies the desired
 * mode in case the rename did not preserve it on some filesystems.
 *
 * Throws on failure and removes the temp file (best-effort) so we never leave
 * partially written content behind.
 */
function writeFileAtomic(path, contents, { mode = 0o600 } = {}) {
  const tmpPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    const fd = openSync(tmpPath, 'wx', mode);
    try {
      writeFileSync(fd, contents); // fd form: loops on partial writes, handles encoding
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    chmodSync(tmpPath, mode);
    renameSync(tmpPath, path);
    chmodSync(path, mode);
    // Best-effort: make the rename itself durable. Directories cannot be
    // opened/fsynced on some platforms (e.g. Windows).
    try {
      const dirFd = openSync(dirname(path), 'r');
      try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
    } catch {}
  } catch (err) {
    try { rmSync(tmpPath, { force: true }); } catch {}
    throw err;
  }
}

export { writeFileAtomic };
