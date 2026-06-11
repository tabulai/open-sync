import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, '..', 'src', 'cli', 'index.js');

describe('cli', () => {
  it('rejects the unsupported detach option', () => {
    const result = spawnSync(process.execPath, [CLI_PATH, 'connect', 'demo-host', '--detach'], {
      encoding: 'utf-8',
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unknown option '--detach'/);
  });
});
