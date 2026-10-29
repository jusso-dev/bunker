'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { paths, run } = require('./common.cjs');
test('rejects nested repositories, including symlink aliases', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bunker-action-'));
  try {
    const work = path.join(root, 'work');
    const nested = path.join(work, 'repo');
    fs.mkdirSync(nested, { recursive: true });
    const alias = path.join(root, 'alias');
    fs.symlinkSync(nested, alias, 'junction');
    const env = { INPUT_REPOSITORY: alias, GITHUB_WORKSPACE: work, BUNKER_PASSPHRASE: randomBytes(32).toString('hex') };
    assert.throws(() => paths(env), /outside the workspace/);
    env.INPUT_REPOSITORY = root;
    assert.throws(() => paths(env), /outside the workspace/);
    const outside = path.join(root, 'outside');
    fs.mkdirSync(outside);
    env.INPUT_REPOSITORY = outside;
    assert.equal(paths(env).repo, fs.realpathSync(outside));
    delete env.BUNKER_PASSPHRASE;
    assert.throws(() => paths(env), /job-level env/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('failed snapshot subprocess is not reported as success', () => {
  assert.throws(() => run(process.execPath, ['-e', 'process.exit(1)']), /failed/);
  assert.throws(() => run(path.join(os.tmpdir(), 'nonexistent-bunker-binary'), []), /failed/);
});
