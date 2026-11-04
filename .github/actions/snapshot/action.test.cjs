'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { paths, run } = require('./common.cjs');
const vm = require('node:vm');
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

function post(env, fail = false) {
  const calls = [], messages = [], errors = [];
  const process = { env, exitCode: undefined };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'post.cjs'), 'utf8'), {
    process,
    require: (name) => {
      assert.equal(name, './common.cjs');
      return { run: (binary, args) => {
        calls.push({ binary, args: Array.from(args) });
        if (fail) throw new Error('Bunker command failed');
      } };
    },
    console: { log: (message) => messages.push(message), error: (message) => errors.push(message) },
  });
  return { calls, messages, errors, exitCode: process.exitCode };
}
test('post step snapshots saved paths with the saved binary', () => {
  const state = { repo: '/private/repo', work: '/workspace', binary: '/bin/bunker' };
  const result = post({ STATE_config: JSON.stringify(state), BUNKER_PASSPHRASE: 'sentinel-secret' });
  assert.deepEqual(result.calls, [{ binary: state.binary,
    args: ['snapshot', '--repo', state.repo, '--workspace', state.work] }]);
  assert.equal(result.messages.length, 1);
  assert.equal(result.exitCode, undefined);
  assert.ok(!JSON.stringify(result).includes('sentinel-secret'));
});
test('post step without saved state is a no-op', () => {
  assert.deepEqual(post({}).calls, []);
  assert.equal(post({}).exitCode, undefined);
});
test('post step fails on missing secret, malformed state, or snapshot failure', () => {
  const env = { STATE_config: JSON.stringify({ repo: '/repo', work: '/work', binary: '/bin/bunker' }),
    BUNKER_PASSPHRASE: 'sentinel-secret' };
  for (const result of [post({ STATE_config: env.STATE_config }),
    post({ ...env, STATE_config: '{' }), post(env, true)]) {
    assert.equal(result.exitCode, 1);
    assert.equal(result.messages.length, 0);
    assert.equal(result.errors.length, 1);
    assert.ok(!JSON.stringify(result).includes('sentinel-secret'));
  }
});
