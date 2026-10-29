'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function paths(env) {
  const repository = env.INPUT_REPOSITORY;
  const workspace = env.INPUT_WORKSPACE || env.GITHUB_WORKSPACE;
  if (!repository || !path.isAbsolute(repository) || !workspace) {
    throw new Error('repository must be absolute and workspace must be set');
  }
  const repo = fs.realpathSync(repository);
  const work = fs.realpathSync(workspace);
  const relative = path.relative(work, repo);
  const reverse = path.relative(repo, work);
  const nested = (value) => value === '' || (!value.startsWith(`..${path.sep}`) && value !== '..' && !path.isAbsolute(value));
  if (nested(relative) || nested(reverse)) {
    throw new Error('repository must be outside the workspace; neither may contain the other');
  }
  if (!fs.statSync(repo).isDirectory() || !fs.statSync(work).isDirectory()) {
    throw new Error('repository and workspace must be directories');
  }
  if (!env.BUNKER_PASSPHRASE) throw new Error('BUNKER_PASSPHRASE must be supplied through job-level env');
  const binary = env.INPUT_BINARY || 'bunker';
  if (binary !== 'bunker' && !path.isAbsolute(binary)) throw new Error('binary must be bunker or an absolute path');
  return { repo, work, binary };
}

function run(binary, args) {
  // Never echo argv, child output or environment: repository errors may expose paths.
  const child = spawnSync(binary, args, { stdio: 'ignore', shell: false });
  if (child.error || child.status !== 0) throw new Error('Bunker command failed; run the same operation locally for diagnosis');
}
module.exports = { paths, run };
