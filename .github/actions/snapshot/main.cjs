'use strict';
const fs = require('node:fs');
const { paths, run } = require('./common.cjs');
try {
  const config = paths(process.env);
  run(config.binary, ['--version']);
  if (!process.env.GITHUB_STATE) throw new Error('GitHub action state file is missing');
  fs.appendFileSync(process.env.GITHUB_STATE, `config=${JSON.stringify(config)}\n`);
  console.log('Bunker repository checked; snapshot registered for the post-job phase.');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
