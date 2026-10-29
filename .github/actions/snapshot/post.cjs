'use strict';
const { run } = require('./common.cjs');
try {
  if (process.env.STATE_config) {
    const { repo, work, binary } = JSON.parse(process.env.STATE_config);
    if (!process.env.BUNKER_PASSPHRASE) throw new Error('BUNKER_PASSPHRASE is unavailable in post phase');
    run(binary, ['snapshot', '--repo', repo, '--workspace', work]);
    console.log('Bunker end-of-job snapshot completed.');
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
