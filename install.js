'use strict';

const { spawnSync } = require('child_process');

// Attempt to build the bundled optional binding
const result = spawnSync('node-gyp', [
  `--target=${process.version}`,
  'rebuild'
], {
  cwd: 'lib/protocol/crypto',
  encoding: 'utf8',
  shell: true,
  stdio: 'inherit',
  windowsHide: true,
});
if (result.error || result.status !== 0)
  console.log('Failed to build optional crypto binding');
else
  console.log('Succeeded in building optional crypto binding');
process.exit(0);
