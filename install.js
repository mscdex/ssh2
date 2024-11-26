'use strict';

const { spawnSync } = require('child_process');

const forceFailOnNonZero = (process.env.CI_CHECK_FAIL === 'ssh2');

// Attempt to build the bundled optional binding
const args = [
  `--target=${process.version}`,
  `--real_openssl_major=${/^\d+/.exec(process.versions.openssl)[0]}`,
  'rebuild',
];
const cmd_args = process.argv.slice(2);
let exe = "node-gyp";
if (cmd_args[0]) {
  exe = `${cmd_args[0]} node-gyp`
}
const result = spawnSync(exe, args, {
  cwd: 'lib/protocol/crypto',
  encoding: 'utf8',
  shell: true,
  stdio: 'inherit',
  windowsHide: true,
});
if (result.error || result.status !== 0) {
  console.log('Failed to build optional crypto binding');
  if (forceFailOnNonZero)
    process.exit(1);
} else {
  console.log('Succeeded in building optional crypto binding');
}
process.exit(0);
