'use strict';

const { execSync } = require('child_process');
const { readdirSync } = require('fs');
const { join } = require('path');

for (const filename of readdirSync(__dirname)) {
  if (filename.startsWith('test-')) {
    const path = join(__dirname, filename);
    console.log(`> Running ${filename} ...`);
    execSync(`${process.argv[0]} ${path}`, { stdio: 'inherit' });
  }
}
