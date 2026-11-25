'use strict';

const assert = require('assert');

const {
  utils: {
    generateKeyPair,
    generateKeyPairSync,
    parseKey,
  },
} = require('..');

const { mustCall } = require('./common.js');

function tryParse(...args) {
  const ret = parseKey(...args);
  if (ret instanceof Error)
    throw ret;
  return ret;
}

const inputs = [
  { args: ['rsa', { bits: 2048 }], sshType: 'ssh-rsa' },
  { args: ['ecdsa', { bits: 256 }], sshType: 'ecdsa-sha2-nistp256' },
  { args: ['ecdsa', { bits: 521 }], sshType: 'ecdsa-sha2-nistp521' },
  { args: ['ed25519'], sshType: 'ssh-ed25519' },
  { args: ['rsa', { bits: 2048, passphrase: 'foo', cipher: 'aes256-cbc' }],
    sshType: 'ssh-rsa' },
  { args: ['rsa', { bits: 2048, comment: 'foobarbaz' }], sshType: 'ssh-rsa' },
];
// About 1 in 256 ed25519 public keys start with a zero byte. Such keys used to
// be written with that byte stripped, producing key files that neither this
// module nor OpenSSH could read. Generate enough keys to be all but certain to
// hit that case.
{
  console.log('Testing generateKeyPairSync("ed25519") with leading zeros ...');
  let leadingZeros = 0;
  for (let i = 0; i < 4000; ++i) {
    const keys = generateKeyPairSync('ed25519');
    const pub = tryParse(keys.public).getPublicSSH();
    // Layout: string "ssh-ed25519" followed by string <32 byte public key>
    assert.strictEqual(pub.length, 4 + 11 + 4 + 32);
    assert.strictEqual(pub.readUInt32BE(4 + 11), 32);
    if (pub[4 + 11 + 4] === 0x00)
      ++leadingZeros;
    assert.deepStrictEqual(tryParse(keys.private).getPublicSSH(), pub);
  }
  assert(leadingZeros > 0, 'Expected a public key with a leading zero byte');
}

(function next() {
  if (inputs.length === 0)
    return;
  const { args, sshType } = inputs.shift();
  const passphrase = (args[1] && args[1].passphrase);
  const comment = ((args[1] && args[1].comment) || '');
  const check = (keys) => {
    let parsed = tryParse(keys.private, passphrase);
    assert.strictEqual(parsed.type, sshType);
    assert.strictEqual(parsed.comment, comment);

    parsed = tryParse(keys.public);
    assert.strictEqual(parsed.type, sshType);
    assert.strictEqual(parsed.comment, comment);
  };
  console.log(`Testing generateKeyPairSync(${JSON.stringify(args)}) ...`);
  check(generateKeyPairSync(...args));
  console.log(`Testing generateKeyPair(${JSON.stringify(args)}) ...`);
  generateKeyPair(...args, mustCall((err, keys) => {
    assert.ifError(err);
    check(keys);
    next();
  }));
})();
