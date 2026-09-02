'use strict';

const assert = require('assert');

const { sigSSHToASN1 } = require('../lib/protocol/utils.js');

const {
  fixtureKey,
  mustCall,
  setup,
} = require('./common.js');

// Fixtures were generated with:
//   ssh-keygen -t ed25519 -N '' -f ssh_user_ca
//   ssh-keygen -t <type> -N '' -f id_<type>_cert_key
//   ssh-keygen -s ssh_user_ca -I ssh2-test-<type> -n 'Cert User' \
//              -V 20200101:22000101 id_<type>_cert_key.pub
// The far-future validity keeps them from expiring under the test suite.

const serverCfg = { hostKeys: [ fixtureKey('ssh_host_rsa_key').raw ] };

const debug = false;

const CERT_SUFFIX = '-cert-v01@openssh.com';

// An SSH signature blob is `string algorithm, string signature`.
function parseSignatureBlob(blob) {
  const algoLen = blob.readUInt32BE(0);
  const algo = blob.utf8Slice(4, 4 + algoLen);
  const sigLen = blob.readUInt32BE(4 + algoLen);
  const signature = blob.slice(8 + algoLen, 8 + algoLen + sigLen);
  return { algo, signature };
}

// Certificates ================================================================
//
// A publickey request names the algorithm twice: the request's own algorithm
// field says what is offered (the certificate type), while the signature blob
// says what actually signed (the plain key type). These tests check both names
// independently, and that the signature verifies against the plain key.
[
  { desc: 'ed25519 certificate',
    keyFile: 'id_ed25519_cert_key',
    certFile: 'id_ed25519_cert_key-cert.pub' },
  { desc: 'RSA certificate',
    keyFile: 'id_rsa_cert_key',
    certFile: 'id_rsa_cert_key-cert.pub' },
  { desc: 'ECDSA certificate',
    keyFile: 'id_ecdsa_cert_key',
    certFile: 'id_ecdsa_cert_key-cert.pub' },
].forEach((test) => {
  const { desc, keyFile, certFile } = test;
  const clientKey = fixtureKey(keyFile);
  const clientCert = fixtureKey(certFile);
  const plainType = clientKey.key.type;
  const certType = clientCert.key.type;
  assert(certType === `${plainType}${CERT_SUFFIX}`,
         `Fixture mismatch: ${certType} is not a certificate for ${plainType}`);

  const username = 'Cert User';
  const { server } = setup(
    desc,
    {
      client: {
        username,
        privateKey: clientKey.raw,
        publicKey: clientCert.raw,
      },
      server: serverCfg,

      debug,
    }
  );

  server.on('connection', mustCall((conn) => {
    let authAttempt = 0;
    conn.on('authentication', mustCall((ctx) => {
      assert(ctx.username === username,
             `Wrong username: ${ctx.username}`);
      switch (++authAttempt) {
        case 1:
          assert(ctx.method === 'none', `Wrong auth method: ${ctx.method}`);
          return ctx.reject();
        case 2:
          assert(ctx.method === 'publickey',
                 `Wrong auth method: ${ctx.method}`);
          assert(!ctx.signature, 'Unexpected signature on the check request');
          assert(ctx.key.algo === certType,
                 `Wrong key algo: ${ctx.key.algo}`);
          assert.deepStrictEqual(ctx.key.data,
                                 clientCert.key.getPublicSSH(),
                                 'Certificate blob mismatch');
          break;
        case 3: {
          assert(ctx.method === 'publickey',
                 `Wrong auth method: ${ctx.method}`);
          assert(ctx.signature, 'Missing publickey signature');
          assert(ctx.key.algo === certType,
                 `Wrong key algo: ${ctx.key.algo}`);

          // The server only unwraps the signature blob when its algorithm
          // matches the request's, which a certificate's never does — so the
          // blob arrives intact and the inner name can be checked directly.
          const { algo, signature } = parseSignatureBlob(ctx.signature);
          assert(algo === plainType,
                 `Signature blob names ${algo}, expected ${plainType}`);

          // What signed is the plain key, so the signature verifies against it.
          const verifiable = sigSSHToASN1(signature, plainType);
          assert(verifiable, 'Malformed signature for the plain key type');
          const result =
            clientKey.key.verify(ctx.blob, verifiable, ctx.hashAlgo);
          assert(result === true, 'Could not verify certificate signature');
          break;
        }
      }
      ctx.accept();
    }, 3)).on('ready', mustCall(() => {
      conn.end();
    }));
  }));
});
