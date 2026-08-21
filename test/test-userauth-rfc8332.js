'use strict';

// Test for RFC 8332 Section 3 compliance: server correctly handles clients
// that put 'ssh-rsa' in the packet algorithm field but 'rsa-sha2-256' or
// 'rsa-sha2-512' in the signature blob's algorithm identifier.
//
// This tests the fix in handlers.misc.js that properly unwraps the signature
// blob regardless of whether its embedded algorithm matches the packet-level
// algorithm field.
//
// NOTE: The true mismatch scenario (packet algo='ssh-rsa', sig blob
// algo='rsa-sha2-256') cannot be easily reproduced with the ssh2 client since
// it always writes the same algorithm in both places. The mismatch case has
// been verified with real clients (TablePlus/libssh) that exhibit this
// behavior per RFC 8332 Section 3. These tests serve as regression tests to
// ensure the unwrapping logic doesn't break the normal paths.

const assert = require('assert');

const {
  fixtureKey,
  mustCall,
  setup,
} = require('./common.js');

const serverCfg = { hostKeys: [fixtureKey('ssh_host_rsa_key').raw] };
const debug = false;

// Test 1: Normal RSA auth still works (baseline regression test)
// The ssh2 client uses rsa-sha2-256 when supported, putting 'rsa-sha2-256'
// in both the packet algo field and the signature blob. This should still work.
{
  const clientKey = fixtureKey('openssh_new_rsa');
  const username = 'RFC8332 Baseline';

  const { server } = setup(
    'RFC 8332 - baseline: rsa-sha2-256 in both packet and sig blob',
    {
      client: { username, privateKey: clientKey.raw },
      server: serverCfg,
      debug,
    }
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      if (ctx.method === 'none')
        return ctx.reject();

      assert(ctx.method === 'publickey',
             `Wrong auth method: ${ctx.method}`);

      if (ctx.signature) {
        const result =
          clientKey.key.verify(ctx.blob, ctx.signature, ctx.hashAlgo);
        assert(result === true,
               `Could not verify publickey signature (hashAlgo: ${ctx.hashAlgo})`);
      }
      ctx.accept();
    }, 3)).on('ready', mustCall(() => {
      conn.end();
    }));
  }));
}

// Test 2: RSA auth with ssh-rsa packet algo (SHA-1 signature)
// Forces the client to use plain ssh-rsa (SHA-1), testing that the
// unwrapping still works when packet algo and sig blob algo match as 'ssh-rsa'.
{
  const clientKey = fixtureKey('openssh_new_rsa');
  const username = 'RFC8332 SSH-RSA';

  const { server } = setup(
    'RFC 8332 - ssh-rsa in both packet and sig blob (SHA-1)',
    {
      client: {
        username,
        privateKey: clientKey.raw,
        algorithms: {
          // Exclude rsa-sha2-* from server host key algos to prevent the
          // client from negotiating them
          serverHostKey: [
            'ssh-rsa',
            'ecdsa-sha2-nistp256',
            'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521',
            'ssh-ed25519',
          ],
        },
      },
      server: serverCfg,
      debug,
    }
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      if (ctx.method === 'none')
        return ctx.reject();

      assert(ctx.method === 'publickey',
             `Wrong auth method: ${ctx.method}`);

      if (ctx.signature) {
        const result =
          clientKey.key.verify(ctx.blob, ctx.signature, ctx.hashAlgo);
        assert(result === true,
               `Could not verify publickey signature (hashAlgo: ${ctx.hashAlgo})`);
      }
      ctx.accept();
    }, 3)).on('ready', mustCall(() => {
      conn.end();
    }));
  }));
}
