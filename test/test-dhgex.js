'use strict';

const assert = require('assert');

const {
  fixture,
  mustCall,
  setup: setup_,
} = require('./common.js');

const clientCfg = { username: 'foo', password: 'bar' };
const serverCfg = { hostKeys: [fixture('ssh_host_rsa_key')] };

const debug = false;

// Use a known safe prime for testing (RFC 3526 2048-bit MODP Group)
const MODP_2048_PRIME = Buffer.from(
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AACAA68FFFFFFFFFFFFFFFF',
  'hex'
);
const MODP_2048_GENERATOR = Buffer.from([0x02]);

{
  // Test: DH-GEX with async callback API
  const { server } = setup_(
    'DH-GEX with async callback getDHParams',
    {
      client: {
        ...clientCfg,
        algorithms: {
          kex: ['diffie-hellman-group-exchange-sha256'],
        },
      },
      server: {
        ...serverCfg,
        algorithms: {
          kex: ['diffie-hellman-group-exchange-sha256'],
        },
        getDHParams: mustCall((minBits, prefBits, maxBits, callback) => {
          assert(typeof minBits === 'number', 'minBits should be a number');
          assert(typeof prefBits === 'number', 'prefBits should be a number');
          assert(typeof maxBits === 'number', 'maxBits should be a number');
          assert(typeof callback === 'function', 'callback should be a function');
          assert(minBits <= prefBits, 'minBits should be <= prefBits');
          assert(prefBits <= maxBits, 'prefBits should be <= maxBits');

          // Simulate async operation
          setImmediate(() => {
            callback(null, MODP_2048_PRIME, MODP_2048_GENERATOR);
          });
        }),
      },
      debug,
    }
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {
      conn.end();
    }));
  }));
}

{
  // Test: DH-GEX with sync-style callback (immediate callback)
  const { server } = setup_(
    'DH-GEX with sync-style callback getDHParams',
    {
      client: {
        ...clientCfg,
        algorithms: {
          kex: ['diffie-hellman-group-exchange-sha256'],
        },
      },
      server: {
        ...serverCfg,
        algorithms: {
          kex: ['diffie-hellman-group-exchange-sha256'],
        },
        getDHParams: mustCall((minBits, prefBits, maxBits, callback) => {
          // Call callback synchronously (sync-style usage)
          callback(null, MODP_2048_PRIME, MODP_2048_GENERATOR);
        }),
      },
      debug,
    }
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {
      conn.end();
    }));
  }));
}

{
  // Test: DH-GEX SHA-256 with command execution after handshake
  const { server, client } = setup_(
    'DH-GEX SHA-256 key exchange with exec',
    {
      client: {
        ...clientCfg,
        algorithms: {
          kex: ['diffie-hellman-group-exchange-sha256'],
        },
      },
      server: {
        ...serverCfg,
        algorithms: {
          kex: ['diffie-hellman-group-exchange-sha256'],
        },
        getDHParams: mustCall((minBits, prefBits, maxBits, callback) => {
          callback(null, MODP_2048_PRIME, MODP_2048_GENERATOR);
        }),
      },
      debug,
    }
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {
      conn.on('session', mustCall((accept, reject) => {
        const session = accept();
        session.on('exec', mustCall((accept, reject, info) => {
          assert.strictEqual(info.command, 'echo test');
          const stream = accept();
          stream.write('test\n');
          stream.exit(0);
          stream.end();
        }));
      }));
    }));
  }));

  client.on('ready', mustCall(() => {
    client.exec('echo test', mustCall((err, stream) => {
      assert.ifError(err);
      let output = '';
      stream.on('data', (data) => {
        output += data;
      });
      stream.on('close', mustCall(() => {
        assert.strictEqual(output, 'test\n');
        client.end();
      }));
    }));
  }));
}

{
  // Test: DH-GEX SHA-1 variant
  const { server } = setup_(
    'DH-GEX SHA-1 key exchange',
    {
      client: {
        ...clientCfg,
        algorithms: {
          kex: ['diffie-hellman-group-exchange-sha1'],
        },
      },
      server: {
        ...serverCfg,
        algorithms: {
          kex: ['diffie-hellman-group-exchange-sha1'],
        },
        getDHParams: mustCall((minBits, prefBits, maxBits, callback) => {
          callback(null, MODP_2048_PRIME, MODP_2048_GENERATOR);
        }),
      },
      debug,
    }
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {
      conn.end();
    }));
  }));
}
