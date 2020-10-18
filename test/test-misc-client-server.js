'use strict';

const assert = require('assert');
const { createHash } = require('crypto');
const { Socket } = require('net');

const Client = require('../lib/client.js');
const Server = require('../lib/server.js');
const { KexInit } = require('../lib/protocol/kex.js');

const {
  fixture,
  mustCall,
  mustNotCall,
  setup: setup_,
  setupSimple,
} = require('./common.js');

const KEY_RSA_BAD = fixture('bad_rsa_private_key');
const HOST_RSA_MD5 = '64254520742d3d0792e918f3ce945a64';
const clientCfg = { username: 'foo', password: 'bar' };
const serverCfg = { hostKeys: [ fixture('ssh_host_rsa_key') ] };

const DEBUG = false;

const setup = setupSimple.bind(undefined, DEBUG);


{
  const { server } = setup_(
    'Verify host fingerprint (sync success, hostHash set)',
    {
      client: {
        ...clientCfg,
        hostHash: 'md5',
        hostVerifier: mustCall((hash) => {
          assert(hash === HOST_RSA_MD5, 'Host fingerprint mismatch');
          return true;
        }),
      },
      server: serverCfg,
    },
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
  const { server } = setup_(
    'Verify host fingerprint (sync success, hostHash not set)',
    {
      client: {
        ...clientCfg,
        hostVerifier: mustCall((key) => {
          assert(Buffer.isBuffer(key), 'Expected buffer');
          let hash = createHash('md5');
          hash.update(key);
          hash = hash.digest('hex');
          assert(hash === HOST_RSA_MD5, 'Host fingerprint mismatch');
          return true;
        }),
      },
      server: serverCfg,
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
  const { server } = setup_(
    'Verify host fingerprint (async success)',
    {
      client: {
        ...clientCfg,
        hostVerifier: mustCall((key, cb) => {
          assert(Buffer.isBuffer(key), 'Expected buffer');
          let hash = createHash('md5');
          hash.update(key);
          hash = hash.digest('hex');
          assert(hash === HOST_RSA_MD5, 'Host fingerprint mismatch');
          process.nextTick(cb, true);
        }),
      },
      server: serverCfg,
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
  const { client, server } = setup_(
    'Verify host fingerprint (sync failure)',
    {
      client: {
        ...clientCfg,
        hostVerifier: mustCall((key) => {
          return false;
        }),
      },
      server: serverCfg,

      noForceClientReady: true,
      noForceServerReady: true,
    },
  );

  client.removeAllListeners('error');
  client.on('ready', mustNotCall())
        .on('error', mustCall((err) => {
    assert(/verification failed/.test(err.message),
           'Wrong client error message');
  }));

  server.on('connection', mustCall((conn) => {
    conn.removeAllListeners('error');

    conn.on('authentication', mustNotCall())
        .on('ready', mustNotCall())
        .on('error', mustCall((err) => {
      assert(/KEY_EXCHANGE_FAILED/.test(err.message),
             'Wrong server error message');
    }));
  }));
}

{
  // connect() on connected client

  const clientCfg_ = { ...clientCfg };
  const client = new Client();
  const server = new Server(serverCfg);

  server.listen(0, 'localhost', mustCall(() => {
    clientCfg_.host = 'localhost';
    clientCfg_.port = server.address().port;
    client.connect(clientCfg_);
  }));

  let connections = 0;
  server.on('connection', mustCall((conn) => {
    if (++connections === 2)
      server.close();
    conn.on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {}));
  }, 2)).on('close', mustCall(() => {}));

  let reconnect = false;
  client.on('ready', mustCall(() => {
    if (reconnect) {
      client.end();
    } else {
      reconnect = true;
      client.connect(clientCfg_);
    }
  }, 2)).on('close', mustCall(() => {}, 2));
}

{
  // Throw when not connected

  const client = new Client({
    username: 'foo',
    password: 'bar',
  });

  assert.throws(mustCall(() => {
    client.exec('uptime', mustNotCall());
  }));
}

{
  const { client, server } = setup(
    'Outstanding callbacks called on disconnect'
  );

  server.on('connection', mustCall((conn) => {
    conn.on('session', mustCall(() => {}, 3));
  }));

  client.on('ready', mustCall(() => {
    function callback(err, stream) {
      assert(err, 'Expected error');
      assert(err.message === 'No response from server',
             `Wrong error message: ${err.message}`);
    }
    client.exec('uptime', mustCall(callback));
    client.shell(mustCall(callback));
    client.sftp(mustCall(callback));
    client.end();
  }));
}

{
  const { client, server } = setup('Pipelined requests');

  server.on('connection', mustCall((conn) => {
    conn.on('ready', mustCall(() => {
      conn.on('session', mustCall((accept, reject) => {
        const session = accept();
        session.on('exec', mustCall((accept, reject, info) => {
          const stream = accept();
          stream.exit(0);
          stream.end();
        }));
      }, 3));
    }));
  }));

  client.on('ready', mustCall(() => {
    let calledBack = 0;
    function callback(err, stream) {
      assert(!err, `Unexpected error: ${err}`);
      stream.resume();
      if (++calledBack === 3)
        client.end();
    }
    client.exec('foo', mustCall(callback));
    client.exec('bar', mustCall(callback));
    client.exec('baz', mustCall(callback));
  }));
}

{
  const { client, server } = setup(
    'Pipelined requests with intermediate rekeying'
  );

  server.on('connection', mustCall((conn) => {
    conn.on('ready', mustCall(() => {
      const reqs = [];
      conn.on('session', mustCall((accept, reject) => {
        if (reqs.length === 0) {
          conn.rekey(mustCall((err) => {
            assert(!err, `Unexpected rekey error: ${err}`);
            reqs.forEach((accept) => {
              const session = accept();
              session.on('exec', mustCall((accept, reject, info) => {
                const stream = accept();
                stream.exit(0);
                stream.end();
              }));
            });
          }));
        }
        reqs.push(accept);
      }, 3));
    }));
  }));

  client.on('ready', mustCall(() => {
    let calledBack = 0;
    function callback(err, stream) {
      assert(!err, `Unexpected error: ${err}`);
      stream.resume();
      if (++calledBack === 3)
        client.end();
    }
    client.exec('foo', mustCall(callback));
    client.exec('bar', mustCall(callback));
    client.exec('baz', mustCall(callback));
  }));
}

{
  const { client, server } = setup('Ignore outgoing after stream close');

  server.on('connection', mustCall((conn) => {
    conn.on('ready', mustCall(() => {
      conn.on('session', mustCall((accept, reject) => {
        const session = accept();
        session.on('exec', mustCall((accept, reject, info) => {
          const stream = accept();
          stream.exit(0);
          stream.end();
        }));
      }));
    }));
  }));

  client.on('ready', mustCall(() => {
    client.exec('foo', mustCall((err, stream) => {
      assert(!err, `Unexpected error: ${err}`);
      stream.on('exit', mustCall((code, signal) => {
        client.end();
      }));
    }));
  }));
}

{
  const { client, server } = setup_(
    'Double pipe on unconnected, passed in net.Socket',
    {
      client: {
        ...clientCfg,
        sock: new Socket(),
      },
      server: serverCfg,
    },
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {}));
  }));
  client.on('ready', mustCall(() => {
    client.end();
  }));
}

{
  const { client, server } = setup(
    'Client auto-rejects inbound connections to unknown bound address'
  );

  const assignedPort = 31337;

  server.on('connection', mustCall((conn) => {
    conn.on('ready', mustCall(() => {
      conn.on('request', mustCall((accept, reject, name, info) => {
        assert(name === 'tcpip-forward', 'Wrong request name');
        assert.deepStrictEqual(
          info,
          { bindAddr: 'good', bindPort: 0 },
          'Wrong request info'
        );
        accept(assignedPort);
        conn.forwardOut(info.bindAddr,
                        assignedPort,
                        'remote',
                        12345,
                        mustCall((err, ch) => {
          assert(!err, `Unexpected error: ${err}`);
          conn.forwardOut('bad',
                          assignedPort,
                          'remote',
                          12345,
                          mustCall((err, ch) => {
            assert(err, 'Should receive error');
            client.end();
          }));
        }));
      }));
    }));
  }));

  client.on('ready', mustCall(() => {
    // request forwarding
    client.forwardIn('good', 0, mustCall((err, port) => {
      assert(!err, `Unexpected error: ${err}`);
      assert(port === assignedPort, 'Wrong assigned port');
    }));
  })).on('tcp connection', mustCall((details, accept, reject) => {
    assert.deepStrictEqual(
      details,
      { destIP: 'good',
        destPort: assignedPort,
        srcIP: 'remote',
        srcPort: 12345
      },
      'Wrong connection details'
    );
    accept();
  }));
}

{
  const { client, server } = setup(
    'Client auto-rejects inbound connections to unknown bound port'
  );

  const assignedPort = 31337;

  server.on('connection', mustCall((conn) => {
    conn.on('ready', mustCall(() => {
      conn.on('request', mustCall((accept, reject, name, info) => {
        assert(name === 'tcpip-forward', 'Wrong request name');
        assert.deepStrictEqual(
          info,
          { bindAddr: 'good', bindPort: 0 },
          'Wrong request info'
        );
        accept(assignedPort);
        conn.forwardOut(info.bindAddr,
                        assignedPort,
                        'remote',
                        12345,
                        mustCall((err, ch) => {
          assert(!err, `Unexpected error: ${err}`);
          conn.forwardOut(info.bindAddr,
                          99999,
                          'remote',
                          12345,
                          mustCall((err, ch) => {
            assert(err, 'Should receive error');
            client.end();
          }));
        }));
      }));
    }));
  }));

  client.on('ready', mustCall(() => {
    // request forwarding
    client.forwardIn('good', 0, mustCall((err, port) => {
      assert(!err, `Unexpected error: ${err}`);
      assert(port === assignedPort, 'Wrong assigned port');
    }));
  })).on('tcp connection', mustCall((details, accept, reject) => {
    assert.deepStrictEqual(
      details,
      { destIP: 'good',
        destPort: assignedPort,
        srcIP: 'remote',
        srcPort: 12345
      },
      'Wrong connection details'
    );
    accept();
  }));
}

{
  const GREETING = 'Hello world!';

  const { client, server } = setup_(
    'Server greeting',
    {
      client: clientCfg,
      server: {
        ...serverCfg,
        greeting: GREETING,
      }
    },
  );

  let sawGreeting = false;

  server.on('connection', mustCall((conn) => {
    conn.on('handshake', mustCall((details) => {
      assert(sawGreeting, 'Client did not see greeting before handshake');
    })).on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {
      conn.end();
    }));
  }));

  client.on('greeting', mustCall((greeting) => {
    assert.strictEqual(greeting, `${GREETING}\r\n`);
    sawGreeting = true;
  })).on('banner', mustNotCall());
}

{
  const BANNER = 'Hello world!';

  const { client, server } = setup_(
    'Server banner',
    {
      client: clientCfg,
      server: {
        ...serverCfg,
        banner: BANNER,
      }
    },
  );

  let sawBanner = false;

  server.on('connection', mustCall((conn) => {
    conn.on('handshake', mustCall((details) => {
      assert(!sawBanner, 'Client saw banner too early');
    })).on('authentication', mustCall((ctx) => {
      assert(sawBanner, 'Client did not see banner before auth');
      ctx.accept();
    })).on('ready', mustCall(() => {
      conn.end();
    }));
  }));

  client.on('greeting', mustNotCall())
        .on('banner', mustCall((message) => {
    assert.strictEqual(message, 'Hello world!\r\n');
    sawBanner = true;
  }));
}

{
  const { client, server } = setup(
    'Server responds to global requests in the right order'
  );

  function sendAcceptLater(accept) {
    if (fastRejectSent)
      accept();
    else
      setImmediate(sendAcceptLater, accept);
  }

  let fastRejectSent = false;

  server.on('connection', mustCall((conn) => {
    conn.on('ready', mustCall(() => {
      conn.on('request', mustCall((accept, reject, name, info) => {
        if (info.bindAddr === 'fastReject') {
          // Will call reject on 'fastReject' soon ...
          reject();
          fastRejectSent = true;
        } else {
          // ... but accept on 'slowAccept' later
          sendAcceptLater(accept);
        }
      }, 2));
    }));
  }));

  client.on('ready', mustCall(() => {
    let replyCnt = 0;

    client.forwardIn('slowAccept', 0, mustCall((err) => {
      assert(!err, `Unexpected error: ${err}`);
      if (++replyCnt === 2)
        client.end();
    }));

    client.forwardIn('fastReject', 0, mustCall((err) => {
      assert(err, 'Expected error');
      if (++replyCnt === 2)
        client.end();
    }));
  }));
}

{
  const { client, server } = setup(
    'Cleanup outstanding channel requests on channel close'
  );

  let timer;

  server.on('connection', mustCall((conn) => {
    conn.on('ready', mustCall(() => {
      conn.on('session', mustCall((accept, reject) => {
        const session = accept();
        session.on('subsystem', mustCall((accept, reject, info) => {
          assert.equal(info.name, 'netconf');

          // XXX: hack to prevent success reply from being sent
          conn._protocol.channelSuccess = () => {};

          const stream = accept();
          stream.close();
          timer = setTimeout(mustNotCall(), 50);
        }));
      }));
    }));
  }));

  client.on('ready', mustCall(() => {
    client.subsys('netconf', mustCall((err, stream) => {
      clearTimeout(timer);
      assert(err);
      client.end();
    }));
  }));
}

{
  const { client, server } = setup_(
    'Handshake errors are emitted',
    {
      client: {
        ...clientCfg,
        algorithms: { cipher: [ 'aes128-cbc' ] },
      },
      server: {
        ...serverCfg,
        algorithms: { cipher: [ 'aes128-ctr' ] },
      },

      noForceClientReady: true,
      noForceServerReady: true,
    },
  );

  client.removeAllListeners('error');

  function onError(err) {
    assert.strictEqual(err.level, 'handshake');
    assert(/handshake failed/i.test(err.message), 'Wrong error message');
  }

  server.on('connection', mustCall((conn) => {
    conn.removeAllListeners('error');

    conn.on('authentication', mustNotCall())
        .on('ready', mustNotCall())
        .on('handshake', mustNotCall())
        .on('error', mustCall(onError))
        .on('close', mustCall(() => {}));
  }));

  client.on('ready', mustNotCall())
        .on('error', mustCall(onError))
        .on('close', mustCall(() => {}));
}

{
  const { client, server } = setup_(
    'Client signing errors are caught and emitted',
    {
      client: {
        username: 'foo',
        privateKey: KEY_RSA_BAD,
      },
      server: serverCfg,

      noForceClientReady: true,
      noForceServerReady: true,
    },
  );

  client.removeAllListeners('error');

  server.on('connection', mustCall((conn) => {
    let authAttempt = 0;
    conn.on('authentication', mustCall((ctx) => {
      assert(!ctx.signature, 'Unexpected signature');
      switch (++authAttempt) {
        case 1:
          assert(ctx.method === 'none'), `Wrong auth method: ${ctx.method}`;
          return ctx.reject();
        case 2:
          assert(ctx.method === 'publickey',
                 `Wrong auth method: ${ctx.method}`);
          ctx.accept();
          break;
      }
    }, 2)).on('ready', mustNotCall()).on('close', mustCall(() => {}));
  }));

  let cliError;
  client.on('ready', mustNotCall()).on('error', mustCall((err) => {
    if (cliError) {
      assert(/all configured/i.test(err.message),
             'Wrong error message');
    } else {
      cliError = err;
      assert(/signing/i.test(err.message), 'Wrong error message');
    }
  }, 2)).on('close', mustCall(() => {}));
}

{
  const { client, server } = setup_(
    'Server signing errors are caught and emitted',
    {
      client: clientCfg,
      server: { hostKeys: [KEY_RSA_BAD] },

      noForceClientReady: true,
      noForceServerReady: true,
    },
  );

  client.removeAllListeners('error');

  server.on('connection', mustCall((conn) => {
    conn.removeAllListeners('error');

    conn.on('error', mustCall((err) => {
      assert(/signature generation failed/i.test(err.message),
             'Wrong error message');
    })).on('authentication', mustNotCall())
       .on('ready', mustNotCall())
       .on('close', mustCall(() => {}));
  }));

  client.on('ready', mustNotCall()).on('error', mustCall((err) => {
    assert(/KEY_EXCHANGE_FAILED/.test(err.message), 'Wrong error message');
  })).on('close', mustCall(() => {}));
}

{
  const { client, server } = setup_(
    'Rekeying with AES-GCM',
    {
      client: {
        ...clientCfg,
        algorithms: { cipher: [ 'aes128-gcm@openssh.com' ] },
      },
      server: {
        ...serverCfg,
        algorithms: { cipher: [ 'aes128-gcm@openssh.com' ] },
      },
    },
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {
      const reqs = [];
      conn.on('session', mustCall((accept, reject) => {
        if (reqs.length === 0) {
          conn.rekey(mustCall((err) => {
            assert(!err, `Unexpected rekey error: ${err}`);
            reqs.forEach((accept) => {
              const session = accept();
              session.on('exec', mustCall((accept, reject, info) => {
                const stream = accept();
                stream.exit(0);
                stream.end();
              }));
            });
          }));
        }
        reqs.push(accept);
      }, 3));
    }));
  }));

  client.on('ready', mustCall(() => {
    let calledBack = 0;
    function callback(err, stream) {
      assert(!err, `Unexpected error: ${err}`);
      stream.resume();
      if (++calledBack === 3)
        client.end();
    }
    client.exec('foo', mustCall(callback));
    client.exec('bar', mustCall(callback));
    client.exec('baz', mustCall(callback));
  }));
}

{
  const { client, server } = setup_(
    'Switch from no compression to compression',
    {
      client: {
        ...clientCfg,
        algorithms: { compress: [ 'none' ] },
      },
      server: {
        ...serverCfg,
        algorithms: { compress: [ 'none', 'zlib@openssh.com' ] },
      },
    },
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {
      const reqs = [];
      conn.on('session', mustCall((accept, reject) => {
        if (reqs.length === 0) {
          // XXX: hack to change algorithms after initial handshake
          client._protocol._offer = new KexInit({
            kex: [ 'ecdh-sha2-nistp256' ],
            srvHostKey: [ 'rsa-sha2-256' ],
            cs: {
              cipher: [ 'aes128-gcm@openssh.com' ],
              mac: [],
              compress: [ 'zlib@openssh.com' ],
              lang: [],
            },
            sc: {
              cipher: [ 'aes128-gcm@openssh.com' ],
              mac: [],
              compress: [ 'zlib@openssh.com' ],
              lang: [],
            },
          });

          conn.rekey(mustCall((err) => {
            assert(!err, `Unexpected rekey error: ${err}`);
            reqs.forEach((accept) => {
              const session = accept();
              session.on('exec', mustCall((accept, reject, info) => {
                const stream = accept();
                stream.exit(0);
                stream.end();
              }));
            });
          }));
        }
        reqs.push(accept);
      }, 3));
    }));
  }));

  let handshakes = 0;
  client.on('handshake', mustCall((info) => {
    switch (++handshakes) {
      case 1:
        assert(info.cs.compress === 'none', 'wrong compress value');
        assert(info.sc.compress === 'none', 'wrong compress value');
        break;
      case 2:
        assert(info.cs.compress === 'zlib@openssh.com',
               'wrong compress value');
        assert(info.sc.compress === 'zlib@openssh.com',
               'wrong compress value');
        break;
    }
  }, 2)).on('ready', mustCall(() => {
    let calledBack = 0;
    function callback(err, stream) {
      assert(!err, `Unexpected error: ${err}`);
      stream.resume();
      if (++calledBack === 3)
        client.end();
    }
    client.exec('foo', mustCall(callback));
    client.exec('bar', mustCall(callback));
    client.exec('baz', mustCall(callback));
  }));
}

{
  const { client, server } = setup_(
    'Switch from compression to no compression',
    {
      client: {
        ...clientCfg,
        algorithms: { compress: [ 'zlib' ] },
      },
      server: {
        ...serverCfg,
        algorithms: { compress: [ 'zlib', 'none' ] },
      }
    },
  );

  server.on('connection', mustCall((conn) => {
    conn.on('authentication', mustCall((ctx) => {
      ctx.accept();
    })).on('ready', mustCall(() => {
      const reqs = [];
      conn.on('session', mustCall((accept, reject) => {
        if (reqs.length === 0) {
          // XXX: hack to change algorithms after initial handshake
          client._protocol._offer = new KexInit({
            kex: [ 'ecdh-sha2-nistp256' ],
            srvHostKey: [ 'rsa-sha2-256' ],
            cs: {
              cipher: [ 'aes128-gcm@openssh.com' ],
              mac: [],
              compress: [ 'none' ],
              lang: [],
            },
            sc: {
              cipher: [ 'aes128-gcm@openssh.com' ],
              mac: [],
              compress: [ 'none' ],
              lang: [],
            },
          });

          conn.rekey(mustCall((err) => {
            assert(!err, `Unexpected rekey error: ${err}`);
            reqs.forEach((accept) => {
              const session = accept();
              session.on('exec', mustCall((accept, reject, info) => {
                const stream = accept();
                stream.exit(0);
                stream.end();
              }));
            });
          }));
        }
        reqs.push(accept);
      }, 3));
    }));
  }));

  let handshakes = 0;
  client.on('handshake', mustCall((info) => {
    switch (++handshakes) {
      case 1:
        assert(info.cs.compress === 'zlib', 'wrong compress value');
        assert(info.sc.compress === 'zlib', 'wrong compress value');
        break;
      case 2:
        assert(info.cs.compress === 'none', 'wrong compress value');
        assert(info.sc.compress === 'none', 'wrong compress value');
        break;
    }
  }, 2)).on('ready', mustCall(() => {
    let calledBack = 0;
    function callback(err, stream) {
      assert(!err, `Unexpected error: ${err}`);
      stream.resume();
      if (++calledBack === 3)
        client.end();
    }
    client.exec('foo', mustCall(callback));
    client.exec('bar', mustCall(callback));
    client.exec('baz', mustCall(callback));
  }));
}
