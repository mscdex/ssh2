// TODO: add more rekey tests that at least include switching from no
// compression to compression and vice versa
'use strict';

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const { chmodSync, readdirSync, readFileSync } = require('fs');
const { basename, join } = require('path');

const Server = require('../lib/server.js');
const { parseKey } = require('../lib/protocol/keyParser.js');

const { mustCall, mustCallAtLeast } = require('./common.js');

let t = -1;
const THIS_FILE = basename(__filename, '.js');
const SPAWN_OPTS = { windowsHide: true };
const fixturesDir = join(__dirname, 'fixtures');
const fixture = (file) => readFileSync(join(fixturesDir, file));

const HOST_KEY_RSA = fixture('ssh_host_rsa_key');
const HOST_KEY_DSA = fixture('ssh_host_dsa_key');
const HOST_KEY_ECDSA = fixture('ssh_host_ecdsa_key');
const CLIENT_KEY_RSA_PATH = join(fixturesDir, 'id_rsa');
const CLIENT_KEY_RSA_RAW = readFileSync(CLIENT_KEY_RSA_PATH);
const CLIENT_KEY_RSA = parseKey(CLIENT_KEY_RSA_RAW);
const CLIENT_KEY_DSA_PATH = join(fixturesDir, 'id_dsa');
const CLIENT_KEY_DSA_RAW = readFileSync(CLIENT_KEY_DSA_PATH);
const CLIENT_KEY_DSA = parseKey(CLIENT_KEY_DSA_RAW);
const CLIENT_KEY_ECDSA_PATH = join(fixturesDir, 'id_ecdsa');
const CLIENT_KEY_ECDSA_RAW = readFileSync(CLIENT_KEY_ECDSA_PATH);
const CLIENT_KEY_ECDSA = parseKey(CLIENT_KEY_ECDSA_RAW);
const CLIENT_TIMEOUT = 5000;
const USER = 'nodejs';
const DEBUG = false;

const opensshPath = 'ssh';
let opensshVer;

// Fix file modes to avoid OpenSSH client complaints about keys' permissions
for (const file of readdirSync(fixturesDir, { withFileTypes: true })) {
  if (file.isFile())
    chmodSync(join(fixturesDir, file.name), 0o600);
}

const tests = [
  { run: mustCall(function(msg) {
      const server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_RSA_PATH },
        { hostKeys: [HOST_KEY_RSA] }
      );

      server.on('connection', mustCall((conn) => {
        let authAttempt = 0;
        conn.on('authentication', mustCall((ctx) => {
          switch (++authAttempt) {
            case 1:
              assert(ctx.method === 'none'),
                     msg(`Wrong method: ${ctx.method}`);
              return ctx.reject();
            case 3:
              assert(ctx.signature !== undefined,
                     msg('Missing publickey signature'));
            // FALLTHROUGH
            case 2:
              assert(ctx.method === 'publickey',
                     msg(`Unexpected auth method: ${ctx.method}`));
              assert(ctx.username === USER,
                     msg(`Unexpected username: ${ctx.username}`));
              assert(ctx.key.algo === 'ssh-rsa',
                     msg(`Unexpected key algo: ${ctx.key.algo}`));
              assert.deepEqual(CLIENT_KEY_RSA.getPublicSSH(),
                               ctx.key.data,
                               msg('Public key mismatch'));
              break;
            default:
              assert(false, msg('Too many auth attempts'));
          }
          if (ctx.signature) {
            assert(CLIENT_KEY_RSA.verify(ctx.blob, ctx.signature) === true,
                   msg('Could not verify PK signature'));
          }
          ctx.accept();
        }, 2)).on('ready', mustCall(() => {
          conn.on('session', mustCall((accept, reject) => {
            const session = accept();
            session.on('exec', mustCall((accept, reject) => {
              const stream = accept();
              stream.exit(0);
              stream.end();
            })).on('pty', mustCall((accept, reject) => {
              accept && accept();
            }));
          }));
        }));
      }));
    }),
    what: 'Authenticate with an RSA key'
  },
  { run: mustCall(function(msg) {
      const server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_DSA_PATH },
        { hostKeys: [HOST_KEY_RSA] }
      );

      server.on('connection', mustCall((conn) => {
        let authAttempt = 0;
        conn.on('authentication', mustCall((ctx) => {
          switch (++authAttempt) {
            case 1:
              assert(ctx.method === 'none'),
                     msg(`Wrong method: ${ctx.method}`);
              return ctx.reject();
            case 3:
              assert(ctx.signature !== undefined,
                     msg('Missing publickey signature'));
            // FALLTHROUGH
            case 2:
              assert(ctx.method === 'publickey',
                     msg(`Unexpected auth method: ${ctx.method}`));
              assert(ctx.username === USER,
                     msg(`Unexpected username: ${ctx.username}`));
              assert(ctx.key.algo === 'ssh-dss',
                     msg(`Unexpected key algo: ${ctx.key.algo}`));
              assert.deepEqual(CLIENT_KEY_DSA.getPublicSSH(),
                               ctx.key.data,
                               msg('Public key mismatch'));
              break;
            default:
              assert(false, msg('Too many auth attempts'));
          }
          if (ctx.signature) {
            assert(CLIENT_KEY_DSA.verify(ctx.blob, ctx.signature) === true,
                   msg('Could not verify PK signature'));
          }
          ctx.accept();
        }, 2)).on('ready', mustCall(() => {
          conn.on('session', mustCall((accept, reject) => {
            const session = accept();
            session.on('exec', mustCall((accept, reject) => {
              const stream = accept();
              stream.exit(0);
              stream.end();
            })).on('pty', mustCall((accept, reject) => {
              accept && accept();
            }));
          }));
        }));
      }));
    }),
    what: 'Authenticate with a DSA key'
  },
  { run: mustCall(function(msg) {
      const server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_ECDSA_PATH },
        { hostKeys: [HOST_KEY_RSA] }
      );

      server.on('connection', mustCall((conn) => {
        let authAttempt = 0;
        conn.on('authentication', mustCall((ctx) => {
          switch (++authAttempt) {
            case 1:
              assert(ctx.method === 'none'),
                     msg(`Wrong method: ${ctx.method}`);
              return ctx.reject();
            case 3:
              assert(ctx.signature !== undefined,
                     msg('Missing publickey signature'));
            // FALLTHROUGH
            case 2:
              assert(ctx.method === 'publickey',
                     msg(`Unexpected auth method: ${ctx.method}`));
              assert(ctx.username === USER,
                     msg(`Unexpected username: ${ctx.username}`));
              assert(ctx.key.algo === 'ecdsa-sha2-nistp256',
                     msg(`Unexpected key algo: ${ctx.key.algo}`));
              assert.deepEqual(CLIENT_KEY_ECDSA.getPublicSSH(),
                               ctx.key.data,
                               msg('Public key mismatch'));
              break;
            default:
              assert(false, msg('Too many auth attempts'));
          }
          if (ctx.signature) {
            assert(CLIENT_KEY_ECDSA.verify(ctx.blob, ctx.signature) === true,
                   msg('Could not verify PK signature'));
          }
          ctx.accept();
        }, 3)).on('ready', mustCall(() => {
          conn.on('session', mustCall((accept, reject) => {
            const session = accept();
            session.on('exec', mustCall((accept, reject) => {
              const stream = accept();
              stream.exit(0);
              stream.end();
            })).on('pty', mustCall((accept, reject) => {
              accept && accept();
            }));
          }));
        }));
      }));
    }),
    what: 'Authenticate with an ECDSA key'
  },
  { run: mustCall(function(msg) {
      const server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_RSA_PATH },
        { hostKeys: [HOST_KEY_DSA] }
      );

      server.on('connection', mustCall((conn) => {
        conn.on('authentication', mustCall((ctx) => {
          ctx.accept();
        })).on('ready', mustCall(() => {
          conn.on('session', mustCall((accept, reject) => {
            const session = accept();
            session.on('exec', mustCall((accept, reject) => {
              const stream = accept();
              stream.exit(0);
              stream.end();
            })).on('pty', mustCall((accept, reject) => {
              accept && accept();
            }));
          }));
        }));
      }));
    }),
    what: 'Server with DSA host key'
  },
  { run: mustCall(function(msg) {
      const server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_RSA_PATH },
        { hostKeys: [HOST_KEY_ECDSA] }
      );

      server.on('connection', mustCall((conn) => {
        conn.on('authentication', mustCall((ctx) => {
          ctx.accept();
        })).on('ready', mustCall(() => {
          conn.on('session', mustCall((accept, reject) => {
            const session = accept();
            session.on('exec', mustCall((accept, reject) => {
              const stream = accept();
              stream.exit(0);
              stream.end();
            })).on('pty', mustCall((accept, reject) => {
              accept && accept();
            }));
          }));
        }));
      }));
    }),
    what: 'Server with ECDSA host key'
  },
  { run: mustCall(function(msg) {
      const server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_RSA_PATH },
        { hostKeys: [HOST_KEY_RSA] }
      );

      server.on('_child', mustCall((childProc) => {
        childProc.stderr.once('data', function(data) {
          childProc.stdin.end();
        });
        childProc.stdin.write('ping');
      })).on('connection', mustCall((conn) => {
        conn.on('authentication', mustCall((ctx) => {
          ctx.accept();
        })).on('ready', mustCall(() => {
          conn.on('session', mustCall((accept, reject) => {
            const session = accept();
            session.on('exec', mustCall((accept, reject) => {
              const stream = accept();
              stream.stdin.on('data', mustCallAtLeast((data) => {
                stream.stdout.write('pong on stdout');
                stream.stderr.write('pong on stderr');
              })).on('end', mustCall(() => {
                stream.stdout.write('pong on stdout');
                stream.stderr.write('pong on stderr');
                stream.exit(0);
                stream.close();
              }));
            })).on('pty', mustCall((accept, reject) => {
              accept && accept();
            }));
          }));
        }));
      }));
    }),
    what: 'Server closes stdin too early'
  },
  { run: mustCall(function(msg) {
      const server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_RSA_PATH },
        { hostKeys: [HOST_KEY_RSA] }
      );

      server.on('connection', mustCall((conn) => {
        let authAttempt = 0;
        conn.on('authentication', mustCall((ctx) => {
          switch (++authAttempt) {
            case 1:
              assert(ctx.method === 'none'),
                     msg(`Wrong method: ${ctx.method}`);
              return ctx.reject();
            case 3:
              assert(ctx.signature !== undefined,
                     msg('Missing publickey signature'));
            // FALLTHROUGH
            case 2:
              assert(ctx.method === 'publickey',
                     msg(`Unexpected auth method: ${ctx.method}`));
              assert(ctx.username === USER,
                     msg(`Unexpected username: ${ctx.username}`));
              assert(ctx.key.algo === 'ssh-rsa',
                     msg(`Unexpected key algo: ${ctx.key.algo}`));
              assert.deepEqual(CLIENT_KEY_RSA.getPublicSSH(),
                               ctx.key.data,
                               msg('Public key mismatch'));
              break;
            default:
              assert(false, msg('Too many auth attempts'));
          }
          if (ctx.signature) {
            assert(CLIENT_KEY_RSA.verify(ctx.blob, ctx.signature) === true,
                   msg('Could not verify PK signature'));
          }
          ctx.accept();
        }, 3)).on('ready', mustCall(() => {
          conn.on('session', mustCall((accept, reject) => {
            const session = accept();
            conn.rekey();
            session.on('exec', mustCall((accept, reject) => {
              const stream = accept();
              stream.exit(0);
              stream.end();
            })).on('pty', mustCall((accept, reject) => {
              accept && accept();
            }));
          }));
        }));
      }));
    }),
    what: 'Rekey'
  },
];

function setup(self, clientCfg, serverCfg) {
  const { next, msg } = self;
  self.state = {
    serverReady: false,
    clientClose: false,
    serverClose: false,
  };

  let client;
  if (DEBUG) {
    console.log('========================================================\n'
                + `[TEST] ${self.what}\n`
                + '========================================================');
    serverCfg.debug = (...args) => {
      console.log(`[${self.what}][SERVER]`, ...args);
    };
  }
  const server = new Server(serverCfg);

  server.on('error', onError)
        .on('connection', mustCall((conn) => {
          conn.on('error', onError)
              .on('ready', mustCall(onReady));
          server.close();
        }))
        .on('close', mustCall(onClose));

  function onError(err) {
    const which = (arguments.length >= 3 ? 'client' : 'server');
    assert(false, msg(`Unexpected ${which} error: ${err}`));
  }

  function onReady() {
    assert(!self.state.serverReady,
           msg('Received multiple ready events for server'));
    self.state.serverReady = true;
    self.onReady && self.onReady();
  }

  function onClose() {
    if (arguments.length >= 3) {
      assert(!self.state.clientClose,
             msg('Received multiple close events for client'));
      self.state.clientClose = true;
    } else {
      assert(!self.state.serverClose,
             msg('Received multiple close events for server'));
      self.state.serverClose = true;
    }
    if (self.state.clientClose
        && self.state.serverClose
        && !getParamNames(self.run.origFn || self.run).includes('next')) {
      next();
    }
  }

  process.nextTick(mustCall(() => {
    server.listen(0, 'localhost', mustCall(() => {
      const args = [
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'CheckHostIP=no',
        '-o', 'ConnectTimeout=3',
        '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'GSSAPIAuthentication=no',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'BatchMode=yes',
        '-o', 'VerifyHostKeyDNS=no',

        '-vvvvvv',
        '-T',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'HostbasedAuthentication=no',
        '-o', 'PasswordAuthentication=no',
        '-o', 'PubkeyAuthentication=yes',
        '-o', 'PreferredAuthentications=publickey'
      ];
      if (clientCfg.privateKeyPath)
        args.push('-o', 'IdentityFile=' + clientCfg.privateKeyPath);
      if (!/^[0-6]\./.test(opensshVer)) {
        // OpenSSH 7.0+ disables DSS/DSA host (and user) key support by
        // default, so we explicitly enable it here
        args.push('-o', 'HostKeyAlgorithms=+ssh-dss');
        args.push('-o', 'PubkeyAcceptedKeyTypes=+ssh-dss');
      }
      args.push('-p', server.address().port.toString(),
                '-l', USER,
                'localhost',
                'uptime');

      client = spawn(opensshPath, args, SPAWN_OPTS);
      server.emit('_child', client);
      if (DEBUG) {
        client.stdout.pipe(process.stdout);
        client.stderr.pipe(process.stderr);
      } else {
        client.stdout.resume();
        client.stderr.resume();
      }
      client.on('error', (err) => {
        onError(err, null, null);
      }).on('exit', (code) => {
        clearTimeout(client.timer);
        if (code !== 0)
          return onError(new Error(`Non-zero exit code ${code}`), null, null);
        onClose(null, null, null);
      });

      client.timer = setTimeout(() => {
        assert(false, msg('Client timeout'));
      }, CLIENT_TIMEOUT);
    }));
  }));

  return server;
}

const getParamNames = (() => {
  const STRIP_COMMENTS = /((\/\/.*$)|(\/\*[\s\S]*?\*\/))/mg;
  const ARGUMENT_NAMES = /([^\s,]+)/g;
  const toString = Function.prototype.toString;
  return (fn) => {
    const s = toString.call(fn).replace(STRIP_COMMENTS, '');
    const result = s.slice(s.indexOf('(') + 1, s.indexOf(')'))
                    .match(ARGUMENT_NAMES);
    return (result || []);
  };
})();

function once(fn) {
  let called = false;
  return (...args) => {
    if (called)
      return;
    called = true;
    fn(...args);
  };
}

function next() {
  if (Array.isArray(process._events.exit))
    process._events.exit = process._events.exit[1];
  if (++t === tests.length)
    return;

  const v = tests[t];
  v.next = once(next);
  v.msg = msg.bind(null, v.what);
  v.run(v.msg, v.next);
}

function msg(what, desc) {
  return `[${THIS_FILE}/${what}]: ${desc}`;
}

process.once('exit', () => {
  const ran = Math.max(t, 0);
  assert(ran === tests.length,
         msg('(exit)', `Finished ${ran}/${tests.length} tests`));
});


{
  // Get OpenSSH client version first
  const {
    error, stderr, stdout
  } = spawnSync(opensshPath, ['-V'], SPAWN_OPTS);

  if (error) {
    console.error('OpenSSH client is required for these tests');
    process.exitCode = 5;
    return;
  }
  const re = /^OpenSSH_([\d.]+)/;
  let m = re.exec(stdout.toString());
  if (!m || !m[1]) {
    m = re.exec(stderr.toString());
    if (!m || !m[1]) {
      console.error('OpenSSH client is required for these tests');
      process.exitCode = 5;
      return;
    }
  }
  opensshVer = m[1];
  console.log(`Testing with OpenSSH version: ${opensshVer}`);
  next();
}
