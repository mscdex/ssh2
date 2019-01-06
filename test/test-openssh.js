var Server = require('../lib/server');
var utils = require('ssh2-streams').utils;

var fs = require('fs');
var path = require('path');
var join = path.join;
var assert = require('assert');
var spawn = require('child_process').spawn;
var exec = require('child_process').exec;

var t = -1;
var group = path.basename(__filename, '.js') + '/';
var fixturesdir = join(__dirname, 'fixtures');

var CLIENT_TIMEOUT = 5000;
var USER = 'nodejs';
var HOST_KEY_RSA = fs.readFileSync(join(fixturesdir, 'ssh_host_rsa_key'));
var HOST_KEY_DSA = fs.readFileSync(join(fixturesdir, 'ssh_host_dsa_key'));
var HOST_KEY_ECDSA = fs.readFileSync(join(fixturesdir, 'ssh_host_ecdsa_key'));
var CLIENT_KEY_RSA_PATH = join(fixturesdir, 'id_rsa');
var CLIENT_KEY_RSA_RAW = fs.readFileSync(CLIENT_KEY_RSA_PATH);
var CLIENT_KEY_RSA = utils.parseKey(CLIENT_KEY_RSA_RAW);
var CLIENT_KEY_DSA_PATH = join(fixturesdir, 'id_dsa');
var CLIENT_KEY_DSA_RAW = fs.readFileSync(CLIENT_KEY_DSA_PATH);
var CLIENT_KEY_DSA = utils.parseKey(CLIENT_KEY_DSA_RAW);
var CLIENT_KEY_ECDSA_PATH = join(fixturesdir, 'id_ecdsa');
var CLIENT_KEY_ECDSA_RAW = fs.readFileSync(CLIENT_KEY_ECDSA_PATH);
var CLIENT_KEY_ECDSA = utils.parseKey(CLIENT_KEY_ECDSA_RAW);

var opensshVer;
var DEBUG = false;

// Fix file modes to avoid OpenSSH client complaints about keys' permissions
fs.readdirSync(fixturesdir).forEach(function(file) {
  fs.chmodSync(join(fixturesdir, file), '0600');
});

var tests = [
  { run: function() {
      var what = this.what;
      var server;

      server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_RSA_PATH },
        { hostKeys: [HOST_KEY_RSA] }
      );

      server.on('connection', function(conn) {
        conn.on('authentication', function(ctx) {
          if (ctx.method === 'none')
            return ctx.reject();
          assert(ctx.method === 'publickey',
                 makeMsg(what, 'Unexpected auth method: ' + ctx.method));
          assert(ctx.username === USER,
                 makeMsg(what, 'Unexpected username: ' + ctx.username));
          assert(ctx.key.algo === 'ssh-rsa',
                 makeMsg(what, 'Unexpected key algo: ' + ctx.key.algo));
          assert.deepEqual(CLIENT_KEY_RSA.getPublicSSH(),
                           ctx.key.data,
                           makeMsg(what, 'Public key mismatch'));
          if (ctx.signature) {
            assert(CLIENT_KEY_RSA.verify(ctx.blob, ctx.signature) === true,
                   makeMsg(what, 'Could not verify PK signature'));
            ctx.accept();
          } else
            ctx.accept();
        }).on('ready', function() {
          conn.on('session', function(accept, reject) {
            var session = accept();
            if (session) {
              session.on('exec', function(accept, reject) {
                var stream = accept();
                if (stream) {
                  stream.exit(0);
                  stream.end();
                }
              }).on('pty', function(accept, reject) {
                accept && accept();
              });
            }
          });
        });
      });
    },
    what: 'Authenticate with an RSA key'
  },
  { run: function() {
      var what = this.what;
      var server;

      server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_DSA_PATH },
        { hostKeys: [HOST_KEY_RSA] }
      );

      server.on('connection', function(conn) {
        conn.on('authentication', function(ctx) {
          if (ctx.method === 'none')
            return ctx.reject();
          assert(ctx.method === 'publickey',
                 makeMsg(what, 'Unexpected auth method: ' + ctx.method));
          assert(ctx.username === USER,
                 makeMsg(what, 'Unexpected username: ' + ctx.username));
          assert(ctx.key.algo === 'ssh-dss',
                 makeMsg(what, 'Unexpected key algo: ' + ctx.key.algo));
          assert.deepEqual(CLIENT_KEY_DSA.getPublicSSH(),
                           ctx.key.data,
                           makeMsg(what, 'Public key mismatch'));
          if (ctx.signature) {
            assert(CLIENT_KEY_DSA.verify(ctx.blob, ctx.signature) === true,
                   makeMsg(what, 'Could not verify PK signature'));
            ctx.accept();
          } else
            ctx.accept();
        }).on('ready', function() {
          conn.on('session', function(accept, reject) {
            var session = accept();
            if (session) {
              session.on('exec', function(accept, reject) {
                var stream = accept();
                if (stream) {
                  stream.exit(0);
                  stream.end();
                }
              }).on('pty', function(accept, reject) {
                accept && accept();
              });
            }
          });
        });
      });
    },
    what: 'Authenticate with a DSA key'
  },
  { run: function() {
      var what = this.what;
      var server;

      server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_ECDSA_PATH },
        { hostKeys: [HOST_KEY_RSA] }
      );

      server.on('connection', function(conn) {
        conn.on('authentication', function(ctx) {
          if (ctx.method === 'none')
            return ctx.reject();
          assert(ctx.method === 'publickey',
                 makeMsg(what, 'Unexpected auth method: ' + ctx.method));
          assert(ctx.username === USER,
                 makeMsg(what, 'Unexpected username: ' + ctx.username));
          assert(ctx.key.algo === 'ecdsa-sha2-nistp256',
                 makeMsg(what, 'Unexpected key algo: ' + ctx.key.algo));
          assert.deepEqual(CLIENT_KEY_ECDSA.getPublicSSH(),
                           ctx.key.data,
                           makeMsg(what, 'Public key mismatch'));
          if (ctx.signature) {
            assert(CLIENT_KEY_ECDSA.verify(ctx.blob, ctx.signature) === true,
                   makeMsg(what, 'Could not verify PK signature'));
            ctx.accept();
          } else
            ctx.accept();
        }).on('ready', function() {
          conn.on('session', function(accept, reject) {
            var session = accept();
            if (session) {
              session.on('exec', function(accept, reject) {
                var stream = accept();
                if (stream) {
                  stream.exit(0);
                  stream.end();
                }
              }).on('pty', function(accept, reject) {
                accept && accept();
              });
            }
          });
        });
      });
    },
    what: 'Authenticate with a ECDSA key'
  },
  { run: function() {
      var server;

      server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_RSA_PATH },
        { hostKeys: [HOST_KEY_DSA] }
      );

      server.on('connection', function(conn) {
        conn.on('authentication', function(ctx) {
          ctx.accept();
        }).on('ready', function() {
          conn.on('session', function(accept, reject) {
            var session = accept();
            if (session) {
              session.on('exec', function(accept, reject) {
                var stream = accept();
                if (stream) {
                  stream.exit(0);
                  stream.end();
                }
              }).on('pty', function(accept, reject) {
                accept && accept();
              });
            }
          });
        });
      });
    },
    what: 'Server with DSA host key'
  },
  { run: function() {
      var server;

      server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_RSA_PATH },
        { hostKeys: [HOST_KEY_ECDSA] }
      );

      server.on('connection', function(conn) {
        conn.on('authentication', function(ctx) {
          ctx.accept();
        }).on('ready', function() {
          conn.on('session', function(accept, reject) {
            var session = accept();
            if (session) {
              session.on('exec', function(accept, reject) {
                var stream = accept();
                if (stream) {
                  stream.exit(0);
                  stream.end();
                }
              }).on('pty', function(accept, reject) {
                accept && accept();
              });
            }
          });
        });
      });
    },
    what: 'Server with ECDSA host key'
  },
  { run: function() {
      var server;
      var what = this.what;

      server = setup(
        this,
        { privateKeyPath: CLIENT_KEY_RSA_PATH },
        { hostKeys: [HOST_KEY_RSA] }
      );

      server.on('_child', function(childProc) {
        childProc.stderr.once('data', function(data) {
          childProc.stdin.end();
        });
        childProc.stdin.write('ping');
      }).on('connection', function(conn) {
        conn.on('authentication', function(ctx) {
          ctx.accept();
        }).on('ready', function() {
          conn.on('session', function(accept, reject) {
            var session = accept();
            assert(session, makeMsg(what, 'Missing session'));
            session.on('exec', function(accept, reject) {
              var stream = accept();
              assert(stream, makeMsg(what, 'Missing exec stream'));
              stream.stdin.on('data', function(data) {
                stream.stdout.write('pong on stdout');
                stream.stderr.write('pong on stderr');
              }).on('end', function() {
                stream.stdout.write('pong on stdout');
                stream.stderr.write('pong on stderr');
                stream.exit(0);
                stream.close();
              });
            }).on('pty', function(accept, reject) {
              accept && accept();
            });
          });
        });
      });
    },
    what: 'Server closes stdin too early'
  },
];

function setup(self, clientcfg, servercfg) {
  self.state = {
    serverReady: false,
    clientClose: false,
    serverClose: false
  };

  var client;
  var server = new Server(servercfg);

  server.on('error', onError)
        .on('connection', function(conn) {
          conn.on('error', onError)
              .on('ready', onReady);
          server.close();
        })
        .on('close', onClose);

  function onError(err) {
    var which = (arguments.length >= 3 ? 'client' : 'server');
    assert(false, makeMsg(self.what, 'Unexpected ' + which + ' error: ' + err));
  }
  function onReady() {
    assert(!self.state.serverReady,
           makeMsg(self.what, 'Received multiple ready events for server'));
    self.state.serverReady = true;
    self.onReady && self.onReady();
  }
  function onClose() {
    if (arguments.length >= 3) {
      assert(!self.state.clientClose,
             makeMsg(self.what, 'Received multiple close events for client'));
      self.state.clientClose = true;
    } else {
      assert(!self.state.serverClose,
             makeMsg(self.what, 'Received multiple close events for server'));
      self.state.serverClose = true;
    }
    if (self.state.clientClose && self.state.serverClose)
      next();
  }

  process.nextTick(function() {
    server.listen(0, 'localhost', function() {
      var cmd = 'ssh';
      var args = ['-o', 'UserKnownHostsFile=/dev/null',
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
                  '-o', 'PreferredAuthentications=publickey'];
      if (clientcfg.privateKeyPath)
        args.push('-o', 'IdentityFile=' + clientcfg.privateKeyPath);
      if (!/^[0-6]\./.test(opensshVer)) {
        // OpenSSH 7.0+ disables DSS/DSA host (and user) key support by
        // default, so we explicitly enable it here
        args.push('-o', 'HostKeyAlgorithms=+ssh-dss');
      }
      args.push('-p', server.address().port.toString(),
                '-l', USER,
                'localhost',
                'uptime');

      client = spawn(cmd, args);
      server.emit('_child', client);
      if (DEBUG) {
        client.stdout.pipe(process.stdout);
        client.stderr.pipe(process.stderr);
      } else {
        client.stdout.resume();
        client.stderr.resume();
      }
      client.on('error', function(err) {
        onError(err, null, null);
      }).on('exit', function(code) {
        clearTimeout(client.timer);
        if (code !== 0)
          return onError(new Error('Non-zero exit code ' + code), null, null);
        onClose(null, null, null);
      });

      client.timer = setTimeout(function() {
        assert(false, makeMsg(self.what, 'Client timeout'));
      }, CLIENT_TIMEOUT);
    });
  });
  return server;
}

function next() {
  if (Array.isArray(process._events.exit))
    process._events.exit = process._events.exit[1];
  if (++t === tests.length)
    return;

  var v = tests[t];
  v.run.call(v);
}

function makeMsg(what, msg) {
  return '[' + group + what + ']: ' + msg;
}

process.once('uncaughtException', function(err) {
  if (t > -1 && !/(?:^|\n)AssertionError: /i.test(''+err))
    console.log(makeMsg(tests[t].what, 'Unexpected Exception:'));
  throw err;
});
process.once('exit', function() {
  assert(t === tests.length,
         makeMsg('_exit',
                 'Only finished ' + t + '/' + tests.length + ' tests'));
});


// Get OpenSSH client version first
exec('ssh -V', function(err, stdout, stderr) {
  if (err) {
    console.log('OpenSSH client is required for these tests');
    process.exitCode = 5;
    return;
  }
  var re = /^OpenSSH_([\d\.]+)/;
  var m = re.exec(stdout.toString());
  if (!m || !m[1]) {
    m = re.exec(stderr.toString());
    if (!m || !m[1]) {
      console.log('OpenSSH client is required for these tests');
      process.exitCode = 5;
      return;
    }
  }
  opensshVer = m[1];
  next();
});
