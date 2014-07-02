var Connection = require('../lib/Connection');

var dns = require('dns'),
    fs = require('fs'),
    net = require('net'),
    cpspawn = require('child_process').spawn,
    cpexec = require('child_process').exec,
    path = require('path'),
    join = path.join,
    inspect = require('util').inspect,
    assert = require('assert');

var t = -1,
    forkedTest,
    group = path.basename(__filename, '.js') + '/',
    tempdir = join(__dirname, 'temp'),
    fixturesdir = join(__dirname, 'fixtures');

var SSHD_PORT,
    LOCALHOST,
    HOST_FINGERPRINT = '64254520742d3d0792e918f3ce945a64',
    PRIVATE_KEY_RSA = fs.readFileSync(join(fixturesdir, 'id_rsa')),
    PRIVATE_KEY_DSA = fs.readFileSync(join(fixturesdir, 'id_dsa')),
    USER = process.env.LOGNAME || process.env.USER || process.env.USERNAME;
    DEFAULT_SSHD_OPTS = {
      'AddressFamily': 'any',
      'AllowUsers': USER,
      'AuthorizedKeysFile': join(fixturesdir, 'authorized_keys'),
      'Banner': 'none',
      'Compression': 'no',
      'HostbasedAuthentication': 'no',
      'HostKey': join(fixturesdir, 'ssh_host_rsa_key'),
      'ListenAddress': 'localhost',
      'LogLevel': 'FATAL',
      'PasswordAuthentication': 'no',
      'PermitRootLogin': 'no',
      'Protocol': '2',
      'PubkeyAuthentication': 'yes',
      'Subsystem': 'sftp internal-sftp',
      'TCPKeepAlive': 'yes',
      'UseDNS': 'no',
      'UsePrivilegeSeparation': 'no'
    };

var tests = [
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready;
        conn.on('ready', function() {
          ready = true;
          this.end();
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    what: 'Authenticate with a RSA key'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready;
        conn.on('ready', function() {
          ready = true;
          this.end();
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    what: 'Authenticate with a DSA key'
  },
  { run: function() {
      // use ssh-agent with a command (this test) to make agent cleanup easier
      if (!process.env.SSH_AUTH_SOCK) {
        var proc = cpspawn('ssh-agent',
                           [process.argv[0], process.argv[1], t],
                           { stdio: 'inherit' });
        proc.on('exit', function(code, signal) {
          if (code === 0 && !signal)
            next();
        });
        return;
      }

      var self = this,
          what = this.what,
          conn = new Connection();

      // add key first
      cpexec('ssh-add ' + join(fixturesdir, 'id_rsa'), function() {
        startServer(function() {
          var error,
              ready;
          conn.on('ready', function() {
            ready = true;
            this.end();
          }).on('error', function(err) {
            error = err;
          }).on('close', function() {
            assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
            assert(ready, makeMsg(what, 'Expected ready'));
          }).connect(self.config);
        });
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      agent: process.env.SSH_AUTH_SOCK
    },
    what: 'Authenticate with an agent (RSA)'
  },
  { run: function() {
      // use ssh-agent with a command (this test) to make agent cleanup easier
      if (!process.env.SSH_AUTH_SOCK) {
        var proc = cpspawn('ssh-agent',
                           [process.argv[0], process.argv[1], t],
                           { stdio: 'inherit' });
        proc.on('exit', function(code, signal) {
          if (code === 0 && !signal)
            next();
        });
        return;
      }

      var self = this,
          what = this.what,
          conn = new Connection();

      // add key first
      cpexec('ssh-add ' + join(fixturesdir, 'id_dsa'), function(err, stdout, stderr) {
        startServer(function() {
          var error,
              ready;
          conn.on('ready', function() {
            ready = true;
            this.end();
          }).on('error', function(err) {
            error = err;
          }).on('close', function() {
            assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
            assert(ready, makeMsg(what, 'Expected ready'));
          }).connect(self.config);
        });
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      agent: process.env.SSH_AUTH_SOCK
    },
    what: 'Authenticate with an agent (DSA)'
  },
  { run: function() {
      // use ssh-agent with a command (this test) to make agent cleanup easier
      if (!process.env.SSH_AUTH_SOCK) {
        var proc = cpspawn('ssh-agent',
                           [process.argv[0], process.argv[1], t],
                           { stdio: 'inherit' });
        proc.on('exit', function(code, signal) {
          if (code === 0 && !signal)
            next();
        });
        return;
      }

      var self = this,
          what = this.what,
          conn = new Connection();

      // ssh-agent has no keys
      startServer({
        'ChallengeResponseAuthentication': 'yes',
        'UsePAM': 'yes'
      }, function() {
        var error,
            ready;
        conn.on('ready', function() {
          ready = true;
          this.end();
        }).on('keyboard-interactive', function (name, instructions, lang, messages, callback) {
          callback(['a']); // wrong password
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(error && /Authentication failure. Available authentication methods/.test(error.message),
                 makeMsg(what, 'Expected authentication failure error'));
          assert(!ready, makeMsg(what, 'Unexpected ready'));
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      agent: process.env.SSH_AUTH_SOCK,
      tryKeyboard: true
    },
    what: 'Authenticate with empty (valid) agent and keyboard-interactive options (bad password)'
  },
  { run: function() {
      // use ssh-agent with a command (this test) to make agent cleanup easier
      if (!process.env.SSH_AUTH_SOCK) {
        var proc = cpspawn('ssh-agent',
                           [process.argv[0], process.argv[1], t],
                           { stdio: 'inherit' });
        proc.on('exit', function(code, signal) {
          if (code === 0 && !signal)
            next();
        });
        return;
      }

      var self = this,
          what = this.what,
          conn = new Connection();

      // ssh-agent has a bad key
      cpexec('ssh-add ' + join(fixturesdir, 'id_rsa.bad'), function(err, stdout, stderr) {
        startServer({
          'ChallengeResponseAuthentication': 'yes',
          'UsePAM': 'yes'
        }, function() {
          var error,
              ready;
          conn.on('ready', function() {
            ready = true;
            this.end();
          }).on('keyboard-interactive', function (name, instructions, lang, messages, callback) {
            callback(['a']); // wrong password
          }).on('error', function(err) {
            error = err;
          }).on('close', function() {
            assert(error && /Authentication failure. Available authentication methods/.test(error.message),
                   makeMsg(what, 'Expected authentication failure error'));
            assert(!ready, makeMsg(what, 'Unexpected ready'));
          }).connect(self.config);
        });
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      agent: process.env.SSH_AUTH_SOCK,
      tryKeyboard: true
    },
    what: 'Authenticate with agent (1 bad key) and keyboard-interactive options (bad password)'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection(),
          fingerprint;
      this.config.hostVerifier = function(host) {
        fingerprint = host;
        return true; // perform actual verification at the end
      };
      startServer(function() {
        var error,
            ready;
        conn.on('ready', function() {
          ready = true;
          this.end();
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(HOST_FINGERPRINT === fingerprint,
                 makeMsg(what, 'Host fingerprint mismatch.\nSaw:\n'
                               + inspect(fingerprint)
                               + '\nExpected:\n'
                               + inspect(HOST_FINGERPRINT)));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA,
      hostHash: 'md5'
    },
    what: 'Verify host fingerprint'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection(),
          bannerPath = join(fixturesdir, 'banner'),
          bannerSent = fs.readFileSync(bannerPath,
                                       { encoding: 'utf8' });
      startServer({ 'Banner': bannerPath }, function() {
        var error,
            ready,
            bannerRecvd;
        conn.on('banner', function(msg) {
          bannerRecvd = msg;
        }).on('ready', function() {
          ready = true;
          this.exec('uptime', function(err) {
            assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
            conn.end();
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(bannerSent === bannerRecvd,
                 makeMsg(what, 'Banner mismatch.\nSaw:\n'
                               + inspect(bannerRecvd)
                               + '\nExpected:\n'
                               + inspect(bannerSent)));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    what: 'Banner message'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready;
        conn.on('ready', function() {
          ready = true;
          this.exec('uptime', function(err) {
            assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
            conn.end();
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    what: 'Simple exec'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer({ 'AcceptEnv': 'SSH2NODETEST' }, function() {
        var error,
            ready,
            out;
        conn.on('ready', function() {
          ready = true;
          this.exec('echo -n $SSH2NODETEST',
                    { env: { SSH2NODETEST: self.expected } },
                    function(err, stream) {
            assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
            stream.stderr.resume();
            bufferStream(stream, 'ascii', function(data) {
              out = data;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(out === self.expected,
                 makeMsg(what, 'Environment variable mismatch.\nSaw:\n'
                               + inspect(out)
                               + '\nExpected:\n'
                               + inspect(self.expected)));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    expected: 'Hello from node.js!!!',
    what: 'Exec with environment set'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            out;
        conn.on('ready', function() {
          ready = true;
          this.exec('(if [ -t 1 ] ; then echo terminal; fi); echo -e "lines\ncols"|tput -S && echo -n $TERM',
                    { pty: {
                        rows: 2,
                        cols: 4,
                        width: 0,
                        height: 0,
                        term: 'vt220'
                      }
                    },
                    function(err, stream) {
            assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
            stream.stderr.resume();
            bufferStream(stream, 'ascii', function(data) {
              out = (data ? stripDebug(data).split(/\r?\n/g) : data);
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert.deepEqual(out,
                           self.expected,
                           makeMsg(what, 'Exec output mismatch.\nSaw:\n'
                                         + inspect(out)
                                         + '\nExpected:\n'
                                         + inspect(self.expected)));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    expected: [
      'terminal',
      '2',
      '4',
      'vt220'
    ],
    what: 'Exec with pty set'
  },
  { run: function() {
      // use ssh-agent with a command (this test) to make agent cleanup easier
      if (!process.env.SSH_AUTH_SOCK) {
        var proc = cpspawn('ssh-agent',
                           [process.argv[0], process.argv[1], t],
                           { stdio: 'inherit' });
        proc.on('exit', function(code, signal) {
          if (code === 0 && !signal)
            next();
        });
        return;
      }

      var self = this,
          what = this.what,
          conn = new Connection();

      // add key first
      cpexec('ssh-add ' + join(fixturesdir, 'id_rsa'), function() {
        startServer(function() {
          var error,
              ready,
              out;
          conn.on('ready', function() {
            ready = true;
            this.exec('echo -n $SSH_AUTH_SOCK', function(err, stream) {
              assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
              stream.stderr.resume();
              bufferStream(stream, 'ascii', function(data) {
                out = data;
                conn.end();
              });
            });
          }).on('error', function(err) {
            error = err;
          }).on('close', function() {
            assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
            assert(ready, makeMsg(what, 'Expected ready'));
            assert(out && out.length,
                   makeMsg(what, 'Expected SSH_AUTH_SOCK in exec environment'));
          }).connect(self.config);
        });
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      agent: process.env.SSH_AUTH_SOCK,
      agentForward: true
    },
    what: 'Exec with OpenSSH agent forwarding'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer({
        'X11DisplayOffset': '50',
        'X11Forwarding': 'yes',
        'X11UseLocalhost': 'yes'
      }, function() {
        var error,
            ready,
            sawX11 = false;
        conn.on('ready', function() {
          ready = true;
          this.exec('xeyes', { x11: true }, function(err, stream) {
            assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
            stream.resume();
            stream.stderr.resume();
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(sawX11, makeMsg(what, 'Expected X11 request'));
          next();
        }).on('x11', function(details, accept, reject) {
          sawX11 = true;
          conn.end();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    what: 'Exec with X11 forwarding'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            out = {
              stdout: undefined,
              stderr: undefined
            };
        conn.on('ready', function() {
          ready = true;
          this.exec('echo -n "hello from stderr" 3>&1 1>&2 2>&3 3>&-',
                    function(err, stream) {
            assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
            bufferStream(stream, 'ascii', function(data) {
              out.stdout = data;
            });
            bufferStream(stream.stderr, 'ascii', function(data) {
              out.stderr = stripDebug(data);
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert.deepEqual(out,
                           self.expected,
                           makeMsg(what, 'Exec output mismatch.\nSaw:\n'
                                         + inspect(out)
                                         + '\nExpected:\n'
                                         + inspect(self.expected)));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    expected: {
      stdout: undefined,
      stderr: 'hello from stderr'
    },
    what: 'Exec with stderr output'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready;
        conn.on('ready', function() {
          ready = true;
          this.shell(function(err) {
            assert(!err, makeMsg(what, 'Unexpected shell error: ' + err));
            conn.end();
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    what: 'Simple shell'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer({ 'AllowTcpForwarding': 'local' }, function() {
        var error,
            ready,
            out;
        conn.on('ready', function() {
          ready = true;
          net.createServer(function(sock) {
            this.close();
            sock.end(self.expected);
          }).listen(0, 'localhost', function() {
            conn.forwardOut(''+this.address().address,
                            '0',
                            ''+this.address().address,
                            ''+this.address().port,
                            function(err, stream) {
              assert(!err, makeMsg(what, 'Unexpected forwardOut error: ' + err));
              bufferStream(stream, 'ascii', function(data) {
                out = data;
                conn.end();
              });
              stream.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert.equal(out,
                       self.expected,
                       makeMsg(what, 'Connection output mismatch.\nSaw:\n'
                                      + inspect(out)
                                      + '\nExpected:\n'
                                      + inspect(self.expected)));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA
    },
    expected: 'hello from node.js and ssh2!',
    what: 'Local port forwarding'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      this.expected.srcIP = LOCALHOST;
      startServer({ 'AllowTcpForwarding': 'remote' }, function() {
        var error,
            ready,
            out;
        conn.on('ready', function() {
          ready = true;
          this.forwardIn('localhost', 0, function(err, port) {
            assert(!err, makeMsg(what, 'Unexpected forwardIn error: ' + err));
            self.expected.destPort = port;
            (new net.Socket({ allowHalfOpen: true }))
              .on('connect', function() {
                self.expected.srcPort = this.localPort;
                this.end(self.expected.out);
              }).connect(port, 'localhost');
          });
        }).on('tcp connection', function(info, accept, reject) {
          out = info;
          accept().on('close', function() {
            conn.end();
          }).on('data', function(d) {
            if (!out.out)
              out.out = d.toString('ascii');
            else
              out.out += d.toString('ascii');
          }).end();
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert.deepEqual(out,
                           self.expected,
                           makeMsg(what, 'Connection output mismatch.\nSaw:\n'
                                         + inspect(out)
                                         + '\nExpected:\n'
                                         + inspect(self.expected)));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY_RSA,
      //debug: console.log
    },
    expected: {
      destIP: 'localhost',
      destPort: 0, // filled in during test
      srcIP: undefined, // filled in during test
      srcPort: 0, // filled in during test
      out: 'hello from node.js and ssh2!'
    },
    what: 'Remote port forwarding (accepted)'
  },
];

function bufferStream(stream, encoding, cb) {
  var buf;
  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = undefined;
  }
  if (!encoding) {
    var nb = 0;
    stream.on('data', function(d) {
      if (nb === 0)
        buf = [ d ];
      else
        buf.push(d);
      nb += d.length;
    }).on((stream.writable ? 'close' : 'end'), function() {
      cb(nb ? Buffer.concat(buf, nb) : buf);
    });
  } else {
    stream.on('data', function(d) {
      if (!buf)
        buf = d;
      else
        buf += d;
    }).on((stream.writable ? 'close' : 'end'), function() {
      cb(buf);
    }).setEncoding(encoding);
  }
}

function stripDebug(str) {
  if (typeof str !== 'string')
    return str;
  return str.replace(/^(?:(?:[\s\S]+)?Environment:\r?\n(?:  [^=]+=[^\r\n]+\r?\n)+)?/, '');
}

function startServer(opts, listencb, exitcb) {
  var sshdOpts = {},
      cmd,
      key,
      val;
  for (key in DEFAULT_SSHD_OPTS)
    sshdOpts[key] = DEFAULT_SSHD_OPTS[key];
  if (typeof opts === 'function') {
    exitcb = listencb;
    listencb = opts;
    opts = undefined;
  }
  if (opts) {
    for (key in opts)
      sshdOpts[key] = opts[key];
  }

  cmd = '`which sshd` -p '
        + SSHD_PORT
        + ' -Dde -f '
        + join(fixturesdir, 'sshd_config');

  for (key in sshdOpts) {
    val = ''+sshdOpts[key];
    if (val.indexOf(' ') > -1)
      val = '"' + val + '"';
    cmd += ' -o ' + key + '=' + val;
  }

  tests[t].config.port = SSHD_PORT;

  stopWaiting = false;
  cpexec(cmd, function(err, stdout, stderr) {
    stopWaiting = true;
    //exitcb(err, stdout, stderr);
  });
  waitForSshd(listencb);
}

function cleanupTemp() {
  // clean up any temporary files left over
  fs.readdirSync(tempdir).forEach(function(file) {
    if (file !== '.gitignore')
      fs.unlinkSync(join(tempdir, file));
  });
}

function next() {
  if (t === forkedTest || t === tests.length - 1)
    return;
  cleanupTemp();
  var v = tests[++t];
  v.run.call(v);
}

function makeMsg(what, msg) {
  return '[' + group + what + ']: ' + msg;
}

var stopWaiting = false;
function waitForSshd(cb) {
  if (stopWaiting)
    return;
  cpexec('lsof -a -u '
         + USER
         + ' -c sshd -i tcp@localhost:'
         + SSHD_PORT
         + ' &>/dev/null', function(err, stdout) {
    if (err) {
      return setTimeout(function() {
        waitForSshd(cb);
      }, 50);
    }
    cb();
  });
}

function cleanup(cb) {
  cleanupTemp();
  cpexec('lsof -Fp -a -u '
         + USER
         + ' -c sshd -i tcp@localhost:'
         + SSHD_PORT, function(err, stdout) {
    if (!err) {
      var pid = parseInt(stdout.trim().replace(/[^\d]/g, ''), 10);
      if (typeof pid === 'number' && !isNaN(pid)) {
        try {
          process.kill(pid);
        } catch (ex) {}
      }
    }
    cb();
  });
}

process.once('uncaughtException', function(err) {
  cleanup(function() {
    throw err;
  });
});
process.once('exit', function() {
  cleanup(function() {
    assert(t === tests.length - 1,
           makeMsg('_exit',
                   'Only finished ' + (t + 1) + '/' + tests.length + ' tests'));
  });
});




function findFreePort() {
  // find an unused port for sshd to listen on ...
  cpexec('netstat -nl --inet --inet6', function(err, stdout) {
    assert(!err, 'Unable to find a free port for starting sshd');
    var portsInUse = stdout.trim()
                           .split('\n')
                           .slice(2) // skip two header lines
                           .map(function(line) {
                             var addr = line.split(/[ \t]+/g)[3];
                             return parseInt(
                              addr.substr(addr.lastIndexOf(':') + 1),
                              10
                             );
                           });
    for (var port = 9000; port < 65535; ++port) {
      if (portsInUse.indexOf(port) === -1) {
        SSHD_PORT = port;
        // get localhost address for reference
        return dns.resolve('localhost', function(err, ips) {
          if (err)
            throw err;
          else if (ips.length === 0)
            throw new Error('Could not find localhost IP');
          LOCALHOST = ips[0];

          // start tests
          next();
        });
      }
    }
    assert(false, 'Unable to find a free port for starting sshd');
  });
}

// check for test prerequisites
cpexec('which sshd', function(err) {
  if (err) {
    return console.error('['
                         + path.basename(__filename, '.js')
                         + ']: OpenSSH server is required for integration tests.');
  }
  findFreePort();
});

// check for forked process
if (process.argv.length > 2) {
  forkedTest = parseInt(process.argv[2], 10);
  if (!isNaN(forkedTest))
    t = forkedTest - 1;
  else
    process.exit(100);
}

// ensure permissions are less permissive to appease sshd
[ 'id_rsa', 'id_rsa.pub',
  'id_dsa', 'id_dsa.pub',
  'ssh_host_rsa_key', 'ssh_host_rsa_key.pub',
  'authorized_keys'
].forEach(function(f) {
  fs.chmodSync(join(fixturesdir, f), '0600');
});
