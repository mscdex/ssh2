var Connection = require('../lib/Connection');

var fs = require('fs'),
    cpspawn = require('child_process').spawn,
    cpexec = require('child_process').exec,
    path = require('path'),
    join = path.join,
    inspect = require('util').inspect,
    assert = require('assert');

var t = -1,
    group = path.basename(__filename, '.js') + '/',
    tempdir = join(__dirname, 'temp'),
    fixturesdir = join(__dirname, 'fixtures');

var SSHD_PORT,
    HOST_FINGERPRINT = '64254520742d3d0792e918f3ce945a64',
    PRIVATE_KEY = fs.readFileSync(join(fixturesdir, 'id_rsa')),
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
      //'UsePrivilegeSeparation': 'no'
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
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'Authenticate with a key'
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
    what: 'Authenticate with an agent'
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
                               + fingerprint
                               + '\nExpected:\n'
                               + HOST_FINGERPRINT));
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY,
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
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
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
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'Simple exec'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection(),
          SSH2NODETEST = 'Hello from node.js!!!';
      startServer({ 'AcceptEnv': 'SSH2NODETEST' }, function() {
        var error,
            ready,
            envvar;
        conn.on('ready', function() {
          ready = true;
          this.exec('echo $SSH2NODETEST',
                    { env: { SSH2NODETEST: SSH2NODETEST } },
                    function(err, stream) {
            assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
            stream.stderr.resume();
            stream.setEncoding('ascii');
            stream.on('data', function(d) {
              if (!envvar)
                envvar = d;
              else
                envvar += d;
            }).on('end', function() {
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: ' + error));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(envvar === SSH2NODETEST,
                 makeMsg(what, 'Environment variable mismatch.\nSaw:\n'
                               + envvar
                               + '\nExpected:\n'
                               + SSH2NODETEST));
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'Exec with environment set'
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
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'Simple shell'
  },
];

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
    if (process.argv.length === 2)
      next();
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
  if (t === tests.length - 1)
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
      if (typeof pid === 'number' && !isNaN(pid))
        process.kill(pid);
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
  for (var port = 1025; port < 65535; ++port) {
    if (portsInUse.indexOf(port)) {
      SSHD_PORT = port;
      // start tests
      return next();
    }
  }
  assert(false, 'Unable to find a free port for starting sshd');
});

// check for forked process
if (process.argv.length > 2) {
  var testnum = parseInt(process.argv[2], 10);
  if (!isNaN(testnum))
    t = testnum - 1;
}
  