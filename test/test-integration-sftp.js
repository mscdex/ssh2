var Connection = require('../lib/Connection');

var fs = require('fs'),
    crypto = require('crypto'),
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
      'UsePrivilegeSeparation': 'no'
    };

var tests = [
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.on('end', function() {
              success = true;
              conn.end();
            }).end();
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected sftp session end'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'End sftp session only'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                        + (err && err.message)));
            if (!fs.existsSync(join(fixturesdir, 'testfile'))) {
              fs.writeFileSync(join(fixturesdir, 'testfile'),
                               crypto.pseudoRandomBytes(6 * 1024 * 1024));
            }
            sftp.fastPut(join(fixturesdir, 'testfile'),
                         join(tempdir, 'testfile'),
                         function(err) {
              assert(!err, makeMsg(what, 'Unexpected fastPut error: '
                                         + (err && err.message)));
              assert(filesEqual(join(fixturesdir, 'testfile'),
                                join(tempdir, 'testfile')),
                     makeMsg(what, 'Expected equal file content'));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected fastPut callback'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'fastPut'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.fastGet(join(tempdir, 'testfile'),
                         join(tempdir, 'testfile-copy'),
                         function(err) {
              assert(!err, makeMsg(what, 'Unexpected fastGet error: '
                                         + (err && err.message)));
              assert(filesEqual(join(tempdir, 'testfile'),
                                join(tempdir, 'testfile-copy')),
                     makeMsg(what, 'Expected equal file content after fastGet'));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected fastGet callback'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'fastGet'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            var ws = sftp.createWriteStream(join(tempdir, 'createWriteStream'));
            ws.on('error', function(err) {
              assert(false, makeMsg(what, 'Unexpected Writable error: '
                                          + (err && err.message)));
            }).on('close', function() {
              assert(filesEqual(join(tempdir, 'createWriteStream'),
                                new Buffer('hello\nworld\n')),
                     makeMsg(what, 'Expected equal file content after fastGet'));
              success = true;
              conn.end();
            });
            ws.write('hello\n');
            ws.write('world\n');
            ws.end();
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected fastGet callback'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'createWriteStream'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            var rs = sftp.createReadStream(join(tempdir, 'createWriteStream'));
            rs.on('error', function(err) {
              assert(false, makeMsg(what, 'Unexpected Readable error: '
                                          + (err && err.message)));
            });
            bufferStream(rs, function(val) {
              assert(filesEqual(val, join(tempdir, 'createWriteStream')),
                     makeMsg(what,
                             'Expected equal file content with createReadStream'));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected createReadStream contents'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'createReadStream'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.open(join(tempdir, 'createWriteStream'),
                      'r',
                      function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected open error: ' + (err && err.message)));
              sftp.close(handle, function(err) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected close error: '
                               + (err && err.message)));
                success = true;
                conn.end();
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected open and close'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'open and close'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.open(join(tempdir, 'createWriteStream'),
                      'r',
                      function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected open error: ' + (err && err.message)));
              sftp.close(handle, function(err) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected close error: '
                               + (err && err.message)));
                success = true;
                conn.end();
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected open and close'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'open and close'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.open(join(tempdir, 'createWriteStream'),
                      'r',
                      function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected open error: ' + (err && err.message)));
              var buf = new Buffer(
                fs.statSync(join(tempdir, 'createWriteStream')).size
              );
              sftp.read(handle, buf, 0, buf.length, 0, function(err) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected read error: ' + (err && err.message)));
                assert(filesEqual(buf, join(tempdir, 'createWriteStream')),
                       makeMsg(what, 'Expected equal file content with read'));
                sftp.close(handle, function(err) {
                  assert(!err,
                         makeMsg(what,
                                 'Unexpected close error: '
                                 + (err && err.message)));
                  success = true;
                  conn.end();
                });
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected read'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'read'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.open(join(tempdir, 'write'),
                      'w',
                      function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected open error: ' + (err && err.message)));
              var buf = new Buffer('node.js rules!\n\n');
              sftp.write(handle, buf, 0, buf.length, 0, function(err) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected write error: '
                               + (err && err.message)));
                sftp.close(handle, function(err) {
                  assert(!err,
                         makeMsg(what,
                                 'Unexpected close error: '
                                 + (err && err.message)));
                  assert(filesEqual(join(tempdir, 'write'), buf),
                         makeMsg(what, 'Expected equal file content with write'));
                  success = true;
                  conn.end();
                });
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected write'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'write'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.open(join(tempdir, 'write'),
                      'r',
                      function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected open error: ' + (err && err.message)));
              sftp.fstat(handle, function(err, stats) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected fstat error: '
                               + (err && err.message)));
                var real = fs.statSync(join(tempdir, 'write'));
                assert(stats.isFile()
                       && !stats.isDirectory()
                       && !stats.isBlockDevice()
                       && !stats.isCharacterDevice()
                       && !stats.isSymbolicLink()
                       && !stats.isFIFO()
                       && !stats.isSocket(),
                       makeMsg(what, 'Unexpected file type'));
                assert(stats.size === real.size,
                       makeMsg(what, 'File size mismatch'));
                assert(stats.uid === real.uid,
                       makeMsg(what, 'File uid mismatch'));
                assert(stats.gid === real.gid,
                       makeMsg(what, 'File gid mismatch'));
                assert(stats.mode === real.mode,
                       makeMsg(what, 'File mode mismatch'));
                assert(stats.atime === real.atime.getTime() / 1000,
                       makeMsg(what, 'File atime mismatch'));
                assert(stats.mtime === real.mtime.getTime() / 1000,
                       makeMsg(what, 'File mtime mismatch'));
                sftp.close(handle, function(err) {
                  assert(!err,
                         makeMsg(what,
                                 'Unexpected close error: '
                                 + (err && err.message)));
                  success = true;
                  conn.end();
                });
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected fstat'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'fstat'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.open(join(tempdir, 'write'),
                      'r',
                      function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected open error: ' + (err && err.message)));
              var time = parseInt(Date.now() / 1000, 10);
              sftp.fsetstat(handle,
                            { atime: time, mtime: time },
                            function(err) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected fsetstat error: '
                               + (err && err.message)));
                var real = fs.statSync(join(tempdir, 'write'));
                assert(time === parseInt(real.atime.getTime() / 1000, 10),
                       makeMsg(what, 'File atime mismatch'));
                assert(time === parseInt(real.mtime.getTime() / 1000, 10),
                       makeMsg(what, 'File mtime mismatch'));
                sftp.close(handle, function(err) {
                  assert(!err,
                         makeMsg(what,
                                 'Unexpected close error: '
                                 + (err && err.message)));
                  success = true;
                  conn.end();
                });
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected fsetstat'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'fsetstat'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.open(join(tempdir, 'write'),
                      'r',
                      function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected open error: ' + (err && err.message)));
              var time = parseInt(Date.now() / 1000, 10);
              sftp.futimes(handle, time, time, function(err) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected futimes error: '
                               + (err && err.message)));
                var real = fs.statSync(join(tempdir, 'write'));
                assert(time === parseInt(real.mtime.getTime() / 1000, 10),
                       makeMsg(what, 'File mtime mismatch'));
                assert(time === parseInt(real.atime.getTime() / 1000, 10),
                       makeMsg(what, 'File atime mismatch'));
                sftp.close(handle, function(err) {
                  assert(!err,
                         makeMsg(what,
                                 'Unexpected close error: '
                                 + (err && err.message)));
                  success = true;
                  conn.end();
                });
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected futimes'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'futimes'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.open(join(tempdir, 'write'),
                      'r',
                      function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected open error: ' + (err && err.message)));
              sftp.fchown(handle,
                          process.getuid(),
                          process.getgid(),
                          function(err) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected fchown error: '
                               + (err && err.message)));
                sftp.close(handle, function(err) {
                  assert(!err,
                         makeMsg(what,
                                 'Unexpected close error: '
                                 + (err && err.message)));
                  success = true;
                  conn.end();
                });
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected fchown'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'fchown'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.open(join(tempdir, 'write'),
                      'r',
                      function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected open error: ' + (err && err.message)));
              sftp.fchmod(handle, '0777', function(err) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected fchmod error: '
                               + (err && err.message)));
                var real = fs.statSync(join(tempdir, 'write'));
                assert(real.mode & 0x1FF === 511,
                       makeMsg(what, 'File mode mismatch'));
                sftp.close(handle, function(err) {
                  assert(!err,
                         makeMsg(what,
                                 'Unexpected close error: '
                                 + (err && err.message)));
                  success = true;
                  conn.end();
                });
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected fchmod'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'fchmod'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.opendir(tempdir, function(err, handle) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected opendir error: '
                             + (err && err.message)));
              sftp.readdir(handle, function(err, list) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected readdir error: '
                               + (err && err.message)));
                assert(Array.isArray(list), makeMsg(what, 'Expected list'));
                list = list.map(function(v) { return v.filename; });
                assert(arraysEqual(list, self.expected),
                       makeMsg(what,
                               'Dir list mismatch.\nSaw:\n'
                               + inspect(list)
                               + '\nExpected:\n'
                               + inspect(self.expected)));
                sftp.close(handle, function(err) {
                  assert(!err,
                         makeMsg(what,
                                 'Unexpected close error: '
                                 + (err && err.message)));
                  success = true;
                  conn.end();
                });
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected opendir/readdir'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    expected: [
      '.gitignore',
      'createWriteStream',
      'testfile',
      'testfile-copy',
      'write'
    ],
    what: 'opendir and readdir(handle)'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.readdir(tempdir, function(err, list) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected readdir error: '
                             + (err && err.message)));
              assert(list !== false, makeMsg(what, 'Expected list'));
              list = list.map(function(v) { return v.filename; });
              assert(arraysEqual(list, self.expected),
                     makeMsg(what,
                             'Dir list mismatch.\nSaw:\n'
                             + inspect(list)
                             + '\nExpected:\n'
                             + inspect(self.expected)));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected readdir'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    expected: [
      '.gitignore',
      'createWriteStream',
      'testfile',
      'testfile-copy',
      'write'
    ],
    what: 'readdir(path)'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.unlink(join(tempdir, 'testfile-copy'), function(err) {
              assert(!err, makeMsg(what, 'Unexpected unlink error: '
                                         + (err && err.message)));
              sftp.readdir(tempdir, function(err, list) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected readdir error: '
                               + (err && err.message)));
                assert(list !== false, makeMsg(what, 'Expected list'));
                list = list.map(function(v) { return v.filename; });
                assert(arraysEqual(list, self.expected),
                       makeMsg(what,
                               'Dir list mismatch.\nSaw:\n'
                               + inspect(list)
                               + '\nExpected:\n'
                               + inspect(self.expected)));
                success = true;
                conn.end();
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected unlink'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    expected: [
      '.gitignore',
      'createWriteStream',
      'testfile',
      'write'
    ],
    what: 'unlink'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.rename(join(tempdir, 'createWriteStream'),
                        join(tempdir, 'writeStream'),
                        function(err) {
              assert(!err, makeMsg(what, 'Unexpected rename error: '
                                         + (err && err.message)));
              sftp.readdir(tempdir, function(err, list) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected readdir error: '
                               + (err && err.message)));
                assert(list !== false, makeMsg(what, 'Expected list'));
                list = list.map(function(v) { return v.filename; });
                assert(arraysEqual(list, self.expected),
                       makeMsg(what,
                               'Dir list mismatch.\nSaw:\n'
                               + inspect(list)
                               + '\nExpected:\n'
                               + inspect(self.expected)));
                success = true;
                conn.end();
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected rename'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    expected: [
      '.gitignore',
      'writeStream',
      'testfile',
      'write'
    ],
    what: 'rename'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.mkdir(join(tempdir, 'mydir'), function(err) {
              assert(!err, makeMsg(what, 'Unexpected mkdir error: '
                                         + (err && err.message)));
              sftp.readdir(tempdir, function(err, list) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected readdir error: '
                               + (err && err.message)));
                assert(list !== false, makeMsg(what, 'Expected list'));
                list = list.map(function(v) { return v.filename; });
                assert(arraysEqual(list, self.expected),
                       makeMsg(what,
                               'Dir list mismatch.\nSaw:\n'
                               + inspect(list)
                               + '\nExpected:\n'
                               + inspect(self.expected)));
                success = true;
                conn.end();
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected mkdir'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    expected: [
      '.gitignore',
      'writeStream',
      'testfile',
      'write',
      'mydir'
    ],
    what: 'mkdir'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.rmdir(join(tempdir, 'mydir'), function(err) {
              assert(!err, makeMsg(what, 'Unexpected rmdir error: '
                                         + (err && err.message)));
              sftp.readdir(tempdir, function(err, list) {
                assert(!err,
                       makeMsg(what,
                               'Unexpected readdir error: '
                               + (err && err.message)));
                assert(list !== false, makeMsg(what, 'Expected list'));
                list = list.map(function(v) { return v.filename; });
                assert(arraysEqual(list, self.expected),
                       makeMsg(what,
                               'Dir list mismatch.\nSaw:\n'
                               + inspect(list)
                               + '\nExpected:\n'
                               + inspect(self.expected)));
                success = true;
                conn.end();
              });
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected rmdir'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    expected: [
      '.gitignore',
      'writeStream',
      'testfile',
      'write'
    ],
    what: 'rmdir'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            var time = parseInt(Date.now() / 1000, 10);
            sftp.utimes(join(tempdir, 'write'), time, time, function(err) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected utimes error: '
                             + (err && err.message)));
              var real = fs.statSync(join(tempdir, 'write'));
              assert(time === parseInt(real.mtime.getTime() / 1000, 10),
                     makeMsg(what, 'File mtime mismatch'));
              assert(time === parseInt(real.atime.getTime() / 1000, 10),
                     makeMsg(what, 'File atime mismatch'));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected utimes'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'utimes'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.chown(join(tempdir, 'write'),
                       process.getuid(),
                       process.getgid(),
                       function(err) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected chown error: '
                             + (err && err.message)));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected chown'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'chown'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.chmod(join(tempdir, 'write'), '0777', function(err) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected chmod error: '
                             + (err && err.message)));
              var real = fs.statSync(join(tempdir, 'write'));
              assert(real.mode & 0x1FF === 511,
                     makeMsg(what, 'File mode mismatch'));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected chmod'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'chmod'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.symlink(join(tempdir, 'write'),
                         join(tempdir, 'write-link'),
                         function(err) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected symlink error: '
                             + (err && err.message)));
              var real = fs.lstatSync(join(tempdir, 'write-link'));
              assert(real.isSymbolicLink(), makeMsg(what, 'File type mismatch'));
              var realTarget = fs.readlinkSync(join(tempdir, 'write-link'));
              assert.equal(realTarget,
                           join(tempdir, 'write'),
                           makeMsg(what,
                                   'Symlink target mismatch.Saw:\n'
                                   + realTarget
                                   + '\nExpected:\n'
                                   + join(tempdir, 'write')));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected symlink'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'symlink'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.readlink(join(tempdir, 'write-link'), function(err, target) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected readlink error: '
                             + (err && err.message)));
              assert.equal(target,
                           join(tempdir, 'write'),
                           makeMsg(what,
                                   'Symlink target mismatch.Saw:\n'
                                   + target
                                   + '\nExpected:\n'
                                   + join(tempdir, 'write')));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected readlink'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'readlink'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.stat(join(tempdir, 'write-link'), function(err, stats) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected stat error: '
                             + (err && err.message)));
              var real = fs.statSync(join(tempdir, 'write-link'));
              assert(stats.isFile()
                     && !stats.isDirectory()
                     && !stats.isBlockDevice()
                     && !stats.isCharacterDevice()
                     && !stats.isSymbolicLink()
                     && !stats.isFIFO()
                     && !stats.isSocket(),
                     makeMsg(what, 'Unexpected file type'));
              assert(stats.size === real.size,
                     makeMsg(what, 'File size mismatch'));
              assert(stats.uid === real.uid,
                     makeMsg(what, 'File uid mismatch'));
              assert(stats.gid === real.gid,
                     makeMsg(what, 'File gid mismatch'));
              assert(stats.mode === real.mode,
                     makeMsg(what, 'File mode mismatch'));
              assert(stats.atime === parseInt(real.atime.getTime() / 1000, 10),
                     makeMsg(what, 'File atime mismatch'));
              assert(stats.mtime === parseInt(real.mtime.getTime() / 1000, 10),
                     makeMsg(what, 'File mtime mismatch'));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected stat'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'stat'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.lstat(join(tempdir, 'write-link'), function(err, stats) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected lstat error: '
                             + (err && err.message)));
              var real = fs.lstatSync(join(tempdir, 'write-link'));
              assert(!stats.isFile()
                     && !stats.isDirectory()
                     && !stats.isBlockDevice()
                     && !stats.isCharacterDevice()
                     && stats.isSymbolicLink()
                     && !stats.isFIFO()
                     && !stats.isSocket(),
                     makeMsg(what, 'Unexpected file type'));
              assert(stats.size === real.size,
                     makeMsg(what, 'File size mismatch'));
              assert(stats.uid === real.uid,
                     makeMsg(what, 'File uid mismatch'));
              assert(stats.gid === real.gid,
                     makeMsg(what, 'File gid mismatch'));
              assert(stats.mode === real.mode,
                     makeMsg(what, 'File mode mismatch'));
              assert(stats.atime === parseInt(real.atime.getTime() / 1000, 10),
                     makeMsg(what, 'File atime mismatch'));
              assert(stats.mtime === parseInt(real.mtime.getTime() / 1000, 10),
                     makeMsg(what, 'File mtime mismatch'));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected lstat'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'lstat'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            var time = parseInt(Date.now() / 1000, 10);
            sftp.setstat(join(tempdir, 'write'),
                         { atime: time, mtime: time },
                         function(err) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected setstat error: '
                             + (err && err.message)));
              var real = fs.statSync(join(tempdir, 'write'));
              assert(time === parseInt(real.atime.getTime() / 1000, 10),
                     makeMsg(what, 'File atime mismatch'));
              assert(time === parseInt(real.mtime.getTime() / 1000, 10),
                     makeMsg(what, 'File mtime mismatch'));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected setstat'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'setstat'
  },
  { run: function() {
      var self = this,
          what = this.what,
          conn = new Connection();
      startServer(function() {
        var error,
            ready,
            success;
        conn.on('ready', function() {
          ready = true;
          this.sftp(function(err, sftp) {
            assert(!err, makeMsg(what, 'Unexpected sftp start error: '
                                       + (err && err.message)));
            sftp.realpath(tempdir + '/..', function(err, abspath) {
              assert(!err,
                     makeMsg(what,
                             'Unexpected realpath error: '
                             + (err && err.message)));
              assert(abspath === join(tempdir, '..'),
                     makeMsg(what, 'Real path mismatch.Saw:\n'
                                   + abspath
                                   + '\nExpected:\n'
                                   + join(tempdir, '..')));
              success = true;
              conn.end();
            });
          });
        }).on('error', function(err) {
          error = err;
        }).on('close', function() {
          assert(!error, makeMsg(what, 'Unexpected client error: '
                                       + (error && error.message)));
          assert(ready, makeMsg(what, 'Expected ready'));
          assert(success, makeMsg(what, 'Expected realpath'));
          next();
        }).connect(self.config);
      });
    },
    config: {
      host: 'localhost',
      username: USER,
      privateKey: PRIVATE_KEY
    },
    what: 'realpath'
  },
];

function arraysEqual(arr1, arr2) {
  var i;
  for (i = 0; i < arr1.length; ++i)
    if (arr2.indexOf(arr1[i]) === -1)
      return false;
  for (i = 0; i < arr2.length; ++i)
    if (arr1.indexOf(arr2[i]) === -1)
      return false;
  return true;
}

function filesEqual(path1, path2) {
  var equal;
  try {
    var data1, data2;

    if (Buffer.isBuffer(path1))
      data1 = path1;
    else
      data1 = fs.readFileSync(path1);

    if (Buffer.isBuffer(path2))
      data2 = path2;
    else
      data2 = fs.readFileSync(path2);

    equal = (crypto.createHash('sha1')
                   .update(data1)
                   .digest('hex')
             ===
             crypto.createHash('sha1')
                   .update(data2)
                   .digest('hex'));
  } catch (ex) {}
  return (equal === true);
}

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
    if (file !== '.gitignore') {
      try {
        var filepath = join(tempdir, file),
            stats = fs.lstatSync(filepath);
        if (stats.isDirectory())
          fs.rmdirSync(filepath);
        else
          fs.unlinkSync(filepath);
      } catch (ex) {}
    }
  });
}

function next() {
  if (t === tests.length - 1)
    return cleanup();
  //cleanupTemp();
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
    cb && cb();
  });
}

function cleanup(cb) {
  cleanupTemp();
  if (fs.existsSync(join(fixturesdir, 'testfile')))
    fs.unlinkSync(join(fixturesdir, 'testfile'));
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
    cb && cb();
  });
}

process.once('uncaughtException', function(err) {
  cleanup(function() {
    throw err;
  });
});
process.once('exit', function() {
  assert(t === tests.length - 1,
         makeMsg('_exit',
                 'Only finished ' + (t + 1) + '/' + tests.length + ' tests'));
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
    for (var port = 1025; port < 65535; ++port) {
      if (portsInUse.indexOf(port)) {
        SSHD_PORT = port;
        // start tests
        return next();
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
  'ssh_host_rsa_key', 'ssh_host_rsa_key.pub',
  'authorized_keys'
].forEach(function(f) {
  fs.chmodSync(join(fixturesdir, f), '0600');
});
fs.chmodSync(fixturesdir, '0700');
fs.chmodSync(tempdir, '0777');
fs.chmodSync(__dirname, '0700');
