var Server = require('../lib/server'),
    utils = require('ssh2-streams').utils;

var fs = require('fs'),
    crypto = require('crypto'),
    net = require('net'),
    path = require('path'),
    join = path.join,
    inspect = require('util').inspect,
    assert = require('assert');

var t = -1,
    group = path.basename(__filename, '.js') + '/',
    fixturesdir = join(__dirname, 'fixtures');

var USER = 'nodejs',
    PASSWORD = 'FLUXCAPACITORISTHEPOWER',
    MD5_HOST_FINGERPRINT = '64254520742d3d0792e918f3ce945a64',
    HOST_KEY_RSA = fs.readFileSync(join(fixturesdir, 'ssh_host_rsa_key')),
    CLIENT_KEY_RSA = fs.readFileSync(join(fixturesdir, 'id_rsa')),
    CLIENT_KEY_RSA_PUB = utils.genPublicKey(utils.parseKey(CLIENT_KEY_RSA)),
    CLIENT_KEY_DSA = fs.readFileSync(join(fixturesdir, 'id_dsa')),
    CLIENT_KEY_DSA_PUB = utils.genPublicKey(utils.parseKey(CLIENT_KEY_DSA)),
    DEBUG = false;

var tests = [
  { run: function() {
      var self = this,
          what = this.what,
          server = new Server({ privateKey: HOST_KEY_RSA }),
          client = new net.Socket();

      client.on('connect', function() {
        client.write('SSH-1.0-\r\n');
      }).on('close', function() {
        server.close();
        next();
      });

      server.on('connection', function(conn) {
        assert(false, makeMsg(what, 'Unexpected server connection event'));
      });

      server.listen(0, '127.0.0.1', function() {
        client.connect(server.address().port, '127.0.0.1');
      });
    },
    what: 'Incompatible client SSH protocol version'
  },
  { run: function() {
      var self = this,
          what = this.what,
          server = new Server({ privateKey: HOST_KEY_RSA }),
          client = new net.Socket();

      client.on('connect', function() {
        var ident = 'SSH-2.0-';
        for (var i = 0; i < 30; ++i)
          ident += 'foobarbaz';
        ident += '\r\n';
        client.write(ident);
      }).on('close', function() {
        server.close();
        next();
      });

      server.on('connection', function(conn) {
        assert(false, makeMsg(what, 'Unexpected server connection event'));
      });

      server.listen(0, '127.0.0.1', function() {
        client.connect(server.address().port, '127.0.0.1');
      });
    },
    what: 'SSH client protocol identification too long (> 255 characters)'
  },
  { run: function() {
      var self = this,
          what = this.what,
          server = new Server({ privateKey: HOST_KEY_RSA }),
          client = new net.Socket();

      client.on('connect', function() {
        client.write('LOL-2.0-asdf\r\n');
      }).on('close', function() {
        server.close();
        next();
      });

      server.on('connection', function(conn) {
        assert(false, makeMsg(what, 'Unexpected server connection event'));
      });

      server.listen(0, '127.0.0.1', function() {
        client.connect(server.address().port, '127.0.0.1');
      });
    },
    what: 'Malformed client protocol identification'
  },
];

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

process.once('exit', function() {
  assert(t === tests.length,
         makeMsg('_exit',
                 'Only finished ' + t + '/' + tests.length + ' tests'));
});

next();
