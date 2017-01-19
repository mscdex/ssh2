var fs = require('fs'),
    path = require('path'),
    assert = require('assert'),
    assertCalled = require('assert-called'),
    ssh2 = require('../');

var c = new ssh2();

c.connect({
  host: 'localhost',
  port: 22,
  username: process.env.USER,
  privateKey: fs.readFileSync(process.env.HOME + '/.ssh/id_rsa'),
  publicKey: fs.readFileSync(process.env.HOME + '/.ssh/id_rsa.pub')
});

c.on('ready', assertCalled(function () {
  c.exec(
    path.join(__dirname, 'fixtures', 'print-and-exit'),
    assertCalled(function (err, stream) {
      var data = '';

      assert(!err);

      stream.on('data', function (chunk, extended) {
        assert(!extended);
        data += chunk.toString('utf8');
      });

      stream.on('exit', assertCalled(function (code, signal) {
        assert.equal(code, 42);
        assert(!signal);

        assert.equal(data, 'Hello, world\n');

        c.end();
      }));
    })
  );
}));
