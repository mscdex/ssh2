var Client = require('../lib/client'),
    Server = require('../lib/server'),
    OPEN_MODE = require('ssh2-streams').SFTPStream.OPEN_MODE,
    STATUS_CODE = require('ssh2-streams').SFTPStream.STATUS_CODE,
    utils = require('ssh2-streams').utils;

var net = require('net'),
    fs = require('fs'),
    crypto = require('crypto'),
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
    HOST_KEY_DSA = fs.readFileSync(join(fixturesdir, 'ssh_host_dsa_key')),
    CLIENT_KEY_PPK_RSA = fs.readFileSync(join(fixturesdir, 'id_rsa.ppk')),
    CLIENT_KEY_PPK_RSA_PUB = utils.parseKey(CLIENT_KEY_PPK_RSA),
    CLIENT_KEY_RSA = fs.readFileSync(join(fixturesdir, 'id_rsa')),
    CLIENT_KEY_RSA_PUB = utils.genPublicKey(utils.parseKey(CLIENT_KEY_RSA)),
    CLIENT_KEY_DSA = fs.readFileSync(join(fixturesdir, 'id_dsa')),
    CLIENT_KEY_DSA_PUB = utils.genPublicKey(utils.parseKey(CLIENT_KEY_DSA)),
    DEBUG = process.env['DEBUG'],
    STRICT_STREAMS2 = process.env['STREAMS2'],
    MAXNUMBER = (process.argv.length > 2 && parseInt(process.argv[2])) || 10000;
    
    
function execServer(server, what, execfunc) {
  server.on('connection', function(conn) {
    conn.on('authentication', function(ctx) {
      ctx.accept();
    }).on('ready', function() {
      conn.once('session', function(accept, reject) {
        var session = accept();
        session.once('exec', function(accept, reject, info) {
          assert(info.command === 'foo --bar',
                 makeMsg(what, 'Wrong exec command: ' + info.command));
          execfunc(conn, accept());
        });
      });
    });
  });  
  return server;
}

function execClient(client, what, execfunc) {
  return client.on('ready', function() {
    client.exec('foo --bar', function(err, stream) {
      assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
      execfunc(stream);
    });
  });
}

function ChunkGenerator(maxNumber, maxSize) {
  this.maxNumber = maxNumber;
  this.maxSize = maxSize;
  this.number = 0;
  this.generated = 0;
  this.remainder = '';
  this.atEnd = false;
}

ChunkGenerator.prototype.next = function() {
  if (this.atEnd) return null;
  
  var chunk;
  
  if (this.maxSize) {
    // random chunkSize with max 
  }
  else {
    // single line
    chunk = new Buffer('' + (this.number++) + "\n", 'ascii');
  }
  
  this.atEnd = (0 === this.remainder.length && this.maxNumber <= this.number);
  this.generated += chunk.length;
  
  return chunk;
}

function ChunkVerifier(maxNumber) {
  this.maxNumber = maxNumber;
  this.number = 0;
  this.checked = 0;
  this.remainder = '';
  this.atEnd = false;
}

ChunkVerifier.prototype.next = function(chunk) {
  if (null === chunk) {
    return this.atEnd || new Error('ChunkVerifier.next(null) but not .atEnd');
  }
  if (this.atEnd) {
    return new Error('ChunkVerifier.next(' + chunk.length + ') called after .atEnd');
  }
  
  var data = chunk.toString('ascii'),
      lines = data.split("\n"),
      hasRemainder = (data[-1] != "\n");
  
  var line, index, number;

  for (var i = 0; i < lines.length; i++) {
    if (0 === i && 0 < this.remainder.length) {
      line = this.remainder + lines[i];
      this.remainder = '';      
    }
    else {
      line = lines[i];
    }
    
    if (i < lines.length - 1 || false === hasRemainder)
    {
      // console.error("verify " + line);
      
      try {
        number = parseInt(line);
      }
      catch(exception) {
        return exception;
      }
    
      if (number !== this.number) {
        return new Error("'" + line + "' different from " + this.number + ' at chunk ' + this.checked);
      }
      this.number += 1;
    }
    else {
      this.remainder = line;
    }
  }
  
  this.atEnd = (0 === this.remainder.length && this.maxNumber <= this.number);
  this.checked += chunk.length;
  
  return null; // no error
}


function writeBigDataWaitOnDrain(stream, generator, done) {
  // code analog to stream.Writable.write documentation example
  
  function write() {
    var ok,
        chunk;
    
    do {
      chunk = generator.next();
      
      // console.error("write " + ((null !== chunk && chunk.length) || '-') + ' ' + generator.atEnd);
      
      if (generator.atEnd) {
        // last time
        return stream.write(chunk, done);
      }
      else {
        ok = stream.write(chunk);
      }
    } while (ok);
    
    // wait on drain
    stream.once('drain', write);
  }
  
  setImmediate(write);
  
  return stream;
}

function writeBigData(stream, generator, done) {
  // code analog to stream.Writable.write documentation example
  
  function write() {
    while (!generator.atEnd) {
      stream.write(generator.next());
    }
    done();
  }
  
  setImmediate(write);
  
  return stream;
}

function streamOnDataVerify(stream, verifier, done) {

  return stream.on('data', function(d) {
    var err = verifier.next(d);
    if (err) {
      return done(err);
    }
    if (verifier.atEnd) {
      return done();
    }
  });
}

var tests = [
  { run: function() {
      var self = this,
          what = this.what,
          out = '',
          outErr = '',
          exitArgs,
          closeArgs,
          client,
          server,
          maxNumber = MAXNUMBER,
          maxChunkSize,
          r;

      r = setup(this,
                { username: USER,
                  password: PASSWORD
                },
                { privateKey: HOST_KEY_RSA
                });
      client = r.client;
      server = r.server;
      
      execServer(server, what, function(conn, stream) {
        var writesEnded = 0;
        
        function end(what) {
          if (undefined !== what) writesEnded |= what;
          console.error('end(' + what + ') => ' + writesEnded);
          
          if (writesEnded != 3) return;
          
          stream.exit(100);
          stream.end();        
          conn.end();
        }
        
        writeBigDataWaitOnDrain(stream, new ChunkGenerator(maxNumber, maxChunkSize), function(err) { 
          console.log('[SERVER] writeBigDataWaitOnDrain:callback(' + inspect(err) + ')');
          assert(!err, 
                 makeMsg(what, 'writeBigDataWaitOnDrain err: ' + inspect(err)));
          end(1);
        });
        writeBigDataWaitOnDrain(stream.stderr, new ChunkGenerator(maxNumber, maxChunkSize), function(err) {          
          console.log('[SERVER] writeBigDataWaitOnDrain.stderr:callback(' + inspect(err) + ')');
          assert(!err, 
                 makeMsg(what, 'writeBigDataWaitOnDrain.stderr err: ' + inspect(err)));
          end(2);
        });
      });

      var stdoutVerifier = new ChunkVerifier(maxNumber),
          stderrVerifier = new ChunkVerifier(maxNumber),
          closeEmitted = false;
      
      execClient(client, what, function(stream) {
        console.error("in execClient execFunc");
        
         streamOnDataVerify(stream, stdoutVerifier, function(err) {
          console.log('[CLIENT] streamOnDataVerify:callback(' + inspect(err) + ')');
          assert(undefined === err, 
                makeMsg(what, 'streamOnDataVerify err: ' + inspect(err)));
        }).on('exit', function(code) {
          exitArgs = new Array(arguments.length);
          console.log('[CLIENT] stream.on:exit(' + inspect(arguments) + ')');
          for (var i = 0; i < exitArgs.length; ++i)
            exitArgs[i] = arguments[i];
        }).on('close', function(code) {
          closeEmitted = true;
          
          console.log('[CLIENT] stream.on:close(' + inspect(arguments) + ')');
          closeArgs = new Array(arguments.length);
          for (var i = 0; i < closeArgs.length; ++i)
            closeArgs[i] = arguments[i];
          
        }).on('end', function() {
          console.log('[CLIENT] stream.on:end()');
          
          if (STRICT_STREAMS2) {
            assert(closeEmitted === false,
                   makeMsg(what, 'stream emitted close before end'));
          }
          else if (closeEmitted) {
            console.error('ignoring stream emitted close before end');
          }
          
          // both verifieres must be atEnd !!
          assert(stdoutVerifier.atEnd, 
                 makeMsg(what, 'stdoutVerifier is not .atEnd'));
          assert(stderrVerifier.atEnd, 
                 makeMsg(what, 'stderrVerifier is not .atEnd'));         
        });
        
        // console.error('stream.on:exit=' + stream.listeners('exit'));
        // console.error('stream.on:data=' + stream.listeners('data'));
        
        streamOnDataVerify(stream.stderr, stderrVerifier, function(err) {
          console.log('[CLIENT] streamOnDataVerify.stderr:callback(' + inspect(err) + ')');
          assert(undefined === err, 
                 makeMsg(what, 'streamOnDataVerify.stderr err: ' + inspect(err)));
        });
      }).on('end', function() {
        console.log('[CLIENT] client.on:end()');
        assert.deepEqual(exitArgs,
                         [100],
                         makeMsg(what, 'Wrong exit args: ' + inspect(exitArgs)));
        assert.deepEqual(closeArgs,
                         [100],
                         makeMsg(what,
                                 'Wrong close args: ' + inspect(closeArgs)));
      });
    },
    what: 'Big-data server.write->client.on:data exec'
  },  
];

function setup(self, clientcfg, servercfg) {
  self.state = {
    readies: 0,
    ends: 0
  };

  if (DEBUG) {
    console.log('========================================================\n'
                + '[TEST] '
                + self.what
                + '\n========================================================');
    clientcfg.debug = function(str) {
      console.log('[CLIENT] ' + str);
    };
    servercfg.debug = function(str) {
      console.log('[SERVER] ' + str);
    };
  }

  var client = new Client(),
      server = new Server(servercfg);

  server.on('error', onError)
        .on('connection', function(conn) {
          conn.on('error', onError)
              .on('ready', onReady);
          server.close();
        })
        .on('close', onClose);
  client.on('error', onError)
        .on('ready', onReady)
        .on('close', onClose);

  function onError(err) {
    var which = (this === client ? 'client' : 'server');
    if (STRICT_STREAMS2) {
      assert(self.state.ends == 0, makeMsg(self.what, which + ' emitted error after close: ' + err));
    }
    if (which === 'server' && err.message === 'Bad identification start') {
      console.error('ignoring ' + which + ' error: ' + err);
    }
    else {
      assert(false, makeMsg(self.what, 'Unexpected ' + which + ' error: ' + err));
    }
  }
  function onReady() {
    assert(self.state.readies < 2,
           makeMsg(self.what, 'Saw too many ready events'));
    if (++self.state.readies === 2)
      self.onReady && self.onReady();
  }
  function onClose() {
    assert(self.state.ends < 2, makeMsg(self.what, 'Saw too many end events'));
    if (++self.state.ends === 2) {
      assert(self.state.readies === 2,
             makeMsg(self.what, 'Expected 2 readies'));
      next();
    }
  }

  process.nextTick(function() {
    server.listen(0, 'localhost', function() {
      if (clientcfg.sock)
        clientcfg.sock.connect(server.address().port, 'localhost');
      else {
        clientcfg.host = 'localhost';
        clientcfg.port = server.address().port;
      }
      client.connect(clientcfg);
    });
  });
  return { client: client, server: server };
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

next();
