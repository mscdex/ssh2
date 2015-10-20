'use strict'

// (c) 2015 Michael Keller, minesworld-technologies.com , published under MIT license

var data_utils = require('./data-utils');

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


function wGD(stream, generator, done) {
  // writeGeneratedData
  
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

function wGDWonDrain(stream, generator, done) {
  // writeGeneratedDataWaitsOnDrain
  
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
sODV
function sODV(stream, verifier, done) {
  // streamOnDataVerify

  return stream.on('data', function(d) {
    var err = verifier.verify(d);
    if (err) {
      return done(err);
    }
    if (verifier.atEnd) {
      return done();
    }
  });
}


function createExecTest(options) {
  
  var run = function() {
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
      
      var writesEnded = 0, 
          exitAtWritesEnded = 0;
          
      // exit and end if all generators finished
      
      function end(what) {
        if (undefined !== what) writesEnded |= what;
        console.error('end(' + what + ') => ' + writesEnded);
        
        if (writesEnded != exitAtWritesEnded) return;
        
        stream.exit(100);
        stream.end();        
        conn.end();
      }
      
      var generator;
      
      // create data writers stdout
      generator = new data_utils.ChunkGenerator('server:stdout', maxNumber, maxChunkSize);
      
      if ('wGD' === options.server.stdout) {
        wGD(stream, generator, function(err) { 
          console.log('[SERVER] wGD:callback(' + inspect(err) + ')');
          assert(!err, 
                 makeMsg(what, 'wGD err: ' + inspect(err)));
          end(1);
        });
        exitAtWritesEnded |= 1;
      } 
      else if ('wGDWonDrain' === options.server.stdout) {
        wGDWonDrain(stream, generator, function(err) { 
          console.log('[SERVER] wGDWonDrain:callback(' + inspect(err) + ')');
          assert(!err, 
                 makeMsg(what, 'wGDWonDrain err: ' + inspect(err)));
          end(1);
        });
        exitAtWritesEnded |= 1;        
      }
     
      // create data writers stderr
      generator = new data_utils.ChunkGenerator('server:stderr', maxNumber, maxChunkSize);
      
      if ('wGD' === options.server.stderr) {
        wGD(stream.stderr, generator, function(err) {          
          console.log('[SERVER] wGD.stderr:callback(' + inspect(err) + ')');
          assert(!err, 
                 makeMsg(what, 'wGD.stderr err: ' + inspect(err)));
          end(2);
        });
        exitAtWritesEnded |= 2;
      }
      else if ('wGDWonDrain' === options.server.stdout) {
        wGDWonDrain(stream.stderr, generator, function(err) { 
          console.log('[SERVER] wGDWonDrain.stderr:callback(' + inspect(err) + ')');
          assert(!err, 
                 makeMsg(what, 'wGDWonDrain.stderr err: ' + inspect(err)));
          end(2);
        });
        exitAtWritesEnded |= 2;        
      }
      if (2 === (exitAtWritesEnded & 2)) {
        server_descs.push('E:' + options.server.stderr);
      }
      
    });

    var closeEmitted = false;
    
    execClient(client, what, function(stream) {
      console.error("in execClient execFunc");
      
      var verifiers = [],
          verifier;
      
      // create verifier on stdout
      verifier = new data_utils.ChunkVerifier('client:stdout', maxNumber);
      
      if ('sODV' === options.client.stdout) {
        sODV(stream, verifier, function(err) {
          console.log('[CLIENT] streamOnDataVerify:callback(' + inspect(err) + ')');
          assert(undefined === err, 
                makeMsg(what, 'streamOnDataVerify err: ' + inspect(err)));
        });
        verifiers.push(verifier);
      }
      
      // create verifier on stderr
      verifier = new data_utils.ChunkVerifier('client:stderr', maxNumber);
      
      if ('sODV' === options.client.stderr) {
        sODV(stream.stderr, verifier, function(err) {
          console.log('[CLIENT] streamOnDataVerify.stderr:callback(' + inspect(err) + ')');
          assert(undefined === err, 
                 makeMsg(what, 'streamOnDataVerify.stderr err: ' + inspect(err)));
        });      
        verifiers.push(verifier);
      }
      
      //
      
      stream.on('exit', function(code) {
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
        
        // all verifieres must be atEnd !!
        for (var verifier of verifiers) {
          assert(verifier.atEnd, 
                 makeMsg(what, 'verifier ' + verifier.name + ' is not .atEnd'));
        }
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
  };
  
  // generate description
  
  var server_descs = [],
      client_descs = [];

  var writers = ['wGD', 'wGDWonDrain'],
      readers = ['sODV']

  if (-1 !== writers.indexOf(options.server.stdout)) {
    server_descs.push('O:' + options.server.stdout);
  }
  if (-1 !== writers.indexOf(options.server.stderr)) {
    server_descs.push('E:' + options.server.stderr);
  }
 
  if (-1 !== readers.indexOf(options.client.stdout)) {
    client_descs.push('O:' + options.client.stdout);
  }
  if (-1 !== readers.indexOf(options.client.stderr)) {
    client_descs.push('E:' + options.client.stderr);
  }
  
  var what = 'Server( ' + server_descs.join(',') + ' )<->Client( ' + client_descs.join(',') + ' )';
  console.log('created exec test ' + what);
  
  return { run:run, what:what };
}




var tests = [
  createExecTest({ 
    server: { stdout:'wGD', stderr:'wGD' },
    client: { stdout:'sODV', stderr:'sODV' }
  }),
  createExecTest({ 
    server: { stdout:'wGDWonDrain', stderr:'wGDWonDrain' },
    client: { stdout:'sODV', stderr:'sODV' }
  }),
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
