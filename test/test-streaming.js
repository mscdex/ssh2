'use strict'

// (c) 2015 Michael Keller, minesworld-technologies.com , published under MIT license
// parts of code (c) mscdex

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
    DEBUG = process.env['DEBUG'];
    
var debug = function() {};

if (DEBUG) {
  debug = function(message) {
    console.log(message);
  }

  for (var key in process.versions) {
    debug('[INFO] ' + key + ': ' + process.versions[key]);
  }
  debug('[INFO] platform: ' + process.platform + ' ' + process.arch);
}

// 

function Timeout(name, ms) {
  if (undefined === ms || 0 > ms) {
    this.renew = function(b, n) {};
    this.clear = function() {};
    return;
  }
  
  var lastRenew = Date.now(),
      lastNumber,
      lastBytes;
  
  var  intervalID = setInterval(function() {
        var d = Date.now() - lastRenew;
        assert(ms > d,
               makeMsg(name, 'timed out after: ' + d + 'ms ' + lastNumber + ',#' + lastBytes));
      }, 500);
      
  this.renew = function(b, n) {
    var d = Date.now() - lastRenew;
    assert(ms > d,
           makeMsg(name, 'timed out after: ' + d + 'ms ' + lastNumber + ',#' + lastBytes + ' -> ' + n + ',#' + b));

    lastBytes = b;
    lastNumber = n;
    
    lastRenew = Date.now();
  };
  
  this.clear = function() {
    clearInterval(intervalID);
  }
  
  this.renew();
}

    
function wGD(stream, generator, timeout, done) {
  // writeGeneratedData
  
  var t = new Timeout(generator.name + ' wGD', timeout);

  function write() {
    
    while (!generator.atEnd) {
      var chunk = generator.next();
      debug('[DATA] ' + generator.name + ' wGD write(' + chunk.length + ') .atEnd=' + generator.atEnd + '  #' + generator.generated);
      stream.write(chunk);
      t.renew(generator.generated, generator.number);
    }
    t.clear();
    done();
  }
  
  setImmediate(write);
  
  return stream;
}

function wGDWonDrain(stream, generator, timeout, done) {
  // writeGeneratedDataWaitsOnDrain
  
  // code analog to stream.Writable.write documentation example

  var t = new Timeout(generator.name + ' wGDWonDrain', timeout);
  
  function write() {
    var ok,
        chunk;
    
    do {
      chunk = generator.next();
      
      debug('[DATA] ' + generator.name + ' wGDWonDrain write(' + chunk.length + ') .atEnd=' + generator.atEnd + '  #' + generator.generated);
       
      if (generator.atEnd) {
        // last time
        return stream.write(chunk, function() {
          t.clear();
          done();
        });
      }
      else {
        ok = stream.write(chunk);
        t.renew(generator.generated, generator.number);
      }
    } while (ok);
    
    // wait on drain
    debug('[DATA] ' + generator.name + ' wGDWonDrain .once:drain  #' + generator.generated);
    stream.once('drain', function() {
      debug('[EVENT] drain ' + generator.name + ' wGDWonDrain  #' + generator.generated);
      write();
    });
  }
  
  setImmediate(write);
  
  return stream;
}

function sODV(stream, verifier, timeout, done) {
  // streamOnDataVerify

  var t = new Timeout(verifier.name + ' sODV', timeout);

  return stream.on('data', function(d) {
    debug('[EVENT] data ' + verifier.name + ' sODV (' + d.length + ') #' + verifier.checked);

    t.renew(verifier.checked, verifier.number);
    
    var err = verifier.verify(d);
    if (err) {
      t.clear();
      return done(err);
    }
    if (verifier.atEnd) {
      t.clear();
      return done();
    }
  });
}

function createExecTest(what, options) {
  
  var run = function() {
    var self = this,
        out = '',
        outErr = '',
        exitArgs,
        closeArgs,
        client,
        server,
        maxNumber = options.maxNumber,
        maxChunkSize,
        strictStreams2 = options.strictStreams2 || options.strict,
        ignoreBadIdenficationStarts = !options.failOnBadIdentificationStarts && !options.strict,
        timeout = (options.timeout && options.timeout * 1000) || -1,
        r;

    r = setup(this,
              { username: USER,
                password: PASSWORD
              },
              { privateKey: HOST_KEY_RSA
              },
              strictStreams2,
              ignoreBadIdenficationStarts);
    client = r.client;
    server = r.server;
    
    // SERVER
    
    server.on('connection', function(conn) {
      debug('[EVENT] connection server(conn)');

      conn.on('authentication', function(ctx) {
        debug('[EVENT] authentication server(ctx)');
        ctx.accept();
      }).on('ready', function() {
        debug('[EVENT] ready server()');

        conn.once('session', function(accept, reject) {
          debug('[EVENT] session server(f,f)');
          
          var session = accept();
          session.once('exec', function(accept, reject, info) {
            assert(info.command === 'foo --bar',
                   makeMsg(what, 'Wrong exec command: ' + info.command));
                   
            debug('[EVENT] exec server.session(f,f,' + inspect(info) + ')');
                   
            var stream = accept();
      
            var writesEnded = 0, 
                exitAtWritesEnded = 0;
          
            // exit and end if all generators finished
      
            function end(what) {
              if (undefined !== what) writesEnded |= what;
              
              debug('[CHECK] server end(' + what + ') => ' + writesEnded);
        
              if (writesEnded != exitAtWritesEnded) return;
        
              stream.exit(100);
              stream.end();        
              conn.end();
            }
      
            var generator;
      
            // create data writers stdout
            generator = new data_utils.ChunkGenerator('server.session.exec.stdout', maxNumber, maxChunkSize);
      
            if ('wGD' === options.server.stdout) {
              wGD(stream, generator, timeout, function(err) { 
                assert(!err, 
                       makeMsg(what, 'wGD ' + generator.name + ' err: ' + inspect(err)));
                       
                debug('[CHECK] ' + generator.name + ' wGD:cb(' + inspect(err) + ')');
                
                end(1);
              });
              exitAtWritesEnded |= 1;
            } 
            else if ('wGDWonDrain' === options.server.stdout) {
              wGDWonDrain(stream, generator, timeout, function(err) { 
                assert(!err, 
                       makeMsg(what, 'wGDWonDrain ' + generator.name + ' err: ' + inspect(err)));
                       
                debug('[CHECK] ' + generator.name + ' wGDWonDrain:cb(' + inspect(err) + ')');
                
                end(1);
              });
              exitAtWritesEnded |= 1;        
            }
            else {
              assert(!options.server.stdout,
                     makeMsg('unhandled server stdout Exec parameter: ' + options.server.stdout));
            }
     
            // create data writers stderr
            generator = new data_utils.ChunkGenerator('server.session.exec.stderr', maxNumber, maxChunkSize);
      
            if ('wGD' === options.server.stderr) {
              wGD(stream.stderr, generator, timeout, function(err) {          
                assert(!err, 
                       makeMsg(what, 'wGD ' + generator.name + ' err: ' + inspect(err)));
                       
                debug('[CHECK] ' + generator.name + ' wGD:cb(' + inspect(err) + ')');
                
                end(2);
              });
              exitAtWritesEnded |= 2;
            }
            else if ('wGDWonDrain' === options.server.stderr) {
              wGDWonDrain(stream.stderr, generator, timeout, function(err) { 
                assert(!err, 
                       makeMsg(what, 'wGDWonDrain ' + generator.name + ' err: ' + inspect(err)));
                       
                debug('[CHECK] ' + generator.name + ' wGDWonDrain:cb(' + inspect(err) + ')');
                
                end(2);
              });
              exitAtWritesEnded |= 2;        
            }
            else {
              assert(!options.server.stderr,
                     makeMsg('unhandled server stderr Exec parameter: ' + options.server.stderr));
            }
            
          }); // session.once:exec
          
        }); // conn.once:session
      }); // conn.on:ready
    }); // server.on:connection
    
    // CLIENT

    client.on('ready', function() {
      debug('[EVENT] ready client()');
      client.exec('foo --bar', function(err, stream) {
        assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
        debug('[CHECK] client.exec(e,s)');
        
        var closeEmitted = false;
    
        var verifiers = [],
            verifier;
    
        // create verifier on stdout
        verifier = new data_utils.ChunkVerifier('client.exec.stdout', maxNumber);
    
        if ('sODV' === options.client.stdout) {
          sODV(stream, verifier, timeout, function(err) {
            assert(undefined === err, 
                  makeMsg(what, 'sODV ' + verifier.name + ' err: ' + inspect(err)));
                  
            debug('[CHECK] ' + verifier.name + ' sODV:cb(' + inspect(err) + ')');
          });
          verifiers.push(verifier);
        }
        else {
          assert(!options.client.stdout,
                 makeMsg('unhandled client stdout Exec parameter: ' + options.client.stdout));
        }
    
        // create verifier on stderr
        verifier = new data_utils.ChunkVerifier('client.exec.stderr', maxNumber);
    
        if ('sODV' === options.client.stderr) {
          sODV(stream.stderr, verifier, timeout, function(err) {
            assert(undefined === err, 
                   makeMsg(what, 'sODV ' + verifier.name + ' err: ' + inspect(err)));

            debug('[CHECK] ' + verifier.name + ' sODV:cb(' + inspect(err) + ')');
          });      
          verifiers.push(verifier);
        }
        else {
          assert(!options.client.stderr,
                 makeMsg('unhandled client stderr Exec parameter: ' + options.client.stderr));
        }
    
        //
    
        stream.on('exit', function(code) {
          debug('[EVENT] exit client.exec.channel(' + inspect(arguments) + ')');
          
          exitArgs = new Array(arguments.length);
          for (var i = 0; i < exitArgs.length; ++i)
            exitArgs[i] = arguments[i];
        }).on('close', function(code) {
          debug('[EVENT] close client.exec.channel(' + inspect(arguments) + ')');

          closeEmitted = true;
      
          closeArgs = new Array(arguments.length);
          for (var i = 0; i < closeArgs.length; ++i)
            closeArgs[i] = arguments[i];
      
        }).on('end', function() {
          debug('[EVENT] end client.exec.channel()');
      
          if (strictStreams2) {
            assert(closeEmitted === false,
                   makeMsg(what, 'client.exec.channel emitted close before end'));
          }
          else if (closeEmitted) {
            debug('[IGNORE] client.exec.channel emitted close before end');
          }
      
          // all verifieres must be atEnd !!
          for (var verifier of verifiers) {
            assert(verifier.atEnd, 
                   makeMsg(what, 'client.exec.channel verifier ' + verifier.name + ' is not .atEnd'));
          }
        }); // stream.on
        
      }); // client.exec
    }).on('end', function() {
      debug('[EVENT] end client()');
      assert.deepEqual(exitArgs,
                       [100],
                       makeMsg(what, 'Wrong exit args: ' + inspect(exitArgs)));
      assert.deepEqual(closeArgs,
                       [100],
                       makeMsg(what,
                               'Wrong close args: ' + inspect(closeArgs)));
    });
  };
  
  debug('[CREATE] created test ' + what);
   
  return { run:run, what:what };
}


//

function parseTestLine(line) {
  line = line.trim()
  
  var numberKeys = [ 'maxNumber', 'timeout' ],
      tests = [ 'Exec' ];
  
  var config = {},
      testFuncName,
      elements = line.split(' ');
            
  // global options - everything without '('
  
  var element,
      subElements;
      
  do {
    if (undefined === elements[0]) {
      return [ new Error('missing test: ' + line) ];
    }
    if (-1 !== elements[0].indexOf('(')) {
      break;
    }
    
    element = elements.shift();
    if ('' === element) {
      continue;
    }
    
    if (undefined === element) {
      return [ new Error('missing test: ' + line) ];
    }
    
    if (-1 !== tests.indexOf(element)) {
      break;
    }

    subElements = element.split('='); 
    if (1 === subElements.length) {
      config[subElements[0]] = true;
    }
    else if (2 === subElements.length) {
      config[subElements[0]] = (-1 === numberKeys.indexOf(subElements[0]) && subElements[1]) || parseInt(subElements[1]);
    }
    else {
      return [ new Error('invalid global option ' + element + ' in line: ' + line) ];
    }
  } while (true);
  
  // type of test

  var m = /^(\S+)\(\s*(\S*)\s*\)<->\(\s*(\S*)\s*\)$/.exec(elements.join(' '));
  if (!m) {
    return [ new Error('invalid test syntax: ' + line)];
  }
  
  testFuncName = 'create' + m[1] + 'Test';
  
  // client and server test parameters
  
  function parseParameters(what, parameterLine) {
    var parameters = {};
    
    for (var parameter of parameterLine.split(',')) {
      var m = /^([iIoOeE]):(\S+)$/.exec(parameter.trim());
      
      if (!m) {
        return [ new Error(what + ' invalid parameter: ' + parameter) ];
      } 
      
      if ('i' === m[1] || 'I' === m[1]) {
        parameters['stdin'] = m[2];
      }
      else if ('o' === m[1] || 'O' === m[1]) {
        parameters['stdout'] = m[2];
      }
      else if ('e' === m[1] || 'E' === m[1]) {
        parameters['stderr'] = m[2];
      }
      
    }
    
    return [ null, parameters ];
  }
  
  var r;
  
  if (undefined === m[2]) {
    return [ new Error('missing client parameters: ' + line) ]
  }

  r = parseParameters('client', m[2]);
  if (r[0]) {
    return [ r[0] ];
  }
  
  config['client'] = r[1];
  
  if (undefined === m[3]) {
    return [ new Error('missing server parameters: ' + line) ]
  }

  r = parseParameters('server', m[3]);
  if (r[0]) {
    return [ r[0] ];
  }
  
  config['server'] = r[1];
  
  return [ null, testFuncName, config ];
}

var tests = [];

function createTestLines(testLines) {
  for (var line of testLines) {
    line = line.trim();
    if ('' === line) {
      continue;
    }
    var r = parseTestLine(line);
    if (r[0]) {
      throw r[0];
    }
  
    if ('createExecTest' === r[1]) {
      tests.push(createExecTest(line, r[2]));
    }
    else {
      throw new Error('unsupported function: ' + r[1]);
    }
  }
}


//


function setup(self, clientcfg, servercfg, strictStreams2, ignoreBadIdenficationStarts) {
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
    if (strictStreams2) {
      assert(self.state.ends == 0, makeMsg(self.what, which + ' emitted error after close: ' + err));
    }
    if (which === 'server' && err.message === 'Bad identification start' && ignoreBadIdenficationStarts) {
      debug('[IGNORE] ' + makeMsg(self.what, which + ' error: ' + err));
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


// starts here - read, generates tests and execute next test


if ('-' === process.argv[2]) {
  // read from stdin
  var inData = '';
  process.stdin.on('data', function(d) {
    inData += d.toString('ascii');
  }).on('end', function() {
    createTestLines(inData.split("\n"));
    next();
  }).on('error', function(err) {
    console.error('error reading tests from stdin: ' + err);
    process.exit(1);
  });
}
else if (process.argv[2]) {
  // read from file at specified path
  createTestLines(fs.readFileSync(process.argv[2], { encoding:'ascii'}).split("\n"));
  next();
} else {
  // hmm? we read from this directory the "standard" tests...
  createTestLines(fs.readFileSync(join(__dirname, 'streaming-tests.txt'), { encoding:'ascii'}).split("\n"));
  next();
}
