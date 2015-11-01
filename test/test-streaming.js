'use strict'

// (c) 2015 Michael Keller, minesworld-technologies.com , published under MIT license
// parts of code (c) mscdex

var EventEmitter = require('events').EventEmitter,
    data_utils = require('./data-utils');

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
    exitOnSourceEnd = process.env['exitOnSourceEnd']
                      && !process.env['strictStreams2']
                      && !process.env['strict'],
    endWorkaround = process.env['endWorkaround']
                    && !process.env['strictStreams2']
                    && !process.env['strict'],
    disconnectOnFirstFinish = process.env['disconnectOnFirstFinish']
                    && !process.env['strictStreams2']
                    && !process.env['strict'];
    
var debug = function() {};

if (DEBUG) {
  debug = function(message) {
    console.log(message);
  }

  for (var key in process.versions) {
    debug('[INFO] ' + key + ': ' + process.versions[key]);
  }
  debug('[INFO] platform: ' + process.platform + ' ' + process.arch);
  
  debug('[INFO] strictStreams2: ' + process.env['strictStreams2']);
  debug('[INFO] failOnBadIdentificationStarts: ' + process.env['failOnBadIdentificationStarts']);
  debug('[INFO] exitOnSourceEnd: ' + exitOnSourceEnd);
  debug('[INFO] endWorkaround: ' + endWorkaround);
  debug('[INFO] disconnectOnFirstFinish: ' + disconnectOnFirstFinish);
  debug('[INFO] strict: ' + process.env['strict']);
}

// 

function wGD(stream, generator, timeout, done) {
  // writeGeneratedData
  
  var t = new data_utils.Timeout(generator.name + ' wGD', timeout, function(name, d, lastNumber, lastBytes) {
            assert(true,
                   makeMsg(name, 'timed out after: ' + d + 'ms ' + lastNumber + ',#' + lastBytes));
          });

  stream
    .on('finish', function() {
      debug('[EVENT] finish ' + generator.name + ' wGD');
      done(null, 'finish');
      if (!endWorkaround) { // done(close) might call stream.end...
        done(null, 'close'); // according to the specs not all streams must emit an close event
      } 
      else {
        debug('[FIX] endWorkaround ' + generator.name + ' wGD stream');
      }
    })
    .on('close', function() {
      debug('[EVENT] close ' + generator.name + ' wGD');
      done(null, 'close'); // all done, can savely close
    })
    .on('error', function(err) {
      debug('[EVENT] error ' + generator.name + ' wGD');
      done(err);
    });
    
  function write() {
    
    while (!generator.atEnd) {
      var chunk = generator.next();
      debug('[DATA] ' + generator.name + ' wGD write(' + chunk.length + ') .atEnd=' + generator.atEnd + '  #' + generator.generated);
      stream.write(chunk);
      t.renew(generator.generated, generator.number);
    }
    t.clear();
    
    if (exitOnSourceEnd) {
      debug('[FIX] exitOnSourceEnd ' + generator.name);
      done(null, 'finish'); // this may call stream.exit()
    }
    if (!endWorkaround) { // don't end stream here as another stream might be still transferring data...
      stream.end(); 
    }
    else {
      debug('[FIX] endWorkaround ' + generator.name + ' wGD write');
    }
  }
  
  setImmediate(write);
  
  return stream;
}

function wGDWonDrain(stream, generator, timeout, done) {
  // writeGeneratedDataWaitsOnDrain
  
  // code analog to stream.Writable.write documentation example

  var t = new data_utils.Timeout(generator.name + ' wGDWonDrain', timeout, function(name, d, lastNumber, lastBytes) {
            assert(true,
                   makeMsg(name, 'timed out after: ' + d + 'ms ' + lastNumber + ',#' + lastBytes));
          });
  
  stream
    .on('finish', function() {
      debug('[EVENT] finish ' + generator.name + ' wGDWonDrain');
      done(null, 'finish');
      if (!endWorkaround) { // done(close) might call stream.end...
        done(null, 'close'); // according to the specs not all streams must emit an close event
      }
      else {
        debug('[FIX] endWorkaround ' + generator.name + ' wGDWonDrain stream');
      }
    })
    .on('close', function() {
      debug('[EVENT] close ' + generator.name + ' wGDWonDrain');
      done(null, 'close'); // all done, can savely close
    })
    .on('error', function(err) {
      debug('[EVENT] error ' + generator.name + ' wGDWonDrain');
      done(err);
    });
    
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

          if (exitOnSourceEnd) {
            debug('[FIX] exitOnSourceEnd ' + generator.name);
            done(null, 'finish'); // this may call stream.exit()
          }
          if (!endWorkaround) { // don't end stream here as another stream might be still transferring data...
            stream.end();
          }
          else {
            debug('[FIX] endWorkaround ' + generator.name + ' wGDWonDrain write');
          }
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

function wStream(stream, generator, timeout, done) {
  // writeStream
  
  function createPipe() {
    var t = new data_utils.Timeout(generator.name + ' wStream', timeout, function(name, d, lastNumber, lastBytes) {
              assert(true,
                     makeMsg(name, 'timed out after: ' + d + 'ms ' + lastNumber + ',#' + lastBytes));
            });

    var source = new data_utils.StreamOfNumberLines(generator);
    
    source
      .on('willpush', function(chunk) {
        t.renew(generator.generated, generator.number);

        if (chunk) {
          debug('[DATA] ' + generator.name + ' wStream push(' + chunk.length + ') .atEnd=' + generator.atEnd + '  #' + generator.generated);
        }
        else {
          debug('[DATA] ' + generator.name + ' wStream push(null) .atEnd=' + generator.atEnd + '  #' + generator.generated);
         }
      })
      .on('end', function() {
        debug('[EVENT] end ' + generator.name + ' wStream #' + generator.generated);
        if (exitOnSourceEnd) {
          debug('[FIX] exitOnSourceEnd ' + generator.name);
          done(null, 'finish'); // this may call stream.exit()
        }
      })
      .on('close', function() {
        debug('[EVENT] close ' + generator.name + ' wStream source #' + generator.generated);
      })      
      .on('error', function(err) {
        t.clear();
        debug('[EVENT] error ' + generator.name + ' wStream source #' + generator.generated);
        done(err);
      })
      
      .pipe(stream, {end:!endWorkaround})
      .on('finish', function() {
        debug('[EVENT] finish ' + generator.name + ' wStream');
        done(null, 'finish');
        if (!endWorkaround) { // don't end stream here as another stream might be still transferring data...
          done(null, 'close'); // according to the specs not all streams must emit an close event    
        }
        else {
          debug('[FIX] endWorkaround ' + generator.name + ' wStream target');
        }
      })
      .on('close', function() {
        t.clear();
        debug('[EVENT] close ' + generator.name + ' wStream target');
        done(null, 'close'); // all done, can savely close
      })      
      .on('error', function(err) {
        t.clear();
        debug('[EVENT] error ' + generator.name + ' wStream target');
        done(err);
      })      
  }
  
  setImmediate(createPipe);
   
  return stream;
}

function sODV(stream, verifier, timeout, done) {
  // streamOnDataVerify

  var t = new data_utils.Timeout(verifier.name + ' sODV', timeout, function(name, d, lastNumber, lastBytes) {
            assert(true,
                   makeMsg(name, 'timed out after: ' + d + 'ms ' + lastNumber + ',#' + lastBytes));
          });

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


function vStream(stream, verifier, timeout, done) {
  // verifyStream

  var t = new data_utils.Timeout(verifier.name + ' vStream', timeout, function(name, d, lastNumber, lastBytes) {
            assert(true,
                   makeMsg(name, 'timed out after: ' + d + 'ms ' + lastNumber + ',#' + lastBytes));
          });
  
  function createPipe() {
    var target = new data_utils.NumberLineStreamVerifier(verifier);
  
    stream
      .on('end', function() {
        debug('[EVENT] end ' + verifier.name + ' vStream');        
      })
      .on('close', function() {
        debug('[EVENT] close ' + verifier.name + ' vStream');        
      })
      .on('error', function(err) {
        t.clear();
        debug('[EVENT] error ' + verifier.name + ' vStream source');        
        done(err);
      })
      .pipe(target)
      .on('verify', function(chunk) {
        debug('[DATA] ' + verifier.name + ' vStream (' + chunk.length + ') #' + verifier.checked);
        t.renew(verifier.checked, verifier.number);
      })
      .on('finish', function() {
        t.clear();
        debug('[EVENT] finish ' + verifier.name + ' vStream');        
        done();
      })
      .on('error', function(err) {
        t.clear();
        debug('[EVENT] error ' + verifier.name + ' vStream target');        
        done(err);
      });
  }
      
  setImmediate(createPipe);   
    
  return stream;
}

//


function serverExec(conn, what, session, options, sOptions, cb) {
  var maxNumber = options.maxNumber,
      maxChunkSize,
      strictStreams2 = options.strictStreams2 || options.strict,
      ignoreBadIdenficationStarts = !options.failOnBadIdentificationStarts && !options.strict,
      timeout = (options.timeout && options.timeout * 1000) || -1;
  
  session.once('exec', function(accept, reject, info) {
    assert(info.command === 'foo --bar',
           makeMsg(what, 'Wrong exec command: ' + info.command));
           
    debug('[EVENT] exec server.session(f,f,' + inspect(info) + ')');
           
    var stream = accept();

    var writesFinished = 0,
        writesClosed = 0,
        writersEmittedFinish = 0,
        flags = 0; // 1=stdout, 2=stderr, 4=stdin
  
    var generator,
        verifier;
    
  
    // exit and end if all generators finished

    function finish(what) {
      if (undefined !== what) writesFinished |= what;
      
      debug('[CHECK] server finish(' + what + ') => ' + writesFinished);

      if (writesFinished != flags) return;

      debug('[CHECK] server.session.exec.exit(100)');
      stream.exit(100);
      
      // this is a critical workaround - as 
      
      if (endWorkaround) {
        close(writesFinished);
      }
    }
    
    function emittedFinish(what) {
      if (undefined !== what) writersEmittedFinish |= what;
      
      if (writersEmittedFinish != flags && !disconnectOnFirstFinish) return;

      cb();
    }
    
    stream.once('finish', function() {
      debug('[EVENT] finish server.session.exec.stream')
      emittedFinish(1);
    });
    
    stream.stderr.once('finish', function() {
      debug('[EVENT] finish server.session.exec.stream.stderr')
      emittedFinish(2);
    });
    
    function close(what) {
      if (undefined !== what) {
        writesClosed |= what;
      }
        
      debug('[CHECK] server close(' + what + ') => ' + writesClosed);

      if (writesClosed != (flags & 3)) return; // ignore stdin
      
      if (endWorkaround) {
        debug('[CHECK] server.session.exec.end()');
        stream.end() // will close BOTH stdout AND stderr !!
      }
    }
    
    function createWriteDoneFunc(name, generator, writer) {
      return function(err, event) {
        assert(!err, 
               makeMsg(what, name + ' ' + generator.name + ' err: ' + inspect(err)));
               
        debug('[CHECK] ' + generator.name + ' ' + name + ':cb(' + inspect(err) + ', ' + event + ')');
        
        if (event === 'finish') {
          finish(writer);
        }
        else if (event === 'close') {
          close(writer);
        }
      }
    }
    
    function createVerifyDoneFunc(name, verifier) {
      return function(err) {
        assert(undefined === err, 
              makeMsg(what, name + ' ' + verifier.name + ' err: ' + inspect(err)));
          
        debug('[CHECK] ' + verifier.name + ' ' + name + ':cb(' + inspect(err) + ')');
        
        finish(4);
      }  
    }
    
    
    
    // create verifier on stdin
    verifier = new data_utils.ChunkVerifier('server.session.exec.stdin', maxNumber);

    if ('sODV' === sOptions.server.stdin) {
      sODV(stream, verifier, timeout, createVerifyDoneFunc('sODV', verifier));
      flags |= 4;
    }
    else if ('vStream' === sOptions.server.stdin) {
      vStream(stream, verifier, timeout, createVerifyDoneFunc('vStream', verifier));
      flags |= 4;
    }
    else {
      assert(!sOptions.server.stdin,
             makeMsg('unhandled server stdin Exec parameter: ' + sOptions.server.stdin));
    }
     

    // create data writers stdout
    generator = new data_utils.ChunkGenerator('server.session.exec.stdout', maxNumber, maxChunkSize);

    if ('wGD' === sOptions.server.stdout) {
      wGD(stream, generator, timeout, createWriteDoneFunc('wGD', generator, 1));
      flags |= 1;
    } 
    else if ('wGDWonDrain' === sOptions.server.stdout) {
      wGDWonDrain(stream, generator, timeout, createWriteDoneFunc('wGDWonDrain', generator, 1));
      flags |= 1;        
    }
    else if ('wStream' === sOptions.server.stdout) {
      wStream(stream, generator, timeout, createWriteDoneFunc('wStream', generator, 1));
      flags |= 1;        
    }
    else {
      assert(!sOptions.server.stdout,
             makeMsg('unhandled server stdout Exec parameter: ' + sOptions.server.stdout));
    }

    // create data writers stderr
    generator = new data_utils.ChunkGenerator('server.session.exec.stderr', maxNumber, maxChunkSize);

    if ('wGD' === sOptions.server.stderr) {
      wGD(stream.stderr, generator, timeout, createWriteDoneFunc('wGD', generator, 2));
      flags |= 2;
    }
    else if ('wGDWonDrain' === sOptions.server.stderr) {
      wGDWonDrain(stream.stderr, generator, timeout, createWriteDoneFunc('wGDWonDrain', generator, 2));
      flags |= 2;        
    }
    else if ('wStream' === sOptions.server.stderr) {
      wStream(stream.stderr, generator, timeout,  createWriteDoneFunc('wStream', generator, 2));
      flags |= 2;        
    }
    else {
      assert(!sOptions.server.stderr,
             makeMsg('unhandled server stderr Exec parameter: ' + sOptions.server.stderr));
    }
    
  }); // session.once:exec
}

function clientExec(what, client, options, sOptions) {
  var maxNumber = options.maxNumber,
      maxChunkSize,
      strictStreams2 = options.strictStreams2 || options.strict,
      ignoreBadIdenficationStarts = !options.failOnBadIdentificationStarts && !options.strict,
      timeout = (options.timeout && options.timeout * 1000) || -1;
    
  var emitter = new EventEmitter();
  
  client.exec('foo --bar', function(err, stream) {
    assert(!err, makeMsg(what, 'Unexpected exec error: ' + err));
    debug('[CHECK] client.exec(e,s)');
    
    var closeEmitted = false;

    var verifiers = [],
        flags = 0,
        writesFinished = 0;
    
    var generator,
        verifier;
        
    function createVerifyDoneFunc(name, verifier) {
      return function(err) {
        assert(undefined === err, 
              makeMsg(what, name + ' ' + verifier.name + ' err: ' + inspect(err)));
              
        debug('[CHECK] ' + verifier.name + ' ' + name + ':cb(' + inspect(err) + ')');
      }  
    }
    
    function createWriteDoneFunc(name, generator, writer) {
      return function(err, event) {
        assert(!err, 
               makeMsg(what, name + ' ' + generator.name + ' err: ' + inspect(err)));
               
        debug('[CHECK] ' + generator.name + ' ' + name + ':cb(' + inspect(err) + ', ' + event + ')');
        
        if (event === 'finish') {
          writesFinished |= 1;
          debug('[CHECK] client.exec.stdin.end()');
          stream.end();
        }
        else if (event === 'close') {
        }
      }
    }
    
    // create data writer stdin
    generator = new data_utils.ChunkGenerator('client.exec.stdin', maxNumber, maxChunkSize);

    if ('wGD' === sOptions.client.stdin) {
      wGD(stream, generator, timeout, createWriteDoneFunc('wGD', generator, 1));
      flags |= 1;
    } 
    else if ('wGDWonDrain' === sOptions.client.stdin) {
      wGDWonDrain(stream, generator, timeout, createWriteDoneFunc('wGDWonDrain', generator, 1));
      flags |= 1;        
    }
    else if ('wStream' === sOptions.client.stdin) {
      wStream(stream, generator, timeout, createWriteDoneFunc('wStream', generator, 1));
      flags |= 1;        
    }
    else {
      assert(!sOptions.server.stdin,
             makeMsg('unhandled client stdin Exec parameter: ' + sOptions.client.stdin));
    }
    

    // create verifier on stdout
    verifier = new data_utils.ChunkVerifier('client.exec.stdout', maxNumber);

    if ('sODV' === sOptions.client.stdout) {
      sODV(stream, verifier, timeout, createVerifyDoneFunc('sODV', verifier));
      verifiers.push(verifier);
    }
    else if ('vStream' === sOptions.client.stdout) {
      vStream(stream, verifier, timeout, createVerifyDoneFunc('vStream', verifier));
      verifiers.push(verifier);
    }
    else {
      assert(!sOptions.client.stdout,
             makeMsg('unhandled client stdout Exec parameter: ' + sOptions.client.stdout));
    }

    // create verifier on stderr
    verifier = new data_utils.ChunkVerifier('client.exec.stderr', maxNumber);

    if ('sODV' === sOptions.client.stderr) {
      sODV(stream.stderr, verifier, timeout, createVerifyDoneFunc('sODV', verifier));      
      verifiers.push(verifier);
    }
    else if ('vStream' === sOptions.client.stderr) {
      vStream(stream.stderr, verifier, timeout, createVerifyDoneFunc('vStream', verifier));
      verifiers.push(verifier);
    }
    else {
      assert(!sOptions.client.stderr,
             makeMsg('unhandled client stderr Exec parameter: ' + sOptions.client.stderr));
    }

    //

    stream.on('exit', function(code) {
      debug('[EVENT] exit client.exec.channel(' + inspect(arguments) + ')');
                
      var args = new Array(arguments.length);
      for (var i = 0; i < args.length; ++i)
        args[i] = arguments[i];
      
      // stdin must have finished
      assert(writesFinished == flags,
        makeMsg(what, 'client.exec.channel emitted close before stdin.end()'));
      
      emitter.emit('exit', args);
    }).on('close', function(code) {
      debug('[EVENT] close client.exec.channel(' + inspect(arguments) + ')');

      closeEmitted = true;
  
      var args = new Array(arguments.length);
      for (var i = 0; i < args.length; ++i)
        args[i] = arguments[i];
      
      emitter.emit('close', args);
  
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
      
      // stdin must have finished
      assert(writesFinished == flags,
        makeMsg(what, 'client.exec.channel emitted close before stdin.end()'));
      
    }); // stream.on
    
  }); // client.exec  
  
  return emitter;
}

//

function createTest(what, options) {
  
  var run = function() {
    var self = this,
        out = '',
        outErr = '',
        exitArgs = [],
        closeArgs = [],
        execTestCount = 0,
        client,
        server,
        strictStreams2 = options.strictStreams2 || options.strict,
        ignoreBadIdenficationStarts = !options.failOnBadIdentificationStarts && !options.strict,
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

        
        var subtests = Array.from(options['subtests']),
            running = 0;
            
        function finishedSubtest(err) {
          running -= 1;
          debug('[EVENT] server finishedSubtest ' + running + ' running')
          if (0 === running) {
            debug('[CHECK] server.end()');
            conn.end();
          }
        }
        
        
        
        conn.on('session', function(accept, reject) {
          debug('[EVENT] session server(f,f)');
          
          // find a matching Exec test
          var subtest;
          
          for (var i = 0; i < subtests.length; i++) {
            if ('Exec' === subtests[i]['type'] ) {
              subtest = subtests.splice(i, 1)[0];
              break;
            }
          }
          
          if (!subtest) {
            throw new Error('server can not handle unmatched test request: session');
          }
          
          var session = accept();
          running += 1;
          serverExec(conn, what, session, options, subtest, finishedSubtest);
 
          
        }); // conn.once:session
      }); // conn.on:ready
    }); // server.on:connection
    
    // CLIENT

    client.on('ready', function() {
      debug('[EVENT] ready client()');
      
      var subtests = Array.from(options['subtests']);
      
      while (0 < subtests.length) {
        var subtest = subtests.shift();
        
        if ('Exec' === subtest['type']) {
          execTestCount += 1;
          clientExec(what, client, options, subtest)
            .on('close', function(args) {
              closeArgs.push(args);
            })
            .on('exit', function(args) {
              exitArgs.push(args);
            })
        }
      }
      

    }).on('end', function() {
      debug('[EVENT] end client()');
      
      assert(execTestCount === exitArgs.length,
             makeMsg(what, 'Wrong number of exits: ' + exitArgs.length));
      assert(execTestCount === closeArgs.length,
             makeMsg(what, 'Wrong number of closes: ' + exitArgs.length));
      
      while (0 < exitArgs.length) {
        var args = exitArgs.shift();
        assert.deepEqual(args,
                         [100],
                         makeMsg(what, 'Wrong exit args: ' + inspect(args)));
      }
      while (0 < closeArgs.length) {
        var args = closeArgs.shift();
        assert.deepEqual(args,
                         [100],
                         makeMsg(what, 'Wrong close args: ' + inspect(args)));
      }
    });
  };
  
  debug('[CREATE] created test ' + what);
   
  return { run:run, what:what };
}

//

function parseTestLine(line) {
  line = line.trim()
  
  var numberKeys = [ 'maxNumber', 'timeout' ],
      tests = [ 'Exec', 'Data' ];
  
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

  // subtests

  function parseParameters(what, parameterLine) {
    if (!parameterLine) {
      return [ new Error(what + ' no parameters') ];
    }
    
    var parameters = {},
        elements  = parameterLine.split(',');
    
    for (var i = 0; i < elements.length; i++) {
      var parameter = elements[i];
      
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
  
  // 

  var s = elements.join(' '),
      r = /(\S+)\(\s*(\S*)\s*\)<->\(\s*(\S*)\s*\)/,
      elements = s.split(r),
      subtests = [],
      subtest = null;
      
  while (0 < elements.length) {
    var element = elements.shift().trim(),
        r;

    if ('' === element) {
      if (subtest) {
        return [ new Error('invalid syntax in line: ' + line)];
      }
      continue;
    }
    
    // new subtest
    
    if (-1 === tests.indexOf(element)) {
      return [ new Error('unknown test type ' + element + ' in line: ' + line )];
    }
    
    subtest = {
      type:element
    };
    
    // client options
    
    r = parseParameters('client', elements.shift());
    if (r[0]) {
      return [ r[0] ];
    }

    subtest['client'] = r[1];

    //  server options
    
    r = parseParameters('server', elements.shift());
    if (r[0]) {
      return [ r[0] ];
    }

    subtest['server'] = r[1];
    
    // 
    
    subtests.push(subtest);
    subtest = null;
  }
    
  config['subtests'] = subtests;
  
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
  
    tests.push(createTest(line, r[2]));
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
