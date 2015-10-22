'use strict'

// (c) 2015 Michael Keller, minesworld-technologies.com , published under MIT license
// parts of code (c) mscdex

var data_utils = require('./data-utils');

var EventEmitter = require('events');

var path = require('path'),
    join = path.join,
    inspect = require('util').inspect,
    assert = require('assert');

var t = -1,
    group = path.basename(__filename, '.js') + '/',
    fixturesdir = join(__dirname, 'fixtures');

var DEBUG = process.env['DEBUG'];

var debug = function() {};

if (DEBUG) {
  debug = function(message) {
    console.log(message);
  }
}


//

var tests = [
  {
    run: function() {
      var self = this,
          what = this.what,
          cfg = {},
          e = setup(this, cfg);

      e.on('start', function() {
        var generator = new data_utils.ChunkGenerator(what, 10),
            expected = '',
            out = '',
            chunk;
          
        for (var i=0; i < 10; i++) {
          expected += '' + i + "\n";
        } 
              
        while (null !== (chunk = generator.next())) {
          out += chunk.toString('ascii');
        }
      
        assert(out === expected, 
              makeMsg(what, generator.name + ' output not expected: ' + out));
        assert(generator.atEnd,
               makeMsg(what, generator.name + ' not .atEnd'));

        e.emit('end');
      });
    },
    what: 'ChunkGenerator(10)'
  },
  {
    run: function() {
      var self = this,
          what = this.what,
          cfg = {},
          e = setup(this, cfg);

      e.on('start', function() {
        var verifier = new data_utils.ChunkVerifier(what, 10),
            inStrs = [ "0", "\n1\n", "2\n", "3", "\n4\n5", "\n", "6\n7", "\n8", "\n9", "\n" ];
          
        for (var inStr of inStrs) {
          var err = verifier.verify(new Buffer(inStr, 'ascii'));
          assert(null === err,
                 makeMsg(what, verifier.name + ' result not expected: ' + inspect(err)));
        }
          
        assert(verifier.atEnd,
               makeMsg(what, verifier.name + ' not .atEnd'));

        e.emit('end');
      });
    },
    what: 'ChunkVerifier(10)'
  },
  {
    run: function() {
      var self = this,
          what = this.what,
          cfg = {},
          e = setup(this, cfg);

      e.on('start', function() {
        var generator = new data_utils.ChunkGenerator(what, 10),
            pipeOrigin = new data_utils.StreamOfNumberLines(generator),
            expected = '',
            out = '',
            chunk;
          
        for (var i=0; i < 10; i++) {
          expected += '' + i + "\n";
        } 
              
        while (null !== (chunk = pipeOrigin.read())) {
          out += chunk.toString('ascii');
        }
      
        assert(out === expected, 
               makeMsg(what, generator.name + ' output not expected: ' + out));
        assert(generator.atEnd,
               makeMsg(what, generator.name + ' not .atEnd'));

        e.emit('end');
      });
    },
    what: 'StreamOfNumberLines(10)'
  },  
  {
    run: function() {
      var self = this,
          what = this.what,
          cfg = {},
          e = setup(this, cfg);

      e.on('start', function() {
        var verifier = new data_utils.ChunkVerifier(what, 10),
            pipeSink = new data_utils.NumberLineStreamVerifier(verifier),
            inStrs = [ "0", "\n1\n", "2\n", "3", "\n4\n5", "\n", "6\n7", "\n8", "\n9", "\n" ];
          
        var i = 0;
        
        function write() {
          while (i < inStrs.length) {
            if (false === pipeSink.write(new Buffer(inStrs[i++], 'ascii'))) {
              return pipeSink.once('drain', write);
            }
          }
        }
        
        write();
        
        pipeSink.end(function() {
           assert(verifier.atEnd,
            makeMsg(what, verifier.name + ' not .atEnd'));
        });
          
        e.emit('end');
      });
    },
    what: 'NumberLineStreamVerifier(10)'
  },
  {
    run: function() {
      var self = this,
          what = this.what,
          cfg = {},
          e = setup(this, cfg);

      e.on('start', function() {
        var generator = new data_utils.ChunkGenerator(what + ' StreamOfNumberLines', 10),
            pipeOrigin = new data_utils.StreamOfNumberLines(generator),     
            verifier = new data_utils.ChunkVerifier(what + ' NumberLineStreamVerifier', 10),
            pipeSink = new data_utils.NumberLineStreamVerifier(verifier);
        
        pipeOrigin
          .on('end', function() {
            debug('[EVENT] finish StreamOfNumberLines');
          })
          .pipe(pipeSink)
          .on('finish', function() {
            debug('[EVENT] finish NumberLineStreamVerifier');
            assert(generator.atEnd,
                   makeMsg(what, generator.name + ' not .atEnd'));
            assert(verifier.atEnd,
                   makeMsg(what, verifier.name + ' not .atEnd'));
            e.emit('end');
          })
          .on('error', function(err) {
            debug('[EVENT] error NumberLineStreamVerifier');
            assert(true,
                   makeMsg(what, '' + err));
            e.emit('end');
          });
       });
    },
    what: 'StreamOfNumberLines(10)->NumberLineStreamVerifier(10)'
  },
  {
    run: function() {
      var self = this,
          what = this.what,
          cfg = {},
          e = setup(this, cfg);

      e.on('start', function() {
        var generator = new data_utils.ChunkGenerator(what + ' StreamOfNumberLines', 10),
            pipeOrigin = new data_utils.StreamOfNumberLines(generator),
            thruVerifier = new data_utils.ChunkVerifier(what + ' VerifyingNumberLinesStream', 10),
            pipeThru = new data_utils.VerifyingNumberLinesStream(thruVerifier),
            verifier = new data_utils.ChunkVerifier(what + ' NumberLineStreamVerifier', 10),
            pipeSink = new data_utils.NumberLineStreamVerifier(verifier);
        
        pipeOrigin
          .on('end', function() {
            debug('[EVENT] finish StreamOfNumberLines');
          })
          .pipe(pipeThru)
          .on('end', function() {
            debug('[EVENT] finish VerifyingNumberLinesStream');
          })
          .pipe(pipeSink)
          .on('finish', function() {
            debug('[EVENT] finish NumberLineStreamVerifier');
            assert(generator.atEnd,
                   makeMsg(what, generator.name + ' not .atEnd'));
            assert(verifier.atEnd,
                   makeMsg(what, verifier.name + ' not .atEnd'));
           assert(thruVerifier.atEnd,
                  makeMsg(what, thruVerifier.name + ' not .atEnd'));
            e.emit('end');
          })
          .on('error', function(err) {
            debug('[EVENT] error NumberLineStreamVerifier');
            assert(true,
                   makeMsg(what, '' + err));
            e.emit('end');
          });
       });
    },
    what: 'StreamOfNumberLines(10)->VerifyingNumberLinesStream(10)->NumberLineStreamVerifier(10)'
  },    
];

//

function setup(self, cfg) {
  self.state = {
    readies: 0,
    ends: 0
  };

  if (DEBUG) {
    console.log('========================================================\n'
                + '[TEST] '
                + self.what
                + '\n========================================================');
    cfg.debug = function(str) {
      console.log('[DATA] ' + str);
    };
  }
  
  var emitter = new EventEmitter()
    .once('end', function() {
      next();
    });
  
  process.nextTick(function() {
    emitter.emit('start');
  });
  
  return emitter;
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


