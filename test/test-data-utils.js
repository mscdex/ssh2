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
          cfg = {};
          
      var e = setup(this, cfg);
     
      e.on('start', function() {
        e.emit('end');
      });
    },
    what: 'nothing'
  }
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
  
  var emitter = new EventEmitter().on('end', function() {
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


