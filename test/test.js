var spawn = require('child_process').spawn,
    join = require('path').join;

var files = require('fs').readdirSync(__dirname).filter(function(f) {
      return (f.substr(0, 5) === 'test-');
    }).map(function(f) {
      return join(__dirname, f);
    }),
    f = -1;

function next() {
  if (++f < files.length) {
    spawn(process.argv[0], [ files[f] ], { stdio: 'inherit' })
      .on('exit', function(code) {
        if (code === 0)
          process.nextTick(next);
      });
  }
}
next();
