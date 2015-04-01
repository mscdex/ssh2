// **BEFORE RUNNING THIS SCRIPT:**
//   1. Install `blessed`: `npm install blessed`
//   2. Create a server host key in this same directory and name it `host.key`

var blessed = require('blessed'),
    Server = require('ssh2').Server;

var RE_SPECIAL = /[\x00-\x1F\x7F]+|(?:\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K])/g,
    MAX_MSG_LEN = 128,
    MAX_NAME_LEN = 10,
    PROMPT_NAME = 'Enter a nickname to use (max ' + MAX_NAME_LEN + ' chars): ';

var users = [];

function formatMessage(msg, output) {
  var output = output;
  output.parseTags = true;
  msg = output._parseTags(msg);
  output.parseTags = false;
  return msg;
}

function userBroadcast(msg, source) {
  var sourceMsg = '> ' + msg,
      name = '{cyan-fg}{bold}' + source.name + '{/}';
  msg = ': ' + msg;
  for (var i = 0; i < users.length; ++i) {
    var user = users[i],
        output = user.output;
    if (source === user)
      output.add(sourceMsg);
    else
      output.add(formatMessage(name, output) + msg);
  }
}

function localMessage(msg, source) {
  var output = source.output;
  output.add(formatMessage(msg, output));
}

function noop(v) {}

new Server({
  privateKey: require('fs').readFileSync('host.key'),
}, function(client) {
  var stream,
      name;

  client.on('authentication', function(ctx) {
    var nick = ctx.username,
        prompt = PROMPT_NAME,
        lowered;
    // try to use username as nickname
    if (nick.length > 0 && nick.length <= MAX_NAME_LEN) {
      lowered = nick.toLowerCase();
      var ok = true;
      for (var i = 0; i < users.length; ++i) {
        if (users[i].name.toLowerCase() === lowered) {
          ok = false;
          prompt = 'That nickname is already in use.\n' + PROMPT_NAME;
          break;
        }
      }
      if (ok) {
        name = nick;
        return ctx.accept();
      }
    } else if (nick.length === 0)
      prompt = 'A nickname is required.\n' + PROMPT_NAME;
    else
      prompt = 'That nickname is too long.\n' + PROMPT_NAME;

    if (ctx.method !== 'keyboard-interactive')
      return ctx.reject(['keyboard-interactive']);

    ctx.prompt(prompt, function retryPrompt(answers) {
      if (answers.length === 0)
        return ctx.reject(['keyboard-interactive']);
      nick = answers[0];
      if (nick.length > MAX_NAME_LEN) {
        return ctx.prompt('That nickname is too long.\n' + PROMPT_NAME,
                          retryPrompt);
      } else if (nick.length === 0) {
        return ctx.prompt('A nickname is required.\n' + PROMPT_NAME,
                          retryPrompt);
      }
      lowered = nick.toLowerCase();
      for (var i = 0; i < users.length; ++i) {
        if (users[i].name.toLowerCase() === lowered) {
          return ctx.prompt('That nickname is already in use.\n' + PROMPT_NAME,
                            retryPrompt);
        }
      }
      name = nick;
      ctx.accept();
    });
  }).on('ready', function() {
    var rows,
        cols,
        term;
    client.once('session', function(accept, reject) {
      accept().once('pty', function(accept, reject, info) {
        rows = info.rows;
        cols = info.cols;
        term = info.term;
        accept && accept();
      }).on('window-change', function(accept, reject, info) {
        rows = info.rows;
        cols = info.cols;
        if (stream) {
          stream.rows = rows;
          stream.columns = cols;
          stream.emit('resize');
        }
        accept && accept();
      }).once('shell', function(accept, reject) {
        stream = accept();
        users.push(stream);

        stream.name = name;
        stream.rows = rows || 24;
        stream.columns = cols || 80;
        stream.isTTY = true;
        stream.setRawMode = noop;
        stream.on('error', noop);

        var screen = new blessed.screen({
          autoPadding: true,
          smartCSR: true,
          program: new blessed.program({
            input: stream,
            output: stream
          }),
          terminal: term || 'ansi'
        });

        screen.title = 'SSH Chat';
        // disable local echo
        screen.program.attr('invisible', true);
        // hide cursor
        //screen.program.hideCursor();
        // XXX this is a hack since `program.hideCursor()` does not seem to
        // work?
        stream.write('\x1b[?25l');

        var output = stream.output = new blessed.log({
          screen: screen,
          top: 0,
          left: 0,
          width: '100%',
          bottom: 2,
          scrollOnInput: true
        })
        screen.append(output);

        screen.append(new blessed.box({
          screen: screen,
          height: 1,
          bottom: 1,
          left: 0,
          width: '100%',
          type: 'line',
          ch: '='
        }));

        var input = new blessed.textbox({
          screen: screen,
          bottom: 0,
          height: 1,
          width: '100%',
          inputOnFocus: true
        });
        screen.append(input);

        input.focus();
        screen.render();

        // local greeting
        localMessage('{blue-bg}{white-fg}{bold}Welcome to SSH Chat!{/}\nThere are {bold}'
                     + (users.length - 1)
                     + '{/} other user(s) connected.',
                     stream);

        // let everyone else know that this user just joined
        for (var i = 0; i < users.length; ++i) {
          var user = users[i],
              output = user.output;
          if (user === stream)
            continue;
          output.add(formatMessage('{green-fg}*** {bold}', output)
                     + name
                     + formatMessage('{/bold} has joined the chat{/}', output));
        }

        // read a line of input from the user
        input.on('submit', function(line) {
          input.clearValue();
          screen.render();
          if (!input.focused)
            input.focus();
          line = line.replace(RE_SPECIAL, '').trim();
          if (line.length > MAX_MSG_LEN)
            line = line.substring(0, MAX_MSG_LEN);
          if (line.length > 0) {
            if (line === '/quit' || line === '/exit')
              stream.end();
            else
              userBroadcast(line, stream);
          }
        });
      });
    });
  }).on('end', function() {
    if (stream !== undefined) {
      spliceOne(users, users.indexOf(stream));
      // let everyone else know that this user just left
      for (var i = 0; i < users.length; ++i) {
        var user = users[i],
            output = user.output;
        output.add(formatMessage('{magenta-fg}*** {bold}', output)
                   + name
                   + formatMessage('{/bold} has left the chat{/}', output));
      }
    }
  });
}).listen(0, function() {
  console.log('Listening on port ' + this.address().port);
});

function spliceOne(list, index) {
  for (var i = index, k = i + 1, n = list.length; k < n; i += 1, k += 1)
    list[i] = list[k];
  list.pop();
}
