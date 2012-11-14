
Description
===========

An SSH2 client module written in pure JavaScript for [node.js](http://nodejs.org/).

Development/testing is done against OpenSSH (6.0 currently).


Requirements
============

* [node.js](http://nodejs.org/) -- v0.8.3 or newer


Install
============

    npm install ssh2


Examples
========

* Authenticate using keys, execute `uptime` on a server, and disconnect afterwards:

```javascript
var Connection = require('ssh2');

var c = new Connection();
c.on('connect', function() {
  console.log('Connection :: connect');
});
c.on('ready', function() {
  console.log('Connection :: ready');
  c.exec('uptime', function(err, stream) {
    if (err)
      throw err;
    stream.on('data', function(data, extended) {
      console.log((extended === 'stderr' ? 'STDERR: ' : 'STDOUT: ')
                  + data);
    });
    stream.on('end', function() {
      console.log('Stream :: EOF');
    });
    stream.on('close', function() {
      console.log('Stream :: close');
    });
    stream.on('exit', function(code, signal) {
      console.log('Stream :: exit :: code: ' + code + ', signal: ' + signal);
      c.end();
    });
  });
});
c.on('error', function(err) {
  console.log('Connection :: error :: ' + err);
});
c.on('end', function() {
  console.log('Connection :: end');
});
c.on('close', function(had_error) {
  console.log('Connection :: close');
});
c.connect({
  host: '192.168.100.100',
  port: 22,
  username: 'frylock',
  privateKey: require('fs').readFileSync('/here/is/my/key'),
  publicKey: require('fs').readFileSync('/here/is/my/key.pub')
});

// example output:
// Connection :: connect
// Connection :: ready
// STDOUT:  17:41:15 up 22 days, 18:09,  1 user,  load average: 0.00, 0.01, 0.05
//
// Stream :: exit :: code: 0, signal: undefined
// Connection :: end
// Connection :: close
```


API
===

`require('ssh2')` returns a **_Connection_** object

Connection events
-----------------

* **connect**() - A connection to the server was successful.

* **ready**() - Authentication was successful.

* **keyboard-interactive**(< _string_ >name, < _string_ >instructions, < _string_ >instructionsLang, < _array_ >prompts, < _function_ >finish) - The server is asking for replies to the given `prompts` for keyboard-interactive user authentication. `name` is generally what you'd use as a window title (for GUI apps). `prompts` is an array of `{ prompt: 'Password: ', echo: false }` style objects (here `echo` indicates whether user input should be displayed on the screen). The answers for all prompts must be provided as an array of strings and passed to `finish` when you are ready to continue. Note: It's possible for the server to come back and ask more questions.

* **error**(< _Error_ >err) - An error occurred. A 'level' property indicates 'connection-socket' for socket-level errors and 'connection-ssh' for SSH disconnection messages. In the case of 'connection-ssh' messages, there may be a 'description' property that provides more detail.

* **end**() - The socket was disconnected.

* **close**(< _boolean_ >hadError) - The socket was closed. `hadError` is set to true if this was due to error.


Connection methods
------------------

* **(constructor)**() - Creates and returns a new Connection instance.

* **connect**(< _object_ >config) - _(void)_ - Attempts a connection to a server using the information given in `config`:

    * **user** - < _string_ > - Username for authentication. **Default:** (none)

    * **password** - < _string_ > - Password for password-based user authentication. **Default:** (none)

    * **host** - < _string_ > - Hostname or IP address of the server. **Default:** ("127.0.0.1")

    * **port** - < _integer_ > - Port number of the server. **Default:** 22

    * **privateKey** - < _mixed_ > - Buffer or string that contains an **unencrypted** private key for key-based user authentication (OpenSSH format). **Default:** (none)

    * **passphrase** - < _string_ > - For an encrypted private key, this is the passphrase used to decrypt it. **Default:** (none)
    
    * **publicKey** - < _mixed_ > - Buffer or string that contains a public key for key-based user authentication (OpenSSH format). **Default:** (none)

    * **tryKeyboard** - < _boolean_ > - Try keyboard-interactive user authentication if primary user authentication method fails. **Default:** (false)

* **exec**(< _string_ >command[, < _object_ >environment], < _function_ >callback]]) - _(void)_ - Executes `command` on the server, with an optional `environment` set before execution. `callback` has 2 parameters: < _Error_ >err, < _ChannelStream_ >stream. For exec, the `stream` will also emit 'exit' when the process finishes. If the process finished normally, the process return value is passed to the 'exit' callback. If the process was interrupted by a signal, the following are passed to the 'exit' callback: < _null_ >code, < _string_ >signalName, < _boolean_ >didCoreDump, < _string_ >description.

* **shell**([< _object_ >window,] < _function_ >callback]]) - _(void)_ - Starts an interactive shell session on the server, with optional terminal `window` settings. Valid `window` properties include: rows (defaults to 24), cols (defaults to 80), height (in pixels, defaults to 480), width (in pixels, defaults to 640), and term (value to use for $TERM, defaults to 'vt100'). Rows and cols overrides width and height when rows and cols are non-zero. Pixel dimensions refer to the drawable area of the window. Zero dimension parameters are ignored. `callback` has 2 parameters: < _Error_ >err, < _ChannelStream_ >stream.

* **end**() - _(void)_ - Disconnects the connection.



ChannelStream
-------------

This is a normal duplex Stream, with the following changes:

* 'data' events are passed a second (string) argument to the callback, which indicates whether the data is a special type. So far the only defined type is 'stderr'.

* A boolean property 'allowHalfOpen' exists and behaves similarly to the property of the same name for net.Socket. When the stream's end() is called, if 'allowHalfOpen' is true, only EOF will be sent (the server can still send data if they have not already sent EOF). The default value for this property is `false`.

* For shell(), an extra function is available:

    * **setWindow**(< _integer_ >rows, < _integer_ >cols, < _integer_ >height, < _integer_ >width) - _(void)_ - Lets the server know that the local terminal window has been resized. The behavior of these arguments is the same as described for shell().

* For shell() and exec(), an extra function is available:

    * **signal**(< _string_ >signalName) - _(void)_ - Sends a POSIX signal to the current process on the server. Valid signal names are: 'ABRT', 'ALRM', 'FPE', 'HUP', 'ILL', 'INT', 'KILL', 'PIPE', 'QUIT', 'SEGV', 'TERM', 'USR1', and 'USR2'. Also, from the RFC: "Some systems may not implement signals, in which case they SHOULD ignore this message."
