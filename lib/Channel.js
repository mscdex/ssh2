var inherits = require('util').inherits,
    EventEmitter = require('events').EventEmitter,
    Stream = require('stream');

var consts = require('./Parser.constants');

var MAX_WINDOW = Math.pow(2, 32) - 1,
    SIGNALS = ['ABRT', 'ALRM', 'FPE', 'HUP', 'ILL', 'INT', 'KILL', 'PIPE',
               'QUIT', 'SEGV', 'TERM', 'USR1', 'USR2'],
    MESSAGE = consts.MESSAGE,
    CHANNEL_EXTENDED_DATATYPE = consts.CHANNEL_EXTENDED_DATATYPE,
    TERMINAL_MODE = consts.TERMINAL_MODE;

function Channel(info, conn) {
  EventEmitter.call(this);

  var self = this;

  this.type = info.type;
  this.subtype = undefined;
  /*
    incoming and outgoing contain these properties:
    {
      id: undefined,
      window: undefined,
      packetSize: undefined,
      state: 'closed'
    }
  */
  this.incoming = info.incoming;
  this.outgoing = info.outgoing;

  this._conn = conn;
  this._stream = undefined;
  this._callbacks = [];
  this._queue = []; // for buffering outoing messages during key (re-)exchanges

  conn._parser.on('CHANNEL_EOF:' + this.incoming.id, function() {
    this.incoming.state = 'eof';
    if (self._stream)
      self._stream.emit('end');
  });

  conn._parser.on('CHANNEL_CLOSE:' + this.incoming.id, function() {
    this.incoming.state = 'closed';
    if (self.outgoing.state !== 'closed') {
      self.close();
      self._conn.channels.splice(self._conn.channels.indexOf(self.incoming.id), 1);
      if (self._stream) {
        var stream = self._stream;
        self._stream = undefined;
        stream.emit('close');
      }
    }
  });

  conn._parser.on('CHANNEL_DATA:' + this.incoming.id, function(data) {
    if (self._stream) {
      if (self._stream._decoder)
        data = self._stream._decoder.write(data);
      self._stream.emit('data', data);
    }
  });

  conn._parser.on('CHANNEL_EXTENDED_DATA:' + this.incoming.id,
    function(type, data) {
      if (self._stream) {
        if (self._stream._decoder)
          data = self._stream._decoder.write(data);
        type = CHANNEL_EXTENDED_DATATYPE[type].toLowerCase();
        self._stream.emit('data', data, type);
      }
    }
  );

  conn._parser.on('CHANNEL_SUCCESS:' + this.incoming.id, function() {
    if (self._callbacks.length)
      self._callbacks.shift()(false);
  });

  conn._parser.on('CHANNEL_FAILURE:' + this.incoming.id, function() {
    if (self._callbacks.length)
      self._callbacks.shift()(true);
  });

  conn._parser.on('CHANNEL_REQUEST:' + this.incoming.id, function(info) {
    if (self._stream) {
      if (info.request === 'exit-status')
        self._stream.emit('exit', info.code);
      else if (info.request === 'exit-signal') {
        self._stream.emit('exit', null, 'SIG' + info.signal, info.coredump,
                          info.description, info.lang);
      } else
        return;
      self.close();
    }
  });

  conn.on('_reexchg', function() {
    self._processQueue();
  });
}

Channel.prototype.eof = function(go) {
  if (!this._conn._sock.writable)
    return null;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['eof']);
    return false;
  }
  if (this._conn._sock.writable && this.outgoing.state === 'open') {
    // Note: CHANNEL_EOF does not consume window space
    /*
      byte      SSH_MSG_CHANNEL_EOF
      uint32    recipient channel
    */
    var buf = new Buffer(1 + 4);
    this.outgoing.state = 'EOF';
    buf[0] = MESSAGE.CHANNEL_EOF;
    buf.writeUInt32BE(this.outgoing.id, 1, true);
    this._conn._send(buf);
    return true;
  } else
    return false;
};

Channel.prototype.close = function(go) {
  if (!this._conn._sock.writable)
    return null;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['close']);
    return false;
  }
  if (this.outgoing.state !== 'closed') {
    // Note: CHANNEL_CLOSE does not consume window space
    /*
      byte      SSH_MSG_CHANNEL_CLOSE
      uint32    recipient channel
    */
    var buf = new Buffer(1 + 4);
    buf[0] = MESSAGE.CHANNEL_CLOSE;
    buf.writeUInt32BE(this.outgoing.id, 1, true);
    this.outgoing.state = 'closed';
    this._conn._send(buf);
    return true;
  } else
    return false;
};

Channel.prototype._sendTermSizeChg = function(rows, cols, height, width, go) {
  if (!this._conn._sock.writable)
    return null;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['_sendTermSizeChg', rows, cols, height, width]);
    return false;
  }
  // Note: CHANNEL_REQUEST does not consume window space
  /*
    byte      SSH_MSG_CHANNEL_REQUEST
    uint32    recipient channel
    string    "window-change"
    boolean   FALSE
    uint32    terminal width, columns
    uint32    terminal height, rows
    uint32    terminal width, pixels
    uint32    terminal height, pixels
  */
  var buf = new Buffer(1 + 4 + 4 + 13 + 1 + 4 + 4 + 4 + 4);
  buf[0] = MESSAGE.CHANNEL_REQUEST;
  buf.writeUInt32BE(this.outgoing.id, 1, true);
  buf.writeUInt32BE(13, 5, true);
  buf.write('window-change', 9, 13, 'ascii');
  buf[22] = 0;
  buf.writeUInt32BE(cols, 23, true);
  buf.writeUInt32BE(rows, 27, true);
  buf.writeUInt32BE(width, 31, true);
  buf.writeUInt32BE(height, 35, true);

  this._conn._send(buf);

  return true;
};

Channel.prototype._sendPtyReq = function(rows, cols, height, width, term, modes,
                                         cb, go) {
  if (!this._conn._sock.writable)
    return null;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['_sendPtyReq', rows, cols, height, width, term, modes, cb]);
    return false;
  }
  // Note: CHANNEL_REQUEST does not consume window space
  /*
    byte      SSH_MSG_CHANNEL_REQUEST
    uint32    recipient channel
    string    "pty-req"
    boolean   want_reply
    string    TERM environment variable value (e.g., vt100)
    uint32    terminal width, characters (e.g., 80)
    uint32    terminal height, rows (e.g., 24)
    uint32    terminal width, pixels (e.g., 640)
    uint32    terminal height, pixels (e.g., 480)
    string    encoded terminal modes
  */
  if (!term || !term.length)
    term = 'vt100';
  if (!modes || !modes.length)
    modes = String.fromCharCode(TERMINAL_MODE.TTY_OP_END);
  var termLen = term.length,
      modesLen = modes.length,
      p = 21,
      buf = new Buffer(1 + 4 + 4 + 7 + 1 + 4 + termLen + 4 + 4 + 4 + 4 + 4
                       + modesLen);
  buf[0] = MESSAGE.CHANNEL_REQUEST;
  buf.writeUInt32BE(this.outgoing.id, 1, true);
  buf.writeUInt32BE(7, 5, true);
  buf.write('pty-req', 9, 7, 'ascii');
  buf[16] = 1;
  buf.writeUInt32BE(termLen, 17, true);
  buf.write(term, 21, termLen, 'utf8');
  buf.writeUInt32BE(cols, p += termLen, true);
  buf.writeUInt32BE(rows, p += 4, true);
  buf.writeUInt32BE(width, p += 4, true);
  buf.writeUInt32BE(height, p += 4, true);
  buf.writeUInt32BE(modesLen, p += 4, true);
  buf.write(modes, p += 4, modesLen, 'utf8');

  this._callbacks.push(function(had_err) {
    if (had_err)
      cb(new Error('Error: Unable to request a pseudo-terminal'));
    else
      cb();
  });

  this._conn._send(buf);

  return true;
};

Channel.prototype._sendShell = function(cb, go) {
  if (!this._conn._sock.writable)
    return null;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['_sendShell', cb]);
    return false;
  }
  // Note: CHANNEL_REQUEST does not consume window space
  /*
    byte      SSH_MSG_CHANNEL_REQUEST
    uint32    recipient channel
    string    "shell"
    boolean   want reply
  */
  var self = this;
  var buf = new Buffer(1 + 4 + 4 + 5 + 1);
  buf[0] = MESSAGE.CHANNEL_REQUEST;
  buf.writeUInt32BE(this.outgoing.id, 1, true);
  buf.writeUInt32BE(5, 5, true);
  buf.write('shell', 9, 5, 'ascii');
  buf[14] = 1;

  this._stream = new ChannelStream(this);
  cb(undefined, this._stream);

  this._callbacks.push(function(had_err) {
    if (had_err) {
      var stream = self._stream;
      self._stream = undefined;
      stream.emit('error', new Error('Error: Unable to open shell'));
      stream.emit('close', true);
    } else
      self.subtype = 'shell';
  });

  this._conn._send(buf);

  return true;
};

Channel.prototype._sendExec = function(cmd, cb, go) {
  if (!this._conn._sock.writable)
    return null;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['_sendExec', cmd, cb]);
    return false;
  }
  // Note: CHANNEL_REQUEST does not consume window space
  /*
    byte      SSH_MSG_CHANNEL_REQUEST
    uint32    recipient channel
    string    "exec"
    boolean   want reply
    string    command
  */
  var self = this;
  var cmdlen = (Buffer.isBuffer(cmd) ? cmd.length : Buffer.byteLength(cmd)),
      buf = new Buffer(1 + 4 + 4 + 4 + 1 + 4 + cmdlen);
  buf[0] = MESSAGE.CHANNEL_REQUEST;
  buf.writeUInt32BE(this.outgoing.id, 1, true);
  buf.writeUInt32BE(4, 5, true);
  buf.write('exec', 9, 4, 'ascii');
  buf[13] = 0;
  buf.writeUInt32BE(cmdlen, 14, true);
  if (Buffer.isBuffer(cmd))
    cmd.copy(buf, 18);
  else
    buf.write(cmd, 18, cmdlen, 'utf8');

  this._stream = new ChannelStream(this);
  cb(undefined, this._stream);
  this.subtype = 'exec';

  this._conn._send(buf);

  return true;
};

Channel.prototype._sendSignal = function(signal, go) {
  if (!this._conn._sock.writable)
    return null;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['_sendSignal', signal]);
    return false;
  }
  // Note: CHANNEL_REQUEST does not consume window space
  /*
    byte      SSH_MSG_CHANNEL_REQUEST
    uint32    recipient channel
    string    "signal"
    boolean   FALSE
    string    signal name (without the "SIG" prefix)
  */
  signal = signal.toUpperCase();
  if (signal.length >= 3
      && signal[0] === 'S' && signal[1] === 'I' && signal[2] === 'G')
    signal = signal.substr(3);
  if (SIGNALS.indexOf(signal) === -1)
    throw new Error('Invalid signal: ' + signal);
  var signalLen = signal.length,
      buf = new Buffer(1 + 4 + 4 + 6 + 1 + 4 + signalLen);
  buf[0] = MESSAGE.CHANNEL_REQUEST;
  buf.writeUInt32BE(this.outgoing.id, 1, true);
  buf.writeUInt32BE(6, 5, true);
  buf.write('signal', 9, 6, 'ascii');
  buf[15] = 0;
  buf.writeUInt32BE(signalLen, 16, true);
  buf.write(signal, 20, signalLen, 'ascii');

  this._conn._send(buf);

  return true;
};

Channel.prototype._sendEnv = function(env, go) {
  if (!this._conn._sock.writable)
    return null;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['_sendEnv', env]);
    return false;
  }
  var keys, buf;
  if (env && (keys = Object.keys(env)).length > 0) {
    // Note: CHANNEL_REQUEST does not consume window space
    /*
      byte      SSH_MSG_CHANNEL_REQUEST
      uint32    recipient channel
      string    "env"
      boolean   want reply
      string    variable name
      string    variable value
    */
    for (var i = 0, klen, vlen, len = keys.length; i < len; ++i) {
      klen = Buffer.byteLength(keys[i]);
      if (Buffer.isBuffer(env[keys[i]]))
        vlen = env[keys[i]].length;
      else
        vlen = Buffer.byteLength(env[keys[i]]);
      buf = new Buffer(1 + 4 + 4 + 3 + 1 + 4 + klen + 4 + vlen);
      buf[0] = MESSAGE.CHANNEL_REQUEST;
      buf.writeUInt32BE(this.outgoing.id, 1, true);
      buf.writeUInt32BE(3, 5, true);
      buf.write('env', 9, 3, 'ascii');
      buf[13] = 0;
      buf.writeUInt32BE(klen, 14, true);
      buf.write(keys[i], 18, klen, 'ascii');
      buf.writeUInt32BE(vlen, 18 + klen, true);
      if (Buffer.isBuffer(env[keys[i]]))
        env[keys[i]].copy(buf, 18 + klen + 4);
      else
        buf.write(env[keys[i]], 18 + klen + 4, vlen, 'utf8');
      this._conn._send(buf);
    }
    return true;
  } else
    return false;
};

Channel.prototype._sendData = function(data, extendedType, go) {
  if (!this._conn._sock.writable)
    return null;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['_sendData', data, extendedType]);
    return false;
  }
  var len = data.length, p = 0, buf, sliceLen;
  while (len - p > 0) {
    if (this.outgoing.window === 0)
      this._sendWndAdjust();
    sliceLen = (len - p < this.outgoing.window ? len - p : this.outgoing.window);
    if (extendedType === undefined) {
      /*
        byte      SSH_MSG_CHANNEL_DATA
        uint32    recipient channel
        string    data
      */
      buf = new Buffer(1 + 4 + 4 + sliceLen);
      buf[0] = MESSAGE.CHANNEL_DATA;
      buf.writeUInt32BE(this.outgoing.id, 1, true);
      buf.writeUInt32BE(sliceLen, 5, true);
      data.copy(buf, 9, p, p + sliceLen);
    } else {
      /*
        byte      SSH_MSG_CHANNEL_EXTENDED_DATA
        uint32    recipient channel
        uint32    data_type_code
        string    data
      */
      buf = new Buffer(1 + 4 + 4 + 4 + sliceLen);
      buf[0] = MESSAGE.CHANNEL_EXTENDED_DATA;
      buf.writeUInt32BE(this.outgoing.id, 1, true);
      buf.writeUInt32BE(extendedType, 5, true);
      buf.writeUInt32BE(sliceLen, 9, true);
      data.copy(buf, 13, p, p + sliceLen);
    }
    p += sliceLen;
    this.outgoing.window -= sliceLen;

    return this._conn._send(buf);
  }
};

Channel.prototype._sendWndAdjust = function(amt, go) {
  if (!this._conn._sock.writable)
    return false;
  else if (!go && this._conn._state !== 'authenticated') {
    this._enqueue(['_sendWndAdjust', amt]);
    return false;
  }
  /*
    byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
    uint32    recipient channel
    uint32    bytes to add
  */
  amt = amt || Math.min(MAX_WINDOW, this.outgoing.packetSize);
  var buf = new Buffer(1 + 4 + 4);
  buf[0] = MESSAGE.CHANNEL_WINDOW_ADJUST;
  buf.writeUInt32BE(this.outgoing.id, 1, true);
  buf.writeUInt32BE(amt, 5, true);

  this._conn._send(buf);
  this.outgoing.window += amt;

  return true;
};

Channel.prototype._processQueue = function() {
  if (!this._conn._sock.writable) {
    this._queue = [];
    return;
  }
  if (this._conn._state === 'authenticated') {
    var paramLen, req, sentData = false;
    while (this._queue.length) {
      req = this._queue.shift();
      if (req[0] === '_sendData')
        sentData = true;
      paramLen = req.length - 1;
      if (paramLen === 0)
        this[req[0]](true);
      else if (paramLen === 1)
        this[req[0]](req[1], true);
      else if (paramLen === 2)
        this[req[0]](req[1], req[2], true);
      else if (paramLen === 3) {
        this[req[0]](req[1], req[2], req[3], true);
      } else {
        var args = req.slice(1);
        args.push(true);
        this[req[0]].apply(this, args);
      }
    }
    if (sentData && this._stream)
      this._stream.emit('drain');
  }
};

Channel.MAX_WINDOW = MAX_WINDOW;

module.exports = Channel;



function ChannelStream(channel) {
  var self = this;
  this.readable = true;
  this.writable = true;
  this.paused = false;
  this._channel = channel;
  this._buffer = [];
  this._decoder = undefined;

  channel._conn._sock.on('drain', function() {
    self.emit('drain');
  });
}
inherits(ChannelStream, Stream);

ChannelStream.prototype.write = function(data, encoding, extended) {
  var extendedType;
  if (Buffer.isBuffer(data)) {
    extended = encoding;
    if (typeof extended === 'string') {
      extendedType = CHANNEL_EXTENDED_DATATYPE[extended.toUpperCase()];
      if (extendedType === undefined)
        throw new Error('Error: Invalid extended data type specified: '
                        + extended);
      extended = extendedType;
    } else if (extended && typeof extended !== 'number')
      throw new Error('Error: Unexpected extended type: ' + extended);

    if (this.paused) {
      this._buffer.push([data, extended]);
      return true;
    } else {
      if (extended)
        return this._channel._sendData(data);
      else
        return this._channel._sendData(data, extended);
    }
  } else if (typeof data === 'string') {
    encoding = encoding || 'utf8';
    data = new Buffer(data, encoding);
    if (typeof extended === 'string') {
      extendedType = CHANNEL_EXTENDED_DATATYPE[extended.toUpperCase()];
      if (extendedType === undefined)
        throw new Error('Error: Invalid extended data type specified: '
                        + extended);
      extended = extendedType;
    } else if (extended && typeof extended !== 'number')
      throw new Error('Error: Unexpected extended type: ' + extended);

    if (this.paused) {
      this._buffer.push([data, extended]);
      return true;
    } else {
      if (extended)
        return this._channel._sendData(data);
      else
        return this._channel._sendData(data, extended);
    }
  } else
    throw new Error('Error: Unexpected data type: ' + typeof data);
};

ChannelStream.prototype.pause = function() {
  this.paused = true;
};

ChannelStream.prototype.resume = function() {
  this.paused = false;
  var i = 0, len = this._buffer.length, sentData = false;

  for (; i < len; ++i) {
    if (this._buffer[i] === null) {
      this._channel.eof();
      this._channel.close();
      break;
    } else {
      sentData = true;
      this._channel._sendData(this._buffer[i][0], this._buffer[i][1]);
    }
  }

  if (len)
    this._buffer = [];

  // only emit drain immediately if we are not in a key re-exchange because
  // processQueues() will emit drain for us after key re-exchange finishes
  if (this._channel._conn._state === 'authenticated')
    this.emit('drain');
};

ChannelStream.prototype.end = function(data, encoding, extended) {
  if (data)
    this.write(data, encoding, extended);
  if (this.paused) {
    this._buffer.push(null);
    this.resume();
  } else {
    this._channel.eof();
    this._channel.close();
  }
};

ChannelStream.prototype.destroy = function() {
  this._channel.eof();
  this._channel.close();
  this._buffer = [];
};

ChannelStream.prototype.setEncoding = function(encoding) {
  var StringDecoder = require('string_decoder').StringDecoder; // lazy load
  this._decoder = new StringDecoder(encoding);
};

// session type-specific methods

ChannelStream.prototype.setWindow = function(rows, cols, height, width) {
  if (this._channel.type === 'session' && this._channel.subtype === 'shell')
    return this._channel._sendTermSizeChg(rows, cols, height, width);
  return null;
};

ChannelStream.prototype.signal = function(signalName) {
  if (this._channel.type === 'session'
      && (this._channel.subtype === 'shell' || this._channel.subtype === 'exec'))
    return this._channel._sendSignal(signalName);
  return null;
};