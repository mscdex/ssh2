var inherits = require('util').inherits,
    EventEmitter = require('events').EventEmitter;

var consts = require('./Parser.constants');

for (var i=0,keys=Object.keys(consts),len=keys.length; i<len; ++i)
  global[keys[i]] = consts[keys[i]];

var MAX_WINDOW = Math.pow(2, 32) - 1;

function Channel(info, conn) {
  EventEmitter.call(this);

  var self = this;

  this.type = info.type;
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
    self._stream.emit('end');
  });

  conn._parser.on('CHANNEL_CLOSE:' + this.incoming.id, function() {
    this.incoming.state = 'closed';
    if (self.outgoing.state !== 'closed') {
      self.close();
      self._conn.channels.splice(self._conn.channels.indexOf(self.incoming.id), 1);
      var stream = self._stream;
      self._stream = undefined;
      stream.emit('close');
    }
  });

  conn._parser.on('CHANNEL_DATA:' + this.incoming.id, function(data) {
    self._stream.emit('data', data);
  });

  conn._parser.on('CHANNEL_EXTENDED_DATA:' + this.incoming.id,
    function(type, data) {
      type = CHANNEL_EXTENDED_DATATYPE[type].toLowerCase();
      self._stream.emit('data', data, type);
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
    var err;
    if (info.request === 'exit-status')
      self._stream.emit('exit', info.code);
    else if (info.request === 'exit-signal') {
      self._stream.emit('exit', null, 'SIG' + info.signal, info.coredump,
                        info.description, info.lang);
    } else
      return;
    self.close();
  });

  conn.on('_reexchg', function() {
    self._processQueue();
  });
}

Channel.prototype.eof = function(go) {
  if (!this._conn._sock.writable)
    return false;
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
    return false;
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

Channel.prototype._sendExec = function(cmd, cb, go) {
  if (!this._conn._sock.writable)
    return false;
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

  this._stream = new EventEmitter();
  cb(undefined, this._stream);

  this._conn._send(buf);

  return true;
};

Channel.prototype._sendEnv = function(env, go) {
  if (!this._conn._sock.writable)
    return false;
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
    return false;
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
    this._conn._send(buf);
  }
  return true;
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
    var paramLen, req;
    while (this._queue.length) {
      req = this._queue.shift();
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
  }
};

Channel.MAX_WINDOW = MAX_WINDOW;

module.exports = Channel;
