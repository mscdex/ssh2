var inherits = require('util').inherits,
    DuplexStream = require('stream').Duplex
                   || require('readable-stream').Duplex,
    ReadableStream = require('stream').Readable
                     || require('readable-stream').Readable,
    WritableStream = require('stream').Writable
                     || require('readable-stream').Writable;

var STDERR = require('ssh2-streams').constants.CHANNEL_EXTENDED_DATATYPE.STDERR;

var PACKET_SIZE = 32 * 1024,
    MAX_WINDOW = 1 * 1024 * 1024,
    CUSTOM_EVENTS = [
      'CHANNEL_EOF',
      'CHANNEL_CLOSE',
      'CHANNEL_DATA',
      'CHANNEL_EXTENDED_DATA',
      'CHANNEL_WINDOW_ADJUST',
      'CHANNEL_SUCCESS',
      'CHANNEL_FAILURE',
      'CHANNEL_REQUEST'
    ],
    CUSTOM_EVENTS_LEN = CUSTOM_EVENTS.length;

function Channel(info, client, opts) {
  var streamOpts = {
    highWaterMark: MAX_WINDOW,
    allowHalfOpen: (!opts || (opts && opts.allowHalfOpen))
  };

  this.allowHalfOpen = streamOpts.allowHalfOpen;

  DuplexStream.call(this, streamOpts);

  var self = this,
      server = opts && opts.server;

  this.server = server;
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

  this._client = client;
  this._callbacks = [];
  this._hasX11 = false;
  this._hasAgentFwd = false;

  function ondrain() {
    if (self._waitClientDrain) {
      self._waitClientDrain = false;
      if (!self._waitWindow) {
        if (self._chunk)
          self._write(self._chunk, null, self._chunkcb);
        else if (self._chunkcb)
          self._chunkcb();
        else if (self._chunkErr)
          self.stderr._write(self._chunkErr, null, self._chunkcbErr);
        else if (self._chunkcbErr)
          self._chunkcbErr();
      }
    }
  }
  client._sock.on('drain', ondrain);

  client._sshstream.once('CHANNEL_EOF:' + this.incoming.id, function() {
    if (self.incoming.state === 'closed')
      return;
    self.incoming.state = 'eof';

    if (self.readable)
      self.push(null);
    if (server && self.stderr.writable)
      self.stderr.end();
    else if (!server && self.stderr.readable)
      self.stderr.push(null);
  }).once('CHANNEL_CLOSE:' + this.incoming.id, function() {
    self.incoming.state = 'closed';

    if (self.readable)
      self.push(null);
    if (server && self.stderr.writable)
      self.stderr.end();
    else if (!server && self.stderr.readable)
      self.stderr.push(null);

    if (self.outgoing.state === 'open' || self.outgoing.state === 'eof')
      self.close();
    if (self.outgoing.state === 'closing')
      self.outgoing.state = 'closed';

    client._channels.splice(client._channels.indexOf(self.incoming.id), 1);

    var state = self._writableState;
    client._sock.removeListener('drain', ondrain);
    if (!state.ending && !state.finished)
      self.end();

    self.emit('close');
    if (!server)
      self.stderr.emit('close');

    for (var i = 0; i < CUSTOM_EVENTS_LEN; ++i) {
      // Since EventEmitters do not actually *delete* event names in the
      // emitter's event array, we must do this manually so as not to leak
      // our custom, channel-specific event names.
      delete client._sshstream._events[CUSTOM_EVENTS[i] + ':' + self.incoming.id];
    }

    // no need to check for unexpected channel end anymore ...
    self._client.removeListener('close', onClientClose);
  }).on('CHANNEL_DATA:' + this.incoming.id, function(data) {
    self.incoming.window -= data.length;

    if (!self.push(data)) {
      self._waitChanDrain = true;
      return;
    }

    if (self.incoming.window === 0)
      windowAdjust(self);
  }).on('CHANNEL_WINDOW_ADJUST:' + this.incoming.id, function(amt) {
    // the server is allowing us to send `amt` more bytes of data
    self.outgoing.window += amt;

    if (self._waitWindow) {
      self._waitWindow = false;
      if (!self._waitClientDrain) {
        if (self._chunk)
          self._write(self._chunk, null, self._chunkcb);
        else if (self._chunkcb)
          self._chunkcb();
        else if (self._chunkErr)
          self.stderr._write(self._chunkErr, null, self._chunkcbErr);
        else if (self._chunkcbErr)
          self._chunkcbErr();
      }
    }
  }).on('CHANNEL_SUCCESS:' + this.incoming.id, function() {
    if (self._callbacks.length)
      self._callbacks.shift()(false);
  }).on('CHANNEL_FAILURE:' + this.incoming.id, function() {
    if (self._callbacks.length)
      self._callbacks.shift()(true);
  }).on('CHANNEL_REQUEST:' + this.incoming.id, function(info) {
    if (!server) {
      if (info.request === 'exit-status') {
        self.emit('exit', info.code);
        self.close();
        return;
      } else if (info.request === 'exit-signal') {
        self.emit('exit',
                  null,
                  'SIG' + info.signal,
                  info.coredump,
                  info.description,
                  info.lang);
        self.close();
        return;
      }
    }

    // keepalive request? OpenSSH will send one as a channel request if there
    // is a channel open

    if (info.wantReply)
      self._client._sshstream.channelFailure(self.outgoing.id);
  });

  this.stdin = this.stdout = this;

  if (server)
    this.stderr = new ServerStderr(this);
  else {
    this.stderr = new ReadableStream(streamOpts);
    this.stderr._read = function(n) {
      if (self._waitChanDrain) {
        self._waitChanDrain = false;
        if (self.incoming.window === 0)
          windowAdjust(self);
      }
    };

    client._sshstream.on('CHANNEL_EXTENDED_DATA:' + this.incoming.id,
      function(type, data) {
        self.incoming.window -= data.length;

        if (!self.stderr.push(data)) {
          self._waitChanDrain = true;
          return;
        }

        if (self.incoming.window === 0)
          windowAdjust(self);
      }
    );
  }

  // outgoing data
  this._waitClientDrain = false; // Client stream-level backpressure
  this._waitWindow = false; // SSH-level backpressure

  // incoming data
  this._waitChanDrain = false; // Channel Readable side backpressure

  this._chunk = undefined;
  this._chunkcb = undefined;
  this._chunkErr = undefined;
  this._chunkcbErr = undefined;

  function onFinish() {
    self.eof();
    if (server || (!server && !self.allowHalfOpen))
      self.close();
  }
  this.on('finish', onFinish)
      .on('prefinish', onFinish); // for node v0.11+

  function onClientClose() {
    if (self.readable) {
      self.push(null);
      self.once('end', function() {
        process.nextTick(function() {
          self.emit('close');
        });
      });
    }
    if (!server && self.stderr.readable) {
      self.stderr.push(null);
      self.stderr.once('end', function() {
        process.nextTick(function() {
          self.stderr.emit('close');
        });
      });
    }
    if (self.writable)
      self.end();
    if (server && self.stderr.writable)
      self.stderr.end();
  }
  this._client.once('close', onClientClose);
}
inherits(Channel, DuplexStream);

Channel.prototype.eof = function() {
  var ret = true;

  if (this.outgoing.state === 'open') {
    this.outgoing.state = 'eof';
    ret = this._client._sshstream.channelEOF(this.outgoing.id);
  }

  return ret;
};

Channel.prototype.close = function() {
  var ret = true;

  if (this.outgoing.state === 'open' || this.outgoing.state === 'eof') {
    this.outgoing.state = 'closing';
    ret = this._client._sshstream.channelClose(this.outgoing.id);
  }

  return ret;
};

Channel.prototype._read = function(n) {
  if (this._waitChanDrain) {
    this._waitChanDrain = false;
    if (this.incoming.window === 0)
      windowAdjust(this);
  }
};

Channel.prototype._write = function(data, encoding, cb) {
  var sshstream = this._client._sshstream,
      len = data.length,
      p = 0,
      ret,
      buf,
      sliceLen;

  while (len - p > 0 && this.outgoing.window > 0) {
    sliceLen = len - p;
    if (sliceLen > this.outgoing.window)
      sliceLen = this.outgoing.window;
    if (sliceLen > this.outgoing.packetSize)
      sliceLen = this.outgoing.packetSize;

    ret = sshstream.channelData(this.outgoing.id, data.slice(p, p + sliceLen));

    p += sliceLen;
    this.outgoing.window -= sliceLen;

    if (!ret) {
      this._waitClientDrain = true;
      this._chunk = undefined;
      this._chunkcb = cb;
      break;
    }
  }

  if (len - p > 0) {
    if (this.outgoing.window === 0)
      this._waitWindow = true;
    if (p > 0) {
      // partial
      buf = new Buffer(len - p);
      data.copy(buf, 0, p);
      this._chunk = buf;
    } else
      this._chunk = data;
    this._chunkcb = cb;
    return;
  }

  if (!this._waitClientDrain)
    cb();
};

Channel.prototype.destroy = function() {
  this.end();
};

// session type-specific methods
Channel.prototype.setWindow = function(rows, cols, height, width) {
  if (this.server)
    throw new Error('Client-only method called in server mode');

  if (this.type === 'session' && this.subtype === 'shell' && this.writable) {
    return this._client._sshstream.windowChange(this.outgoing.id,
                                                rows,
                                                cols,
                                                height,
                                                width);
  }

  return true;
};
Channel.prototype.signal = function(signalName) {
  if (this.server)
    throw new Error('Client-only method called in server mode');

  if (this.type === 'session'
      && (this.subtype === 'shell' || this.subtype === 'exec')
      && this.writable)
    return this._client._sshstream.signal(this.outgoing.id, signalName);

  return true;
};
Channel.prototype.exit = function(name, coreDumped, msg) {
  if (!this.server)
    throw new Error('Server-only method called in client mode');

  if (this.type === 'session' && this.subtype === 'exec' && this.writable) {
    if (typeof name === 'number')
      return this._client._sshstream.exitStatus(this.outgoing.id, name);
    else {
      return this._client._sshstream.exitSignal(this.outgoing.id,
                                                name,
                                                coreDumped,
                                                msg);
    }
  }

  return true;
};

Channel.MAX_WINDOW = MAX_WINDOW;
Channel.PACKET_SIZE = PACKET_SIZE;

function windowAdjust(self, amt) {
  amt = amt || MAX_WINDOW;
  return self._client._sshstream.channelWindowAdjust(self.outgoing.id, amt);
}

function ServerStderr(channel) {
  WritableStream.call(this, { highWaterMark: MAX_WINDOW });
  this._channel = channel;
}
inherits(ServerStderr, WritableStream);

ServerStderr.prototype._write = function(data, encoding, cb) {
  var channel = this._channel,
      sshstream = channel._client._sshstream,
      len = data.length,
      p = 0,
      ret,
      buf,
      sliceLen;

  while (len - p > 0 && channel.outgoing.window > 0) {
    sliceLen = len - p;
    if (sliceLen > channel.outgoing.window)
      sliceLen = channel.outgoing.window;
    if (sliceLen > channel.outgoing.packetSize)
      sliceLen = channel.outgoing.packetSize;

    ret = sshstream.channelExtData(channel.outgoing.id,
                                   data.slice(p, p + sliceLen),
                                   STDERR);

    p += sliceLen;
    channel.outgoing.window -= sliceLen;

    if (!ret) {
      channel._waitClientDrain = true;
      channel._chunkErr = undefined;
      channel._chunkcbErr = cb;
      break;
    }
  }

  if (len - p > 0) {
    if (channel.outgoing.window === 0)
      channel._waitWindow = true;
    if (p > 0) {
      // partial
      buf = new Buffer(len - p);
      data.copy(buf, 0, p);
      channel._chunkErr = buf;
    } else
      channel._chunkErr = data;
    channel._chunkcbErr = cb;
    return;
  }

  if (!channel._waitClientDrain)
    cb();
};

module.exports = Channel;
