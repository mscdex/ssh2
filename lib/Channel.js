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
  this.incoming = info.incoming;
  this.outgoing = info.outgoing;

  this._conn = conn;
  this._stream = new EventEmitter();
  this._buffer = [];

  conn._parser.on('CHANNEL_EOF:' + this.outgoing.id, function() {
    self._stream.emit('end');
  });

  conn._parser.on('CHANNEL_CLOSE:' + this.outgoing.id, function() {
    if (self.outgoing.state !== 'closed')
      self.close();
    self._stream.emit('close');
  });

  conn._parser.on('CHANNEL_DATA:' + this.outgoing.id, function(data) {
    self._stream.emit('data', data);
  });

  conn._parser.on('CHANNEL_EXTENDED_DATA:' + this.outgoing.id,
    function(type, data) {
      type = CHANNEL_EXTENDED_DATATYPE[type].toLowerCase();
      self._stream.emit('data', data, type);
    }
  );

  conn.on('_reexchg', function() {
    for (var i = 0, len = self._buffer.length; i < len; ++i)
      self._send(self._buffer[i][0], self._buffer[i][1]);
    self._buffer = [];
  });
}

Channel.prototype.eof = function() {
  if (this._conn._sock.writable && this.outgoing.state === 'open') {
    // Note: CHANNEL_EOF does not consume window space
    /*
      byte      SSH_MSG_CHANNEL_EOF
      uint32    recipient channel
    */
    var buf = new Buffer(1 + 4);
    this.outgoing.state = 'EOF';
    buf[0] = MESSAGE.CHANNEL_EOF;
    buf.writeUInt32BE(this.incoming.id, 1, true);
    this._conn._send(buf);
    return true;
  } else
    return false;
};

Channel.prototype.close = function() {
  if (this._conn._sock.writable && this.outgoing.state !== 'closed') {
    // Note: CHANNEL_CLOSE does not consume window space
    /*
      byte      SSH_MSG_CHANNEL_CLOSE
      uint32    recipient channel
    */
    var buf = new Buffer(1 + 4);
    buf[0] = MESSAGE.CHANNEL_CLOSE;
    buf.writeUInt32BE(this.remote, 1, true);
    this.outgoing.state = 'closed';
    this._conn._send(buf);
    return true;
  } else
    return false;
};

Channel.prototype._send = function(data, extendedType) {
  if (!this._conn._sock.writable)
    return false;
  else if (this._conn._state !== 'authenticated') {
    this._buffer.push([data, extendedType]);
    return data.length;
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
      buf.writeUInt32BE(this.incoming.id, 1, true);
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
      buf.writeUInt32BE(this.incoming.id, 1, true);
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

Channel.prototype._sendWndAdjust = function(amt) {
  if (!this._conn._sock.writable)
    return false;
  /*
    byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
    uint32    recipient channel
    uint32    bytes to add
  */
  amt = amt || Math.min(MAX_WINDOW, this.outgoing.packetSize);
  var buf = new Buffer(1 + 4 + 4);
  buf[0] = MESSAGE.CHANNEL_WINDOW_ADJUST;
  buf.writeUInt32BE(this.incoming.id, 1, true);
  buf.writeUInt32BE(amt, 5, true);
  this._conn._send(buf);
  this.outgoing.window += amt;

  return true;
};

module.exports = Channel;
