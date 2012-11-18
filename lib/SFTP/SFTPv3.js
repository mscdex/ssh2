var EventEmitter = require('events').EventEmitter,
    inherits = require('util').inherits,
    Stream = require('stream');

var MAX_REQID = Math.pow(2, 32) - 1,
    VERSION_BUFFER = new Buffer([0, 0, 0, 3]),
    EMPTY_CALLBACK = function() {};

function SFTP(stream) {
  var self = this;

  this._stream = stream;
  this._requests = {};
  this._reqid = 0;
  this._reqidmaxed = false;

  this._count = 0;
  this._value = 0;
  this._string = undefined;
  this._field = 'packet_length';
  this._data = { len: 0, type: undefined, subtype: undefined };

  stream.on('data', function(data) {
    self._parse(data);
  });
}
inherits(SFTP, EventEmitter);

SFTP.prototype.open = function(filename, mode, attrs, cb) {

  if (typeof attrs === 'function') {
    cb = attrs;
    attrs = undefined;
  }

  if (mode === 'r')
    mode = OPEN_MODE.READ;
  else if (mode === 'r+')
    mode = OPEN_MODE.READ | OPEN_MODE.WRITE;
  else if (mode === 'w')
    mode = OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.WRITE;
  else if (mode === 'wx' || mode === 'xw')
    mode = OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.WRITE | OPEN_MODE.EXCL;
  else if (mode === 'w+')
    mode = OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE;
  else if (mode === 'wx+' || mode === 'xw+') {
    mode = OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE
           | OPEN_MODE.EXCL;
  } else if (mode === 'a')
    mode = OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.WRITE;
  else if (mode === 'ax' || mode === 'xa')
    mode = OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.WRITE | OPEN_MODE.EXCL;
  else if (mode === 'a+')
    mode = OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE;
  else if (mode === 'ax+' || mode === 'xa+') {
    mode = OPEN_MODE.APPEND | OPEN_MODE.CREAT | OPEN_MODE.READ | OPEN_MODE.WRITE
           | OPEN_MODE.EXCL;
  } else
    throw new Error('Invalid mode');

  var flags = 0, attrBytes = 0;
  if (typeof attrs === 'object') {
    attrs = attrsToBytes(attrs);
    flags = attrs[0];
    attrBytes = attrs[1];
    attrs = attrs[2];
  }

  /*
    uint32        id
    string        filename
    uint32        pflags
    ATTRS         attrs
  */
  var fnamelen = Buffer.byteLength(filename),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + fnamelen + 4 + 4 + attrBytes);
  buf[0] = REQUEST.OPEN;
  buf.writeUInt32BE(fnamelen, p, true);
  buf.write(filename, p += 4, fnamelen, 'utf8');
  buf.writeUInt32BE(mode, p += fnamelen, true);
  buf.writeUInt32BE(flags, p += 4, true);
  if (flags) {
    p += 4;
    for (var i = 0, len = attrs.length; i < len; ++i)
      for (var j = 0, len2 = attrs[i].length; j < len2; ++j)
        buf[p++] = attrs[i][j];
  }

  return this._send(buf, cb);
};

SFTP.prototype.close = function(handle, cb) {
  if (!Buffer.isBuffer(handle))
    throw new Error('handle is not a Buffer');
  /*
    uint32     id
    string     handle
  */
  var handlelen = handle.length,
      p = 5,
      buf = new Buffer(1 + 4 + 4 + handlelen);
  buf[0] = REQUEST.CLOSE;
  buf.writeUInt32BE(handlelen, p, true);
  handle.copy(buf, p += 4);

  return this._send(buf, cb);
};

SFTP.prototype.read = function(handle, buffer, offset, length, position, cb) {
  // TODO: emulate support for position === null to match fs.read()
  if (!Buffer.isBuffer(handle))
    throw new Error('handle is not a Buffer');

  var isStreaming = false;
  if (typeof length === 'function') {
    isStreaming = true;
    cb = length;
    length = buffer;
    position = offset;
  }

  if (!isStreaming) {
    if (!Buffer.isBuffer(buffer))
      throw new Error('buffer is not a Buffer');
    else if (offset >= buffer.length)
      throw new Error('offset is out of bounds');
    else if (offset + length > buffer.length)
      throw new Error('length extends beyond buffer');
  }
  if (position === null)
    throw new Error('null position currently unsupported');
  /*
    uint32     id
    string     handle
    uint64     offset
    uint32     len
  */
  var handlelen = handle.length,
      p = 5,
      buf = new Buffer(1 + 4 + 4 + handlelen + 8 + 4);
  buf[0] = REQUEST.READ;
  buf.writeUInt32BE(handlelen, p, true);
  handle.copy(buf, p += 4);
  p += handlelen;
  for (var i = 7; i >= 0; --i) {
    buf[p + i] = position & 0xFF;
    position /= 256;
  }
  buf.writeUInt32BE(length, p += 8, true);

  if (isStreaming) {
    var stream = new ReadStream(this);
    return this._send(buf, function(err) {
      if (err)
        return cb(err);
      cb(undefined, stream);
    }, stream);
  } else {
    return this._send(buf, function(err, data) {
      if (err)
        return cb(err);
      cb(undefined, data.length, data);
    });
  }
};

SFTP.prototype.write = function(handle, buffer, offset, length, position, cb) {
  // TODO: emulate support for position === null to match fs.write()
  if (!Buffer.isBuffer(handle))
    throw new Error('handle is not a Buffer');
  else if (!Buffer.isBuffer(buffer))
    throw new Error('buffer is not a Buffer');
  else if (offset >= buffer.length)
    throw new Error('offset is out of bounds');
  else if (offset + length > buffer.length)
    throw new Error('length extends beyond buffer');
  else if (position === null)
    throw new Error('null position currently unsupported');

  /*
    uint32     id
    string     handle
    uint64     offset
    string     data
  */
  var handlelen = handle.length,
      p = 5,
      buf = new Buffer(1 + 4 + 4 + handlelen + 8 + 4 + length);
  buf[0] = REQUEST.WRITE;
  buf.writeUInt32BE(handlelen, p, true);
  handle.copy(buf, p += 4);
  p += handlelen;
  for (var i = 7; i >= 0; --i) {
    buf[p + i] = position & 0xFF;
    position /= 256;
  }
  buf.writeUInt32BE(length, p += 8, true);
  buffer.copy(buf, p += 4, offset, offset + length);

  return this._send(buf, cb);
};

SFTP.prototype.unlink = function(filename, cb) {
  /*
    uint32     id
    string     filename
  */
  var fnamelen = Buffer.byteLength(filename),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + fnamelen);
  buf[0] = REQUEST.REMOVE;
  buf.writeUInt32BE(fnamelen, p, true);
  buf.write(filename, p += 4, fnamelen, 'utf8');

  return this._send(buf, cb);
};

SFTP.prototype.rename = function(oldPath, newPath, cb) {
  /*
    uint32     id
    string     oldpath
    string     newpath
  */
  var oldlen = Buffer.byteLength(oldPath),
      newlen = Buffer.byteLength(newPath),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + oldlen + 4 + newlen);
  buf[0] = REQUEST.RENAME;
  buf.writeUInt32BE(oldlen, p, true);
  buf.write(oldPath, p += 4, oldlen, 'utf8');
  buf.writeUInt32BE(newlen, p += oldlen, true);
  buf.write(newPath, p += 4, newlen, 'utf8');

  return this._send(buf, cb);
};

SFTP.prototype.mkdir = function(path, attrs, cb) {
  var flags = 0, attrBytes = 0;
  if (typeof attrs === 'object') {
    attrs = attrsToBytes(attrs);
    flags = attrs[0];
    attrBytes = attrs[1];
    attrs = attrs[2];
  }
  /*
    uint32     id
    string     path
    ATTRS      attrs
  */
  var pathlen = Buffer.byteLength(path),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + pathlen + 4 + attrBytes);
  buf[0] = REQUEST.MKDIR;
  buf.writeUInt32BE(pathlen, p, true);
  buf.write(path, p += 4, pathlen, 'utf8');
  buf.writeUInt32BE(flags, p += pathlen);
  if (flags) {
    p += 4;
    for (var i = 0, len = attrs.length; i < len; ++i)
      for (var j = 0, len2 = attrs[i].length; j < len2; ++j)
        buf[p++] = attrs[i][j];
  }

  return this._send(buf, cb);
};

SFTP.prototype.rmdir = function(path, cb) {
  /*
    uint32     id
    string     path
  */
  var pathlen = Buffer.byteLength(path),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + pathlen);
  buf[0] = REQUEST.RMDIR;
  buf.writeUInt32BE(pathlen, p, true);
  buf.write(path, p += 4, pathlen, 'utf8');

  return this._send(buf, cb);
};

SFTP.prototype.readdir = function(handle, cb) {
  if (!Buffer.isBuffer(handle))
    throw new Error('handle is not a Buffer');
  /*
    uint32     id
    string     handle
  */
  var handlelen = handle.length,
      p = 5,
      buf = new Buffer(1 + 4 + 4 + handlelen);
  buf[0] = REQUEST.READDIR;
  buf.writeUInt32BE(handlelen, p, true);
  handle.copy(buf, p += 4);

  return this._send(buf, cb);
};

SFTP.prototype.fstat = function(handle, cb) {
  if (!Buffer.isBuffer(handle))
    throw new Error('handle is not a Buffer');
  /*
    uint32     id
    string     handle
  */
  var handlelen = handle.length,
      p = 5,
      buf = new Buffer(1 + 4 + 4 + handlelen);
  buf[0] = REQUEST.FSTAT;
  buf.writeUInt32BE(handlelen, p, true);
  handle.copy(buf, p += 4);

  return this._send(buf, cb);
};

SFTP.prototype.stat = function(path, cb) {
  /*
    uint32     id
    string     path
  */
  var pathlen = Buffer.byteLength(path),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + pathlen);
  buf[0] = REQUEST.STAT;
  buf.writeUInt32BE(pathlen, p, true);
  buf.write(path, p += 4, pathlen, 'utf8');

  return this._send(buf, cb);
};

SFTP.prototype.lstat = function(path, cb) {
  /*
    uint32     id
    string     path
  */
  var pathlen = Buffer.byteLength(path),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + pathlen);
  buf[0] = REQUEST.LSTAT;
  buf.writeUInt32BE(pathlen, p, true);
  buf.write(path, p += 4, pathlen, 'utf8');

  return this._send(buf, cb);
};

SFTP.prototype.opendir = function(path, cb) {
  /*
    uint32     id
    string     path
  */
  var pathlen = Buffer.byteLength(path),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + pathlen);
  buf[0] = REQUEST.OPENDIR;
  buf.writeUInt32BE(pathlen, p, true);
  buf.write(path, p += 4, pathlen, 'utf8');

  return this._send(buf, cb);
};

SFTP.prototype.setstat = function(path, attrs, cb) {
  var flags = 0, attrBytes = 0;
  if (typeof attrs === 'object') {
    attrs = attrsToBytes(attrs);
    flags = attrs[0];
    attrBytes = attrs[1];
    attrs = attrs[2];
  }
  /*
    uint32     id
    string     path
    ATTRS      attrs
  */
  var pathlen = Buffer.byteLength(path),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + pathlen + 4 + attrBytes);
  buf[0] = REQUEST.SETSTAT;
  buf.writeUInt32BE(pathlen, p, true);
  buf.write(path, p += 4, pathlen, 'utf8');
  buf.writeUInt32BE(flags, p += pathlen);
  if (flags) {
    p += 4;
    for (var i = 0, len = attrs.length; i < len; ++i)
      for (var j = 0, len2 = attrs[i].length; j < len2; ++j)
        buf[p++] = attrs[i][j];
  }

  return this._send(buf, cb);
};

SFTP.prototype.fsetstat = function(handle, attrs, cb) {
  var flags = 0, attrBytes = 0;

  if (!Buffer.isBuffer(handle))
    throw new Error('handle is not a Buffer');

  if (typeof attrs === 'object') {
    attrs = attrsToBytes(attrs);
    flags = attrs[0];
    attrBytes = attrs[1];
    attrs = attrs[2];
  }
  /*
    uint32     id
    string     handle
    ATTRS      attrs
  */
  var handlelen = Buffer.byteLength(handle),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + handlelen + 4 + attrBytes);
  buf[0] = REQUEST.FSETSTAT;
  buf.writeUInt32BE(handlelen, p, true);
  handle.copy(buf, p += 4);
  buf.writeUInt32BE(flags, p += handlelen);
  if (flags) {
    p += 4;
    for (var i = 0, len = attrs.length; i < len; ++i)
      for (var j = 0, len2 = attrs[i].length; j < len2; ++j)
        buf[p++] = attrs[i][j];
  }

  return this._send(buf, cb);
};

SFTP.prototype.readlink = function(path, cb) {
  /*
    uint32     id
    string     path
  */
  var pathlen = Buffer.byteLength(path),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + pathlen);
  buf[0] = REQUEST.READLINK;
  buf.writeUInt32BE(pathlen, p, true);
  buf.write(path, p += 4, pathlen, 'utf8');

  return this._send(buf, cb);
};

SFTP.prototype.symlink = function(linkPath, targetPath, cb) {
  /*
    uint32     id
    string     linkpath
    string     targetpath
  */
  var linklen = Buffer.byteLength(linkPath),
      targetlen = Buffer.byteLength(targetPath),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + linklen + 4 + targetlen);
  buf[0] = REQUEST.SYMLINK;
  buf.writeUInt32BE(linklen, p, true);
  buf.write(linkPath, p += 4, linklen, 'utf8');
  buf.writeUInt32BE(targetlen, p += linklen, true);
  buf.write(targetPath, p += 4, targetlen, 'utf8');

  return this._send(buf, cb);
};

SFTP.prototype.realpath = function(path, cb) {
  /*
    uint32     id
    string     path
  */
  var pathlen = Buffer.byteLength(path),
      p = 5,
      buf = new Buffer(1 + 4 + 4 + pathlen);
  buf[0] = REQUEST.REALPATH;
  buf.writeUInt32BE(pathlen, p, true);
  buf.write(path, p += 4, pathlen, 'utf8');

  return this._send(buf, function(err, names) {
    if (err)
      return cb(err);
    cb(undefined, names[0].filename);
  });
};

SFTP.prototype._send = function(data, cb, stream) {
  var err;
  if (this._reqid === MAX_REQID && !this._reqidmaxed) {
    this._reqid = 0;
    this._reqidmaxed = true;
  }
  if (this._reqidmaxed) {
    var found = false, i = 0;
    for (; i < MAX_REQID; ++i) {
      if (!this._requests[i]) {
        this._reqid = i;
        found = true;
        break;
      }
    }
    if (!found) {
      err = new Error('Exhausted available SFTP request IDs');
      if (typeof cb === 'function')
        cb(err);
      else
        this.emit('error', err);
      return;
    }
  }

  if (!this._stream.writable) {
    err = new Error('Underlying stream not writable');
    if (typeof cb === 'function')
      cb(err);
    else
      this.emit('error', err);
    return;
  }

  if (typeof cb !== 'function')
    cb = EMPTY_CALLBACK;
  else if (stream) {
    // temporary callback hack used to ensure all is well before sending
    // for streaming functions (currently read() and write())
    cb();
    cb = undefined;
  }
  this._requests[this._reqid] = { cb: cb, stream: stream };
  
  data.writeUInt32BE(this._reqid++, 1, true);

  return this._stream.write(data);
};

SFTP.prototype._init = function() {
  /*
    uint32 version
    <extension data>
  */
  if (!this._stream.writable) {
    err = new Error('Underlying stream not writable');
    return this.emit('error', err);
  }

  return this._stream.write(VERSION_BUFFER);
};

SFTP.prototype._parse = function(chunk) {
  var data = this._data, chunklen = chunk.length, cb, stream;
  chunk.i = 0;
  while (chunk.i < chunklen) {
    if (data.type === 'discard')
      --data.len;
    else if (this._field === 'packet_length') {
      if ((data.len = this._readUInt32BE(chunk)) !== false)
        this._field = 'type';
    } else if (this._field === 'type') {
      --data.len;
      data.type = chunk[chunk.i];
      if (!data.type)
        throw new Error('Unsupported packet type: ' + chunk[chunk.i]);
      this._field = 'payload';
    } else if (data.type === RESPONSE.VERSION) {
      /*
        uint32 version
        <extension data>
      */
      if (!data.subtype) {
        --data.len;
        if ((data.version = this._readUInt32BE(chunk)) !== false) {
          if (data.version !== 3)
            return this.emit('error', new Error('Incompatible SFTP version'));
          //data.subtype = 'extension';
          data.type = 'discard';
          this.emit('ready');
        }
      } else if (data.subtype === 'extension') {
        // TODO
      }
    } else if (data.type === RESPONSE.STATUS) {
      /*
        uint32     id
        uint32     error/status code
        string     error message (ISO-10646 UTF-8)
        string     language tag
      */
      if (!data.subtype) {
        --data.len;
        if ((data.reqid = this._readUInt32BE(chunk)) !== false)
          data.subtype = 'status code';
      } else if (data.subtype === 'status code') {
        --data.len;
        if ((data.statusCode = this._readUInt32BE(chunk)) !== false)
          data.subtype = 'error message';
      } else if (data.subtype === 'error message') {
        if ((data.errMsg = this._readString(chunk, 'utf8')) !== false)
          data.subtype = 'language';
      } else if (data.subtype === 'language') {
        if ((data.lang = this._readString(chunk, 'utf8')) !== false) {
          data.type = 'discard';
          cb = this._requests[data.reqid].cb;
          stream = this._requests[data.reqid].stream;
          delete this._requests[data.reqid];
          if (data.statusCode === STATUS_CODE.OK)
            cb();
          else if (data.statusCode === STATUS_CODE.EOF) {
            if (stream)
              stream.emit('end');
            else
              cb(undefined, false);
          } else {
            var err = new Error(data.errMsg);
            err.type = STATUS_CODE[data.statusCode];
            err.lang = data.lang;
            cb(err);
          }
        }
      }
    } else if (data.type === RESPONSE.HANDLE) {
      /*
        uint32     id
        string     handle
      */
      if (!data.subtype) {
        --data.len;
        if ((data.reqid = this._readUInt32BE(chunk)) !== false)
          data.subtype = 'handle blob';
      } else if (data.subtype === 'handle blob') {
        if ((data.handle = this._readString(chunk)) !== false) {
          data.type = 'discard';
          cb = this._requests[data.reqid].cb;
          delete this._requests[data.reqid];
          cb(undefined, data.handle);
        }
      }
    } else if (data.type === RESPONSE.DATA) {
      /*
        uint32     id
        string     data
      */
      if (!data.subtype) {
        --data.len;
        if ((data.reqid = this._readUInt32BE(chunk)) !== false)
          data.subtype = 'data';
      } else if (data.subtype === 'data') {
        if (this._requests[data.reqid].stream) {
          if ((data.done = this._readString(chunk, undefined, true)) !== false) {
            data.type = 'discard';
            this._requests[data.reqid].stream.emit('end');
            delete this._requests[data.reqid];
          }
        } else {
          if ((data.data = this._readString(chunk)) !== false) {
            data.type = 'discard';
            cb = this._requests[data.reqid].cb;
            delete this._requests[data.reqid];
            cb(undefined, data.data);
          }
        }
      }
    } else if (data.type === RESPONSE.NAME) {
      /*
        uint32     id
        uint32     count
        repeats count times:
                string     filename
                string     longname
                ATTRS      attrs
      */
      if (!data.subtype) {
        --data.len;
        if ((data.reqid = this._readUInt32BE(chunk)) !== false)
          data.subtype = 'count';
      } else if (data.subtype === 'count') {
        --data.len;
        if ((data.count = this._readUInt32BE(chunk)) !== false) {
          data.names = new Array(data.count);
          if (data.count > 0) {
            data.c = 0;
            data.subtype = 'filename';
          } else {
            data.type = 'discard';
            cb = this._requests[data.reqid].cb;
            delete this._requests[data.reqid];
            cb(undefined, data.names);
          }
        }
      } else if (data.subtype === 'filename') {
        if (!data.names[data.c]) {
          data.names[data.c] = {
            filename: undefined,
            longname: undefined,
            attrs: undefined
          };
        }
        if ((data.names[data.c].filename = this._readString(chunk, 'utf8')) !== false)
          data.subtype = 'longname';
      } else if (data.subtype === 'longname') {
        if ((data.names[data.c].longname = this._readString(chunk, 'utf8')) !== false)
          data.subtype = 'attrs';
      } else if (data.subtype === 'attrs') {
        if ((data.names[data.c].attrs = this._readAttrs(chunk)) !== false) {
          if (++data.c < data.count)
            data.subtype = 'filename';
          else {
            data.type = 'discard';
            cb = this._requests[data.reqid].cb;
            delete this._requests[data.reqid];
            cb(undefined, data.names);
          }
        }
      }
    } else if (data.type === RESPONSE.ATTRS) {
      /*
        uint32     id
        ATTRS      attrs
      */
      if (!data.subtype) {
        --data.len;
        if ((data.reqid = this._readUInt32BE(chunk)) !== false)
          data.subtype = 'attrs';
      } else if (data.subtype === 'attrs') {
        if ((data.attrs = this._readAttrs(chunk)) !== false) {
          data.type = 'discard';
          cb = this._requests[data.reqid].cb;
          delete this._requests[data.reqid];
          cb(undefined, data.attrs);
        }
      }
    } else if (data.type === RESPONSE.EXTENDED) {
      /*
        uint32     id
        string     extended-request
        ... any request-specific data ...
      */
      // TODO
      --data.len;
      data.type = 'discard';
    }

    if (data.len === 0 && this._field !== 'packet_length')
      this._reset();
    ++chunk.i;
  }
};

SFTP.prototype._readUInt32BE = function(chunk) {
  this._value <<= 8;
  this._value += chunk[chunk.i];
  if (++this._count === 4) {
    var val = this._value;
    this._count = 0;
    this._value = 0;
    return val;
  }
  return false;
};

SFTP.prototype._readUInt64BE = function(chunk) {
  this._value *= 256;
  this._value <<= 8;
  this._value += chunk[chunk.i];
  if (++this._count === 8) {
    var val = this._value;
    this._count = 0;
    this._value = 0;
    return val;
  }
  return false;
};

SFTP.prototype._readString = function(chunk, encoding, isDataStream) {
  if (this._count < 4 && this._string === undefined) {
    this._value <<= 8;
    this._value += chunk[chunk.i];
    if (++this._count === 4) {
      this._count = 0;
      if (this._value === 0) {
        if (isDataStream)
          return true;
        else if (!encoding)
          return new Buffer(0);
        else
          return '';
      }
      if (!isDataStream) {
        if (!encoding)
          this._string = new Buffer(this._value);
        else
          this._string = '';
      }
    }
  } else if (this._string !== undefined) {
    if (this._value <= chunk.length - chunk.i) {
      // rest of string is in the rest of the chunk
      var str;
      if (isDataStream) {
        this._requests[this._data.reqid]
            .stream.emit('data', chunk.slice(chunk.i, chunk.i + this._value));
        str = true;
      } else if (!encoding) {
        chunk.copy(this._string, this._count, chunk.i, chunk.i + this._value);
        str = this._string;
      } else {
        str = this._string + chunk.toString(encoding || 'ascii', chunk.i,
                                            chunk.i + this._value);
      }
      chunk.i += this._value - 1;
      this._data.len -= this._value + 1;
      this._string = undefined;
      this._value = 0;
      this._count = 0;
      return str;
    } else {
      // only part or none of string in rest of chunk
      var diff = chunk.length - chunk.i;
      if (diff > 0) {
        if (isDataStream) {
          this._requests[this._data.reqid]
              .stream.emit('data', chunk.slice(chunk.i));
        } else if (!encoding) {
          chunk.copy(this._string, this._count, chunk.i);
          this._count += diff;
        } else
          this._string += chunk.toString(encoding || 'ascii', chunk.i);
        chunk.i = chunk.length;
        this._data.len -= diff;
        this._value -= diff;
      }
    }
  }

  return false;
};

SFTP.prototype._readAttrs = function(chunk) {
  /*
    uint32   flags
    uint64   size           present only if flag SSH_FILEXFER_ATTR_SIZE
    uint32   uid            present only if flag SSH_FILEXFER_ATTR_UIDGID
    uint32   gid            present only if flag SSH_FILEXFER_ATTR_UIDGID
    uint32   permissions    present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
    uint32   atime          present only if flag SSH_FILEXFER_ACMODTIME
    uint32   mtime          present only if flag SSH_FILEXFER_ACMODTIME
    uint32   extended_count present only if flag SSH_FILEXFER_ATTR_EXTENDED
    string   extended_type
    string   extended_data
    ...      more extended data (extended_type - extended_data pairs),
               so that number of pairs equals extended_count
  */
  var data = this._data;
  if (!data._attrs)
    data._attrs = {};

  if (typeof data._flags !== 'number')
    data._flags = this._readUInt32BE(chunk);
  else if (data._flags & ATTR.SIZE) {
    if ((data._attrs.size = this._readUInt64BE(chunk)) !== false)
      data._flags &= ~ATTR.SIZE;
  } else if (data._flags & ATTR.UIDGID) {
    if (typeof data._attrs.uid !== 'number')
      data._attrs.uid = this._readUInt32BE(chunk);
    else if ((data._attrs.gid = this._readUInt32BE(chunk)) !== false)
      data._flags &= ~ATTR.UIDGID;
  } else if (data._flags & ATTR.PERMISSIONS) {
    if ((data._attrs.permissions = this._readUInt32BE(chunk)) !== false)
      data._flags &= ~ATTR.PERMISSIONS;
  } else if (data._flags & ATTR.ACMODTIME) {
    if (typeof data._attrs.atime !== 'number')
      data._attrs.atime = this._readUInt32BE(chunk);
    else if ((data._attrs.mtime = this._readUInt32BE(chunk)) !== false)
      data._flags &= ~ATTR.ACMODTIME;
  } else if (data._flags & ATTR.EXTENDED) {
    //data._flags &= ~ATTR.EXTENDED;
    data._flags = 0;
    /*if (typeof data._attrsnExt !== 'number')
      data._attrsnExt = this._readUInt32BE(chunk);*/
  }

  if (data._flags === 0) {
    var ret = data._attrs;
    data._flags = undefined;
    data._attrs = undefined;
    return ret;
  }

  return false;
};

SFTP.prototype._reset = function() {
  this._count = 0;
  this._value = 0;
  this._string = undefined;
  this._field = 'packet_length';
  this._data = { len: 0, type: undefined, subtype: undefined };
};

var ATTR = {
  SIZE: 0x00000001,
  UIDGID: 0x00000002,
  PERMISSIONS: 0x00000004,
  ACMODTIME: 0x00000008,
  EXTENDED: 0x80000000
};

var STATUS_CODE = {
  OK: 0,
  EOF: 1,
  NO_SUCH_FILE: 2,
  PERMISSION_DENIED: 3,
  FAILURE: 4,
  BAD_MESSAGE: 5,
  NO_CONNECTION: 6,
  CONNECTION_LOST: 7,
  OP_UNSUPPORTED: 8
};
for (var i=0,keys=Object.keys(STATUS_CODE),len=keys.length; i<len; ++i)
  STATUS_CODE[STATUS_CODE[keys[i]]] = keys[i];

var REQUEST = {
  INIT: 1,
  OPEN: 3,
  CLOSE: 4,
  READ: 5,
  WRITE: 6,
  LSTAT: 7,
  FSTAT: 8,
  SETSTAT: 9,
  FSETSTAT: 10,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  MKDIR: 14,
  RMDIR: 15,
  REALPATH: 16,
  STAT: 17,
  RENAME: 18,
  READLINK: 19,
  SYMLINK: 20
};
for (var i=0,keys=Object.keys(REQUEST),len=keys.length; i<len; ++i)
  REQUEST[REQUEST[keys[i]]] = keys[i];
var RESPONSE = {
  VERSION: 2,
  STATUS: 101,
  HANDLE: 102,
  DATA: 103,
  NAME: 104,
  ATTRS: 105,
  EXTENDED: 201
};
for (var i=0,keys=Object.keys(RESPONSE),len=keys.length; i<len; ++i)
  RESPONSE[RESPONSE[keys[i]]] = keys[i];

var OPEN_MODE = {
  READ: 0x00000001,
  WRITE: 0x00000002,
  APPEND: 0x00000004,
  CREAT: 0x00000008,
  TRUNC: 0x00000010,
  EXCL: 0x00000020
};


function attrsToBytes(attrs) {
  var flags = 0, attrBytes = 0, attrs = [], i = 0;

  if (typeof attrs.size === 'number') {
    flags |= ATTR.SIZE;
    attrBytes += 8;
    var sizeBytes = new Array(8), val = attrs.size;
    for (i = 7; i >= 0; --i) {
      sizeBytes[i] = val & 0xFF;
      val /= 256;
    }
    attrs.push(sizeBytes);
  }
  if (typeof attrs.uid === 'number' && typeof attrs.gid === 'number') {
    flags |= ATTR.UIDGID;
    attrBytes += 8;
    attrs.push([(attrs.uid >> 24) & 0xFF, (attrs.uid >> 16) & 0xFF,
                (attrs.uid >> 8) & 0xFF, attrs.uid & 0xFF]);
    attrs.push([(attrs.gid >> 24) & 0xFF, (attrs.gid >> 16) & 0xFF,
                (attrs.gid >> 8) & 0xFF, attrs.gid & 0xFF]);
  }
  if (typeof attrs.permissions === 'number') {
    flags |= ATTR.PERMISSIONS;
    attrBytes += 4;
    attrs.push([(attrs.permissions >> 24) & 0xFF,
                (attrs.permissions >> 16) & 0xFF,
                (attrs.permissions >> 8) & 0xFF,
                attrs.permissions & 0xFF]);
  }
  if (typeof attrs.atime === 'number' && typeof attrs.mtime === 'number') {
    flags |= ATTR.ACMODTIME;
    attrBytes += 8;
    attrs.push([(attrs.atime >> 24) & 0xFF, (attrs.atime >> 16) & 0xFF,
                (attrs.atime >> 8) & 0xFF, attrs.atime & 0xFF]);
    attrs.push([(attrs.mtime >> 24) & 0xFF, (attrs.mtime >> 16) & 0xFF,
                (attrs.mtime >> 8) & 0xFF, attrs.mtime & 0xFF]);
  }
  // TODO: extended attributes

  return [flags, attrBytes, attrs];
}


function ReadStream(sftp) {
  this._sftp = sftp;
  this._buffer = [];
  this.readable = true;
  this._paused = false;
  this._decoder = undefined;
}
inherits(ReadStream, Stream);

ReadStream.prototype._emit = ReadStream.prototype.emit;
ReadStream.prototype.emit = function(ev, arg1) {
  if (this._paused)
    this._buffer.push([ev, arg1]);
  else {
    if (ev === 'data' && this._decoder)
      this._emit(ev, this._decoder.write(arg1));
    else
      this._emit(ev, arg1);
  }
};
ReadStream.prototype.pause = function() {
  this._sftp._stream.pause();
  this._paused = true;
};
ReadStream.prototype.resume = function() {
  if (this._buffer.length) {
    for (var i = 0, len = this._buffer.length; i < len; ++i) {
      if (ev === 'data' && this._decoder)
        this._emit(this._buffer[i][0], this._decoder.write(this._buffer[i][1]));
      else
        this._emit(this._buffer[i][0], this._buffer[i][1]);
    }
    this._buffer = [];
  }
  this._paused = false;
  this._sftp._stream.resume();
};
ReadStream.prototype.destroy = function() {
  this.readable = false;
  this._buffer = [];
  this._decoder = undefined;
};
ReadStream.prototype.setEncoding = function(encoding) {
  var StringDecoder = require('string_decoder').StringDecoder; // lazy load
  this._decoder = new StringDecoder(encoding);
};
