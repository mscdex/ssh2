// This wrapper class is used to retain backwards compatibility with
// pre-v0.4 ssh2. If it weren't for `read()` and `write()` being used by the
// streams2/3 API, we could just pass the SFTPStream directly to the end user...

var inherits = require('util').inherits,
    EventEmitter = require('events').EventEmitter;

function SFTPWrapper(stream) {
  var self = this;

  EventEmitter.call(this);

  this._stream = stream;

  stream.on('error', function(err) {
    self.emit('error', err);
  }).on('end', function() {
    self.emit('end');
  }).on('continue', function() {
    self.emit('continue');
  });
}
inherits(SFTPWrapper, EventEmitter);

// stream-related methods to pass on
SFTPWrapper.prototype.end = function() {
  return this._stream.end();
};
// SFTPStream client methods
SFTPWrapper.prototype.createReadStream = function(path, options) {
  return this._stream.createReadStream(path, options);
};
SFTPWrapper.prototype.createWriteStream = function(path, options) {
  return this._stream.createWriteStream(path, options);
};
SFTPWrapper.prototype.open = function(path, flags, attrs, cb) {
  return this._stream.open(path, flags, attrs, cb);
};
SFTPWrapper.prototype.close = function(handle, cb) {
  return this._stream.close(handle, cb);
};
SFTPWrapper.prototype.read = function(handle, buf, off, len, position, cb) {
  return this._stream.readData(handle, buf, off, len, position, cb);
};
SFTPWrapper.prototype.write = function(handle, buf, off, len, position, cb) {
  return this._stream.writeData(handle, buf, off, len, position, cb);
};
SFTPWrapper.prototype.fastGet = function(remotePath, localPath, opts, cb) {
  return this._stream.fastGet(remotePath, localPath, opts, cb);
};
SFTPWrapper.prototype.fastPut = function(localPath, remotePath, opts, cb) {
  return this._stream.fastPut(localPath, remotePath, opts, cb);
};
SFTPWrapper.prototype.readFile = function(path, options, callback_) {
  return this._stream.readFile(path, options, callback_);
};
SFTPWrapper.prototype.writeFile = function(path, data, options, callback_) {
  return this._stream.writeFile(path, data, options, callback_);
};
SFTPWrapper.prototype.appendFile = function(path, data, options, callback_) {
  return this._stream.appendFile(path, data, options, callback_);
};
SFTPWrapper.prototype.exists = function(path, cb) {
  return this._stream.exists(path, cb);
};
SFTPWrapper.prototype.unlink = function(filename, cb) {
  return this._stream.unlink(filename, cb);
};
SFTPWrapper.prototype.rename = function(oldPath, newPath, cb) {
  return this._stream.rename(oldPath, newPath, cb);
};
SFTPWrapper.prototype.mkdir = function(path, attrs, cb) {
  return this._stream.mkdir(path, attrs, cb);
};
SFTPWrapper.prototype.rmdir = function(path, cb) {
  return this._stream.rmdir(path, cb);
};
SFTPWrapper.prototype.readdir = function(where, opts, cb) {
  return this._stream.readdir(where, opts, cb);
};
SFTPWrapper.prototype.fstat = function(handle, cb) {
  return this._stream.fstat(handle, cb);
};
SFTPWrapper.prototype.stat = function(path, cb) {
  return this._stream.stat(path, cb);
};
SFTPWrapper.prototype.lstat = function(path, cb) {
  return this._stream.lstat(path, cb);
};
SFTPWrapper.prototype.opendir = function(path, cb) {
  return this._stream.opendir(path, cb);
};
SFTPWrapper.prototype.setstat = function(path, attrs, cb) {
  return this._stream.setstat(path, attrs, cb);
};
SFTPWrapper.prototype.fsetstat = function(handle, attrs, cb) {
  return this._stream.fsetstat(handle, attrs, cb);
};
SFTPWrapper.prototype.futimes = function(handle, atime, mtime, cb) {
  return this._stream.futimes(handle, atime, mtime, cb);
};
SFTPWrapper.prototype.utimes = function(path, atime, mtime, cb) {
  return this._stream.utimes(path, atime, mtime, cb);
};
SFTPWrapper.prototype.fchown = function(handle, uid, gid, cb) {
  return this._stream.fchown(handle, uid, gid, cb);
};
SFTPWrapper.prototype.chown = function(path, uid, gid, cb) {
  return this._stream.chown(path, uid, gid, cb);
};
SFTPWrapper.prototype.fchmod = function(handle, mode, cb) {
  return this._stream.fchmod(handle, mode, cb);
};
SFTPWrapper.prototype.chmod = function(path, mode, cb) {
  return this._stream.chmod(path, mode, cb);
};
SFTPWrapper.prototype.readlink = function(path, cb) {
  return this._stream.readlink(path, cb);
};
SFTPWrapper.prototype.symlink = function(targetPath, linkPath, cb) {
  return this._stream.symlink(targetPath, linkPath, cb);
};
SFTPWrapper.prototype.realpath = function(path, cb) {
  return this._stream.realpath(path, cb);
};
// extended requests
SFTPWrapper.prototype.ext_openssh_rename = function(oldPath, newPath, cb) {
  return this._stream.ext_openssh_rename(oldPath, newPath, cb);
};
SFTPWrapper.prototype.ext_openssh_statvfs = function(path, cb) {
  return this._stream.ext_openssh_statvfs(path, cb);
};
SFTPWrapper.prototype.ext_openssh_fstatvfs = function(handle, cb) {
  return this._stream.ext_openssh_fstatvfs(handle, cb);
};
SFTPWrapper.prototype.ext_openssh_hardlink = function(oldPath, newPath, cb) {
  return this._stream.ext_openssh_hardlink(oldPath, newPath, cb);
};
SFTPWrapper.prototype.ext_openssh_fsync = function(handle, cb) {
  return this._stream.ext_openssh_fsync(handle, cb);
};

module.exports = SFTPWrapper;
