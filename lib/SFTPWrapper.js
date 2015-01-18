// This wrapper class is used to retain backwards compatibility with
// pre-v0.4 ssh2. If it weren't for `read()` and `write()` being used by the
// streams2/3 API, we could just pass the SFTPStream directly to the end user...

function SFTPWrapper(stream) {
  var self = this;

  this._stream = stream;

  stream.on('error', function(err) {
    self.emit('error', err);
  }).on('end', function() {
    self.emit('end');
  });
}
// stream-related methods to pass on
SFTPWrapper.prototype.end = function() {
  this._stream.end();
};
// SFTPStream client methods
SFTPWrapper.prototype.createReadStream = function(path, options) {
  this._stream.createReadStream(path, options);
};
SFTPWrapper.prototype.createWriteStream = function(path, options) {
  this._stream.createWriteStream(path, options);
};
SFTPWrapper.prototype.open = function(path, flags, attrs, cb) {
  this._stream.open(path, flags, attrs, cb);
};
SFTPWrapper.prototype.close = function(handle, cb) {
  this._stream.close(handle, cb);
};
SFTPWrapper.prototype.read = function(handle, buf, off, len, position, cb) {
  this._stream.readData(handle, buf, off, len, position, cb);
};
SFTPWrapper.prototype.write = function(handle, buf, off, len, position, cb) {
  this._stream.writeData(handle, buf, off, len, position, cb);
};
SFTPWrapper.prototype.fastGet = function(remotePath, localPath, opts, cb) {
  this._stream.fastGet(remotePath, localPath, opts, cb);
};
SFTPWrapper.prototype.fastPut = function(localPath, remotePath, opts, cb) {
  this._stream.fastPut(localPath, remotePath, opts, cb);
};
SFTPWrapper.prototype.readFile = function(path, options, callback_) {
  this._stream.readFile(path, options, callback_);
};
SFTPWrapper.prototype.writeFile = function(path, data, options, callback_) {
  this._stream.writeFile(path, data, options, callback_);
};
SFTPWrapper.prototype.appendFile = function(path, data, options, callback_) {
  this._stream.appendFile(path, data, options, callback_);
};
SFTPWrapper.prototype.exists = function(path, cb) {
  this._stream.exists(path, cb);
};
SFTPWrapper.prototype.unlink = function(filename, cb) {
  this._stream.unlink(filename, cb);
};
SFTPWrapper.prototype.rename = function(oldPath, newPath, cb) {
  this._stream.rename(oldPath, newPath, cb);
};
SFTPWrapper.prototype.mkdir = function(path, attrs, cb) {
  this._stream.mkdir(path, attrs, cb);
};
SFTPWrapper.prototype.rmdir = function(path, cb) {
  this._stream.rmdir(path, cb);
};
SFTPWrapper.prototype.readdir = function(where, opts, cb) {
  this._stream.readdir(where, opts, cb);
};
SFTPWrapper.prototype.fstat = function(handle, cb) {
  this._stream.fstat(handle, cb);
};
SFTPWrapper.prototype.stat = function(path, cb) {
  this._stream.stat(path, cb);
};
SFTPWrapper.prototype.lstat = function(path, cb) {
  this._stream.lstat(path, cb);
};
SFTPWrapper.prototype.opendir = function(path, cb) {
  this._stream.opendir(path, cb);
};
SFTPWrapper.prototype.setstat = function(path, attrs, cb) {
  this._stream.setstat(path, attrs, cb);
};
SFTPWrapper.prototype.fsetstat = function(handle, attrs, cb) {
  this._stream.fsetstat(handle, attrs, cb);
};
SFTPWrapper.prototype.futimes = function(handle, atime, mtime, cb) {
  this._stream.futimes(handle, atime, mtime, cb);
};
SFTPWrapper.prototype.utimes = function(path, atime, mtime, cb) {
  this._stream.utimes(path, atime, mtime, cb);
};
SFTPWrapper.prototype.fchown = function(handle, uid, gid, cb) {
  this._stream.fchown(handle, uid, gid, cb);
};
SFTPWrapper.prototype.chown = function(path, uid, gid, cb) {
  this._stream.chown(path, uid, gid, cb);
};
SFTPWrapper.prototype.fchmod = function(handle, mode, cb) {
  this._stream.fchmod(handle, mode, cb);
};
SFTPWrapper.prototype.chmod = function(path, mode, cb) {
  this._stream.chmod(path, mode, cb);
};
SFTPWrapper.prototype.readlink = function(path, cb) {
  this._stream.readlink(path, cb);
};
SFTPWrapper.prototype.symlink = function(targetPath, linkPath, cb) {
  this._stream.symlink(targetPath, linkPath, cb);
};
SFTPWrapper.prototype.realpath = function(path, cb) {
  this._stream.realpath(path, cb);
};
// extended requests
SFTPWrapper.prototype.ext_openssh_rename = function(oldPath, newPath, cb) {
  this._stream.ext_openssh_rename(oldPath, newPath, cb);
};
SFTPWrapper.prototype.ext_openssh_statvfs = function(path, cb) {
  this._stream.ext_openssh_statvfs(path, cb);
};
SFTPWrapper.prototype.ext_openssh_fstatvfs = function(handle, cb) {
  this._stream.ext_openssh_fstatvfs(handle, cb);
};
SFTPWrapper.prototype.ext_openssh_hardlink = function(oldPath, newPath, cb) {
  this._stream.ext_openssh_hardlink(oldPath, newPath, cb);
};
SFTPWrapper.prototype.ext_openssh_fsync = function(handle, cb) {
  this._stream.ext_openssh_fsync(handle, cb);
};

module.exports = SFTPWrapper;