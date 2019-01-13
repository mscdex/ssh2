var crypto = require('crypto');
var constants = require('constants');
var fs = require('fs');

var ssh2 = require('ssh2');
var OPEN_MODE = ssh2.SFTP_OPEN_MODE;
var STATUS_CODE = ssh2.SFTP_STATUS_CODE;

var allowedUser = Buffer.from('foo');
var allowedPassword = Buffer.from('bar');

new ssh2.Server({
  hostKeys: [fs.readFileSync('host.key')]
}, function(client) {
  console.log('Client connected!');

  client.on('authentication', function(ctx) {
    var user = Buffer.from(ctx.username);
    if (user.length !== allowedUser.length
        || !crypto.timingSafeEqual(user, allowedUser)) {
      return ctx.reject(['password']);
    }

    switch (ctx.method) {
      case 'password':
        var password = Buffer.from(ctx.password);
        if (password.length !== allowedPassword.length
            || !crypto.timingSafeEqual(password, allowedPassword)) {
          return ctx.reject(['password']);
        }
        break;
      default:
        return ctx.reject(['password']);
    }

    ctx.accept();
  }).on('ready', function() {
    console.log('Client authenticated!');

    client.on('session', function(accept, reject) {
      var session = accept();
      session.on('sftp', function(accept, reject) {
        console.log('Client SFTP session');
        var openFiles = {};
        var handleCount = 0;
        // `sftpStream` is an `SFTPStream` instance in server mode
        // see: https://github.com/mscdex/ssh2-streams/blob/master/SFTPStream.md
        var sftpStream = accept();
        sftpStream.on('OPEN', function(reqid, filename, flags, attrs) {
          console.log('OPEN', filename);
          // only allow opening /tmp/foo.txt for writing
          if (filename !== '/tmp/foo.txt' || !(flags & OPEN_MODE.READ))
            return sftpStream.status(reqid, STATUS_CODE.FAILURE);
          // create a fake handle to return to the client, this could easily
          // be a real file descriptor number for example if actually opening
          // the file on the disk
          var handle = new Buffer(4);
          openFiles[handleCount] = { read: false };
          handle.writeUInt32BE(handleCount++, 0, true);
          sftpStream.handle(reqid, handle);
          console.log('Opening file for read')
        }).on('READ', function(reqid, handle, offset, length) {
          if (handle.length !== 4 || !openFiles[handle.readUInt32BE(0, true)])
            return sftpStream.status(reqid, STATUS_CODE.FAILURE);
          // fake the read
          var state = openFiles[handle.readUInt32BE(0, true)];
          if (state.read)
            sftpStream.status(reqid, STATUS_CODE.EOF);
          else {
            state.read = true;
            sftpStream.data(reqid, 'bar');
            console.log('Read from file at offset %d, length %d', offset, length);
          }
        }).on('CLOSE', function(reqid, handle) {
          var fnum;
          if (handle.length !== 4 || !openFiles[(fnum = handle.readUInt32BE(0, true))])
            return sftpStream.status(reqid, STATUS_CODE.FAILURE);
          delete openFiles[fnum];
          sftpStream.status(reqid, STATUS_CODE.OK);
          console.log('Closing file');
        }).on('REALPATH', function(reqid, path) {
          var name = [{
            filename: '/tmp/foo.txt',
            longname: '-rwxrwxrwx 1 foo foo 3 Dec 8 2009 foo.txt',
            attrs: {}
          }];
          sftpStream.name(reqid, name);
        }).on('STAT', onSTAT)
          .on('LSTAT', onSTAT);
        function onSTAT(reqid, path) {
          if (path !== '/tmp/foo.txt')
            return sftpStream.status(reqid, STATUS_CODE.FAILURE);
          var mode = constants.S_IFREG; // Regular file
          mode |= constants.S_IRWXU; // read, write, execute for user
          mode |= constants.S_IRWXG; // read, write, execute for group
          mode |= constants.S_IRWXO; // read, write, execute for other
          sftpStream.attrs(reqid, {
            mode: mode,
            uid: 0,
            gid: 0,
            size: 3,
            atime: Date.now(),
            mtime: Date.now()
          });
        }
      });
    });
  }).on('end', function() {
    console.log('Client disconnected');
  });
}).listen(0, '127.0.0.1', function() {
  console.log('Listening on port ' + this.address().port);
});
