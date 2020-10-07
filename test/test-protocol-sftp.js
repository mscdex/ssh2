'use strict';

const assert = require('assert');
const { readFileSync, constants } = require('fs');
const { join, basename } = require('path');

const { mustCall, mustCallAtLeast } = require('./common.js');

const Client = require('../lib/client.js');
const Server = require('../lib/server.js');
const { OPEN_MODE, Stats, STATUS_CODE } = require('../lib/protocol/SFTP.js');

let t = -1;
const THIS_FILE = basename(__filename, '.js');
const fixturesDir = join(__dirname, 'fixtures');
const fixture = (file) => readFileSync(join(fixturesDir, file));

const USER = 'nodejs';
const PASSWORD = 'FLUXCAPACITORISTHEPOWER';
const HOST_KEY_RSA = fixture('ssh_host_rsa_key');
const DEBUG = false;
const DEFAULT_TEST_TIMEOUT = 30 * 1000;

const tests = [
  // Successful client requests
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/tmp/foo.txt';
        const handle_ = Buffer.from('node.js');
        server.on('OPEN', mustCall((id, path, pflags, attrs) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          assert(pflags === (OPEN_MODE.TRUNC
                             | OPEN_MODE.CREAT
                             | OPEN_MODE.WRITE),
                 msg(`Wrong flags: ${flagsToHuman(pflags)}`));
          server.handle(id, handle_);
          server.end();
        }));
        client.open(path_, 'w', mustCall((err, handle) => {
          assert(!err, msg('Unexpected open() error: ' + err));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
        }));
      });
    }),
    what: 'open'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const handle_ = Buffer.from('node.js');
        server.on('CLOSE', mustCall((id, handle) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.close(handle_, mustCall((err) => {
          assert(!err, msg('Unexpected close() error: ' + err));
        }));
      });
    }),
    what: 'close'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const expected =
          Buffer.from('node.jsnode.jsnode.jsnode.jsnode.jsnode.js');
        const handle_ = Buffer.from('node.js');
        const buf = Buffer.alloc(expected.length);
        server.on('READ', mustCall((id, handle, offset, len) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          assert(offset === 5, msg(`Wrong read offset: ${offset}`));
          assert(len === buf.length, msg(`Wrong read len: ${len}`));
          server.data(id, expected);
          server.end();
        }));
        client.read(handle_, buf, 0, buf.length, 5, mustCall((err, nb) => {
          assert(!err, msg('Unexpected read() error: ' + err));
          assert.deepStrictEqual(buf, expected, msg('read data mismatch'));
        }));
      });
    }),
    what: 'read'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const handle_ = Buffer.from('node.js');
        const buf = Buffer.from('node.jsnode.jsnode.jsnode.jsnode.jsnode.js');
        server.on('WRITE', mustCall((id, handle, offset, data) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          assert(offset === 5, msg(`Wrong write offset: ${offset}`));
          assert.deepStrictEqual(data, buf, msg('write data mismatch'));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.write(handle_, buf, 0, buf.length, 5, mustCall((err, nb) => {
          assert(!err, msg(`Unexpected write() error: ${err}`));
          assert.strictEqual(nb, buf.length, msg('wrong bytes written'));
        }));
      });
    }),
    what: 'write'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const handle_ = Buffer.from('node.js');
        const buf = Buffer.allocUnsafe(3 * 32 * 1024);
        let reqs = 0;
        server.on('WRITE', mustCall((id, handle, offset, data) => {
          ++reqs;
          assert.strictEqual(id, reqs - 1, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          assert.strictEqual(offset,
                             (reqs - 1) * 32 * 1024,
                             msg(`Wrong write offset: ${offset}`));
          assert((offset + data.length) <= buf.length, msg('bad offset'));
          assert.deepStrictEqual(data,
                                 buf.slice(offset, offset + data.length),
                                 msg('write data mismatch'));
          server.status(id, STATUS_CODE.OK);
          if (reqs === 3)
            server.end();
        }, 3));
        client.write(handle_, buf, 0, buf.length, 0, mustCall((err, nb) => {
          assert(!err, msg('Unexpected write() error: ' + err));
          assert.strictEqual(nb, buf.length, msg('wrote bytes written'));
        }));
      });
    }),
    what: 'write (overflow)'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        const attrs_ = new Stats({
          size: 10 * 1024,
          uid: 9001,
          gid: 9001,
          atime: (Date.now() / 1000) | 0,
          mtime: (Date.now() / 1000) | 0
        });
        server.on('LSTAT', mustCall((id, path) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          server.attrs(id, attrs_);
          server.end();
        }));
        client.lstat(path_, mustCall((err, attrs) => {
          assert(!err, msg(`Unexpected lstat() error: ${err}`));
          assert.deepStrictEqual(attrs, attrs_, msg('attrs mismatch'));
        }));
      });
    }),
    what: 'lstat'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const handle_ = Buffer.from('node.js');
        const attrs_ = new Stats({
          size: 10 * 1024,
          uid: 9001,
          gid: 9001,
          atime: (Date.now() / 1000) | 0,
          mtime: (Date.now() / 1000) | 0
        });
        server.on('FSTAT', mustCall((id, handle) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          server.attrs(id, attrs_);
          server.end();
        }));
        client.fstat(handle_, mustCall((err, attrs) => {
          assert(!err, msg(`Unexpected fstat() error: ${err}`));
          assert.deepStrictEqual(attrs, attrs_, msg('attrs mismatch'));
        }));
      });
    }),
    what: 'fstat'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        const attrs_ = new Stats({
          uid: 9001,
          gid: 9001,
          atime: (Date.now() / 1000) | 0,
          mtime: (Date.now() / 1000) | 0
        });
        server.on('SETSTAT', mustCall((id, path, attrs) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          assert.deepStrictEqual(attrs, attrs_, msg('attrs mismatch'));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.setstat(path_, attrs_, mustCall((err) => {
          assert(!err, msg(`Unexpected setstat() error: ${err}`));
        }));
      });
    }),
    what: 'setstat'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const handle_ = Buffer.from('node.js');
        const attrs_ = new Stats({
          uid: 9001,
          gid: 9001,
          atime: (Date.now() / 1000) | 0,
          mtime: (Date.now() / 1000) | 0
        });
        server.on('FSETSTAT', mustCall((id, handle, attrs) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          assert.deepStrictEqual(attrs, attrs_, msg('attrs mismatch'));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.fsetstat(handle_, attrs_, mustCall((err) => {
          assert(!err, msg(`Unexpected fsetstat() error: ${err}`));
        }));
      });
    }),
    what: 'fsetstat'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const handle_ = Buffer.from('node.js');
        const path_ = '/tmp';
        server.on('OPENDIR', mustCall((id, path) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          server.handle(id, handle_);
          server.end();
        }));
        client.opendir(path_, mustCall((err, handle) => {
          assert(!err, msg(`Unexpected opendir() error: ${err}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
        }));
      });
    }),
    what: 'opendir'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const handle_ = Buffer.from('node.js');
        const list_ = [
          { filename: '.',
            longname: 'drwxr-xr-x  56 nodejs nodejs      4096 Nov 10 01:05 .',
            attrs: new Stats({
              mode: 0o755 | constants.S_IFDIR,
              size: 4096,
              uid: 9001,
              gid: 8001,
              atime: 1415599549,
              mtime: 1415599590
            })
          },
          { filename: '..',
            longname: 'drwxr-xr-x   4 root   root        4096 May 16  2013 ..',
            attrs: new Stats({
              mode: 0o755 | constants.S_IFDIR,
              size: 4096,
              uid: 0,
              gid: 0,
              atime: 1368729954,
              mtime: 1368729999
            })
          },
          { filename: 'foo',
            longname: 'drwxrwxrwx   2 nodejs nodejs      4096 Mar  8  2009 foo',
            attrs: new Stats({
              mode: 0o777 | constants.S_IFDIR,
              size: 4096,
              uid: 9001,
              gid: 8001,
              atime: 1368729954,
              mtime: 1368729999
            })
          },
          { filename: 'bar',
            longname: '-rw-r--r--   1 nodejs nodejs 513901992 Dec  4  2009 bar',
            attrs: new Stats({
              mode: 0o644 | constants.S_IFREG,
              size: 513901992,
              uid: 9001,
              gid: 8001,
              atime: 1259972199,
              mtime: 1259972199
            })
          }
        ];
        server.on('READDIR', mustCall((id, handle) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          server.name(id, list_);
          server.end();
        }));
        client.readdir(handle_, mustCall((err, list) => {
          assert(!err, msg(`Unexpected readdir() error: ${err}`));
          assert.deepStrictEqual(list,
                                 list_.slice(2),
                                 msg('dir list mismatch'));
        }));
      });
    }),
    what: 'readdir'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const handle_ = Buffer.from('node.js');
        const list_ = [
          { filename: '.',
            longname: 'drwxr-xr-x  56 nodejs nodejs      4096 Nov 10 01:05 .',
            attrs: new Stats({
              mode: 0o755 | constants.S_IFDIR,
              size: 4096,
              uid: 9001,
              gid: 8001,
              atime: 1415599549,
              mtime: 1415599590
            })
          },
          { filename: '..',
            longname: 'drwxr-xr-x   4 root   root        4096 May 16  2013 ..',
            attrs: new Stats({
              mode: 0o755 | constants.S_IFDIR,
              size: 4096,
              uid: 0,
              gid: 0,
              atime: 1368729954,
              mtime: 1368729999
            })
          },
          { filename: 'foo',
            longname: 'drwxrwxrwx   2 nodejs nodejs      4096 Mar  8  2009 foo',
            attrs: new Stats({
              mode: 0o777 | constants.S_IFDIR,
              size: 4096,
              uid: 9001,
              gid: 8001,
              atime: 1368729954,
              mtime: 1368729999
            })
          },
          { filename: 'bar',
            longname: '-rw-r--r--   1 nodejs nodejs 513901992 Dec  4  2009 bar',
            attrs: new Stats({
              mode: 0o644 | constants.S_IFREG,
              size: 513901992,
              uid: 9001,
              gid: 8001,
              atime: 1259972199,
              mtime: 1259972199
            })
          }
        ];
        server.on('READDIR', mustCall((id, handle) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          server.name(id, list_);
          server.end();
        }));
        client.readdir(handle_, { full: true }, mustCall((err, list) => {
          assert(!err, msg(`Unexpected readdir() error: ${err}`));
          assert.deepStrictEqual(list, list_, msg('dir list mismatch'));
        }));
      });
    }),
    what: 'readdir (full)'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        server.on('REMOVE', mustCall((id, path) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.unlink(path_, mustCall((err) => {
          assert(!err, msg(`Unexpected unlink() error: ${err}`));
        }));
      });
    }),
    what: 'unlink'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        server.on('MKDIR', mustCall((id, path) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.mkdir(path_, mustCall((err) => {
          assert(!err, msg(`Unexpected mkdir() error: ${err}`));
        }));
      });
    }),
    what: 'mkdir'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        server.on('RMDIR', mustCall((id, path) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.rmdir(path_, mustCall((err) => {
          assert(!err, msg(`Unexpected rmdir() error: ${err}`));
        }));
      });
    }),
    what: 'rmdir'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        const name_ = { filename: '/tmp/foo' };
        server.on('REALPATH', mustCall((id, path) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          server.name(id, name_);
          server.end();
        }));
        client.realpath(path_, mustCall((err, name) => {
          assert(!err, msg(`Unexpected realpath() error: ${err}`));
          assert.deepStrictEqual(name, name_.filename, msg('name mismatch'));
        }));
      });
    }),
    what: 'realpath'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        const attrs_ = new Stats({
          size: 10 * 1024,
          uid: 9001,
          gid: 9001,
          atime: (Date.now() / 1000) | 0,
          mtime: (Date.now() / 1000) | 0
        });
        server.on('STAT', mustCall((id, path) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          server.attrs(id, attrs_);
          server.end();
        }));
        client.stat(path_, mustCall((err, attrs) => {
          assert(!err, msg(`Unexpected stat() error: ${err}`));
          assert.deepStrictEqual(attrs, attrs_, msg('attrs mismatch'));
        }));
      });
    }),
    what: 'stat'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const oldPath_ = '/foo/bar/baz';
        const newPath_ = '/tmp/foo';
        server.on('RENAME', mustCall((id, oldPath, newPath) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(oldPath === oldPath_, msg(`Wrong old path: ${oldPath}`));
          assert(newPath === newPath_, msg(`Wrong new path: ${newPath}`));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.rename(oldPath_, newPath_, mustCall((err) => {
          assert(!err, msg(`Unexpected rename() error: ${err}`));
        }));
      });
    }),
    what: 'rename'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const linkPath_ = '/foo/bar/baz';
        const name = { filename: '/tmp/foo' };
        server.on('READLINK', mustCall((id, linkPath) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(linkPath === linkPath_, msg(`Wrong link path: ${linkPath}`));
          server.name(id, name);
          server.end();
        }));
        client.readlink(linkPath_, mustCall((err, targetPath) => {
          assert(!err, msg(`Unexpected readlink() error: ${err}`));
          assert(targetPath === name.filename,
                 msg(`Wrong target path: ${targetPath}`));
        }));
      });
    }),
    what: 'readlink'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const linkPath_ = '/foo/bar/baz';
        const targetPath_ = '/tmp/foo';
        server.on('SYMLINK', mustCall((id, linkPath, targetPath) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(linkPath === linkPath_,
                 msg(`Wrong link path: ${linkPath}`));
          assert(targetPath === targetPath_,
                 msg(`Wrong target path: ${targetPath}`));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.symlink(targetPath_, linkPath_, mustCall((err) => {
          assert(!err, msg(`Unexpected symlink() error: ${err}`));
        }));
      });
    }),
    what: 'symlink'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        const handle_ = Buffer.from('hi mom!');
        const data_ = Buffer.from('hello world');
        server.on('OPEN', mustCall((id, path, pflags, attrs) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          assert(pflags === OPEN_MODE.READ,
                 msg(`Wrong flags: ${flagsToHuman(pflags)}`));
          server.handle(id, handle_);
        })).on('FSTAT', mustCall((id, handle) => {
          assert(id === 1, msg(`Wrong request id: ${id}`));
          const attrs = new Stats({
            size: data_.length,
            uid: 9001,
            gid: 9001,
            atime: (Date.now() / 1000) | 0,
            mtime: (Date.now() / 1000) | 0
          });
          server.attrs(id, attrs);
        })).on('READ', mustCall((id, handle, offset, len) => {
          assert(id === 2, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          assert(offset === 0, msg(`Wrong read offset: ${offset}`));
          server.data(id, data_);
        })).on('CLOSE', mustCall((id, handle) => {
          assert(id === 3, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.readFile(path_, mustCall((err, buf) => {
          assert(!err, msg(`Unexpected error: ${err}`));
          assert.deepStrictEqual(buf, data_, msg('data mismatch'));
        }));
      });
    }),
    what: 'readFile'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        const handle_ = Buffer.from('hi mom!');
        const data_ = Buffer.from('hello world');
        let reads = 0;
        server.on('OPEN', mustCall((id, path, pflags, attrs) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          assert(pflags === OPEN_MODE.READ,
            msg(`Wrong flags: ${flagsToHuman(pflags)}`));
          server.handle(id, handle_);
        })).on('FSTAT', mustCall((id, handle) => {
          assert(id === 1, msg(`Wrong request id: ${id}`));
          const attrs = new Stats({
            uid: 9001,
            gid: 9001,
            atime: (Date.now() / 1000) | 0,
            mtime: (Date.now() / 1000) | 0
          });
          server.attrs(id, attrs);
        })).on('READ', mustCall((id, handle, offset, len) => {
          assert(++reads + 1 === id, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          switch (id) {
            case 2:
              assert(offset === 0,
                     msg(`Wrong read offset for first read: ${offset}`));
              server.data(id, data_);
              break;
            case 3:
              assert(offset === data_.length,
                     msg(`Wrong read offset for second read: ${offset}`));
              server.status(id, STATUS_CODE.EOF);
              break;
          }
        }, 2)).on('CLOSE', mustCall((id, handle) => {
          assert(id === 4, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        client.readFile(path_, mustCall((err, buf) => {
          assert(!err, msg(`Unexpected error: ${err}`));
          assert.deepStrictEqual(buf, data_, msg('data mismatch'));
        }));
      });
    }),
    what: 'readFile (no size from fstat)'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        let reads = 0;
        const path_ = '/foo/bar/baz';
        const handle_ = Buffer.from('hi mom!');
        const data_ = Buffer.from('hello world');
        server.on('OPEN', mustCall((id, path, pflags, attrs) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          assert(pflags === OPEN_MODE.READ,
                 msg(`Wrong flags: ${flagsToHuman(pflags)}`));
          server.handle(id, handle_);
        })).on('READ', mustCall((id, handle, offset, len) => {
          assert(id === ++reads, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          if (reads === 1) {
            assert(offset === 0, msg(`Wrong read offset: ${offset}`));
            server.data(id, data_);
          } else {
            server.status(id, STATUS_CODE.EOF);
          }
        }, 2)).on('CLOSE', mustCall((id, handle) => {
          assert(id === 3, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        let buf = [];
        client.createReadStream(path_)
              .on('readable', mustCallAtLeast(function() {
          let chunk;
          while ((chunk = this.read()) !== null)
            buf.push(chunk);
        })).on('end', mustCall(() => {
          buf = Buffer.concat(buf);
          assert.deepStrictEqual(buf, data_, msg('data mismatch'));
        }));
      });
    }),
    what: 'ReadStream'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        const handle_ = Buffer.from('hi mom!');
        const data_ = Buffer.from('hello world');
        server.on('OPEN', mustCall((id, path, pflags, attrs) => {
          server.handle(id, handle_);
        })).on('READ', mustCallAtLeast((id, handle, offset, len) => {
          if (offset > data_.length) {
            server.status(id, STATUS_CODE.EOF);
          } else {
            // Only read 4 bytes at a time
            server.data(id, data_.slice(offset, offset + 4));
          }
        })).on('CLOSE', mustCall((id, handle) => {
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));
        let buf = [];
        client.createReadStream(path_)
              .on('readable', mustCallAtLeast(function() {
          let chunk;
          while ((chunk = this.read()) !== null)
            buf.push(chunk);
        })).on('end', mustCall(() => {
          buf = Buffer.concat(buf);
          assert.deepStrictEqual(buf, data_, msg('data mismatch'));
        }));
      });
    }),
    what: 'ReadStream (fewer bytes than requested)'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const path_ = '/foo/bar/baz';
        server.on('OPEN', mustCall((id, path, pflags, attrs) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          assert(pflags === OPEN_MODE.READ,
                 msg(`Wrong flags: ${flagsToHuman(pflags)}`));
          server.status(id, STATUS_CODE.NO_SUCH_FILE);
          server.end();
        }));
        client.createReadStream(path_).on('error', mustCall((err) => {
          assert(err.code === STATUS_CODE.NO_SUCH_FILE);
        }));
      });
    }),
    what: 'ReadStream (error)'
  },
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        let writes = 0;
        const path_ = '/foo/bar/baz';
        const handle_ = Buffer.from('hi mom!');
        const data_ = Buffer.from('hello world');
        const expFlags = OPEN_MODE.TRUNC | OPEN_MODE.CREAT | OPEN_MODE.WRITE;
        server.on('OPEN', mustCall((id, path, pflags, attrs) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert(path === path_, msg(`Wrong path: ${path}`));
          assert(pflags === expFlags,
                 msg(`Wrong flags: ${flagsToHuman(pflags)}`));
          server.handle(id, handle_);
        })).on('FSETSTAT', mustCall((id, handle, attrs) => {
          assert(id === 1, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          assert.strictEqual(attrs.mode, 0o666, msg('Wrong file mode'));
          server.status(id, STATUS_CODE.OK);
        })).on('WRITE', mustCall((id, handle, offset, data) => {
          assert(id === ++writes + 1, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          assert(offset === ((writes - 1) * data_.length),
                 msg(`Wrong write offset: ${offset}`));
          assert.deepStrictEqual(data, data_, msg('Wrong data'));
          server.status(id, STATUS_CODE.OK);
        }, 3)).on('CLOSE', mustCall((id, handle) => {
          assert(id === 5, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          server.status(id, STATUS_CODE.OK);
          server.end();
        }));

        const writer = client.createWriteStream(path_);
        writer.cork && writer.cork();
        writer.write(data_);
        writer.write(data_);
        writer.write(data_);
        writer.uncork && writer.uncork();
        writer.end();
      });
    }),
    what: 'WriteStream'
  },

  // Other client request scenarios
  { run: mustCall(function(msg) {
      this.onReady = mustCall((client, server) => {
        const handle_ = Buffer.from('node.js');
        server.on('READDIR', mustCall((id, handle) => {
          assert(id === 0, msg(`Wrong request id: ${id}`));
          assert.deepStrictEqual(handle, handle_, msg('handle mismatch'));
          server.status(id, STATUS_CODE.EOF);
          server.end();
        }));
        client.readdir(handle_, mustCall((err, list) => {
          assert(err && err.code === STATUS_CODE.EOF,
                 msg(`Expected EOF, got: ${err}`));
        }));
      });
    }),
    what: 'readdir (EOF)'
  },
];

function setup(self, clientCfg, serverCfg, timeout) {
  const { next, msg } = self;
  let clientReady = false;
  let serverReady = false;
  let clientSFTP = false;
  let serverSFTP = false;
  let clientClose = false;
  let serverClose = false;

  if (DEBUG) {
    console.log('========================================================\n'
                + `[TEST] ${self.what}\n`
                + '========================================================');
    clientCfg.debug = (...args) => {
      console.log(`[${self.what}][CLIENT]`, ...args);
    };
    serverCfg.debug = (...args) => {
      console.log(`[${self.what}][SERVER]`, ...args);
    };
  }

  const client = new Client();
  const server = new Server(serverCfg);
  if (timeout === undefined)
    timeout = DEFAULT_TEST_TIMEOUT;
  let timer;

  server.on('error', onError)
        .on('connection', mustCall((conn) => {
          conn.on('authentication', mustCall((ctx) => {
            ctx.accept();
          })).on('error', onError)
            .on('ready', mustCall(onReady));
          server.close();
        }))
        .on('close', mustCall(onClose));
  client.on('error', onError)
        .on('ready', mustCall(onReady))
        .on('close', mustCall(onClose));

  function onError(err) {
    const which = (this === client ? 'client' : 'server');
    assert(false, msg(`Unexpected ${which} error: ${err}`));
  }

  function onSFTP() {
    if (clientSFTP && serverSFTP)
      self.onReady(clientSFTP, serverSFTP);
  }

  function onReady() {
    if (this === client) {
      assert(!clientReady,
             msg('Received multiple ready events for client'));
      clientReady = true;
      this.sftp(mustCall((err, sftp) => {
        assert(!err, msg(`Unexpected client sftp start error: ${err}`));
        clientSFTP = sftp;
        sftp.on('end', mustCall(() => {
          this.end();
        }));
        onSFTP.call(this);
      }));
    } else {
      assert(!serverReady,
             msg('Received multiple ready events for server'));
      serverReady = true;
      this.once('session', mustCall((accept, reject) => {
        accept().once('sftp', mustCall((accept, reject) => {
          const sftp = accept();
          serverSFTP = sftp;
          sftp.on('end', mustCall(() => {
            this.end();
          }));
          onSFTP.call(this);
        }));
      }));
    }
  }

  function onClose() {
    if (this === client) {
      assert(!clientClose,
             msg('Received multiple close events for client'));
      clientClose = true;
    } else {
      assert(!serverClose,
             msg('Received multiple close events for server'));
      serverClose = true;
    }
    if (clientClose
        && serverClose
        && !getParamNames(self.run.origFn || self.run).includes('next')) {
      clearTimeout(timer);
      next();
    }
  }

  process.nextTick(mustCall(() => {
    server.listen(0, 'localhost', mustCall(() => {
      if (timeout >= 0) {
        timer = setTimeout(() => {
          assert(false, msg('Test timed out'));
        }, timeout);
      }
      if (clientCfg.sock) {
        clientCfg.sock.connect(server.address().port, 'localhost');
      } else {
        clientCfg.host = 'localhost';
        clientCfg.port = server.address().port;
      }
      client.connect(clientCfg);
    }));
  }));

  return { client, server };
}

function flagsToHuman(flags) {
  const ret = [];

  for (const [name, value] of Object.entries(OPEN_MODE)) {
    if (flags & value)
      ret.push(name);
  }

  return ret.join(' | ');
}

const getParamNames = (() => {
  const STRIP_COMMENTS = /((\/\/.*$)|(\/\*[\s\S]*?\*\/))/mg;
  const ARGUMENT_NAMES = /([^\s,]+)/g;
  const toString = Function.prototype.toString;
  return (fn) => {
    const s = toString.call(fn).replace(STRIP_COMMENTS, '');
    const result = s.slice(s.indexOf('(') + 1, s.indexOf(')'))
                    .match(ARGUMENT_NAMES);
    return (result || []);
  };
})();

function once(fn) {
  let called = false;
  return (...args) => {
    if (called)
      return;
    called = true;
    fn(...args);
  };
}

function next() {
  if (Array.isArray(process._events.exit))
    process._events.exit = process._events.exit[1];
  if (++t === tests.length)
    return;

  const v = tests[t];
  v.next = once(next);
  v.msg = msg.bind(null, v.what);
  v.run(v.msg, v.next);
  setup(
    v,
    { username: USER, password: PASSWORD },
    { hostKeys: [HOST_KEY_RSA] }
  );
}

function msg(what, desc) {
  return `[${THIS_FILE}/${what}]: ${desc}`;
}

process.once('exit', () => {
  const ran = Math.max(t, 0);
  assert(ran === tests.length,
         msg('(exit)', `Finished ${ran}/${tests.length} tests`));
});

next();
