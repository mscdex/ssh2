var inspect = require('util').inspect;
require('buffer').INSPECT_MAX_BYTES = Infinity;

var net = require('net'),
    zlib = require('zlib'),
    crypto = require('crypto');
var Parser = require('./Parser'),
    consts = require('./Parser.constants');
var inherits = require('util').inherits,
    EventEmitter = require('events').EventEmitter;

var MODULE_VER = require('../package.json').version;
var SSH_IDENT = 'SSH-2.0-ssh2js' + MODULE_VER;

for (var i=0,keys=Object.keys(consts),len=keys.length; i<len; ++i)
  global[keys[i]] = consts[keys[i]];

var I = 0;
var STATE_HANDSHAKE = I++,
    STATE_AUTHENTICATED = I++;

var AUTH_PASSWORD = 1,
    AUTH_KEYBOARD = 2,
    AUTH_PUBKEY = 4;

var Session = function(opts) {
  var self = this;
  this._host = undefined;
  this._port = undefined;
  this._compress = undefined;
  this._state = undefined;
  this._username = undefined;

  // for user/pass and keyboard interactive auth
  this._password = undefined;

  // for public key-based auth
  this._pubkey = undefined;
  this._privkey = undefined;
  this._passphrase = undefined;

  // for ssh agent auth
  this._agent = undefined;

  this._sock = undefined;
  if (opts && typeof opts.debug === 'function')
    this._debug = opts.debug;
  else
    this._debug = false;

  this._parser = new Parser();

  this._parser.on('header', function(header) {
    self._debug&&self._debug('header', header);
    if (header.versions.protocol !== '1.99'
        && header.versions.protocol !== '2.0') {
      self._parser.reset();
      return self._sock.destroy();
    }
    self._server_ident_raw = header.ident_raw;
  });

  this._parser.on('packet', function(type, typeid, data) {
    self._debug&&self._debug('packet', type, typeid, data);
  });

  this._parser.on('DEBUG', function(msg, lang) {
    self._debug&&self._debug('debug', msg, lang);
  });

  this._parser.on('KEXINIT', function(init) {
    crypto.randomBytes(16, function(err, my_cookie) {
      /*
        byte         SSH_MSG_KEXINIT
        byte[16]     cookie (random bytes)
        name-list    kex_algorithms
        name-list    server_host_key_algorithms
        name-list    encryption_algorithms_client_to_server
        name-list    encryption_algorithms_server_to_client
        name-list    mac_algorithms_client_to_server
        name-list    mac_algorithms_server_to_client
        name-list    compression_algorithms_client_to_server
        name-list    compression_algorithms_server_to_client
        name-list    languages_client_to_server
        name-list    languages_server_to_client
        boolean      first_kex_packet_follows
        uint32       0 (reserved for future extension)
      */
      var kexInitSize = 1 + 16
                        + 4 + ALGORITHMS.KEX_LIST_SIZE
                        + 4 + ALGORITHMS.SERVER_HOST_KEY_LIST_SIZE
                        + (2 * (4 + ALGORITHMS.CIPHER_LIST_SIZE))
                        + (2 * (4 + ALGORITHMS.HMAC_LIST_SIZE))
                        + (2 * (4 + ALGORITHMS.COMPRESS_LIST_SIZE))
                        + (2 * (4 /* languages skipped */))
                        + 1 + 4,
          bufKexInit = new Buffer(kexInitSize),
          p = 17, i, len;

      bufKexInit.fill(0);
      bufKexInit[0] = MESSAGE.KEXINIT;

      if (!err)
        my_cookie.copy(bufKexInit, 1);

      bufKexInit.writeUInt32BE(ALGORITHMS.KEX_LIST_SIZE, p, true);
      p += 4;
      ALGORITHMS.KEX_LIST.copy(bufKexInit, p);
      p += ALGORITHMS.KEX_LIST_SIZE;

      bufKexInit.writeUInt32BE(ALGORITHMS.SERVER_HOST_KEY_LIST_SIZE, p, true);
      p += 4;
      ALGORITHMS.SERVER_HOST_KEY_LIST.copy(bufKexInit, p);
      p += ALGORITHMS.SERVER_HOST_KEY_LIST_SIZE;

      bufKexInit.writeUInt32BE(ALGORITHMS.CIPHER_LIST_SIZE, p, true);
      p += 4;
      ALGORITHMS.CIPHER_LIST.copy(bufKexInit, p);
      p += ALGORITHMS.CIPHER_LIST_SIZE;

      bufKexInit.writeUInt32BE(ALGORITHMS.CIPHER_LIST_SIZE, p, true);
      p += 4;
      ALGORITHMS.CIPHER_LIST.copy(bufKexInit, p);
      p += ALGORITHMS.CIPHER_LIST_SIZE;

      bufKexInit.writeUInt32BE(ALGORITHMS.HMAC_LIST_SIZE, p, true);
      p += 4;
      ALGORITHMS.HMAC_LIST.copy(bufKexInit, p);
      p += ALGORITHMS.HMAC_LIST_SIZE;

      bufKexInit.writeUInt32BE(ALGORITHMS.HMAC_LIST_SIZE, p, true);
      p += 4;
      ALGORITHMS.HMAC_LIST.copy(bufKexInit, p);
      p += ALGORITHMS.HMAC_LIST_SIZE;

      bufKexInit.writeUInt32BE(ALGORITHMS.COMPRESS_LIST_SIZE, p, true);
      p += 4;
      ALGORITHMS.COMPRESS_LIST.copy(bufKexInit, p);
      p += ALGORITHMS.COMPRESS_LIST_SIZE;

      bufKexInit.writeUInt32BE(ALGORITHMS.COMPRESS_LIST_SIZE, p, true);
      p += 4;
      ALGORITHMS.COMPRESS_LIST.copy(bufKexInit, p);
      p += ALGORITHMS.COMPRESS_LIST_SIZE;

      // skip language lists, first_kex_packet_follows, and reserved bytes

      self._kexinit = bufKexInit;
      self._send(bufKexInit, function() {
        // check for agreeable server->client cipher
        for (i=0,len=ALGORITHMS.CIPHER.length;
             i<len && init.algorithms.sc.encrypt.indexOf(ALGORITHMS.CIPHER[i])
                      === -1;
             ++i);
        if (i === len) {
          // no suitable match found!
          self._parser.reset();
          return self._disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
        }

        self._parser._decryptType = ALGORITHMS.CIPHER[i];

        // check for agreeable client->server cipher
        for (i=0,len=ALGORITHMS.CIPHER.length;
             i<len && init.algorithms.cs.encrypt.indexOf(ALGORITHMS.CIPHER[i])
                      === -1;
             ++i);
        if (i === len) {
          // no suitable match found!
          self._parser.reset();
          return self._disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
        }

        self._encryptType = ALGORITHMS.CIPHER[i];

        // check for agreeable key exchange algorithm
        for (i=0,len=ALGORITHMS.KEX.length;
             i<len && init.algorithms.kex.indexOf(ALGORITHMS.KEX[i]) === -1;
             ++i);
        if (i === len) {
          // no suitable match found!
          self._parser.reset();
          return self._disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
        }

        var kex_algorithm = ALGORITHMS.KEX[i],
            pubkey, pubkeyLen,
            bufDHInit;

        // check for agreeable client->server hmac algorithm
        for (i=0,len=ALGORITHMS.HMAC.length;
             i<len && init.algorithms.cs.mac.indexOf(ALGORITHMS.HMAC[i]) === -1;
             ++i);
        if (i === len) {
          // no suitable match found!
          self._parser.reset();
          return self._disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
        }

        self._hmac = ALGORITHMS.HMAC[i];

        // check for agreeable server->client hmac algorithm
        for (i=0,len=ALGORITHMS.HMAC.length;
             i<len && init.algorithms.sc.mac.indexOf(ALGORITHMS.HMAC[i]) === -1;
             ++i);
        if (i === len) {
          // no suitable match found!
          self._parser.reset();
          return self._disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
        }

        self._parser._hmac = ALGORITHMS.HMAC[i];

        // check for agreeable client->server compression algorithm
        for (i=0,len=ALGORITHMS.COMPRESS.length;
             i<len && init.algorithms.cs.compress
                                        .indexOf(ALGORITHMS.COMPRESS[i]) === -1;
             ++i);
        if (i === len) {
          // no suitable match found!
          self._parser.reset();
          return self._disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
        }

        self._compressType = ALGORITHMS.COMPRESS[i];

        // check for agreeable server->client compression algorithm
        for (i=0,len=ALGORITHMS.COMPRESS.length;
             i<len && init.algorithms.sc.compress
                                        .indexOf(ALGORITHMS.COMPRESS[i]) === -1;
             ++i);
        if (i === len) {
          // no suitable match found!
          self._parser.reset();
          return self._disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
        }

        self._parser._compressType = ALGORITHMS.COMPRESS[i];

        // check for agreeable server host key format
        for (i=0,len=ALGORITHMS.SERVER_HOST_KEY.length;
             i<len && init.algorithms.srvHostKey
                          .indexOf(ALGORITHMS.SERVER_HOST_KEY[i]) === -1;
             ++i);
        if (i === len) {
          // no suitable match found!
          self._parser.reset();
          return self._disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
        }

        self._hostkey_format = ALGORITHMS.SERVER_HOST_KEY[i];

        if (kex_algorithm === 'diffie-hellman-group1-sha1')
          self._kex = crypto.getDiffieHellman('modp2');
        else if (kex_algorithm === 'diffie-hellman-group14-sha1')
          self._kex = crypto.getDiffieHellman('modp14');

        self._pubkey = new Buffer(self._kex.generateKeys('binary'), 'binary');
        if (self._pubkey[0] & 0x80) {
          var key = new Buffer(self._pubkey.length + 1);
          key[0] = 0;
          self._pubkey.copy(key, 1);
          self._pubkey = key;
        }

        bufDHInit = new Buffer(1 + 4 + self._pubkey.length);
        bufDHInit[0] = MESSAGE.KEXDH_INIT;
        bufDHInit.writeUInt32BE(self._pubkey.length, 1, true);
        self._pubkey.copy(bufDHInit, 5);

        self._send(bufDHInit);
      });
    });
  });

  this._parser.on('KEXDH_REPLY', function(info) {
    if (info.hostkey_format !== self._hostkey_format) {
      // expected and actual server host key format do not match!
      self._parser.reset();
      return self._disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
    }
    var slicepos = -1;
    for (var i=0,len=info.pubkey.length; i<len; ++i) {
      if (info.pubkey[i] === 0)
        ++slicepos;
      else
        break;
    }
    if (slicepos > -1)
      info.pubkey = info.pubkey.slice(slicepos + 1);
    var compSecret = self._kex.computeSecret(info.pubkey, 'binary', 'binary');
    info.secret = new Buffer(compSecret, 'binary');
    // SHA1 for both currently supported DH kex methods
    var hash = crypto.createHash('sha1');
    var len_ident = Buffer.byteLength(SSH_IDENT),
        len_sident = Buffer.byteLength(self._server_ident_raw),
        len_init = self._kexinit.length,
        len_sinit = self._parser._kexinit.length,
        len_hostkey = info.hostkey.length,
        len_pubkey = self._pubkey.length,
        len_spubkey = info.pubkey.length,
        len_secret = info.secret.length;
    if (self._pubkey[0] & 0x80)
      ++len_pubkey;
    if (info.pubkey[0] & 0x80)
      ++len_spubkey;
    if (info.secret[0] & 0x80)
      ++len_secret;
    var exchangeBuf = new Buffer(len_ident + len_sident + len_init + len_sinit
                                 + len_hostkey + len_pubkey + len_spubkey
                                 + len_secret + (4 * 8)),
        p = 0;
    exchangeBuf.writeUInt32BE(len_ident, p, true);
    p += 4;
    exchangeBuf.write(SSH_IDENT, p, 'utf8');
    p += len_ident;

    exchangeBuf.writeUInt32BE(len_sident, p, true);
    p += 4;
    exchangeBuf.write(self._server_ident_raw, p, 'utf8');
    p += len_sident;

    exchangeBuf.writeUInt32BE(len_init, p, true);
    p += 4;
    self._kexinit.copy(exchangeBuf, p);
    p += len_init;

    exchangeBuf.writeUInt32BE(len_sinit, p, true);
    p += 4;
    self._parser._kexinit.copy(exchangeBuf, p);
    p += len_sinit;

    exchangeBuf.writeUInt32BE(len_hostkey, p, true);
    p += 4;
    info.hostkey.copy(exchangeBuf, p);
    p += len_hostkey;

    exchangeBuf.writeUInt32BE(len_pubkey, p, true);
    p += 4;
    if (self._pubkey[0] & 0x80)
      exchangeBuf[p++] = 0;
    self._pubkey.copy(exchangeBuf, p);
    p += len_pubkey - (self._pubkey[0] & 0x80 ? 1 : 0);

    exchangeBuf.writeUInt32BE(len_spubkey, p, true);
    p += 4;
    if (info.pubkey[0] & 0x80)
      exchangeBuf[p++] = 0;
    info.pubkey.copy(exchangeBuf, p);
    p += len_spubkey - (info.pubkey[0] & 0x80 ? 1 : 0);

    exchangeBuf.writeUInt32BE(len_secret, p, true);
    p += 4;
    if (info.secret[0] & 0x80)
      exchangeBuf[p++] = 0;
    info.secret.copy(exchangeBuf, p);

    self._exchange_hash = new Buffer(hash.update(exchangeBuf)
                                         .digest('binary'), 'binary');

    if (self._sessionid === undefined)
      self._sessionid = self._exchange_hash;
    self._kexreply = info;
    self._send(new Buffer([MESSAGE.NEWKEYS]));
  });

  this._parser.on('NEWKEYS', function() {
    var iv, key, blocklen = 8, keylen = 0, p = 0,
        secret, len_secret = (self._kexreply.secret[0] & 0x80 ? 1 : 0)
                             + self._kexreply.secret.length;
    secret = new Buffer(4 + len_secret);
    secret.writeUInt32BE(len_secret, p, true);
    p += 4;
    if (self._kexreply.secret[0] & 0x80)
      secret[p++] = 0;
    self._kexreply.secret.copy(secret, p);
    iv = new Buffer(crypto.createHash('sha1')
                          .update(secret)
                          .update(self._exchange_hash)
                          .update('A', 'ascii')
                          .update(self._sessionid)
                          .digest('binary'), 'binary');
    switch (self._encryptType) {
      case 'aes256-cbc':
      case 'aes192-cbc':
      case 'aes128-cbc':
      case 'aes256-ctr':
      case 'aes192-ctr':
      case 'aes128-ctr':
        blocklen = 16;
    }
    self._encryptSize = blocklen;
    while (blocklen > iv.length) {
      iv = Buffer.concat([iv, new Buffer(crypto.createHash('sha1')
                                               .update(secret)
                                               .update(self._exchange_hash)
                                               .update(iv)
                                               .digest('binary'), 'binary')]);
    }
    iv = iv.slice(0, blocklen);
    switch (self._encryptType) {
      case 'aes256-cbc':
      case 'aes256-ctr':
      case 'arcfour256':
        keylen = 32; // eg. 256 / 8
        break;
      case '3des-cbc':
      case '3des-ctr':
      case 'aes192-cbc':
      case 'aes192-ctr':
        keylen = 24; // eg. 192 / 8
        break;
      case 'aes128-cbc':
      case 'aes128-ctr':
      case 'arcfour':
      case 'arcfour128':
        keylen = 16; // eg. 128 / 8
        break;
    }
    key = new Buffer(crypto.createHash('sha1')
                           .update(secret)
                           .update(self._exchange_hash)
                           .update('C', 'ascii')
                           .update(self._sessionid)
                           .digest('binary'), 'binary');
    while (keylen > key.length) {
      key = Buffer.concat([key, new Buffer(crypto.createHash('sha1')
                                                 .update(secret)
                                                 .update(self._exchange_hash)
                                                 .update(key)
                                                 .digest('binary'), 'binary')]);
    }
    key = key.slice(0, keylen);
    self._encrypt = crypto.createCipheriv(SSH_TO_OPENSSL[self._encryptType],
                                          key, iv);
    self._encrypt.setAutoPadding(false);

    // and now for decrypting ...

    blocklen = 8;
    keylen = 0;
    iv = new Buffer(crypto.createHash('sha1')
                          .update(secret)
                          .update(self._exchange_hash)
                          .update('B', 'ascii')
                          .update(self._sessionid)
                          .digest('binary'), 'binary');
    switch (self._parser._decryptType) {
      case 'aes256-cbc':
      case 'aes192-cbc':
      case 'aes128-cbc':
      case 'aes256-ctr':
      case 'aes192-ctr':
      case 'aes128-ctr':
        blocklen = 16;
    }
    self._parser._decryptSize = blocklen;
    while (blocklen > iv.length) {
      iv = Buffer.concat([iv, new Buffer(crypto.createHash('sha1')
                                               .update(secret)
                                               .update(self._exchange_hash)
                                               .update(iv)
                                               .digest('binary'), 'binary')]);
    }
    iv = iv.slice(0, blocklen);
    switch (self._parser._decryptType) {
      case 'aes256-cbc':
      case 'aes256-ctr':
      case 'arcfour256':
        keylen = 32; // eg. 256 / 8
        break;
      case '3des-cbc':
      case '3des-ctr':
      case 'aes192-cbc':
      case 'aes192-ctr':
        keylen = 24; // eg. 192 / 8
        break;
      case 'aes128-cbc':
      case 'aes128-ctr':
      case 'arcfour':
      case 'arcfour128':
        keylen = 16; // eg. 128 / 8
        break;
    }
    key = new Buffer(crypto.createHash('sha1')
                           .update(secret)
                           .update(self._exchange_hash)
                           .update('D', 'ascii')
                           .update(self._sessionid)
                           .digest('binary'), 'binary');
    while (keylen > key.length) {
      key = Buffer.concat([key, new Buffer(crypto.createHash('sha1')
                                                 .update(secret)
                                                 .update(self._exchange_hash)
                                                 .update(key)
                                                 .digest('binary'), 'binary')]);
    }
    key = key.slice(0, keylen);
    self._parser._decrypt = crypto.createDecipheriv(SSH_TO_OPENSSL[self._parser
                                                                   ._decryptType],
                                                    key, iv);
    self._parser._decrypt.setAutoPadding(false);

    /* The "arcfour128" algorithm is the RC4 cipher, as described in
       [SCHNEIER], using a 128-bit key.  The first 1536 bytes of keystream
       generated by the cipher MUST be discarded, and the first byte of the
       first encrypted packet MUST be encrypted using the 1537th byte of
       keystream.

       -- http://tools.ietf.org/html/rfc4345#section-4 */
    if (self._encryptType === 'arcfour128'
        || self._encryptType === 'arcfour256') {
      var emptyBuf = new Buffer(1536);
      emptyBuf.fill(0);
      self._encrypt.update(emptyBuf);
    }
    if (self._parser._decryptType === 'arcfour128'
        || self._parser._decryptType === 'arcfour256') {
      var emptyBuf = new Buffer(1536);
      emptyBuf.fill(0);
      self._parser._decrypt.update(emptyBuf);
    }

    var createKeyLen = 0, checkKeyLen = 0;
    switch (self._hmac) {
      case 'hmac-sha1':
      case 'hmac-sha1-96':
        createKeyLen = 20;
        break;
      case 'hmac-md5':
      case 'hmac-md5-96':
        createKeyLen = 16;
    }
    switch (self._parser._hmac) {
      case 'hmac-sha1':
        checkKeyLen = 20;
        self._parser._hmacSize = 20;
        break;
      case 'hmac-sha1-96':
        checkKeyLen = 20;
        self._parser._hmacSize = 12;
        break;
      case 'hmac-md5':
        checkKeyLen = 16;
        self._parser._hmacSize = 16;
        break;
      case 'hmac-md5-96':
        checkKeyLen = 16;
        self._parser._hmacSize = 12;
    }
    switch (self._hmac) {
      case 'hmac-sha1':
        self._hmacSize = 20;
        break;
      case 'hmac-md5':
        self._hmacSize = 16;
        break;
      case 'hmac-sha1-96':
      case 'hmac-md5-96':
        self._hmacSize = 12;
    }
    key = new Buffer(crypto.createHash('sha1')
                           .update(secret)
                           .update(self._exchange_hash)
                           .update('E', 'ascii')
                           .update(self._sessionid)
                           .digest('binary'), 'binary');
    while (createKeyLen > key.length) {
      key = Buffer.concat([key, new Buffer(crypto.createHash('sha1')
                                                 .update(secret)
                                                 .update(self._exchange_hash)
                                                 .update(key)
                                                 .digest('binary'), 'binary')]);
    }
    self._hmacKey = key.slice(0, createKeyLen);
    key = new Buffer(crypto.createHash('sha1')
                           .update(secret)
                           .update(self._exchange_hash)
                           .update('F', 'ascii')
                           .update(self._sessionid)
                           .digest('binary'), 'binary');
    while (checkKeyLen > key.length) {
      key = Buffer.concat([key, new Buffer(crypto.createHash('sha1')
                                                 .update(secret)
                                                 .update(self._exchange_hash)
                                                 .update(key)
                                                 .digest('binary'), 'binary')]);
    }
    self._parser._hmacKey = key.slice(0, checkKeyLen);

    if (self._compressType !== 'none' && self._compress)
      self._compress = zlib.createDeflate();
    if (self._parser._compressType !== 'none')
      self._parser._compress = zlib.createInflate();

    // attempt to begin to perform user auth
    var svcBuf = new Buffer(1 + 4 + 12);
    svcBuf[0] = MESSAGE.SERVICE_REQUEST;
    svcBuf.writeUInt32BE(12, 1, true);
    svcBuf.write('ssh-userauth', 5, 12, 'ascii');
    self._send(svcBuf);
  });

  this._parser.on('SERVICE_ACCEPT', function(svc) {
    if (svc === 'ssh-userauth') {
      if (self._password)
        self._authPwd();
      else if (self._passphrase && self._privkey) {
      } else if (self._agent) {
      }
    }
  });
};
inherits(Session, EventEmitter);

Session.prototype.connect = function(opts) {
  var self = this;
  this._host = opts.host || '127.0.0.1';
  this._port = opts.port || 22;
  this._compress = opts.compress || false;
  this._state = STATE_HANDSHAKE;

  this._username = opts.username;
  this._password = opts.password;
  this._privkey = opts.privkey;
  this._passphrase = opts.passphrase;
  this._agent = opts.agent;

  this._sock = new net.Socket();
  this._seqno = 0;
  this._encryptSize = 8;
  this._encrypt = false;
  this._hmacKey = undefined;
  this._hmacSize = undefined;
  this._hmac = false;
  this._server_ident_raw = undefined;
  this._kexinit = undefined;
  this._sessionid = undefined
  this._parser.reset();

  this._sock.on('connect', function() {
console.log('EVENT :: connect');
    self._sock.write(SSH_IDENT + '\r\n');
  });
  this._sock.on('data', function(data) {
console.log('data: ' + inspect(data));
    self._parser.execute(data);
  });
  this._sock.on('error', function(err) {
console.log('EVENT :: error :: ' + err);
  });
  this._sock.on('end', function() {
console.log('EVENT :: end');
  });
  this._sock.on('close', function(had_err) {
console.log('EVENT :: close');
    self._parser.reset();
  });
  this._sock.connect(this._port, this._host);
};

Session.prototype._send = function(payload, cb) {
  // TODO: implement length checks
  var pktLen = payload.length + 9,
      padLen,
      self = this;
  pktLen += ((this._encryptSize - 1) * pktLen) % this._encryptSize;
  padLen = pktLen - payload.length - 5;
  // TODO: make this async again
  //crypto.randomBytes(padLen, function(err, padBytes) {
  padBytes = crypto.randomBytes(padLen);
    var buf = new Buffer(pktLen),
        hmac;
    buf.writeUInt32BE(pktLen - 4, 0, true);
    buf[4] = padLen;
    payload.copy(buf, 5);
    //if (!err)
      padBytes.copy(buf, 5 + payload.length);
    if (self._hmac !== false && self._hmacKey) {
      hmac = crypto.createHmac(SSH_TO_OPENSSL[self._hmac], self._hmacKey);
      var bufSeqNo = new Buffer(4);
      bufSeqNo.writeUInt32BE(self._seqno, 0, true);
      hmac.update(bufSeqNo);
      hmac.update(buf);
      hmac = hmac.digest('binary');
      if (self._hmac.length > 3 && self._hmac.substr(-3) === '-96') {
        // only keep 96 bits of hash
        hmac = new Buffer(hmac, 'binary').toString('binary', 0, 96 / 8);
      }
      hmac = new Buffer(hmac, 'binary');
    }
    if (self._encrypt !== false) {
      var encbuf = new Buffer(self._encrypt.update(buf, 'binary', 'binary'), 'binary');
      var newbuf = new Buffer(encbuf.length + hmac.length);
      encbuf.copy(newbuf);
      hmac.copy(newbuf, encbuf.length);
      self._sock.write(newbuf);
    } else
      self._sock.write(buf);

    /*if (hmac !== undefined)
      self._sock.write(hmac, 'binary');*/

    if (++self._seqno > Parser.MAX_SEQNO)
      self._seqno = 0;

    cb&&cb();
  //});
};

module.exports = Session;