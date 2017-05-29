var crypto = require('crypto');
var Socket = require('net').Socket;
var dnsLookup = require('dns').lookup;
var EventEmitter = require('events').EventEmitter;
var inherits = require('util').inherits;
var HASHES = crypto.getHashes();

var ssh2_streams = require('ssh2-streams');
var SSH2Stream = ssh2_streams.SSH2Stream;
var SFTPStream = ssh2_streams.SFTPStream;
var consts = ssh2_streams.constants;
var BUGS = consts.BUGS;
var ALGORITHMS = consts.ALGORITHMS;
var parseKey = ssh2_streams.utils.parseKey;
var decryptKey = ssh2_streams.utils.decryptKey;
var genPublicKey = ssh2_streams.utils.genPublicKey;

var Channel = require('./Channel');
var agentQuery = require('./agent');
var SFTPWrapper = require('./SFTPWrapper');

var MAX_CHANNEL = Math.pow(2, 32) - 1;
var RE_OPENSSH = /^OpenSSH_(?:(?![0-4])\d)|(?:\d{2,})/;
var DEBUG_NOOP = function(msg) {};

function Client() {
  if (!(this instanceof Client))
    return new Client();

  EventEmitter.call(this);

  this.config = {
    host: undefined,
    port: undefined,
    forceIPv4: undefined,
    forceIPv6: undefined,
    keepaliveCountMax: undefined,
    keepaliveInterval: undefined,
    readyTimeout: undefined,

    username: undefined,
    password: undefined,
    privateKey: undefined,
    publicKey: undefined,
    tryKeyboard: undefined,
    agent: undefined,
    allowAgentFwd: undefined,

    hostHashAlgo: undefined,
    hostHashCb: undefined,
    strictVendor: undefined,
    debug: undefined
  };

  this._readyTimeout = undefined;
  this._channels = undefined;
  this._callbacks = undefined;
  this._forwarding = undefined;
  this._forwardingUnix = undefined;
  this._acceptX11 = undefined;
  this._agentFwdEnabled = undefined;
  this._curChan = undefined;
  this._remoteVer = undefined;

  this._sshstream = undefined;
  this._sock = undefined;
  this._resetKA = undefined;
}
inherits(Client, EventEmitter);

Client.prototype.connect = function(cfg) {
  var self = this;

  if (this._sock && this._sock.writable) {
    this.once('close', function() {
      self.connect(cfg);
    });
    this.end();
    return;
  }

  this.config.host = cfg.hostname || cfg.host || 'localhost';
  this.config.port = cfg.port || 22;
  this.config.forceIPv4 = cfg.forceIPv4 || false;
  this.config.forceIPv6 = cfg.forceIPv6 || false;
  this.config.keepaliveCountMax = (typeof cfg.keepaliveCountMax === 'number'
                                   && cfg.keepaliveCountMax >= 0
                                   ? cfg.keepaliveCountMax
                                   : 3);
  this.config.keepaliveInterval = (typeof cfg.keepaliveInterval === 'number'
                                   && cfg.keepaliveInterval > 0
                                   ? cfg.keepaliveInterval
                                   : 0);
  this.config.readyTimeout = (typeof cfg.readyTimeout === 'number'
                              && cfg.readyTimeout >= 0
                              ? cfg.readyTimeout
                              : 20000);

  var algorithms = {
    kex: undefined,
    kexBuf: undefined,
    cipher: undefined,
    cipherBuf: undefined,
    serverHostKey: undefined,
    serverHostKeyBuf: undefined,
    hmac: undefined,
    hmacBuf: undefined,
    compress: undefined,
    compressBuf: undefined
  };
  var i;
  if (typeof cfg.algorithms === 'object' && cfg.algorithms !== null) {
    var algosSupported;
    var algoList;

    algoList = cfg.algorithms.kex;
    if (Array.isArray(algoList) && algoList.length > 0) {
      algosSupported = ALGORITHMS.SUPPORTED_KEX;
      for (i = 0; i < algoList.length; ++i) {
        if (algosSupported.indexOf(algoList[i]) === -1)
          throw new Error('Unsupported key exchange algorithm: ' + algoList[i]);
      }
      algorithms.kex = algoList;
    }

    algoList = cfg.algorithms.cipher;
    if (Array.isArray(algoList) && algoList.length > 0) {
      algosSupported = ALGORITHMS.SUPPORTED_CIPHER;
      for (i = 0; i < algoList.length; ++i) {
        if (algosSupported.indexOf(algoList[i]) === -1)
          throw new Error('Unsupported cipher algorithm: ' + algoList[i]);
      }
      algorithms.cipher = algoList;
    }

    algoList = cfg.algorithms.serverHostKey;
    if (Array.isArray(algoList) && algoList.length > 0) {
      algosSupported = ALGORITHMS.SUPPORTED_SERVER_HOST_KEY;
      for (i = 0; i < algoList.length; ++i) {
        if (algosSupported.indexOf(algoList[i]) === -1) {
          throw new Error('Unsupported server host key algorithm: '
                           + algoList[i]);
        }
      }
      algorithms.serverHostKey = algoList;
    }

    algoList = cfg.algorithms.hmac;
    if (Array.isArray(algoList) && algoList.length > 0) {
      algosSupported = ALGORITHMS.SUPPORTED_HMAC;
      for (i = 0; i < algoList.length; ++i) {
        if (algosSupported.indexOf(algoList[i]) === -1)
          throw new Error('Unsupported HMAC algorithm: ' + algoList[i]);
      }
      algorithms.hmac = algoList;
    }

    algoList = cfg.algorithms.compress;
    if (Array.isArray(algoList) && algoList.length > 0) {
      algosSupported = ALGORITHMS.SUPPORTED_COMPRESS;
      for (i = 0; i < algoList.length; ++i) {
        if (algosSupported.indexOf(algoList[i]) === -1)
          throw new Error('Unsupported compression algorithm: ' + algoList[i]);
      }
      algorithms.compress = algoList;
    }
  }
  if (algorithms.compress === undefined) {
    if (cfg.compress) {
      algorithms.compress = ['zlib@openssh.com', 'zlib'];
      if (cfg.compress !== 'force')
        algorithms.compress.push('none');
    } else if (cfg.compress === false)
      algorithms.compress = ['none'];
  }

  if (typeof cfg.username === 'string')
    this.config.username = cfg.username;
  else if (typeof cfg.user === 'string')
    this.config.username = cfg.user;
  else
    throw new Error('Invalid username');

  this.config.password = (typeof cfg.password === 'string'
                          ? cfg.password
                          : undefined);
  this.config.privateKey = (typeof cfg.privateKey === 'string'
                            || Buffer.isBuffer(cfg.privateKey)
                            ? cfg.privateKey
                            : undefined);
  this.config.publicKey = undefined;
  this.config.localHostname = (typeof cfg.localHostname === 'string'
                               && cfg.localHostname.length
                               ? cfg.localHostname
                               : undefined);
  this.config.localUsername = (typeof cfg.localUsername === 'string'
                               && cfg.localUsername.length
                               ? cfg.localUsername
                               : undefined);
  this.config.tryKeyboard = (cfg.tryKeyboard === true);
  this.config.agent = (typeof cfg.agent === 'string' && cfg.agent.length
                       ? cfg.agent
                       : undefined);
  this.config.allowAgentFwd = (cfg.agentForward === true
                               && this.config.agent !== undefined);

  this.config.strictVendor = (typeof cfg.strictVendor === 'boolean'
                              ? cfg.strictVendor
                              : true);

  var debug = this.config.debug = (typeof cfg.debug === 'function'
                                   ? cfg.debug
                                   : DEBUG_NOOP);

  if (cfg.agentForward === true && !this.config.allowAgentFwd)
    throw new Error('You must set a valid agent path to allow agent forwarding');

  var callbacks = this._callbacks = [];
  this._channels = {};
  this._forwarding = {};
  this._forwardingUnix = {};
  this._acceptX11 = 0;
  this._agentFwdEnabled = false;
  this._curChan = -1;
  this._remoteVer = undefined;

  if (this.config.privateKey) {
    var privKeyInfo = parseKey(this.config.privateKey);
    if (privKeyInfo instanceof Error)
      throw new Error('Cannot parse privateKey: ' + privKeyInfo.message);
    if (!privKeyInfo.private)
      throw new Error('privateKey value does not contain a (valid) private key');
    if (privKeyInfo.encryption) {
      if (typeof cfg.passphrase !== 'string')
        throw new Error('Encrypted private key detected, but no passphrase given');
      decryptKey(privKeyInfo, cfg.passphrase);
    }
    this.config.privateKey = privKeyInfo;
    this.config.publicKey = genPublicKey(privKeyInfo);
  }

  var stream = this._sshstream = new SSH2Stream({
    algorithms: algorithms,
    debug: (debug === DEBUG_NOOP ? undefined : debug)
  });
  var sock = this._sock = (cfg.sock || new Socket());

  // drain stderr if we are connection hopping using an exec stream
  if (this._sock.stderr)
    this._sock.stderr.resume();

  // keepalive-related
  var kainterval = this.config.keepaliveInterval;
  var kacountmax = this.config.keepaliveCountMax;
  var kacount = 0;
  var katimer;
  function sendKA() {
    if (++kacount > kacountmax) {
      clearInterval(katimer);
      if (sock.readable) {
        var err = new Error('Keepalive timeout');
        err.level = 'client-timeout';
        self.emit('error', err);
        sock.destroy();
      }
      return;
    }
    if (sock.writable) {
      // append dummy callback to keep correct callback order
      callbacks.push(resetKA);
      stream.ping();
    } else
      clearInterval(katimer);
  }
  function resetKA() {
    if (kainterval > 0) {
      kacount = 0;
      clearInterval(katimer);
      if (sock.writable)
        katimer = setInterval(sendKA, kainterval);
    }
  }
  this._resetKA = resetKA;

  stream.on('USERAUTH_BANNER', function(msg) {
    self.emit('banner', msg);
  });

  sock.on('connect', function() {
    debug('DEBUG: Client: Connected');
    self.emit('connect');
    if (!cfg.sock)
      stream.pipe(sock).pipe(stream);
  }).on('timeout', function() {
    self.emit('timeout');
  }).on('error', function(err) {
    clearTimeout(self._readyTimeout);
    err.level = 'client-socket';
    self.emit('error', err);
  }).on('end', function() {
    stream.unpipe(sock);
    clearTimeout(self._readyTimeout);
    clearInterval(katimer);
    self.emit('end');
  }).on('close', function() {
    stream.unpipe(sock);
    clearTimeout(self._readyTimeout);
    clearInterval(katimer);
    self.emit('close');

    // notify outstanding channel requests of disconnection ...
    var callbacks_ = callbacks;
    var err = new Error('No response from server');
    callbacks = self._callbacks = [];
    for (i = 0; i < callbacks_.length; ++i)
      callbacks_[i](err);

    // simulate error for any channels waiting to be opened. this is safe
    // against successfully opened channels because the success and failure
    // event handlers are automatically removed when a success/failure response
    // is received
    var chanNos = Object.keys(self._channels);
    self._channels = {};
    for (i = 0; i < chanNos.length; ++i) {
      stream.emit('CHANNEL_OPEN_FAILURE:' + chanNos[i], err);
      // emitting CHANNEL_CLOSE should be safe too and should help for any
      // special channels which might otherwise keep the process alive, such
      // as agent forwarding channels which have open unix sockets ...
      stream.emit('CHANNEL_CLOSE:' + chanNos[i]);
    }
  });
  stream.on('drain', function() {
    self.emit('drain');
  }).once('header', function(header) {
    self._remoteVer = header.versions.software;
    if (header.greeting)
      self.emit('greeting', header.greeting);
  }).on('continue', function() {
    self.emit('continue');
  }).on('error', function(err) {
    err.level = 'protocol';
    self.emit('error', err);
  });

  if (typeof cfg.hostVerifier === 'function') {
    if (HASHES.indexOf(cfg.hostHash) === -1)
      throw new Error('Invalid host hash algorithm: ' + cfg.hostHash);
    var hashCb = cfg.hostVerifier;
    var hasher = crypto.createHash(cfg.hostHash);
    stream.once('fingerprint', function(key, verify) {
      hasher.update(key);
      var ret = hashCb(hasher.digest('hex'), verify);
      if (ret !== undefined)
        verify(ret);
    });
  }

  // begin authentication handling =============================================
  var auths = ['none'];
  var curAuth;
  var agentKeys;
  var agentKeyPos = 0;
  if (this.config.password !== undefined)
    auths.push('password');
  if (this.config.publicKey !== undefined)
    auths.push('publickey');
  if (this.config.agent !== undefined)
    auths.push('agent');
  if (this.config.tryKeyboard)
    auths.push('keyboard-interactive');
  if (this.config.publicKey !== undefined
      && this.config.localHostname !== undefined
      && this.config.localUsername !== undefined)
    auths.push('hostbased');
  function tryNextAuth() {
    // TODO: better shutdown
    if (!auths.length) {
      stream.removeListener('USERAUTH_FAILURE', onUSERAUTH_FAILURE);
      stream.removeListener('USERAUTH_PK_OK', onUSERAUTH_PK_OK);
      var err = new Error('All configured authentication methods failed');
      err.level = 'client-authentication';
      self.emit('error', err);
      if (stream.writable)
        self.end();
      return;
    }

    curAuth = auths.shift();
    switch (curAuth) {
      case 'password':
        stream.authPassword(self.config.username, self.config.password);
      break;
      case 'publickey':
        stream.authPK(self.config.username, self.config.publicKey);
        stream.once('USERAUTH_PK_OK', onUSERAUTH_PK_OK);
      break;
      case 'hostbased':
        function hostbasedCb(buf, cb) {
          var algo;
          switch (self.config.privateKey.fulltype) {
            case 'ssh-rsa':
              algo = 'RSA-SHA1';
              break;
            case 'ssh-dss':
              algo = 'DSA-SHA1';
              break;
            case 'ecdsa-sha2-nistp256':
              algo = 'sha256';
              break;
            case 'ecdsa-sha2-nistp384':
              algo = 'sha384';
              break;
            case 'ecdsa-sha2-nistp521':
              algo = 'sha512';
              break;
          }
          var signature = crypto.createSign(algo);
          signature.update(buf);
          signature = trySign(signature, self.config.privateKey.privateOrig);
          if (signature instanceof Error) {
            signature.message = 'Error while signing data with privateKey: '
                                + signature.message;
            signature.level = 'client-authentication';
            self.emit('error', signature);
            return tryNextAuth();
          }

          cb(signature);
        }
        stream.authHostbased(self.config.username,
                             self.config.publicKey,
                             self.config.localHostname,
                             self.config.localUsername,
                             hostbasedCb);
      break;
      case 'agent':
        agentQuery(self.config.agent, function(err, keys) {
          if (err) {
            err.level = 'agent';
            self.emit('error', err);
            agentKeys = undefined;
            return tryNextAuth();
          } else if (keys.length === 0) {
            debug('DEBUG: Agent: No keys stored in agent');
            agentKeys = undefined;
            return tryNextAuth();
          }

          agentKeys = keys;
          agentKeyPos = 0;

          stream.authPK(self.config.username, keys[0]);
          stream.once('USERAUTH_PK_OK', onUSERAUTH_PK_OK);
        });
      break;
      case 'keyboard-interactive':
        stream.authKeyboard(self.config.username);
        stream.on('USERAUTH_INFO_REQUEST', onUSERAUTH_INFO_REQUEST);
      break;
      case 'none':
        stream.authNone(self.config.username);
      break;
    }
  }
  function tryNextAgentKey() {
    if (curAuth === 'agent') {
      if (agentKeyPos >= agentKeys.length)
        return;
      if (++agentKeyPos >= agentKeys.length) {
        debug('DEBUG: Agent: No more keys left to try');
        debug('DEBUG: Client: agent auth failed');
        agentKeys = undefined;
        tryNextAuth();
      } else {
        debug('DEBUG: Agent: Trying key #' + (agentKeyPos + 1));
        stream.authPK(self.config.username, agentKeys[agentKeyPos]);
        stream.once('USERAUTH_PK_OK', onUSERAUTH_PK_OK);
      }
    }
  }
  function onUSERAUTH_INFO_REQUEST(name, instructions, lang, prompts) {
    var nprompts = (Array.isArray(prompts) ? prompts.length : 0);
    if (nprompts === 0) {
      debug('DEBUG: Client: Sending automatic USERAUTH_INFO_RESPONSE');
      return stream.authInfoRes();
    }
    // we sent a keyboard-interactive user authentication request and now the
    // server is sending us the prompts we need to present to the user
    self.emit('keyboard-interactive',
              name,
              instructions,
              lang,
              prompts,
              function(answers) {
                stream.authInfoRes(answers);
              });
  }
  function onUSERAUTH_PK_OK() {
    if (curAuth === 'agent') {
      var agentKey = agentKeys[agentKeyPos];
      var keyLen = agentKey.readUInt32BE(0, true);
      var pubKeyFullType = agentKey.toString('ascii', 4, 4 + keyLen);
      var pubKeyType = pubKeyFullType.slice(4);
      // Check that we support the key type first
      switch (pubKeyFullType) {
        case 'ssh-rsa':
        case 'ssh-dss':
        case 'ecdsa-sha2-nistp256':
        case 'ecdsa-sha2-nistp384':
        case 'ecdsa-sha2-nistp521':
          break;
        default:
          debug('DEBUG: Agent: Skipping unsupported key type: '
                + pubKeyFullType);
          return tryNextAgentKey();
      }
      stream.authPK(self.config.username, 
                    agentKey,
                    function(buf, cb) {
        agentQuery(self.config.agent,
                   agentKey,
                   pubKeyType,
                   buf,
                   function(err, signed) {
          if (err) {
            err.level = 'agent';
            self.emit('error', err);
          } else {
            var sigFullTypeLen = signed.readUInt32BE(0, true);
            if (4 + sigFullTypeLen + 4 < signed.length) {
              var sigFullType = signed.toString('ascii', 4, 4 + sigFullTypeLen);
              if (sigFullType !== pubKeyFullType) {
                err = new Error('Agent key/signature type mismatch');
                err.level = 'agent';
                self.emit('error', err);
              } else {
                // skip algoLen + algo + sigLen
                return cb(signed.slice(4 + sigFullTypeLen + 4));
              }
            }
          }

          tryNextAgentKey();
        });
      });
    } else if (curAuth === 'publickey') {
      stream.authPK(self.config.username,
                    self.config.publicKey,
                    function(buf, cb) {
        var algo;
        switch (self.config.privateKey.fulltype) {
          case 'ssh-rsa':
            algo = 'RSA-SHA1';
            break;
          case 'ssh-dss':
            algo = 'DSA-SHA1';
            break;
          case 'ecdsa-sha2-nistp256':
            algo = 'sha256';
            break;
          case 'ecdsa-sha2-nistp384':
            algo = 'sha384';
            break;
          case 'ecdsa-sha2-nistp521':
            algo = 'sha512';
            break;
        }
        var signature = crypto.createSign(algo);
        signature.update(buf);
        signature = trySign(signature, self.config.privateKey.privateOrig);
        if (signature instanceof Error) {
          signature.message = 'Error while signing data with privateKey: '
                              + signature.message;
          signature.level = 'client-authentication';
          self.emit('error', signature);
          return tryNextAuth();
        }
        cb(signature);
      });
    }
  }
  function onUSERAUTH_FAILURE(authsLeft, partial) {
    stream.removeListener('USERAUTH_PK_OK', onUSERAUTH_PK_OK);
    stream.removeListener('USERAUTH_INFO_REQUEST', onUSERAUTH_INFO_REQUEST);
    if (curAuth === 'agent') {
      debug('DEBUG: Client: Agent key #' + (agentKeyPos + 1) + ' failed');
      return tryNextAgentKey();
    } else
      debug('DEBUG: Client: ' + curAuth + ' auth failed');

    tryNextAuth();
  }
  stream.once('USERAUTH_SUCCESS', function() {
    auths = undefined;
    stream.removeListener('USERAUTH_FAILURE', onUSERAUTH_FAILURE);
    stream.removeListener('USERAUTH_INFO_REQUEST', onUSERAUTH_INFO_REQUEST);
    /*if (self.config.agent && self._agentKeys)
      self._agentKeys = undefined;*/

    // start keepalive mechanism
    resetKA();

    clearTimeout(self._readyTimeout);

    self.emit('ready');
  }).on('USERAUTH_FAILURE', onUSERAUTH_FAILURE);
  // end authentication handling ===============================================

  // handle initial handshake completion
  stream.once('ready', function() {
    stream.service('ssh-userauth');
    stream.once('SERVICE_ACCEPT', function(svcName) {
      if (svcName === 'ssh-userauth')
        tryNextAuth();
    });
  });

  // handle incoming requests from server, typically a forwarded TCP or X11
  // connection
  stream.on('CHANNEL_OPEN', function(info) {
    onCHANNEL_OPEN(self, info);
  });

  // handle responses for tcpip-forward and other global requests
  stream.on('REQUEST_SUCCESS', function(data) {
    if (callbacks.length)
      callbacks.shift()(false, data);
  }).on('REQUEST_FAILURE', function() {
    if (callbacks.length)
      callbacks.shift()(true);
  });

  stream.on('GLOBAL_REQUEST', function(name, wantReply, data) {
    // auto-reject all global requests, this can be especially useful if the
    // server is sending us dummy keepalive global requests
    if (wantReply)
      stream.requestFailure();
  });

  if (!cfg.sock) {
    var host = this.config.host;
    var forceIPv4 = this.config.forceIPv4;
    var forceIPv6 = this.config.forceIPv6;

    debug('DEBUG: Client: Trying '
          + host
          + ' on port '
          + this.config.port
          + ' ...');

    function doConnect() {
      startTimeout();
      self._sock.connect(self.config.port, host);
      self._sock.setNoDelay(true);
      self._sock.setMaxListeners(0);
      self._sock.setTimeout(typeof cfg.timeout === 'number' ? cfg.timeout : 0);
    }

    if ((!forceIPv4 && !forceIPv6) || (forceIPv4 && forceIPv6))
      doConnect();
    else {
      dnsLookup(host, (forceIPv4 ? 4 : 6), function(err, address, family) {
        if (err) {
          var error = new Error('Error while looking up '
                                + (forceIPv4 ? 'IPv4' : 'IPv6')
                                + ' address for host '
                                + host
                                + ': ' + err);
          clearTimeout(self._readyTimeout);
          error.level = 'client-dns';
          self.emit('error', error);
          self.emit('close');
          return;
        }
        host = address;
        doConnect();
      });
    }
  } else {
    startTimeout();
    stream.pipe(sock).pipe(stream);
  }

  function startTimeout() {
    if (self.config.readyTimeout > 0) {
      self._readyTimeout = setTimeout(function() {
        var err = new Error('Timed out while waiting for handshake');
        err.level = 'client-timeout';
        self.emit('error', err);
        sock.destroy();
      }, self.config.readyTimeout);
    }
  }
};

Client.prototype.end = function() {
  if (this._sock
      && this._sock.writable
      && this._sshstream
      && this._sshstream.writable)
    return this._sshstream.disconnect();
  return false;
};

Client.prototype.destroy = function() {
  this._sock && this._sock.destroy();
};

Client.prototype.exec = function(cmd, opts, cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  if (typeof opts === 'function') {
    cb = opts;
    opts = {};
  }

  var self = this;
  var extraOpts = { allowHalfOpen: (opts.allowHalfOpen !== false) };

  return openChannel(this, 'session', extraOpts, function(err, chan) {
    if (err)
      return cb(err);

    var todo = [];

    function reqCb(err) {
      if (err) {
        chan.close();
        return cb(err);
      }
      if (todo.length)
        todo.shift()();
    }

    if (self.config.allowAgentFwd === true
        || (opts
            && opts.agentForward === true
            && self.config.agent !== undefined)) {
      todo.push(function() {
        reqAgentFwd(chan, reqCb);
      });
    }

    if (typeof opts === 'object') {
      if (typeof opts.env === 'object')
        reqEnv(chan, opts.env);
      if (typeof opts.pty === 'object' || opts.pty === true)
        todo.push(function() { reqPty(chan, opts.pty, reqCb); });
      if (typeof opts.x11 === 'object'
          || opts.x11 === 'number'
          || opts.x11 === true)
        todo.push(function() { reqX11(chan, opts.x11, reqCb); });
    }

    todo.push(function() { reqExec(chan, cmd, opts, cb); });
    todo.shift()();
  });
};

Client.prototype.shell = function(wndopts, opts, cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  // start an interactive terminal/shell session
  var self = this;

  if (typeof wndopts === 'function') {
    cb = wndopts;
    wndopts = opts = undefined;
  } else if (typeof opts === 'function') {
    cb = opts;
    opts = undefined;
  }
  if (wndopts && (wndopts.x11 !== undefined || wndopts.env !== undefined)) {
    opts = wndopts;
    wndopts = undefined;
  }

  return openChannel(this, 'session', function(err, chan) {
    if (err)
      return cb(err);

    var todo = [];

    function reqCb(err) {
      if (err) {
        chan.close();
        return cb(err);
      }
      if (todo.length)
        todo.shift()();
    }

    if (self.config.allowAgentFwd === true
        || (opts
            && opts.agentForward === true
            && self.config.agent !== undefined)) {
      todo.push(function() {
        reqAgentFwd(chan, reqCb);
      });
    }

    if (wndopts !== false)
      todo.push(function() { reqPty(chan, wndopts, reqCb); });

    if (typeof opts === 'object') {
      if (typeof opts.env === 'object')
        reqEnv(chan, opts.env);
      if (typeof opts.x11 === 'object'
          || opts.x11 === 'number'
          || opts.x11 === true)
        todo.push(function() { reqX11(chan, opts.x11, reqCb); });
    }

    todo.push(function() { reqShell(chan, cb); });
    todo.shift()();
  });
};

Client.prototype.subsys = function(name, cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

	return openChannel(this, 'session', function(err, chan) {
		if (err)
			return cb(err);

		reqSubsystem(chan, name, function(err, stream) {
			if (err)
				return cb(err);

			cb(undefined, stream);
		});
	});
};

Client.prototype.sftp = function(cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  var self = this;

  // start an SFTP session
  return openChannel(this, 'session', function(err, chan) {
    if (err)
      return cb(err);

    reqSubsystem(chan, 'sftp', function(err, stream) {
      if (err)
        return cb(err);

      var serverIdentRaw = self._sshstream._state.incoming.identRaw;
      var cfg = { debug: self.config.debug };
      var sftp = new SFTPStream(cfg, serverIdentRaw);

      function onError(err) {
        sftp.removeListener('ready', onReady);
        stream.removeListener('exit', onExit);
        cb(err);
      }

      function onReady() {
        sftp.removeListener('error', onError);
        stream.removeListener('exit', onExit);
        cb(undefined, new SFTPWrapper(sftp));
      }

      function onExit(code, signal) {
        sftp.removeListener('ready', onReady);
        sftp.removeListener('error', onError);
        var msg;
        if (typeof code === 'number') {
          msg = 'Received exit code '
                + code
                + ' while establishing SFTP session';
        } else {
          msg = 'Received signal '
                + signal
                + ' while establishing SFTP session';
        }
        var err = new Error(msg);
        err.code = code;
        err.signal = signal;
        cb(err);
      }

      sftp.once('error', onError)
          .once('ready', onReady)
          .once('close', function() {
            stream.end();
          });

      // OpenSSH server sends an exit-status if there was a problem spinning up
      // an sftp server child process, so we listen for that here in order to
      // properly raise an error.
      stream.once('exit', onExit);

      sftp.pipe(stream).pipe(sftp);
    });
  });
};

Client.prototype.forwardIn = function(bindAddr, bindPort, cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  // send a request for the server to start forwarding TCP connections to us
  // on a particular address and port

  var self = this;
  var wantReply = (typeof cb === 'function');

  if (wantReply) {
    this._callbacks.push(function(had_err, data) {
      if (had_err) {
        return cb(had_err !== true
                  ? had_err
                  : new Error('Unable to bind to ' + bindAddr + ':' + bindPort));
      }

      var realPort = bindPort;
      if (bindPort === 0 && data && data.length >= 4) {
        realPort = data.readUInt32BE(0, true);
        if (!(self._sshstream.remoteBugs & BUGS.DYN_RPORT_BUG))
          bindPort = realPort;
      }

      self._forwarding[bindAddr + ':' + bindPort] = realPort;

      cb(undefined, realPort);
    });
  }

  return this._sshstream.tcpipForward(bindAddr, bindPort, wantReply);
};

Client.prototype.unforwardIn = function(bindAddr, bindPort, cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  // send a request to stop forwarding us new connections for a particular
  // address and port

  var self = this;
  var wantReply = (typeof cb === 'function');

  if (wantReply) {
    this._callbacks.push(function(had_err) {
      if (had_err) {
        return cb(had_err !== true
                  ? had_err
                  : new Error('Unable to unbind from '
                              + bindAddr + ':' + bindPort));
      }

      delete self._forwarding[bindAddr + ':' + bindPort];

      cb();
    });
  }

  return this._sshstream.cancelTcpipForward(bindAddr, bindPort, wantReply);
};

Client.prototype.forwardOut = function(srcIP, srcPort, dstIP, dstPort, cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  // send a request to forward a TCP connection to the server

  var cfg = {
    srcIP: srcIP,
    srcPort: srcPort,
    dstIP: dstIP,
    dstPort: dstPort
  };

  return openChannel(this, 'direct-tcpip', cfg, cb);
};

Client.prototype.openssh_noMoreSessions = function(cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  var wantReply = (typeof cb === 'function');

  if (!this.config.strictVendor
      || (this.config.strictVendor && RE_OPENSSH.test(this._remoteVer))) {
    if (wantReply) {
      this._callbacks.push(function(had_err) {
        if (had_err) {
          return cb(had_err !== true
                    ? had_err
                    : new Error('Unable to disable future sessions'));
        }

        cb();
      });
    }

    return this._sshstream.openssh_noMoreSessions(wantReply);
  } else if (wantReply) {
    process.nextTick(function() {
      cb(new Error('strictVendor enabled and server is not OpenSSH or compatible version'));
    });
  }

  return true;
};

Client.prototype.openssh_forwardInStreamLocal = function(socketPath, cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  var wantReply = (typeof cb === 'function');
  var self = this;

  if (!this.config.strictVendor
      || (this.config.strictVendor && RE_OPENSSH.test(this._remoteVer))) {
    if (wantReply) {
      this._callbacks.push(function(had_err) {
        if (had_err) {
          return cb(had_err !== true
                    ? had_err
                    : new Error('Unable to bind to ' + socketPath));
        }
        self._forwardingUnix[socketPath] = true;
        cb();
      });
    }

    return this._sshstream.openssh_streamLocalForward(socketPath, wantReply);
  } else if (wantReply) {
    process.nextTick(function() {
      cb(new Error('strictVendor enabled and server is not OpenSSH or compatible version'));
    });
  }

  return true;
};

Client.prototype.openssh_unforwardInStreamLocal = function(socketPath, cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  var wantReply = (typeof cb === 'function');
  var self = this;

  if (!this.config.strictVendor
      || (this.config.strictVendor && RE_OPENSSH.test(this._remoteVer))) {
    if (wantReply) {
      this._callbacks.push(function(had_err) {
        if (had_err) {
          return cb(had_err !== true
                    ? had_err
                    : new Error('Unable to unbind on ' + socketPath));
        }
        delete self._forwardingUnix[socketPath];
        cb();
      });
    }

    return this._sshstream.openssh_cancelStreamLocalForward(socketPath,
                                                            wantReply);
  } else if (wantReply) {
    process.nextTick(function() {
      cb(new Error('strictVendor enabled and server is not OpenSSH or compatible version'));
    });
  }

  return true;
};

Client.prototype.openssh_forwardOutStreamLocal = function(socketPath, cb) {
  if (!this._sock
      || !this._sock.writable
      || !this._sshstream
      || !this._sshstream.writable)
    throw new Error('Not connected');

  if (!this.config.strictVendor
      || (this.config.strictVendor && RE_OPENSSH.test(this._remoteVer))) {
    var cfg = { socketPath: socketPath };
    return openChannel(this, 'direct-streamlocal@openssh.com', cfg, cb);
  } else {
    process.nextTick(function() {
      cb(new Error('strictVendor enabled and server is not OpenSSH or compatible version'));
    });
  }

  return true;
};

function openChannel(self, type, opts, cb) {
  // ask the server to open a channel for some purpose
  // (e.g. session (sftp, exec, shell), or forwarding a TCP connection
  var localChan = nextChannel(self);
  var initWindow = Channel.MAX_WINDOW;
  var maxPacket = Channel.PACKET_SIZE;
  var ret = true;

  if (localChan === false)
    return cb(new Error('No free channels available'));

  if (typeof opts === 'function') {
    cb = opts;
    opts = {};
  }

  self._channels[localChan] = true;

  var sshstream = self._sshstream;
  sshstream.once('CHANNEL_OPEN_CONFIRMATION:' + localChan, onSuccess)
           .once('CHANNEL_OPEN_FAILURE:' + localChan, onFailure)
           .once('CHANNEL_CLOSE:' + localChan, onFailure);

  if (type === 'session')
    ret = sshstream.session(localChan, initWindow, maxPacket);
  else if (type === 'direct-tcpip')
    ret = sshstream.directTcpip(localChan, initWindow, maxPacket, opts);
  else if (type === 'direct-streamlocal@openssh.com') {
    ret = sshstream.openssh_directStreamLocal(localChan,
                                              initWindow,
                                              maxPacket,
                                              opts);
  }

  return ret;

  function onSuccess(info) {
    sshstream.removeListener('CHANNEL_OPEN_FAILURE:' + localChan, onFailure);
    sshstream.removeListener('CHANNEL_CLOSE:' + localChan, onFailure);

    var chaninfo = {
      type: type,
      incoming: {
        id: localChan,
        window: initWindow,
        packetSize: maxPacket,
        state: 'open'
      },
      outgoing: {
        id: info.sender,
        window: info.window,
        packetSize: info.packetSize,
        state: 'open'
      }
    };
    cb(undefined, new Channel(chaninfo, self));
  }

  function onFailure(info) {
    sshstream.removeListener('CHANNEL_OPEN_CONFIRMATION:' + localChan,
                             onSuccess);
    sshstream.removeListener('CHANNEL_OPEN_FAILURE:' + localChan, onFailure);
    sshstream.removeListener('CHANNEL_CLOSE:' + localChan, onFailure);

    delete self._channels[localChan];

    var err;
    if (info instanceof Error)
      err = info;
    else if (typeof info === 'object' && info !== null) {
      err = new Error('(SSH) Channel open failure: ' + info.description);
      err.reason = info.reason;
      err.lang = info.lang;
    } else {
      err = new Error('(SSH) Channel open failure: '
                      + 'server closed channel unexpectedly');
      err.reason = err.lang = '';
    }
    cb(err);
  }
}

function nextChannel(self) {
  // get the next available channel number

  // optimized path
  if (self._curChan < MAX_CHANNEL)
    return ++self._curChan;

  // slower lookup path
  for (var i = 0, channels = self._channels; i < MAX_CHANNEL; ++i)
    if (!channels[i])
      return i;

  return false;
}

function reqX11(chan, screen, cb) {
  // asks server to start sending us X11 connections
  var cfg = {
    single: false,
    protocol: 'MIT-MAGIC-COOKIE-1',
    cookie: crypto.randomBytes(16).toString('hex'),
    screen: (typeof screen === 'number' ? screen : 0)
  };

  if (typeof screen === 'function')
    cb = screen;
  else if (typeof screen === 'object') {
    if (typeof screen.single === 'boolean')
      cfg.single = screen.single;
    if (typeof screen.screen === 'number')
      cfg.screen = screen.screen;
  }

  var wantReply = (typeof cb === 'function');

  if (chan.outgoing.state !== 'open') {
    wantReply && cb(new Error('Channel is not open'));
    return true;
  }

  if (wantReply) {
    chan._callbacks.push(function(had_err) {
      if (had_err) {
        return cb(had_err !== true
                  ? had_err
                  : new Error('Unable to request X11'));
      }

      chan._hasX11 = true;
      ++chan._client._acceptX11;
      chan.once('close', function() {
        if (chan._client._acceptX11)
          --chan._client._acceptX11;
      });

      cb();
    });
  }

  return chan._client._sshstream.x11Forward(chan.outgoing.id, cfg, wantReply);
}

function reqPty(chan, opts, cb) {
  var rows = 24;
  var cols = 80;
  var width = 640;
  var height = 480;
  var term = 'vt100';

  if (typeof opts === 'function')
    cb = opts;
  else if (typeof opts === 'object') {
    if (typeof opts.rows === 'number')
      rows = opts.rows;
    if (typeof opts.cols === 'number')
      cols = opts.cols;
    if (typeof opts.width === 'number')
      width = opts.width;
    if (typeof opts.height === 'number')
      height = opts.height;
    if (typeof opts.term === 'string')
      term = opts.term;
  }

  var wantReply = (typeof cb === 'function');

  if (chan.outgoing.state !== 'open') {
    wantReply && cb(new Error('Channel is not open'));
    return true;
  }

  if (wantReply) {
    chan._callbacks.push(function(had_err) {
      if (had_err) {
        return cb(had_err !== true
                  ? had_err
                  : new Error('Unable to request a pseudo-terminal'));
      }
      cb();
    });
  }

  return chan._client._sshstream.pty(chan.outgoing.id,
                                     rows,
                                     cols,
                                     height,
                                     width,
                                     term,
                                     null,
                                     wantReply);
}

function reqAgentFwd(chan, cb) {
  var wantReply = (typeof cb === 'function');

  if (chan.outgoing.state !== 'open') {
    wantReply && cb(new Error('Channel is not open'));
    return true;
  } else if (chan._client._agentFwdEnabled) {
    wantReply && cb(false);
    return true;
  }

  chan._client._agentFwdEnabled = true;

  chan._callbacks.push(function(had_err) {
    if (had_err) {
      chan._client._agentFwdEnabled = false;
      wantReply && cb(had_err !== true
                      ? had_err
                      : new Error('Unable to request agent forwarding'));
      return;
    }

    wantReply && cb();
  });

  return chan._client._sshstream.openssh_agentForward(chan.outgoing.id, true);
}

function reqShell(chan, cb) {
  if (chan.outgoing.state !== 'open') {
    cb(new Error('Channel is not open'));
    return true;
  }
  chan._callbacks.push(function(had_err) {
    if (had_err) {
      return cb(had_err !== true
                ? had_err
                : new Error('Unable to open shell'));
    }
    chan.subtype = 'shell';
    cb(undefined, chan);
  });

  return chan._client._sshstream.shell(chan.outgoing.id, true);
}

function reqExec(chan, cmd, opts, cb) {
  if (chan.outgoing.state !== 'open') {
    cb(new Error('Channel is not open'));
    return true;
  }
  chan._callbacks.push(function(had_err) {
    if (had_err) {
      return cb(had_err !== true
                ? had_err
                : new Error('Unable to exec'));
    }
    chan.subtype = 'exec';
    chan.allowHalfOpen = (opts.allowHalfOpen !== false);
    cb(undefined, chan);
  });

  return chan._client._sshstream.exec(chan.outgoing.id, cmd, true);
}

function reqEnv(chan, env) {
  if (chan.outgoing.state !== 'open')
    return true;
  var ret = true;
  var keys = Object.keys(env || {});
  var key;
  var val;

  for (var i = 0, len = keys.length; i < len; ++i) {
    key = keys[i];
    val = env[key];
    ret = chan._client._sshstream.env(chan.outgoing.id, key, val, false);
  }

  return ret;
}

function reqSubsystem(chan, name, cb) {
  if (chan.outgoing.state !== 'open') {
    cb(new Error('Channel is not open'));
    return true;
  }
  chan._callbacks.push(function(had_err) {
    if (had_err) {
      return cb(had_err !== true
                ? had_err
                : new Error('Unable to start subsystem: ' + name));
    }
    chan.subtype = 'subsystem';
    cb(undefined, chan);
  });

  return chan._client._sshstream.subsystem(chan.outgoing.id, name, true);
}

function onCHANNEL_OPEN(self, info) {
  // the server is trying to open a channel with us, this is usually when
  // we asked the server to forward us connections on some port and now they
  // are asking us to accept/deny an incoming connection on their side

  var localChan = false;
  var reason;

  function accept() {
    var chaninfo = {
      type: info.type,
      incoming: {
        id: localChan,
        window: Channel.MAX_WINDOW,
        packetSize: Channel.PACKET_SIZE,
        state: 'open'
      },
      outgoing: {
        id: info.sender,
        window: info.window,
        packetSize: info.packetSize,
        state: 'open'
      }
    };
    var stream = new Channel(chaninfo, self);

    self._sshstream.channelOpenConfirm(info.sender,
                                       localChan,
                                       Channel.MAX_WINDOW,
                                       Channel.PACKET_SIZE);
    return stream;
  }
  function reject() {
    if (reason === undefined) {
      if (localChan === false)
        reason = consts.CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE;
      else
        reason = consts.CHANNEL_OPEN_FAILURE.CONNECT_FAILED;
    }

    self._sshstream.channelOpenFail(info.sender, reason, '', '');
  }

  if (info.type === 'forwarded-tcpip'
      || info.type === 'x11'
      || info.type === 'auth-agent@openssh.com'
      || info.type === 'forwarded-streamlocal@openssh.com') {

    // check for conditions for automatic rejection
    var rejectConn = (
     (info.type === 'forwarded-tcpip'
      && self._forwarding[info.data.destIP
                         + ':'
                         + info.data.destPort] === undefined)
     || (info.type === 'forwarded-streamlocal@openssh.com'
         && self._forwardingUnix[info.data.socketPath] === undefined)
     || (info.type === 'x11' && self._acceptX11 === 0)
     || (info.type === 'auth-agent@openssh.com'
         && !self._agentFwdEnabled)
    );

    if (!rejectConn) {
      localChan = nextChannel(self);

      if (localChan === false) {
        self.config.debug('DEBUG: Client: Automatic rejection of incoming channel open: no channels available');
        rejectConn = true;
      } else
        self._channels[localChan] = true;
    } else {
      reason = consts.CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED;
      self.config.debug('DEBUG: Client: Automatic rejection of incoming channel open: unexpected channel open for: '
                        + info.type);
    }

    // TODO: automatic rejection after some timeout?

    if (rejectConn)
      reject();

    if (localChan !== false) {
      if (info.type === 'forwarded-tcpip') {
        if (info.data.destPort === 0) {
          info.data.destPort = self._forwarding[info.data.destIP
                                                + ':'
                                                + info.data.destPort];
        }
        self.emit('tcp connection', info.data, accept, reject);
      } else if (info.type === 'x11') {
        self.emit('x11', info.data, accept, reject);
      } else if (info.type === 'forwarded-streamlocal@openssh.com') {
        self.emit('unix connection', info.data, accept, reject);
      } else {
        agentQuery(self.config.agent, accept, reject);
      }
    }
  } else {
    // automatically reject any unsupported channel open requests
    self.config.debug('DEBUG: Client: Automatic rejection of incoming channel open: unsupported type: '
                      + info.type);
    reason = consts.CHANNEL_OPEN_FAILURE.UNKNOWN_CHANNEL_TYPE;
    reject();
  }
}

function trySign(sig, key) {
  try {
    return sig.sign(key);
  } catch (err) {
    return err;
  }
}

Client.Client = Client;
Client.Server = require('./server');
// pass some useful utilities on to end user (e.g. parseKey(), genPublicKey())
Client.utils = ssh2_streams.utils;
// expose useful SFTPStream constants for sftp server usage
Client.SFTP_STATUS_CODE = SFTPStream.STATUS_CODE;
Client.SFTP_OPEN_MODE = SFTPStream.OPEN_MODE;

module.exports = Client; // backwards compatibility
