var crypto = require('crypto'),
    Socket = require('net').Socket,
    EventEmitter = require('events').EventEmitter,
    inherits = require('util').inherits;

var SSH2Stream = require('ssh2-streams').SSH2Stream,
    SFTPStream = require('ssh2-streams').SFTPStream,
    consts = require('ssh2-streams').constants,
    parseKey = require('ssh2-streams').utils.parseKey,
    decryptKey = require('ssh2-streams').utils.decryptKey,
    genPublicKey = require('ssh2-streams').utils.genPublicKey;

var Channel = require('./channel'),
    agentQuery = require('./agent');

var MAX_CHANNEL = Math.pow(2, 32) - 1,
    RE_OPENSSH = /^OpenSSH_[56]/;

function DEBUG_NOOP(msg) {}

function Client() {
  if (!(this instanceof Client))
    return new Client();

  EventEmitter.call(this);

  this.config = {
    host: undefined,
    port: undefined,
    pingInterval: undefined,
    readyTimeout: undefined,
    compress: undefined,

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
  this._acceptX11 = undefined;
  this._acceptAgentFwd = undefined;
  this._curChan = undefined;
  this._remoteVer = undefined;

  this._sshstream = undefined;
  this._sock = undefined;
}
inherits(Client, EventEmitter);

Client.prototype.connect = function(cfg) {
  var self = this;

  this.config.host = cfg.hostname || cfg.host || 'localhost';
  this.config.port = cfg.port || 22;
  this.config.pingInterval = (typeof cfg.pingInterval === 'number'
                              && cfg.pingInterval >= 0
                              ? cfg.pingInterval
                              : 60000);
  this.config.readyTimeout = (typeof cfg.readyTimeout === 'number'
                              && cfg.readyTimeout >= 0
                              ? cfg.readyTimeout
                              : 10000);
  this.config.compress = cfg.compress;

  this.config.username = cfg.username || cfg.user;
  this.config.password = (typeof cfg.password === 'string'
                          ? cfg.password
                          : undefined);
  this.config.privateKey = (typeof cfg.privateKey === 'string'
                            || Buffer.isBuffer(cfg.privateKey)
                            ? cfg.privateKey
                            : undefined);
  this.config.publicKey = undefined;
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

  if (typeof this.config.username !== 'string')
    throw new Error('Invalid username');

  if (cfg.agentForward === true && !this.config.allowAgentFwd)
    throw new Error('You must set a valid agent path to allow agent forwarding');

  this._readyTimeout = setTimeout(function() {
    if (self._state !== 'authenticated' && self._state !== 'reexchg') {
      var err = new Error('Timed out while waiting for handshake');
      err.level = 'client-timeout';
      self.emit('error', err);
      self.destroy();
    }
  }, this.config.readyTimeout);

  this._channels = [];
  this._callbacks = [];
  this._forwarding = [];
  this._acceptX11 = 0;
  this._acceptAgentFwd = 0;
  this._curChan = -1;

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
        debug: (debug === DEBUG_NOOP ? undefined : debug)
      }),
      sock = this._sock = (cfg.sock || new Socket()),
      pinger;

  // drain stderr if we are connection hopping using an exec stream
  if (this._sock.stderr)
    this._sock.stderr.resume();

  stream.pipe(sock).pipe(stream);

  sock.on('connect', function() {
    debug('DEBUG: Client: Connected');
    self.emit('connect');
  }).on('timeout', function() {
    self.emit('timeout');
  }).on('error', function(err) {
    clearTimeout(self._readyTimeout);
    err.level = 'client-socket';
    self.emit('error', err);
  }).on('end', function() {
    clearTimeout(self._readyTimeout);
    clearInterval(pinger);
    self.emit('end');
  }).on('close', function(hasErr) {
    clearTimeout(self._readyTimeout);
    clearInterval(pinger);
    self.emit('close', hasErr);
  });
  stream.on('drain', function() {
    self.emit('drain');
  }).once('header', function(header) {
    self._remoteVer = header.versions.software;
  });

  if (typeof cfg.hostVerifier === 'function'
      && ~crypto.getHashes().indexOf(cfg.hostHash)) {
    var hashCb = cfg.hostVerifier,
        hasher = crypto.createHash(cfg.hostHash);
    stream.once('fingerprint', function(key, verify) {
      hasher.update(key, 'binary');
      verify(hashCb(hasher.digest('hex')));
    });
  }

  // begin authentication handling =============================================
  var auths = [],
      curAuth,
      agentKeys,
      agentKeyPos = 0;
  if (this.config.password !== undefined)
    auths.push('password');
  if (this.config.publicKey !== undefined)
    auths.push('publickey');
  if (this.config.agent !== undefined)
    auths.push('agent');
  if (this.config.tryKeyboard)
    auths.push('keyboard-interactive');
  auths.push('none');
  function tryNextAuth() {
    // TODO: better shutdown
    if (!auths.length) {
      stream.removeListener('USERAUTH_FAILURE', onUSERAUTH_FAILURE);
      stream.removeListener('USERAUTH_PK_OK', onUSERAUTH_PK_OK);
      var err = new Error('All configured authentication methods failed');
      err.level = 'client-authentication';
      self.emit('error', err);
      return self.end();
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
  function onUSERAUTH_PK_OK(keyAlgo, key) {
    if (curAuth === 'agent') {
      var agentKey = agentKeys[agentKeyPos],
          pubKeyFullType = agentKey.toString('ascii',
                                             4,
                                             4 + agentKey.readUInt32BE(0, true)),
          pubKeyType = pubKeyFullType.substring(4, 7);
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
            agentKeys = undefined;
            return tryNextAuth();
          }

          var signature;

          if (signed.toString('ascii', 4, 11) === 'ssh-' + pubKeyType) {
            // skip algoLen + algo + sigLen
            signature = signed.slice(4 + 7 + 4);
          } else
            signature = signed;

          cb(signature);
        });
      });
    } else if (curAuth === 'publickey') {
      stream.authPK(self.config.username,
                    self.config.publicKey,
                    function(buf, cb) {
        var signature = crypto.createSign(self.config.privateKey.type === 'rsa'
                                          ? 'RSA-SHA1'
                                          : 'DSA-SHA1');
        signature.update(buf);
        signature = signature.sign(self.config.privateKey.privateOrig, 'binary');
        signature = new Buffer(signature, 'binary');

        if (self.config.privateKey.type === 'dss' && signature.length > 40) {
          // this is a quick and dirty way to get from DER encoded r and s that
          // OpenSSL gives us, to just the bare values back to back (40 bytes
          // total) like OpenSSH (and possibly others) are expecting
          var newsig = new Buffer(40),
              rlen = signature[3],
              rstart = 4,
              sstart = 4 + 1 + rlen + 1;
          while (signature[rstart] === 0)
            ++rstart;
          while (signature[sstart] === 0)
            ++sstart;
          signature.copy(newsig, 0, rstart, rstart + 20);
          signature.copy(newsig, 20, sstart, sstart + 20);
          signature = newsig;
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
      if (++agentKeyPos >= agentKeys.length) {
        debug('DEBUG: Agent: No more keys left to try');
        debug('DEBUG: Client: ' + curAuth + ' auth failed');
        agentKeys = undefined;
        tryNextAuth();
      } else {
        debug('DEBUG: Agent: Trying key #' + (agentKeyPos + 1));
        stream.authPK(self.config.username, agentKeys[agentKeyPos]);
        stream.once('USERAUTH_PK_OK', onUSERAUTH_PK_OK);
      }
      return;
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

    pinger = setInterval(function pingerCb() {
      if (!stream.ping()) {
        clearInterval(pinger);
        stream.once('drain', function() {
          pinger = setInterval(pingerCb, self.config.pingInterval);
        });
      }
    }, self.config.pingInterval);

    clearTimeout(self._readyTimeout);

    self.emit('ready');
  }).on('USERAUTH_FAILURE', onUSERAUTH_FAILURE);
  // end authentication handling ===============================================

  // handle initial handshake completion
  stream.once('NEWKEYS', function() {
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

  // handle responses for tcpip-forward requests
  stream.on('REQUEST_SUCCESS', function(data) {
    if (self._callbacks.length)
      self._callbacks.shift()(false, data);
  }).on('REQUEST_FAILURE', function() {
    if (self._callbacks.length)
      self._callbacks.shift()(true);
  });

  if (!cfg.sock) {
    debug('DEBUG: Client: Trying '
          + this.config.host
          + ' on port '
          + this.config.port
          + ' ...');
    this._sock.connect(this.config.port, this.config.host);
    this._sock.setNoDelay(true);
    this._sock.setMaxListeners(0);
    this._sock.setTimeout(typeof cfg.timeout === 'number' ? cfg.timeout : 0);
    if (typeof cfg.keepAliveDelay === 'number')
      this._sock.setKeepAlive(true, cfg.keepAliveDelay);
    else
      this._sock.setKeepAlive(true);
  }
};

Client.prototype.end = function() {
  return this._sshstream.disconnect();
};

Client.prototype.destroy = function() {
  this._sock && this._sock.destroy();
};

Client.prototype.exec = function(cmd, opts, cb) {
  if (typeof opts === 'function') {
    cb = opts;
    opts = {};
  }

  var self = this,
      extraOpts = { allowHalfOpen: (opts.allowHalfOpen ? true : false) };

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
        || (opts && opts.agentForward === true)) {
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
  // start an interactive terminal/shell session
  var self = this;

  if (typeof wndopts === 'function') {
    cb = wndopts;
    wndopts = opts = undefined;
  } else if (typeof opts === 'function') {
    cb = opts;
    opts = undefined;
  }
  if (wndopts && wndopts.x11 !== undefined) {
    opts = wndopts;
    wndopts = undefined;
  }

  return openChannel(this, 'session', function(err, chan) {
    if (err)
      return cb(err);

    reqPty(chan, wndopts, function(err) {
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
        || (opts && opts.agentForward === true)) {
        todo.push(function() {
          reqAgentFwd(chan, reqCb);
        });
      }

      if (typeof opts === 'object') {
        if (typeof opts.x11 === 'object'
            || opts.x11 === 'number'
            || opts.x11 === true)
          todo.push(function() { reqX11(chan, opts.x11, reqCb); });
      }

      todo.push(function() { reqShell(chan, cb); });
      todo.shift()();
    });
  });
};

Client.prototype.subsys = function(name, cb) {
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
  var self = this;

  // start an SFTP session
  return openChannel(this, 'session', function(err, chan) {
    if (err)
      return cb(err);

    reqSubsystem(chan, 'sftp', function(err, stream) {
      if (err)
        return cb(err);

      var serverIdentRaw = self._sshstream._state.incoming.identRaw;
      var sftp = new SFTPStream(null, serverIdentRaw);

      function onError(err) {
        sftp.removeListener('ready', onReady);
        cb(err);
      }

      function onReady() {
        sftp.removeListener('error', onError);
        cb(undefined, sftp);
      }

      sftp.once('error', onError)
          .once('ready', onReady)
          .once('close', function() {
            stream.end();
          });
    });
  });
};

Client.prototype.noMoreSessions = function(cb) {
  var wantReply = (typeof cb === 'function');

  if (!this.config.strictVendor
      || (this.config.strictVendor && RE_OPENSSH.test(this._remoteVer))) {
    if (wantReply) {
      this._callbacks.push(function(had_err) {
        if (had_err)
          return cb(new Error('Unable to disable future sessions'));

        cb();
      });
    }

    return this._sshstream.noMoreSessions(wantReply);
  } else if (wantReply) {
    process.nextTick(function() {
      cb(new Error('strictVendor enabled and server is not OpenSSH or compatible version'));
    });
  }

  return true;
};

Client.prototype.forwardIn = function(bindAddr, bindPort, cb) {
  // send a request for the server to start forwarding TCP connections to us
  // on a particular address and port

  var self = this,
      wantReply = (typeof cb === 'function');

  if (wantReply) {
    this._callbacks.push(function(had_err, data) {
      if (had_err)
        return cb(new Error('Unable to bind ' + bindAddr + ':' + bindPort));

      if (data && data.length)
        bindPort = data.readUInt32BE(0, true);

      self._forwarding.push(bindAddr + ':' + bindPort);

      cb(undefined, bindPort);
    });
  }

  return this._sshstream.tcpipForward(bindAddr, bindPort, wantReply);
};

Client.prototype.unforwardIn = function(bindAddr, bindPort, cb) {
  // send a request to stop forwarding us new connections for a particular
  // address and port

  var self = this,
      wantReply = (typeof cb === 'function');

  if (wantReply) {
    this._callbacks.push(function(had_err) {
      if (had_err)
        return cb(new Error('Unable to unbind ' + bindAddr + ':' + bindPort));

      self._forwarding.splice(self._forwarding.indexOf(bindAddr + ':' + bindPort),
                              1);
      cb();
    });
  }

  return this._sshstream.cancelTcpipForward(bindAddr, bindPort, wantReply);
};

Client.prototype.forwardOut = function(srcIP, srcPort, dstIP, dstPort, cb) {
  // send a request to forward a TCP connection to the server

  var cfg = {
    srcIP: srcIP,
    srcPort: srcPort,
    dstIP: dstIP,
    dstPort: dstPort
  };

  return openChannel(this, 'direct-tcpip', cfg, cb);
};

function openChannel(self, type, opts, cb) {
  // ask the server to open a channel for some purpose
  // (e.g. session (sftp, exec, shell), or forwarding a TCP connection
  var localChan = nextChannel(self),
      initWindow = Channel.MAX_WINDOW,
      maxPacket = Channel.PACKET_SIZE,
      ret;

  if (localChan === false)
    return cb(new Error('No free channels available'));

  if (typeof opts === 'function') {
    cb = opts;
    opts = {};
  }

  self._channels.push(localChan);

  self._sshstream.once('CHANNEL_OPEN_CONFIRMATION:' + localChan, function(info) {
    // Since EventEmitters do not actually *delete* event names in the
    // emitter's event array, we must do this manually so as not to leak
    // our custom, channel-specific event names.
    delete self._sshstream._events['CHANNEL_OPEN_CONFIRMATION:' + localChan];
    delete self._sshstream._events['CHANNEL_OPEN_FAILURE:' + localChan];

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
  }).once('CHANNEL_OPEN_FAILURE:' + localChan, function(info) {
    // Since EventEmitters do not actually *delete* event names in the
    // emitter's event array, we must do this manually so as not to leak
    // our custom, channel-specific event names.
    delete self._sshstream._events['CHANNEL_OPEN_CONFIRMATION:' + localChan];
    delete self._sshstream._events['CHANNEL_OPEN_FAILURE:' + localChan];

    self._channels.splice(self._channels.indexOf(localChan), 1);
    var err = new Error('(SSH) Channel open failure: ' + info.description);
    err.reason = info.reason;
    err.lang = info.lang;
    cb(err);
  });

  if (type === 'session')
    ret = self._sshstream.session(localChan, initWindow, maxPacket);
  else if (type === 'direct-tcpip')
    ret = self._sshstream.directTcpip(localChan, initWindow, maxPacket, opts);

  return ret;
}

function nextChannel(self) {
  // get the next available channel number

  // optimized path
  if (self._curChan < MAX_CHANNEL)
    if (++self._curChan <= MAX_CHANNEL)
      return self._curChan;

  // slower lookup path
  for (var i = 0; i < MAX_CHANNEL; ++i)
    if (self._channels.indexOf(i))
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

  if (wantReply) {
    chan._callbacks.push(function(had_err) {
      if (had_err)
        return cb(new Error('Unable to request X11'));

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
  var rows = 24,
      cols = 80,
      width = 640,
      height = 480,
      term = 'vt100';

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

  if (wantReply) {
    chan._callbacks.push(function(had_err) {
      if (had_err)
        return cb(new Error('Unable to request a pseudo-terminal'));
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

  if (wantReply) {
    chan._callbacks.push(function(had_err) {
      if (had_err)
        return cb(new Error('Unable to request agent forwarding'));

      chan._hasAgentFwd = true;
      ++chan._client._acceptAgentFwd;
      chan.once('close', function() {
        if (chan._client._acceptAgentFwd)
          --chan._client._acceptAgentFwd;
      });

      cb();
    });
  }

  return chan._client._sshstream.agentForward(chan.outgoing.id, wantReply);
}

function reqShell(chan, cb) {
  chan._callbacks.push(function(had_err) {
    if (had_err)
      return cb(new Error('Unable to open shell'));
    chan.subtype = 'shell';
    cb(undefined, chan);
  });

  return chan._client._sshstream.shell(chan.outgoing.id, true);
}

function reqExec(chan, cmd, opts, cb) {
  chan._callbacks.push(function(had_err) {
    if (had_err)
      return cb(new Error('Unable to exec'));
    chan.subtype = 'exec';
    chan.allowHalfOpen = (opts.allowHalfOpen ? true : false);
    cb(undefined, chan);
  });

  return chan._client._sshstream.exec(chan.outgoing.id, cmd, true);
}

function reqEnv(chan, env) {
  var ret = true,
      keys = Object.keys(env || {}),
      key,
      val;

  for (var i = 0, len = keys.length; i < len; ++i) {
    key = keys[i];
    val = env[key];
    ret = chan._client._sshstream.env(chan.outgoing.id, key, val, false);
  }

  return ret;
}

function reqSubsystem(chan, name, cb) {
  chan._callbacks.push(function(had_err) {
    if (had_err)
      return cb(new Error('Unable to start subsystem: ' + name));
    chan.subtype = 'subsystem';
    cb(undefined, chan);
  });

  return chan._client._sshstream.subsystem(chan.outgoing.id, name, true);
}

function onCHANNEL_OPEN(self, info) {
  // the server is trying to open a channel with us, this is usually when
  // we asked the server to forward us connections on some port and now they
  // are asking us to accept/deny an incoming connection on their side

  var localChan = false,
      reason;

  function accept() {
    var chaninfo = {
      type: info.type,
      incoming: {
        id: localChan,
        window: Channel.MAX_WINDOW,
        packetSize: Channel.MAX_WINDOW,
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
                                       Channel.MAX_WINDOW);
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
      || info.type === 'auth-agent@openssh.com') {
    // check for conditions for automatic rejection
    var rejectConn = ((info.type === 'forwarded-tcpip'
                       && self._forwarding.indexOf(info.data.destIP
                                                   + ':'
                                                   + info.data.destPort) === -1)
                      || (info.type === 'x11' && self._acceptX11 === 0)
                      || (info.type === 'auth-agent@openssh.com'
                          && self._acceptAgentFwd === 0));
    if (!rejectConn) {
      localChan = nextChannel(self);

      if (localChan === false) {
        self.config.debug('DEBUG: Client: Automatic rejection of incoming channel open: no channels available');
        rejectConn = true;
      } else
        self._channels.push(localChan);
    } else {
      reason = consts.CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED;
      self.config.debug('DEBUG: Client: Automatic rejection of incoming channel open: unexpected channel open for: '
                        + info.type);
    }

    // TODO: automatic rejection after some timeout?

    if (rejectConn)
      reject();

    if (localChan !== false) {
      if (info.type === 'forwarded-tcpip')
        self.emit('tcp connection', info.data, accept, reject);
      else if (info.type === 'x11')
        self.emit('x11', info.data, accept, reject);
      else
        agentQuery(self.config.agent, accept, reject);
    }
  } else {
    // automatically reject any unsupported channel open requests
    self.config.debug('DEBUG: Client: Automatic rejection of incoming channel open: unsupported type: '
                      + info.type);
    reason = consts.CHANNEL_OPEN_FAILURE.UNKNOWN_CHANNEL_TYPE;
    reject();
  }
}

Client.Client = Client;
Client.Server = require('./server');
module.exports = Client; // backwards compatibility
