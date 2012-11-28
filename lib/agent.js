var Socket = require('net').Socket;

var REQUEST_IDENTITIES = 11,
    IDENTITIES_ANSWER = 12,
    SIGN_REQUEST = 13,
    SIGN_RESPONSE = 14,
    FAILURE = 5;

var OLD_SIGNATURE = 1; // for ssh-dss keys

module.exports = function(sockPath, key, keyType, data, cb) {
  var sock = new Socket(), error,
      sig, keylen = 0, datalen, flags, isSigning = Buffer.isBuffer(key);

  if (isSigning) {
    keylen = key.length;
    datalen = data.length;
    flags = (keyType === 'dss' ? OLD_SIGNATURE : 0);
  } else {
    cb = key;
    key = undefined;
  }

  sock.once('connect', function() {
    var buf;
    if (isSigning) {
      /*
        byte        SSH2_AGENTC_SIGN_REQUEST
        string      key_blob
        string      data
        uint32      flags (SSH_AGENT_OLD_SIGNATURE for ssh-dss key)
      */
      var p = 9;
      buf = new Buffer(4 + 1 + 4 + keylen + 4 + datalen + 4);
      buf.writeUInt32BE(buf.length - 4, 0, true);
      buf[4] = SIGN_REQUEST;
      buf.writeUInt32BE(keylen, 5, true);
      key.copy(buf, p);
      buf.writeUInt32BE(datalen, p += keylen, true);
      data.copy(buf, p += 4);
      buf.writeUInt32BE(flags, p += datalen, true);
      sock.write(buf);
    } else {
      /*
        byte        SSH2_AGENTC_REQUEST_IDENTITIES
      */
      sock.write(new Buffer([0, 0, 0, 1, REQUEST_IDENTITIES]));
    }
  });
  var type, count = 0,
      siglen = 0,
      nkeys = 0, keys, comlen = 0, comment = false;
  sock.on('data', function(chunk) {
    for (var i = 0, len = chunk.length; i < len; ++i) {
      if (type === undefined) {
        // skip over packet length
        if (++count === 5) {
          type = chunk[i];
          count = 0;
        }
      } else if (type === SIGN_RESPONSE) {
        /*
          byte        SSH2_AGENT_SIGN_RESPONSE
          string      signature_blob
        */
        if (!sig) {
          siglen <<= 8;
          siglen += chunk[i];
          if (++count === 4) {
            sig = new Buffer(siglen);
            count = 0;
          }
        } else {
          sig[count] = chunk[i];
          if (++count === siglen) {
            sock.removeAllListeners('data');
            return sock.destroy();
          }
        }
      } else if (type === IDENTITIES_ANSWER) {
        /*
          byte        SSH2_AGENT_IDENTITIES_ANSWER
          uint32      num_keys

        Followed by zero or more consecutive keys, encoded as:

          string      public key blob
          string      public key comment
        */
        if (keys === undefined) {
          nkeys <<= 8;
          nkeys += chunk[i];
          if (++count === 4) {
            keys = new Array(nkeys);
            count = 0;
            if (nkeys === 0) {
              sock.removeAllListeners('data');
              return sock.destroy();
            }
          }
        } else {
          if (!key) {
            keylen <<= 8;
            keylen += chunk[i];
            if (++count === 4) {
              key = new Buffer(keylen);
              count = 0;
            }
          } else if (comment === false) {
            key[count] = chunk[i];
            if (++count === keylen) {
              keys[nkeys - 1] = key;
              keylen = 0;
              count = 0;
              comment = true;
              if (--nkeys === 0) {
                key = undefined;
                sock.removeAllListeners('data');
                return sock.destroy();
              }
            }
          } else if (comment === true) {
            comlen <<= 8;
            comlen += chunk[i];
            if (++count === 4) {
              count = 0;
              comlen = 0;
              if (comlen > 0)
                comment = comlen;
              else {
                key = undefined;
                comment = false;
              }
            }
          } else {
            // skip comments
            if (++count === comment) {
              comment = false;
              count = 0;
              key = undefined;
            }
          }
        }
      } else if (type === FAILURE) {
        if (isSigning)
          error = new Error('Agent unable to sign data');
        else
          error = new Error('Unable to retrieve list of keys from agent');
        sock.removeAllListeners('data');
        return sock.destroy();
      }
    }
  });
  sock.once('error', function(err) {
    error = err;
  });
  sock.once('close', function(had_err) {
    if (error)
      cb(error);
    else if ((isSigning && !sig) || (!isSigning && !keys))
      cb(new Error('Unexpected disconnection from agent'));
    else if (isSigning && sig)
      cb(undefined, sig);
    else if (!isSigning && keys)
      cb(undefined, keys);
  });

  sock.connect(sockPath);
};
