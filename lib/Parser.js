var inspect = require('util').inspect;

// TODO: * Filter control codes from strings
//          (as per http://tools.ietf.org/html/rfc4251#section-9.2)

var crypto = require('crypto');
var consts = require('./Parser.constants');
var inherits = require('util').inherits,
    EventEmitter = require('events').EventEmitter;

var MESSAGE = consts.MESSAGE;

// parser states
var I = 0;
var STATE_INIT = I++,
    STATE_GREETING = I++,
    STATE_HEADER = I++,
    STATE_PACKETBEFORE = I++,
    STATE_PACKET = I++,
    STATE_PACKETDATA = I++,
    STATE_PACKETDATAVERIFY = I++,
    STATE_PACKETDATAAFTER = I++;

var MAX_SEQNO = 4294967295;

// common byte arrays for matching purposes
var EXP_BYTES_CRLF = bytes('\r\n'),
    EXP_BYTES_SSHHEADER = bytes('SSH-'),
    EXP_BYTES_SSHHEADERGREETING = EXP_BYTES_CRLF.concat(EXP_BYTES_SSHHEADER);

var EXP_ACTION_NONE = 0, // skip expected bytes
    EXP_ACTION_BUFFER = 1, // buffer expected bytes
    EXP_ACTION_EMIT = 2; // emit expected bytes as some event

var EXP_TYPE_MATCH = 0, // waits for byte array match
    EXP_TYPE_BYTES = 1; // waits until n bytes have been seen

function Parser() {
  this.reset();
}
inherits(Parser, EventEmitter);

Parser.prototype.execute = function(b, start, end) {
  start || (start = 0);
  end || (end = b.length);

  var i = start, buffer, skipDecrypt = false, j, info, buf, lang, message;
  while (true) {
    // begin expecting bytes handlers
    if (this._expectLen) {
      if (i >= end)
        break;
      // simple case: just counting n bytes
      if (this._expectType === EXP_TYPE_BYTES) {
        if (this._expectBuf) {
          this._expectBuf[this._expectPtr++] = b[i++];
          if (this._expectPtr === this._expectLen) {
            buffer = this._expectBuf;
            this._expectBuf = undefined;
            this._expectBufLen = 0;
            this._expectPtr = 0;
            this._expectLen = undefined;
            this._expect = undefined;
            this._expectType = undefined;
            this._expectEmit = undefined;
            start = i;
          }
        } else
          ++i;
        continue;
      }
      // complex case: searching for byte array match
      if (b[i] === this._expect[this._expectPtr])
        ++this._expectPtr;
      else {
        if (this._expectPtr > 0) {
          if (i - start > 0) {
            buf = new Buffer(i - start);
            b.copy(buf, 0, start, start + (i - start));
          } else {
            buf = new Buffer(this._expectPtr);
            for (j = 0; j < this._expectPtr; ++j)
              buf[j] = this._expect[j];
          }
          if (this._expectEmit !== undefined)
            this.emit(this._expectEmit, buf);
          else if (this._expectBuf !== undefined) {
            this._expectBuf.push(buf);
            this._expectBufLen += buf.length;
          }
          start = i;
        }
        this._expectPtr = 0;
        if (b[i] === this._expect[this._expectPtr])
          ++this._expectPtr;
      }
      ++i;
      if (this._expectPtr < this._expectLen) {
        if (this._expectPtr === 0 && i === end) {
          if (this._expectEmit !== undefined)
            this.emit(this._expectEmit, (start === 0 ? b : b.slice(start)));
          else if (this._expectBuf !== undefined) {
            buf = (start === 0 ? b : b.slice(start));
            this._expectBuf.push(buf);
            this._expectBufLen += buf.length;
          }
        }
        continue;
      } else {
        var leftovers = i - this._expectLen - start;
        if (leftovers < 0)
          leftovers = 0;
        if (this._expectEmit !== undefined && leftovers) {
          this.emit(this._expectEmit,
                    b.slice(start, start + leftovers));
        } else if (this._expectBuf !== undefined) {
          var expbuflen = this._expectBuf.length;
          if (expbuflen === 0) {
            if (leftovers)
              this._expectBuf = b.slice(start, start + leftovers);
            else
              this._expectBuf = null;
          } else if (expbuflen === 1 && leftovers === 0)
            this._expectBuf = this._expectBuf[0];
          else {
            buf = new Buffer(this._expectBufLen + leftovers);
            var pos = 0, len = this._expectBuf.length;
            for (j = 0; j < len; ++j) {
              this._expectBuf[j].copy(buf, pos);
              pos += this._expectBuf[j].length;
            }
            if (leftovers)
              b.copy(buf, pos, start, start + leftovers);
            this._expectBuf = buf;
          }
        }
        buffer = this._expectBuf;
        this._expectBuf = undefined;
        this._expectBufLen = 0;
        this._expectPtr = 0;
        this._expectLen = undefined;
        this._expect = undefined;
        this._expectType = undefined;
        this._expectEmit = undefined;
        start = i;
      }
    }
    // end expecting bytes handlers
    switch (this._state) {
      case STATE_INIT:
        // retrieve all bytes that may come before the header
        this.expect(EXP_BYTES_SSHHEADER, EXP_ACTION_BUFFER);
        this._state = STATE_GREETING;
        break;
      case STATE_GREETING:
        if (buffer && buffer.length)
          this._greeting = buffer;
        // retrieve the identification bytes after the "SSH-" header
        this.expect(EXP_BYTES_CRLF, EXP_ACTION_BUFFER);
        this._state = STATE_HEADER;
        break;
      case STATE_HEADER:
        buffer = buffer.toString('ascii');
        var idxDash = buffer.indexOf('-'),
            idxSpace = buffer.indexOf(' ');
        var header = {
          // RFC says greeting SHOULD be utf8
          greeting: (this._greeting ? this._greeting.toString('utf8') : null),
          ident_raw: 'SSH-' + buffer,
          versions: {
            protocol: buffer.substr(0, idxDash),
            server: (idxSpace === -1
                     ? buffer.substr(idxDash + 1)
                     : buffer.substring(idxDash + 1, idxSpace))
          },
          comments: (idxSpace > -1 ? buffer.substring(idxSpace + 1) : undefined)
        };
        this._greeting = undefined;
        this.emit('header', header);
        if (this._state === STATE_INIT) {
          // we reset from an event handler
          // possibly due to an unsupported SSH protocol version?
          return;
        }
        this._state = STATE_PACKETBEFORE;
        break;
      case STATE_PACKETBEFORE:
        // wait for the right number of bytes so we can determine the incoming
        // packet length
        this.expect(this._decryptSize, EXP_ACTION_BUFFER);
        this._state = STATE_PACKET;
        break;
      case STATE_PACKET:
        if (this._decrypt)
          buffer = this.decrypt(buffer);
        this._pktLen = buffer.readUInt32BE(0, true); // reset
        this._padLen = buffer[4]; // reset
        var remainLen = this._pktLen + 4 - this._decryptSize;
        if (remainLen > 0) {
          this._pktExtra = buffer.slice(5); // reset
          // grab the rest of the packet
          this.expect(remainLen, EXP_ACTION_BUFFER);
          this._state = STATE_PACKETDATA;
        } else if (remainLen < 0)
          this._state = STATE_PACKETBEFORE;
        else {
          // entire message fit into one block
          skipDecrypt = true;
          this._state = STATE_PACKETDATA;
          continue;
        }
        break;
      case STATE_PACKETDATA:
        if (this._decrypt && !skipDecrypt)
          buffer = this.decrypt(buffer);
        else if (skipDecrypt)
          skipDecrypt = false;
        var padStart = this._pktLen - this._padLen - 1;
        if (this._pktExtra) {
          buf = new Buffer(this._pktExtra.length + buffer.length);
          this._pktExtra.copy(buf);
          buffer.copy(buf, this._pktExtra.length);
          this._payload = buf.slice(0, padStart); // reset
        } else {
          // entire message fit into one block
          buf = buffer;
          this._payload = buf.slice(5, 5 + padStart); // reset
        }
        if (this._hmacSize !== undefined) { // reset
          // wait for hmac hash
          this.expect(this._hmacSize, EXP_ACTION_BUFFER);
          this._state = STATE_PACKETDATAVERIFY;
          this._packet = buf; // reset
        } else
          this._state = STATE_PACKETDATAAFTER;
        this._pktExtra = undefined;
        buf = undefined;
        break;
      case STATE_PACKETDATAVERIFY:
        // verify packet data integrity
        //if (this.hmacVerify(buffer)) {
          this._state = STATE_PACKETDATAAFTER;
          this._packet = undefined;
        /*} else {
          this.emit('error', new Error('Invalid HMAC'));
          return this.reset();
        }*/
        break;
      case STATE_PACKETDATAAFTER:
        var payload = this._payload;
        if (++this._seqno > MAX_SEQNO) // reset
          this._seqno = 0;
        this.emit('packet', MESSAGE[payload[0]], payload[0], payload.slice(1));

        // payload[0] === packet type
        switch (payload[0]) {
          case MESSAGE.IGNORE:
            /*
              byte      SSH_MSG_IGNORE
              string    data
            */
            break;
          case MESSAGE.DISCONNECT:
            /*
              byte      SSH_MSG_DISCONNECT
              uint32    reason code
              string    description in ISO-10646 UTF-8 encoding
              string    language tag
            */
            var reason = payload.readUInt32BE(1, true),
                description = readString(payload, 5, 'utf8');
            lang = readString(payload, payload._pos, 'ascii');
            this.emit('DISCONNECT', DISCONNECT_REASON[reason],
                      reason, description, lang);
            break;
          case MESSAGE.DEBUG:
            /*
              byte      SSH_MSG_DEBUG
              boolean   always_display
              string    message in ISO-10646 UTF-8 encoding
              string    language tag
            */
            message = readString(payload, 2, 'utf8');
            lang = readString(payload, payload._pos, 'ascii');
            this.emit('DEBUG', message, lang);
            break;
          case MESSAGE.KEXINIT:
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
            var init = this._kexinit_info = { // reset
              algorithms: {
                kex: undefined,
                srvHostKey: undefined,
                cs: {
                  encrypt: undefined,
                  mac: undefined,
                  compress: undefined
                },
                sc: {
                  encrypt: undefined,
                  mac: undefined,
                  compress: undefined
                }
              },
              languages: {
                cs: undefined,
                sc: undefined
              }
            };
            init.algorithms.kex = readList(payload, 17);
            init.algorithms.srvHostKey = readList(payload, payload._pos);
            init.algorithms.cs.encrypt = readList(payload, payload._pos);
            init.algorithms.sc.encrypt = readList(payload, payload._pos);
            init.algorithms.cs.mac = readList(payload, payload._pos);
            init.algorithms.sc.mac = readList(payload, payload._pos);
            init.algorithms.cs.compress = readList(payload, payload._pos);
            init.algorithms.sc.compress = readList(payload, payload._pos);
            init.languages.cs = readList(payload, payload._pos);
            init.languages.sc = readList(payload, payload._pos);
            this._kexinit = payload; // reset
            this.emit('KEXINIT', init);
            break;
          case MESSAGE.KEXDH_REPLY:
            /*
              byte      SSH_MSG_KEXDH_REPLY
              string    server public host key and certificates (K_S)
              mpint     f
              string    signature of H
            */
            info = {
              hostkey: readString(payload, 1),
              hostkey_format: undefined,
              pubkey: readString(payload, payload._pos),
              sig: readString(payload, payload._pos),
              sig_format: undefined
            };
            info.hostkey_format = readString(info.hostkey, 0, 'ascii');
            info.sig_format = readString(info.sig, 0, 'ascii');
            this.emit('KEXDH_REPLY', info);
            break;
          case MESSAGE.NEWKEYS:
            /*
              byte      SSH_MSG_NEW_KEYS
            */
            this.emit('NEWKEYS');
            break;
          case MESSAGE.SERVICE_ACCEPT:
            /*
              byte      SSH_MSG_NEW_KEYS
            */
            var serviceName = readString(payload, 1, 'ascii');
            this.emit('SERVICE_ACCEPT', serviceName);
            break;
          case MESSAGE.USERAUTH_SUCCESS:
            /*
              byte      SSH_MSG_USERAUTH_SUCCESS
            */
            this.emit('USERAUTH_SUCCESS');
            break;
          case MESSAGE.USERAUTH_FAILURE:
            /*
              byte      SSH_MSG_USERAUTH_FAILURE
              name-list    authentications that can continue
              boolean      partial success
            */
            var auths = readString(payload, 1, 'ascii').split(','),
                partSuccess = (payload[payload._pos] !== 0);
            this.emit('USERAUTH_FAILURE', auths, partSuccess);
            break;
          case MESSAGE.USERAUTH_BANNER:
            /*
              byte      SSH_MSG_USERAUTH_BANNER
              string    message in ISO-10646 UTF-8 encoding
              string    language tag
            */
            message = readString(payload, 1, 'utf8');
            lang = readString(payload, payload._pos, 'utf8');
            this.emit('USERAUTH_BANNER', message, lang);
            break;
          case 60: // user auth context-specific messages
            if (this._authMethod === 'password') {
              /*
                byte      SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
                string    prompt in ISO-10646 UTF-8 encoding
                string    language tag
              */
              message = readString(payload, 1, 'utf8');
              lang = readString(payload, payload._pos, 'utf8');
              this.emit('USERAUTH_PASSWD_CHANGEREQ', message, lang);
            } else if (this._authMethod === 'keyboard-interactive') {
              /*
                byte      SSH_MSG_USERAUTH_INFO_REQUEST
                string    name (ISO-10646 UTF-8)
                string    instruction (ISO-10646 UTF-8)
                string    language tag -- MAY be empty
                int       num-prompts
                string    prompt[1] (ISO-10646 UTF-8)
                boolean   echo[1]
                ...
                string    prompt[num-prompts] (ISO-10646 UTF-8)
                boolean   echo[num-prompts]
              */
              var name, instr, nprompts;

              name = readString(payload, 1, 'utf8');
              instr = readString(payload, payload._pos, 'utf8');
              lang = readString(payload, payload._pos, 'utf8');
              nprompts = payload.readUInt32BE(payload._pos, true);

              payload._pos += 4;
              if (nprompts > 0) {
                var prompts = new Array(nprompts);
                for (var prompt = 0; prompt < nprompts; ++prompt) {
                  prompts.push({
                    prompt: readString(payload, payload._pos, 'utf8'),
                    echo: (payload[payload._pos++] !== 0)
                  });
                }
                this.emit('USERAUTH_INFO_REQUEST', name, instr, lang, prompts);
              } else
                this.emit('USERAUTH_INFO_REQUEST', name, instr, lang);
            } else if (this._authMethod === 'pubkey') {
              /*
                byte      SSH_MSG_USERAUTH_PK_OK
                string    public key algorithm name from the request
                string    public key blob from the request
              */
              this.emit('USERAUTH_PK_OK');
            }
            break;
          case MESSAGE.CHANNEL_OPEN:
            /*
              byte      SSH_MSG_CHANNEL_OPEN
              string    channel type in US-ASCII only
              uint32    sender channel
              uint32    initial window size
              uint32    maximum packet size
              ....      channel type specific data follows
            */
            var chanType = readString(payload, 1, 'ascii');
            if (chanType === 'forwarded-tcpip') {
              /*
                string    address that was connected
                uint32    port that was connected
                string    originator IP address
                uint32    originator port
              */
              var channel = {
                type: chanType,
                sender: payload.readUInt32BE(payload._pos, true),
                window: payload.readUInt32BE(payload._pos += 4, true),
                packetSize: payload.readUInt32BE(payload._pos += 4, true),
                data: {
                  destIP: readString(payload, payload._pos += 4, 'ascii'),
                  destPort: payload.readUInt32BE(payload._pos, true),
                  srcIP: readString(payload, payload._pos += 4, 'ascii'),
                  srcPort: payload.readUInt32BE(payload._pos, true)
                }
              };
              this.emit('CHANNEL_OPEN', channel);
            }
            break;
          case MESSAGE.CHANNEL_OPEN_CONFIRMATION:
            /*
              byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
              uint32    recipient channel
              uint32    sender channel
              uint32    initial window size
              uint32    maximum packet size
              ....      channel type specific data follows
            */
            // "The 'recipient channel' is the channel number given in the
            // original open request, and 'sender channel' is the channel number
            // allocated by the other side."
            info = {
              recipient: payload.readUInt32BE(1, true),
              sender: payload.readUInt32BE(5, true),
              window: payload.readUInt32BE(9, true),
              packetSize: payload.readUInt32BE(13, true),
              data: undefined
            };
            if (payload.length > 17)
              info.data = payload.slice(17);
            this.emit('CHANNEL_OPEN_CONFIRMATION:' + info.recipient, info);
            break;
          case MESSAGE.CHANNEL_OPEN_FAILURE:
            /*
              byte      SSH_MSG_CHANNEL_OPEN_FAILURE
              uint32    recipient channel
              uint32    reason code
              string    description in ISO-10646 UTF-8 encoding
              string    language tag
            */
            payload._pos = 9;
            info = {
              recipient: payload.readUInt32BE(1, true),
              reasonCode: payload.readUInt32BE(5, true),
              reason: undefined,
              description: readString(payload, payload._pos, 'utf8'),
              lang: readString(payload, payload._pos, 'utf8')
            };
            info.reason = CHANNEL_OPEN_FAILURE[info.reasonCode];
            this.emit('CHANNEL_OPEN_FAILURE:' + info.recipient, info);
            break;
          case MESSAGE.CHANNEL_DATA:
            /*
              byte      SSH_MSG_CHANNEL_DATA
              uint32    recipient channel
              string    data
            */
            this.emit('CHANNEL_DATA:' + payload.readUInt32BE(1, true),
                      readString(payload, 5));
            break;
          case MESSAGE.CHANNEL_EXTENDED_DATA:
            /*
              byte      SSH_MSG_CHANNEL_EXTENDED_DATA
              uint32    recipient channel
              uint32    data_type_code
              string    data
            */
            this.emit('CHANNEL_EXTENDED_DATA:' + payload.readUInt32BE(1, true),
                      payload.readUInt32BE(5, true),
                      readString(payload, 9));
            break;
          case MESSAGE.CHANNEL_SUCCESS:
            /*
              byte      SSH_MSG_CHANNEL_SUCCESS
              uint32    recipient channel
            */
            this.emit('CHANNEL_SUCCESS:' + payload.readUInt32BE(1, true));
            break;
          case MESSAGE.CHANNEL_FAILURE:
            /*
              byte      SSH_MSG_CHANNEL_FAILURE
              uint32    recipient channel
            */
            this.emit('CHANNEL_FAILURE:' + payload.readUInt32BE(1, true));
            break;
          case MESSAGE.CHANNEL_REQUEST:
            var recipient = payload.readUInt32BE(1, true),
                request = readString(payload, 5, 'ascii');
            if (request === 'exit-status') {
              /*
                byte      SSH_MSG_CHANNEL_REQUEST
                uint32    recipient channel
                string    "exit-status"
                boolean   FALSE
                uint32    exit_status
              */
              info = {
                recipient: recipient,
                request: request,
                code: payload.readUInt32BE(1 + payload._pos, true)
              };
              this.emit('CHANNEL_REQUEST:' + recipient, info);
            } else if (request === 'exit-signal') {
              /*
                byte      SSH_MSG_CHANNEL_REQUEST
                uint32    recipient channel
                string    "exit-signal"
                boolean   FALSE
                string    signal name (without the "SIG" prefix)
                boolean   core dumped
                string    error message in ISO-10646 UTF-8 encoding
                string    language tag
              */
              info = {
                recipient: recipient,
                request: request,
                signal: readString(payload, 1 + payload._pos, 'ascii'),
                coredump: (payload[payload._pos] !== 0),
                description: readString(payload, ++payload._pos, 'utf8'),
                lang: readString(payload, payload._pos, 'utf8')
              };
              this.emit('CHANNEL_REQUEST:' + recipient, info);
            }
            break;
          case MESSAGE.UNIMPLEMENTED:
            /*
              byte      SSH_MSG_UNIMPLEMENTED
              uint32    packet sequence number of rejected message
            */
            // TODO
            break;
          default:
        }
        if (this._state === STATE_INIT) {
          // we were reset due to some error/disagreement ?
          return;
        }
        this._state = STATE_PACKETBEFORE;
        this._payload = undefined;
        break;
    }
    if (buffer !== undefined)
      buffer = undefined;
  }
};

Parser.prototype.hmacVerify = function(hmac) {
  // seqno + pktLen + padLen + (payload + padding) length
  var buf = new Buffer(4 + 4 + 1 + this._packet.length);
  buf.writeUInt32BE(this._seqno, 0, true);
  buf.writeUInt32BE(this._pktLen, 4, true);
  buf[8] = this._padLen;
  this._packet.copy(buf, 9);
  var calcHmac = crypto.createHmac(this._hmac, this._hmacKey);
  calcHmac.update(buf);
  return (calcHmac.digest('binary') === hmac.toString('binary'));
};

Parser.prototype.decrypt = function(data) {
  var ret = new Buffer(this._decrypt.update(data, 'binary', 'binary'), 'binary');
  return ret;
};

Parser.prototype.expect = function(what, action, emitEventName) {
  this._expect = what;
  this._expectType = (Array.isArray(what) ? EXP_TYPE_MATCH : EXP_TYPE_BYTES);
  this._expectLen = (Array.isArray(what) ? what.length : what);
  this._expectPtr = 0;
  if (action === EXP_ACTION_BUFFER) {
    if (Array.isArray(what))
      this._expectBuf = [];
    else
      this._expectBuf = new Buffer(what);
  } else
    this._expectBuf = undefined;
  this._expectBufLen = 0;
  this._expectEmit = (action === EXP_ACTION_EMIT ? emitEventName : undefined);
};

Parser.prototype.reset = function() {
  this._state = STATE_INIT;
  this._expect = undefined;
  this._expectType = undefined;
  this._expectLen = undefined;
  this._expectPtr = 0;
  this._expectBuf = undefined;
  this._expectBufLen = 0;
  this._expectEmit = undefined;

  this._greeting = undefined;
  this._decryptSize = 8;
  this._decrypt = false;
  this._authMethod = undefined;
};

Parser.prototype._emitError = function(msg) {
  this.emit('error', new Error(msg));
  this.reset();
};

function bytes(str) {
  var ret = new Array(str.length);
  for (var i=0,len=ret.length; i<len; ++i)
    ret[i] = str.charCodeAt(i);
  return ret;
}

function readString(buffer, start, encoding) {
  start || (start = 0);

  var blen = buffer.length, slen;
  if ((blen - start) < 4)
    return false;
  slen = buffer.readUInt32BE(start, true);
  if ((blen - start) < (4 + slen))
    return false;
  buffer._pos = start + 4 + slen;
  if (encoding)
    return buffer.toString(encoding, start + 4, start + 4 + slen);
  else
    return buffer.slice(start + 4, start + 4 + slen);
}

function readList(buffer, start) {
  var list = readString(buffer, start, 'ascii');
  return (list !== false ? (list.length ? list.split(',') : []) : false);
}

Parser.MAX_SEQNO = MAX_SEQNO;
module.exports = Parser;
