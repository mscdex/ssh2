var HttpAgent = require('http').Agent;
var HttpsAgent = require('https').Agent;
var inherits = require('util').inherits;

var Client;

[HttpAgent, HttpsAgent].forEach((ctor) => {
  function SSHAgent(connectCfg, agentOptions) {
    if (!(this instanceof SSHAgent))
      return new SSHAgent(connectCfg, agentOptions);

    ctor.call(this, agentOptions);

    this._connectCfg = connectCfg;
    this._defaultSrcIP = (agentOptions && agentOptions.srcIP) || 'localhost';
  }
  inherits(SSHAgent, ctor);

  SSHAgent.prototype.createConnection = createConnection;

  exports[ctor === HttpAgent ? 'SSHTTPAgent' : 'SSHTTPSAgent'] = SSHAgent;
});

function createConnection(options, cb) {
  var srcIP = (options && options.localAddress) || this._defaultSrcIP;
  var srcPort = (options && options.localPort) || 0;
  var dstIP = options.host;
  var dstPort = options.port;

  if (Client === undefined)
    Client = require('./client').Client;

  var client = new Client();
  var triedForward = false;
  client.on('ready', () => {
    client.forwardOut(srcIP, srcPort, dstIP, dstPort, (err, stream) => {
      triedForward = true;
      if (err) {
        client.end();
        return cb(err);
      }
      stream.once('close', () => {
        client.end();
      });
      cb(null, decorateStream(stream));
    });
  }).on('error', cb).on('close', () => {
    if (!triedForward)
      cb(new Error('Unexpected connection loss'));
  }).connect(this._connectCfg);
}

function noop() {}

function decorateStream(stream) {
  stream.setKeepAlive = noop;
  stream.setNoDelay = noop;
  stream.setTimeout = noop;
  stream.ref = noop;
  stream.unref = noop;
  stream.destroySoon = stream.destroy;
  return stream;
}
