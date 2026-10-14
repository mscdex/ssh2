'use strict';

const assert = require('assert');
const { Channel } = require('../lib/Channel.js');

// close() after end() while writes wait for window credit must flush them
const sent = [];
const protocol = {
  channelData: (id, data) => sent.push(['data', data.length]),
  channelEOF: () => sent.push(['eof']),
  channelClose: () => sent.push(['close']),
};
const client = { _protocol: protocol };
const info = {
  type: 'session',
  incoming: { id: 0, window: 1024, packetSize: 1024, state: 'open' },
  outgoing: { id: 1, window: 4, packetSize: 1024, state: 'open' },
};
const channel = new Channel(client, info);

let cbs = 0;
channel.write(Buffer.alloc(10), () => ++cbs);
channel.destroy();
assert.deepStrictEqual(sent, [['data', 4]]);
assert.strictEqual(channel.outgoing.state, 'open');

// Simulate CHANNEL_WINDOW_ADJUST flushing the parked chunk
channel.outgoing.window += 100;
channel._waitWindow = false;
channel._write(channel._chunk, null, channel._chunkcb);

setImmediate(() => {
  assert.strictEqual(cbs, 1);
  assert.deepStrictEqual(sent, [['data', 4], ['data', 6], ['eof'], ['close']]);
});
