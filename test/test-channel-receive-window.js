'use strict';

const assert = require('assert');
const { mustCall, setupSimple } = require('./common.js');

// Exercise the real connection handlers with bounded, backpressured channels.
function checkWindow(conn, extended) {
  for (const window of [ 0, 1, 4 ]) {
    for (const length of [ 0, 1, 4, 5 ]) {
      let received = 0;
      const push = () => {
        ++received;
        return false;
      };
      const channel = { incoming: { window }, push, stderr: { push } };
      const recipient = conn._chanMgr.add(channel);
      const name = (extended ? 'CHANNEL_EXTENDED_DATA' : 'CHANNEL_DATA');
      conn._protocol._handlers[name](conn._protocol, recipient,
                                     Buffer.alloc(length), 1);
      const accepted = (window > 0 && length <= window);
      assert.strictEqual(received, accepted ? 1 : 0,
                         `${name}: window=${window}, length=${length}`);
      assert.strictEqual(channel.incoming.window,
                         accepted ? window - length : window);
      conn._chanMgr.remove(recipient);
    }
  }
}

const { client, server } = setupSimple(false, 'Enforce receive windows');
server.on('connection', mustCall((conn) => {
  conn.on('ready', mustCall(() => checkWindow(conn, false)));
}));
client.on('ready', mustCall(() => {
  checkWindow(client, false);
  checkWindow(client, true);
  client.end();
}));
