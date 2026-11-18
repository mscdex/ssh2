'use strict';

const assert = require('assert');
const handlers = require('../lib/protocol/handlers.misc.js');
const { MESSAGE, DISCONNECT_REASON } = require('../lib/protocol/constants.js');
const { mustCall, mustNotCall } = require('./common.js');

for (const type of [ 'CHANNEL_OPEN', 'CHANNEL_OPEN_CONFIRMATION' ]) {
  for (const packetSize of [ 0, 1, 32768, 0xFFFFFFFF ]) {
    const prefix = (type === 'CHANNEL_OPEN'
                    ? Buffer.from([ MESSAGE[type], 0, 0, 0, 7,
                                    ...Buffer.from('session') ])
                    : Buffer.from([ MESSAGE[type], 0, 0, 0, 1 ]));
    const fields = Buffer.alloc(12);
    fields.writeUInt32BE(2, 0);
    fields.writeUInt32BE(1024, 4);
    fields.writeUInt32BE(packetSize, 8);
    const invalid = (packetSize === 0);
    const protocol = {
      _handlers: {
        [type]: (invalid ? mustNotCall() : mustCall((p, info) => {
          assert.strictEqual(info.packetSize, packetSize);
        })),
      },
      disconnect: (invalid ? mustCall((reason) => {
        assert.strictEqual(reason, DISCONNECT_REASON.PROTOCOL_ERROR);
      }) : mustNotCall()),
      _destruct: (invalid ? mustCall() : mustNotCall()),
      _onError: (invalid ? mustCall((err) => {
        assert.match(err.message, /packet size/i);
      }) : mustNotCall()),
    };
    handlers[MESSAGE[type]](protocol, Buffer.concat([ prefix, fields ]));
  }
}
