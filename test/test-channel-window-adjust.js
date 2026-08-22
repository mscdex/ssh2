'use strict';

const assert = require('assert');

const {
  mustCall,
  mustNotCall,
  setupSimple,
} = require('./common.js');

const {
  windowAdjust,
  MAX_WINDOW,
} = require('../lib/Channel.js');

const DEBUG = false;

const setup = setupSimple.bind(undefined, DEBUG);

// windowAdjust must not send after close() (outgoing.state === 'closing')
{
  const mockChannel = {
    outgoing: { state: 'closing', id: 0 },
    incoming: { window: 0 },
    _client: {
      _protocol: {
        channelWindowAdjust: mustNotCall(
          'channelWindowAdjust must not be called in closing state'
        ),
      },
    },
  };

  windowAdjust(mockChannel);
}

// windowAdjust works normally in open state
{
  let called = false;
  const mockChannel = {
    outgoing: { state: 'open', id: 0 },
    incoming: { window: 0 },
    _client: {
      _protocol: {
        channelWindowAdjust: (id, amt) => {
          called = true;
          assert.strictEqual(id, 0);
          assert.strictEqual(amt, MAX_WINDOW);
        },
      },
    },
  };

  windowAdjust(mockChannel);
  assert(called, 'channelWindowAdjust must be called in open state');
}

// windowAdjust must not send when outgoing.state === 'closed'
{
  const mockChannel = {
    outgoing: { state: 'closed', id: 0 },
    incoming: { window: 0 },
    _client: {
      _protocol: {
        channelWindowAdjust: mustNotCall(
          'channelWindowAdjust must not be called in closed state'
        ),
      },
    },
  };

  windowAdjust(mockChannel);
}

// _read() must not trigger windowAdjust after close()
{
  const { client, server } = setup(
    '_read() must not trigger windowAdjust after close()'
  );

  const COMMAND = 'test-window-adjust';

  server.on('connection', mustCall((conn) => {
    conn.on('ready', mustCall(() => {
      conn.on('session', mustCall((accept, reject) => {
        accept().on('exec', mustCall((accept, reject, info) => {
          const stream = accept();
          stream.write(Buffer.alloc(1024));
          stream.exit(0);
          stream.end();
        }));
      }));
    }));
  }));

  client.on('ready', mustCall(() => {
    client.exec(COMMAND, mustCall((err, stream) => {
      assert(!err, `Unexpected exec error: ${err}`);

      let windowAdjustCalledAfterClose = false;
      const origWindowAdjust =
        client._protocol.channelWindowAdjust.bind(client._protocol);

      stream.on('close', mustCall(() => {
        assert(!windowAdjustCalledAfterClose,
               'channelWindowAdjust must not be called after close');
        client.end();
      }));

      stream.once('data', () => {
        // Monkeypatch to detect calls after close
        client._protocol.channelWindowAdjust = (...args) => {
          if (stream.outgoing.state === 'closing'
              || stream.outgoing.state === 'closed') {
            windowAdjustCalledAfterClose = true;
          }
          return origWindowAdjust(...args);
        };

        stream.destroy();

        // Manually trigger _read to simulate a pending read callback
        // arriving after close() has set state to 'closing'
        if (stream.outgoing.state === 'closing') {
          stream.incoming.window = 0;
          stream._read(1);
        }
      });
    }));
  }));
}
