'use strict';

const assert = require('assert');
const { generateKeyPairSync } = require('crypto');

const { mustCall, setup } = require('./common.js');
const { SFTP } = require('../lib/protocol/SFTP.js');
const { ChannelManager, onCHANNEL_CLOSE } = require('../lib/utils.js');

const hostKey = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
}).privateKey;

for (const initiator of ['server', 'server-duplicate', 'client']) {
  const { client, server } = setup(`SFTP close initiated by ${initiator}`, {
    client: { username: 'foo', password: 'bar' },
    server: { hostKeys: [hostKey] },
  });
  let serverSFTP;
  let serverCloseReplies = 0;

  server.on('connection', mustCall((conn) => {
    const onClose = conn._protocol._handlers.CHANNEL_CLOSE;
    conn._protocol._handlers.CHANNEL_CLOSE = (...args) => {
      if (serverSFTP && args[1] === serverSFTP.incoming.id)
        ++serverCloseReplies;
      return onClose(...args);
    };
    conn.on('authentication', mustCall((ctx) => ctx.accept()));
    conn.on('ready', mustCall(() => {
      conn.on('session', mustCall((accept) => {
        const session = accept();
        session.on('sftp', (acceptSFTP) => {
          serverSFTP = acceptSFTP();
          serverSFTP.on('close', mustCall(() => {
            assert.strictEqual(serverSFTP.outgoing.state, 'closed');
          }));
          serverSFTP.on('REALPATH', mustCall((id) => {
            serverSFTP.name(id, [
              { filename: '/fixture', longname: '/fixture', attrs: {} },
            ]);
            if (initiator !== 'client') {
              serverSFTP.destroy();
              if (initiator === 'server-duplicate')
                conn._protocol.channelClose(serverSFTP.outgoing.id);
            }
          }));
        });
        session.on('exec', (acceptExec) => {
          assert.strictEqual(
            conn._chanMgr.get(serverSFTP.incoming.id),
            undefined,
            'SFTP channel must be released before the next request'
          );
          assert.strictEqual(serverCloseReplies, 1);
          const channel = acceptExec();
          channel.write('still connected');
          channel.exit(0);
          channel.end();
        });
      }, 2));
    }));
  }));

  client.on('ready', mustCall(() => {
    client.sftp(mustCall((err, sftp) => {
      assert.ifError(err);
      sftp.on('close', mustCall(() => {
        assert.strictEqual(sftp.outgoing.state, 'closed');
        client.exec('after-close', mustCall((err, channel) => {
          assert.ifError(err);
          let output = '';
          channel.on('data', (data) => { output += data; });
          channel.on('close', mustCall(() => {
            assert.strictEqual(output, 'still connected');
            client.end();
          }));
        }));
      }));
      sftp.realpath('/fixture', mustCall((err, path) => {
        assert.ifError(err);
        assert.strictEqual(path, '/fixture');
        if (initiator === 'client')
          sftp.destroy();
      }));
    }));
  }));
}

for (const [state, dead] of [
  ['closing', false],
  ['closed', false],
  ['open', true],
]) {
  const client = {
    _protocol: {
      channelClose: mustCall(() => {}, 0),
    },
  };
  client._chanMgr = new ChannelManager(client);
  const sftp = new SFTP(client, {
    type: 'session',
    incoming: { id: 0, state: 'open' },
    outgoing: { id: 0, state },
  });
  const id = client._chanMgr.add(sftp);
  sftp.on('close', mustCall());
  onCHANNEL_CLOSE(client, id, sftp, undefined, dead);
  onCHANNEL_CLOSE(client, id, sftp, undefined, dead);
  assert.strictEqual(sftp.outgoing.state, dead ? state : 'closed');
}
