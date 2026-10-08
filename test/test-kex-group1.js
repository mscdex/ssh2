'use strict';

// Some crypto backends (e.g. BoringSSL, as used by Electron) do not provide the
// legacy 'modp1' and 'modp2' named groups. Remove them before loading the
// library to make sure diffie-hellman-group1-sha1 does not need them.
const crypto = require('crypto');
const createDiffieHellmanGroup = crypto.createDiffieHellmanGroup;
crypto.createDiffieHellmanGroup = (name) => {
  if (name === 'modp1' || name === 'modp2')
    throw new Error('Unknown DH group');
  return createDiffieHellmanGroup(name);
};

const { fixtureKey, mustCall, setup } = require('./common.js');

const debug = false;

const algorithms = { kex: [ 'diffie-hellman-group1-sha1' ] };
const { client, server } = setup(
  'diffie-hellman-group1-sha1 without named group support',
  {
    client: { username: 'Password User', password: '12345', algorithms },
    server: { hostKeys: [ fixtureKey('ssh_host_rsa_key').raw ], algorithms },
    debug,
  }
);

server.on('connection', mustCall((conn) => {
  conn.on('authentication', mustCall((ctx) => {
    ctx.accept();
  }));
}));

client.on('ready', mustCall(() => {
  client.end();
}));
