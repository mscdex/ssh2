'use strict';

// Tests that AgentProtocol (server mode) correctly handles unknown message
// types such as SSH_AGENTC_EXTENSION (27), which OpenSSH >=8.9 sends for
// session-bind@openssh.com hostkey binding before identity requests.
//
// Bug: the `default` case in the server-mode message parser did not advance
// the read position past the message body. This left the extension body bytes
// in the parse buffer, corrupting subsequent message parsing.

const assert = require('assert');

const {
  AgentProtocol,
  utils: { parseKey },
} = require('../lib/index.js');
const { fixtureKey } = require('./common.js');

const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENTC_EXTENSION = 27;
const SSH_AGENT_FAILURE = 5;
const SSH_AGENT_IDENTITIES_ANSWER = 12;

const clientKey = fixtureKey('openssh_new_rsa');

/**
 * Build a framed SSH agent message: uint32 length + byte type + body
 */
function buildMessage(type, body) {
  body = body || Buffer.alloc(0);
  const buf = Buffer.alloc(4 + 1 + body.length);
  buf.writeUInt32BE(1 + body.length, 0);
  buf[4] = type;
  body.copy(buf, 5);
  return buf;
}

/**
 * Build an SSH_AGENTC_EXTENSION message with the given extension name and
 * contents — mimics OpenSSH's session-bind@openssh.com request.
 */
function buildExtensionMessage(name, contents) {
  const nameBuf = Buffer.from(name, 'utf8');
  const body = Buffer.alloc(4 + nameBuf.length + (contents ? contents.length : 0));
  body.writeUInt32BE(nameBuf.length, 0);
  nameBuf.copy(body, 4);
  if (contents)
    contents.copy(body, 4 + nameBuf.length);
  return buildMessage(SSH_AGENTC_EXTENSION, body);
}

/**
 * Collect output from the protocol into a buffer and parse agent messages.
 */
function collectResponses(protocol) {
  const responses = [];
  let buf = Buffer.alloc(0);

  protocol.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);

    while (buf.length >= 5) {
      const msgLen = buf.readUInt32BE(0);
      const totalLen = 4 + msgLen;
      if (buf.length < totalLen) break;

      responses.push({
        type: buf[4],
        body: buf.slice(5, totalLen),
      });
      buf = buf.slice(totalLen);
    }
  });

  return responses;
}

// --------------------------------------------------------------------------
// Test 1: Extension message followed by identity request — both in one write
// --------------------------------------------------------------------------
{
  const label = 'AgentProtocol: extension + identities in single write';
  console.log(`  Testing: ${label}`);

  const protocol = new AgentProtocol(false); // server mode
  const responses = collectResponses(protocol);

  // Handle identity requests
  protocol.on('identities', (req) => {
    const pubKey = parseKey(clientKey.key.getPublicSSH());
    protocol.getIdentitiesReply(req, [pubKey]);
  });

  // Build combined payload: extension message + identities request
  const extMsg = buildExtensionMessage('session-bind@openssh.com', Buffer.alloc(64));
  const idMsg = buildMessage(SSH_AGENTC_REQUEST_IDENTITIES);
  const combined = Buffer.concat([extMsg, idMsg]);

  protocol.write(combined);

  // Allow microtask queue to flush
  setImmediate(() => {
    assert.strictEqual(
      responses.length, 2,
      `Expected 2 responses, got ${responses.length}`
    );

    // First response: SSH_AGENT_FAILURE for the extension
    assert.strictEqual(
      responses[0].type, SSH_AGENT_FAILURE,
      `Expected SSH_AGENT_FAILURE (${SSH_AGENT_FAILURE}) for extension, `
        + `got type ${responses[0].type}`
    );

    // Second response: SSH_AGENT_IDENTITIES_ANSWER for the identity request
    assert.strictEqual(
      responses[1].type, SSH_AGENT_IDENTITIES_ANSWER,
      `Expected SSH_AGENT_IDENTITIES_ANSWER (${SSH_AGENT_IDENTITIES_ANSWER}), `
        + `got type ${responses[1].type}`
    );

    protocol.destroy();
    console.log(`  PASS: ${label}`);
  });
}

// --------------------------------------------------------------------------
// Test 2: Extension message and identity request in separate writes
// --------------------------------------------------------------------------
{
  const label = 'AgentProtocol: extension + identities in separate writes';
  console.log(`  Testing: ${label}`);

  const protocol = new AgentProtocol(false); // server mode
  const responses = collectResponses(protocol);

  protocol.on('identities', (req) => {
    const pubKey = parseKey(clientKey.key.getPublicSSH());
    protocol.getIdentitiesReply(req, [pubKey]);
  });

  const extMsg = buildExtensionMessage('session-bind@openssh.com', Buffer.alloc(128));
  const idMsg = buildMessage(SSH_AGENTC_REQUEST_IDENTITIES);

  protocol.write(extMsg);

  setImmediate(() => {
    assert.strictEqual(responses.length, 1, 'Expected 1 response after extension');
    assert.strictEqual(responses[0].type, SSH_AGENT_FAILURE);

    protocol.write(idMsg);

    setImmediate(() => {
      assert.strictEqual(
        responses.length, 2,
        `Expected 2 responses total, got ${responses.length}`
      );
      assert.strictEqual(
        responses[1].type, SSH_AGENT_IDENTITIES_ANSWER,
        `Expected SSH_AGENT_IDENTITIES_ANSWER, got type ${responses[1].type}`
      );

      protocol.destroy();
      console.log(`  PASS: ${label}`);
    });
  });
}

// --------------------------------------------------------------------------
// Test 3: Multiple extensions followed by identity request
// --------------------------------------------------------------------------
{
  const label = 'AgentProtocol: multiple extensions + identities';
  console.log(`  Testing: ${label}`);

  const protocol = new AgentProtocol(false); // server mode
  const responses = collectResponses(protocol);

  protocol.on('identities', (req) => {
    const pubKey = parseKey(clientKey.key.getPublicSSH());
    protocol.getIdentitiesReply(req, [pubKey]);
  });

  const ext1 = buildExtensionMessage('session-bind@openssh.com', Buffer.alloc(64));
  const ext2 = buildExtensionMessage('some-other-extension@vendor.com', Buffer.alloc(32));
  const idMsg = buildMessage(SSH_AGENTC_REQUEST_IDENTITIES);
  const combined = Buffer.concat([ext1, ext2, idMsg]);

  protocol.write(combined);

  setImmediate(() => {
    assert.strictEqual(
      responses.length, 3,
      `Expected 3 responses, got ${responses.length}`
    );
    assert.strictEqual(responses[0].type, SSH_AGENT_FAILURE);
    assert.strictEqual(responses[1].type, SSH_AGENT_FAILURE);
    assert.strictEqual(responses[2].type, SSH_AGENT_IDENTITIES_ANSWER);

    protocol.destroy();
    console.log(`  PASS: ${label}`);
  });
}
