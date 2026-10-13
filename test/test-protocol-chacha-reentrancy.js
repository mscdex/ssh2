'use strict';

const assert = require('assert');
const {
  CIPHER_INFO,
  createCipher,
  createDecipher,
  init: cryptoInit,
} = require('../lib/protocol/crypto.js');

(async () => {
  await cryptoInit;
  const cipherInfo = CIPHER_INFO['chacha20-poly1305@openssh.com'];
  const key = Buffer.alloc(64, 0x42);
  const payload = Buffer.concat([
    Buffer.from([5, 0, 0, 0, 12]),
    Buffer.from('ssh-userauth'),
  ]);

  for (const nested of [false, true]) {
    for (const seqno of [0, 3, 0xFFFFFFFF]) {
      const chunks = [];
      const received = [];
      const outer = createCipher({
        outbound: {
          cipherInfo,
          cipherKey: Buffer.alloc(64, 0x23),
          seqno: 9,
          forceNative: true,
          onWrite() {},
        },
      });
      const inner = createCipher({
        outbound: {
          cipherInfo,
          cipherKey: key,
          seqno,
          forceNative: true,
          onWrite(data) {
            chunks.push(Buffer.from(data));
            if (nested) {
              const packet = outer.allocPacket(1);
              packet[5] = 2;
              outer.encrypt(packet);
            }
          },
        },
      });
      const decipher = createDecipher({
        inbound: {
          decipherInfo: cipherInfo,
          decipherKey: key,
          seqno,
          forceNative: true,
          onPayload(data) {
            received.push(Buffer.from(data));
          },
        },
      });

      const packet = inner.allocPacket(payload.length);
      payload.copy(packet, 5);
      inner.encrypt(packet);
      const wire = Buffer.concat(chunks);
      decipher.decrypt(wire, 0, wire.length);
      assert.deepStrictEqual(received, [payload],
                             `nested=${nested}, seqno=${seqno}`);
      inner.free();
      outer.free();
      decipher.free();
    }
  }
  console.log('Native ChaCha nested-write regression passed (6 cases)');
})().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
