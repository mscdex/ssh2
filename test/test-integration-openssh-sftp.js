'use strict';

const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const readline = require('readline');

const Server = require('../lib/server.js');

const {
  fixture,
  fixtureKey,
  mustCall,
  mustCallAtLeast,
} = require('./common.js');

const SPAWN_OPTS = { windowsHide: true };
const CLIENT_TIMEOUT = 5000;

const debug = false;
const opensshPath = 'ssh';
const sftpPath = 'sftp';
let opensshVer;

// TODO: figure out why this test is failing on Windows
if (process.platform === 'win32') {
  console.log('Skipping OpenSSH integration tests on Windows');
  process.exit(0);
}

{
  // Get OpenSSH client version first
  const {
    error, stderr, stdout
  } = spawnSync(opensshPath, ['-V'], SPAWN_OPTS);

  if (error) {
    console.error('OpenSSH client is required for these tests');
    process.exitCode = 5;
    return;
  }

  const re = /^OpenSSH_([\d.]+)/;
  let m = re.exec(stdout.toString());
  if (!m || !m[1]) {
    m = re.exec(stderr.toString());
    if (!m || !m[1]) {
      console.error('OpenSSH client is required for these tests');
      process.exitCode = 5;
      return;
    }
  }

  opensshVer = m[1];
  console.log(`Testing with OpenSSH version: ${opensshVer}`);
}

{
  const clientKey = fixtureKey('openssh_new_rsa');
  const username = 'KeyUser';
  const { server } = setup(
    'Client closes the connection',
    {
      client: {
        username,
        privateKeyPath: clientKey.fullPath,
      },
      server: { hostKeys: [ fixture('ssh_host_rsa_key') ] },
      debug,
    }
  );

  server.on('_child', mustCall((childProc) => {
    childProc.stdin.write('bye\r');
    childProc.stdin.end();
  })).on('connection', mustCall((conn) => {
    let authAttempt = 0;
    conn.on('authentication', mustCallAtLeast((ctx) => {
      assert(ctx.username === username,
             `Wrong username: ${ctx.username}`);
      switch (++authAttempt) {
        case 1:
          assert(ctx.method === 'none',
                 `Wrong auth method: ${ctx.method}`);
          return ctx.reject();
        case 2:
        case 3:
          if (authAttempt === 3)
            assert(ctx.signature, 'Missing publickey signature');
          assert(ctx.method === 'publickey',
                 `Wrong auth method: ${ctx.method}`);
          assert(ctx.key.algo === clientKey.key.type,
                 `Wrong key algo: ${ctx.key.algo}`);
          assert.deepStrictEqual(clientKey.key.getPublicSSH(),
                                 ctx.key.data,
                                 'Public key mismatch');
          break;
        default:
          assert(false, 'Unexpected number of auth attempts');
      }
      if (ctx.signature) {
        assert(clientKey.key.verify(ctx.blob, ctx.signature) === true,
               'Could not verify publickey signature');
        // We should not expect any further auth attempts after we verify a
        // signature
        authAttempt = Infinity;
      }
      ctx.accept();
    }, 2)).on('ready', mustCall(() => {
      conn.on('session', mustCall((accept, reject) => {
        accept().on('sftp', mustCall((accept, reject) => {
          const sftp = accept();
          sftp.on('REALPATH', mustCall((id, path) => {
            assert(path === '.');
            sftp.name(id, { filename: '/' });
          })).on('end', mustCall(() => {
          }));
        }));
      }));
    }));
  }));
}

function setup(title, configs) {
  const {
    client: clientCfg,
    server: serverCfg,
    allReady: allReady_,
    timeout: timeout_,
    debug,
    noForceServerReady,
  } = configs;
  let clientClose = false;
  let serverClose = false;
  let serverReady = false;
  let client;
  const msg = (text) => {
    return `${title}: ${text}`;
  };

  const timeout = (typeof timeout_ === 'number'
                   ? timeout_
                   : CLIENT_TIMEOUT);

  const allReady = (typeof allReady_ === 'function' ? allReady_ : undefined);

  if (debug) {
    serverCfg.debug = (...args) => {
      console.log(`[${title}][SERVER]`, ...args);
    };
  }

  const serverReadyFn = (noForceServerReady ? onReady : mustCall(onReady));
  const server = new Server(serverCfg);

  server.on('error', onError)
        .on('connection', mustCall((conn) => {
          conn.on('error', onError)
              .on('ready', serverReadyFn);
          server.close();
        }))
        .on('close', mustCall(onClose));

  function onError(err) {
    const which = (arguments.length >= 3 ? 'client' : 'server');
    assert(false, msg(`Unexpected ${which} error: ${err}`));
  }

  function onReady() {
    assert(!serverReady, msg('Received multiple ready events for server'));
    serverReady = true;
    allReady && allReady();
  }

  function onClose() {
    if (arguments.length >= 3) {
      assert(!clientClose, msg('Received multiple close events for client'));
      clientClose = true;
    } else {
      assert(!serverClose, msg('Received multiple close events for server'));
      serverClose = true;
    }
  }

  process.nextTick(mustCall(() => {
    server.listen(0, 'localhost', mustCall(() => {
      const args = [
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'CheckHostIP=no',
        '-o', 'ConnectTimeout=3',
        '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'GSSAPIAuthentication=no',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'BatchMode=yes',
        '-o', 'VerifyHostKeyDNS=no',

        '-vvvvv',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'HostbasedAuthentication=no',
        '-o', 'PasswordAuthentication=no',
        '-o', 'PubkeyAuthentication=yes',
        '-o', 'PreferredAuthentications=publickey'
      ];

      if (clientCfg.privateKeyPath)
        args.push('-o', `IdentityFile=${clientCfg.privateKeyPath}`);

      if (!/^[0-6]\./.test(opensshVer)) {
        // OpenSSH 7.0+ disables DSS/DSA host (and user) key support by
        // default, so we explicitly enable it here
        args.push('-o', 'HostKeyAlgorithms=+ssh-dss');
        args.push('-o', 'PubkeyAcceptedKeyTypes=+ssh-dss');
      }

      args.push('-P', server.address().port.toString(),
                `${clientCfg.username}@localhost`);

      client = spawn(sftpPath, args, SPAWN_OPTS);
      server.emit('_child', client);

      if (debug) {
        readline.createInterface({
          input: client.stdout
        }).on('line', (line) => {
          console.log(`[${title}][CLIENT][STDOUT]`, line);
        });
        readline.createInterface({
          input: client.stderr
        }).on('line', (line) => {
          console.error(`[${title}][CLIENT][STDERR]`, line);
        });
      } else {
        client.stdout.resume();
        client.stderr.resume();
      }

      client.on('error', (err) => {
        onError(err, null, null);
      }).on('exit', (code) => {
        clearTimeout(client.timer);
        if (code !== 0)
          return onError(new Error(`Non-zero exit code ${code}`), null, null);
        onClose(null, null, null);
      });

      client.timer = setTimeout(() => {
        assert(false, msg('Client timeout'));
      }, timeout);
    }));
  }));

  return { server };
}
