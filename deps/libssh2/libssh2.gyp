{
  'targets': [
    {
      'target_name': 'libssh2_lib',
      'type': 'static_library',
      'include_dirs': [ 'src', 'include' ],
      'defines': [
        'LIBSSH2_HAVE_ZLIB',
      ],
      'dependencies': [
        '../zlib/zlib.gyp:zlib',
        '../openssl/openssl.gyp:openssl',
      ],
      'conditions': [
        [ 'OS=="win"', {
          'include_dirs': [
            'win32',
          ],
          'defines': [],
          'libraries': [
            'ws2_32.lib'
          ],
        }],
        [ 'OS=="linux"', {
          'sources': [],
        }]
      ],
      'cflags': [ '-O3' ],
      'sources': [
        'src/agent.c',
        'src/channel.c',
        'src/comp.c',
        'src/crypt.c',
        'src/global.c',
        'src/hostkey.c',
        'src/keepalive.c',
        'src/kex.c',
        'src/knownhost.c',
        'src/mac.c',
        'src/misc.c',
        'src/openssl.c',
        'src/packet.c',
        'src/pem.c',
        'src/publickey.c',
        'src/scp.c',
        'src/session.c',
        'src/sftp.c',
        'src/transport.c',
        'src/userauth.c',
        'src/version.c',
      ],
    },
  ]
}
