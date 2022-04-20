{
  'variables': {
    'real_openssl_major%': '0',
  },
  'targets': [
    {
      'target_name': 'sshcrypto',
      'include_dirs': [
        "<!(node -e \"require('nan')\")",
      ],
      'sources': [
        'src/binding.cc'
      ],
      'cflags': [ '-O3' ],

      # Needed for OpenSSL 3.x/node.js v17.x+
      'defines': [
        'OPENSSL_API_COMPAT=0x10100000L',
        'REAL_OPENSSL_MAJOR=<(real_openssl_major)',
      ],

      'conditions': [
        [ 'OS=="win"', {
          'conditions': [
            ['target_arch=="x64"', {
              'variables': {
                'openssl_root%': 'C:/Program Files/OpenSSL-Win64'
                },
            }, {
              'variables': {
                'openssl_root%': 'C:/Program Files/OpenSSL-Win32'
                },
            }],
          ],
          'libraries': [
            # libeay32.lib for OpenSSL < 3
            '-l<(openssl_root)/lib/libcrypto.lib',
          ],
          'include_dirs': [
            '<(openssl_root)/include',
          ],
        }]
      ],

    },
  ],
}
