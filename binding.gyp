{
  'targets': [
    {
      'target_name': 'sshcrypto',
      'include_dirs': [
        "<!(node -e \"require('nan')\")",
      ],
      'sources': [
        'lib/protocol/crypto/src/binding.cc'
      ],
      'cflags': [ '-O3' ],
      'includes': [
                  './common.gypi'
                ]
    },
  ],
}
