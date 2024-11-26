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
      'includes': [
                  './common.gypi'
                ]
    },
  ],
}
