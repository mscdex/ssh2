{
  'targets': [
    {
      'target_name': 'ssh2',
      'sources': [
        'src/session.cc',
        #'src/channel.cc',
      ],
      'include_dirs': [
        'deps/libssh2/include',
      ],
      'cflags': [ '-O3' ],
      'dependencies': [
        'deps/libssh2/libssh2.gyp:libssh2_lib',
      ],
      'conditions': [
        [ 'OS=="win"', {
          'link_settings': {
            'libraries': [
              '-lws2_32.lib',
              '-lpsapi.lib',
              '-liphlpapi.lib'
            ],
          }
        }],
        [ 'OS=="mac"', {
          'direct_dependent_settings': {
            'libraries': [
              '$(SDKROOT)/System/Library/Frameworks/CoreServices.framework',
            ],
          },
        }],
        [ 'OS=="linux"', {
          'direct_dependent_settings': {
            'libraries': [ '-lrt' ],
          },
        }],
        [ 'OS=="solaris"', {
          'direct_dependent_settings': {
            'libraries': [
              '-lsocket',
              '-lnsl',
            ],
          },
        }],
      ]
    },
  ],
}