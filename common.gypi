{
# 为什么要这个配置  https://github.com/nodejs/node-gyp/issues/26
  'cflags!': ['-fno-exceptions'],
  'cflags_cc!': ['-fno-exceptions'],
  'conditions': [
    ['OS=="mac"', {
      'cflags+': ['-fvisibility=hidden'],
      'xcode_settings': {
        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
        'CLANG_CXX_LIBRARY': 'libc++',
        'MACOSX_DEPLOYMENT_TARGET': '10.7',
        'GCC_SYMBOLS_PRIVATE_EXTERN': 'YES', # -fvisibility=hidden
      }
    }],
    ['OS=="win"', { 
      'msvs_settings': {
        'VCCLCompilerTool': {
          'ExceptionHandling': 1,
          'AdditionalOptions': ['/source-charset:utf-8']
        },
      },
      'defines':[
        '_HAS_EXCEPTIONS=1',
        'NOMINMAX'
      ]
    }]
  ],
  # node16 打包会出现的问题
  'variables' : {
      'openssl_fips': '',
  }
}
