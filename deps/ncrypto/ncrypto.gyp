{
  'variables': {
    'ncrypto_sources': [
      'engine.cc',
      'ncrypto.cc',
      'ncrypto.h',
    ],
  },
  'targets': [
    {
      'target_name': 'ncrypto',
      'type': 'static_library',
      'include_dirs': [ '.', '<(DEPTH)/third_party/libc++/src/include',
                        '<(DEPTH)/buildtools/third_party/libc++/',
       ],
      'direct_dependent_settings': {
        'include_dirs': ['.'],
      },
      'sources': [ '<@(ncrypto_sources)' ],
      'conditions': [
        ['node_shared_openssl=="false"', {
          'dependencies': [
            '../openssl/openssl.gyp:openssl'
          ]
        }],
      ]
    },
  ]
}
