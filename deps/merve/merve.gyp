{
  'variables': {
    'merve_sources': [ 'merve.cpp' ],
  },
  'targets': [
    {
      'target_name': 'merve',
      'type': 'static_library',
      'include_dirs': [
        '.',
        '../../../simdutf',
      ],
      'direct_dependent_settings': {
        'include_dirs': ['.'],
      },
      'defines': [ 'MERVE_USE_SIMDUTF=1' ],
      'sources': [ '<@(merve_sources)' ],
      'conditions': [
        ['OS=="win"', {
          'msvs_settings': {
            'VCCLCompilerTool': {
              'AdditionalOptions': ['/std:c++20'],
            },
          },
          'include_dirs': [
            '<(PRODUCT_DIR)/../../third_party/libc++/src/include',
            '<(PRODUCT_DIR)/../../third_party/libc++',
            '<(PRODUCT_DIR)/../../buildtools/third_party/libc++',
          ],
        }],
        ['OS!="win"', {
          'cflags_cc': ['-std=c++20'],
          'xcode_settings': {
            'CLANG_CXX_LANGUAGE_STANDARD': 'c++20',
          },
        }],
      ],
    },
  ]
}
