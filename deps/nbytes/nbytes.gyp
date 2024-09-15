{
  'variables': {
    'nbytes_sources': [ 'src/nbytes.cpp' ],
  },
  'targets': [
    {
      'target_name': 'nbytes',
      'type': 'static_library',
      'include_dirs': ['include', '<(DEPTH)/third_party/libc++/src/include',
                       '<(DEPTH)/buildtools/third_party/libc++/',
                      ],
      'direct_dependent_settings': {
        'include_dirs': ['include'],
      },
      'sources': [ '<@(nbytes_sources)' ]
    },
  ]
}
