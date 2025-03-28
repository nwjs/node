{
  'variables': {
    'ada_sources': [ 'ada.cpp' ],
    'icu_gyp_path%': '../../../icu/icu.gyp',
  },
  'targets': [
    {
      'target_name': 'ada',
      'type': 'static_library',
      'include_dirs': ['.'],
      'direct_dependent_settings': {
        'include_dirs': ['.'],
      },
      'sources': [ '<@(ada_sources)' ]
    },
  ]
}
