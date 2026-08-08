{
  'variables': {
    'perfetto_sdk_sources': [
      'sdk/perfetto.cc',
      'sdk/perfetto.h',
    ]
  },
  'targets': [
    {
      'target_name': 'perfetto_sdk',
      'type': 'static_library',
      'include_dirs': [ 'sdk' ],
      'direct_dependent_settings': {
        # Use like `#include "perfetto.h"`
        'include_dirs': [ 'sdk' ],
      },
      'sources': [
        '<@(perfetto_sdk_sources)',
      ],
      'conditions': [
        # nwjs: the amalgamation includes <windows.h> (sdk/perfetto.cc:73773)
        # and then <winsock2.h> two lines later. Without WIN32_LEAN_AND_MEAN
        # the first pulls in the Winsock 1.1 <winsock.h>, and winsock2.h then
        # redefines protoent/WSAData. Chromium builds this same source with
        # WIN32_LEAN_AND_MEAN (build/config/win/BUILD.gn); upstream node never
        # hits it because v8_use_perfetto defaults to 0 there, so nothing but
        # nw compiles the bundled SDK.
        ['OS=="win"', {
          'defines': [ 'WIN32_LEAN_AND_MEAN' ],
        }],
      ],
    },
  ]
}
