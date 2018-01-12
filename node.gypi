{
  'conditions': [
    [ 'node_shared=="false"', {
      'msvs_settings': {
        'VCManifestTool': {
          'EmbedManifest': 'true',
          'AdditionalManifestFiles': 'src/res/node.exe.extra.manifest'
        }
      },
    }, {
      'defines': [
        'NODE_SHARED_MODE',
      ],
    }],
    [ 'node_enable_d8=="true"', {
      'dependencies': [ 'deps/v8/src/d8.gyp:d8' ],
    }],
    [ 'node_use_bundled_v8=="true"', {
      'dependencies': [
        #'deps/v8/src/v8.gyp:v8',
        #'deps/v8/src/v8.gyp:v8_libplatform'
      ],
    }],
    [ 'node_use_v8_platform=="true"', {
      'defines': [
        'NODE_USE_V8_PLATFORM=1',
      ],
    }, {
      'defines': [
        'NODE_USE_V8_PLATFORM=0',
      ],
    }],
    [ 'node_tag!=""', {
      'defines': [ 'NODE_TAG="<(node_tag)"' ],
    }],
    [ 'node_v8_options!=""', {
      'defines': [ 'NODE_V8_OPTIONS="<(node_v8_options)"'],
    }],
    # No node_main.cc for anything except executable
    [ 'node_target_type!="executable"', {
      'sources!': [
        'src/node_main.cc',
      ],
    }],
    [ 'node_release_urlbase!=""', {
      'defines': [
        'NODE_RELEASE_URLBASE="<(node_release_urlbase)"',
      ]
    }],
    [
      'debug_http2==1', {
      'defines': [ 'NODE_DEBUG_HTTP2=1' ]
    }],
    ['node_target_type=="shared_library"', {
      'direct_dependent_settings': {
        'defines': [
          'USING_UV_SHARED=1',
          'BUILDING_NODE_EXTENSION=1',
        ],
      },
    }],
    ['clang==1', {
      'cflags': ['-Wno-error=missing-declarations', '-Wno-error=array-bounds'],
    }],
    [ 'v8_enable_i18n_support==1', {
      'defines': [ 'NODE_HAVE_I18N_SUPPORT=1' ],
      'dependencies': [
        '../icu/icu.gyp:icui18n',
        '../icu/icu.gyp:icuuc',
      ],
      'conditions': [
        [ 'icu_small=="true"', {
          'defines': [ 'NODE_HAVE_SMALL_ICU=1' ],
      }]],
    }],
    [ 'node_use_bundled_v8=="true" and \
       node_enable_v8_vtunejit=="true" and (target_arch=="x64" or \
       target_arch=="ia32" or target_arch=="x32")', {
      'defines': [ 'NODE_ENABLE_VTUNE_PROFILING' ],
      'dependencies': [
        'deps/v8/src/third_party/vtune/v8vtune.gyp:v8_vtune'
      ],
    }],
    [ 'node_use_lttng=="true"', {
      'defines': [ 'HAVE_LTTNG=1' ],
      'include_dirs': [ '<(SHARED_INTERMEDIATE_DIR)' ],
      'libraries': [ '-llttng-ust' ],
      'sources': [
        'src/node_lttng.cc'
      ],
    } ],
    [ 'node_use_etw=="true" and node_target_type!="static_library"', {
      'defines': [ 'HAVE_ETW=1' ],
      'dependencies': [ 'node_etw' ],
      'sources': [
        'src/node_win32_etw_provider.h',
        'src/node_win32_etw_provider-inl.h',
        'src/node_win32_etw_provider.cc',
        'src/node_dtrace.cc',
        'tools/msvs/genfiles/node_etw_provider.h',
        'tools/msvs/genfiles/node_etw_provider.rc',
      ]
    } ],
    [ 'node_use_perfctr=="true" and node_target_type!="static_library"', {
      'defines': [ 'HAVE_PERFCTR=1' ],
      'dependencies': [ 'node_perfctr' ],
      'sources': [
        'src/node_win32_perfctr_provider.h',
        'src/node_win32_perfctr_provider.cc',
        'src/node_counters.cc',
        'src/node_counters.h',
        'tools/msvs/genfiles/node_perfctr_provider.rc',
      ]
    } ],
    [ 'node_no_browser_globals=="true"', {
      'defines': [ 'NODE_NO_BROWSER_GLOBALS' ],
    } ],
    [ 'node_use_bundled_v8=="true" and v8_postmortem_support=="true"', {
      'dependencies': [ '../../v8/src/v8.gyp:postmortem-metadata' ],
      'conditions': [
        # -force_load is not applicable for the static library
        [ 'node_target_type!="static_library"', {
          'xcode_settings': {
            'OTHER_LDFLAGS': [
              '-Wl,-force_load,<(V8_BASE)',
            ],
          },
        }],
      ],
    }],
    [ 'node_shared_zlib=="false"', {
      'dependencies': [ 'deps/zlib/zlib.gyp:zlib' ],
    }],

    [ 'node_shared_http_parser=="false"', {
      'dependencies': [ 'deps/http_parser/http_parser.gyp:http_parser' ],
    }],

    [ 'node_shared_cares=="false"', {
      'dependencies': [ 'deps/cares/cares.gyp:cares' ],
    }],

    [ 'node_shared_libuv=="false"', {
      'dependencies': [ 'deps/uv/uv.gyp:libuv' ],
    }],

    [ 'node_shared_nghttp2=="false"', {
      'dependencies': [ 'deps/nghttp2/nghttp2.gyp:nghttp2' ],
    }],
    [ 'OS=="win" and component=="shared_library"', {
      'libraries': [ '<(PRODUCT_DIR)/../nw/v8.dll.lib' ]
    }],

    [ 'OS=="mac"', {
      # linking Corefoundation is needed since certain OSX debugging tools
      # like Instruments require it for some features
      'libraries': [ '-framework CoreFoundation' ],
      'defines!': [
        'NODE_PLATFORM="mac"',
      ],
      'defines': [
        # we need to use node's preferred "darwin" rather than gyp's preferred "mac"
        'NODE_PLATFORM="darwin"',
      ],
     'postbuilds': [
       {
         'postbuild_name': 'Fix Framework Link',
         'action': [
           'install_name_tool',
           '-change',
           '@executable_path/../Versions/<(version_full)/<(mac_product_name) Framework.framework/<(mac_product_name) Framework',
           '@loader_path/<(mac_product_name) Framework',
           '${BUILT_PRODUCTS_DIR}/${EXECUTABLE_PATH}'
         ],
       },
     ],
    }],
    [ 'OS=="freebsd"', {
      'libraries': [
        '-lutil',
        '-lkvm',
      ],
    }],
    [ 'OS=="aix"', {
      'defines': [
        '_LINUX_SOURCE_COMPAT',
      ],
    }],
    [ 'OS=="solaris"', {
      'libraries': [
        '-lkstat',
        '-lumem',
      ],
      'defines!': [
        'NODE_PLATFORM="solaris"',
      ],
      'defines': [
        # we need to use node's preferred "sunos"
        # rather than gyp's preferred "solaris"
        'NODE_PLATFORM="sunos"',
      ],
    }],
    [ 'OS=="linux"', {
      'cflags': [ "-Wno-unused-result" ],
    }],
    [ 'OS=="linux" and component == "shared_library"', {
          'ldflags': [ '-L<(PRODUCT_DIR)/../nw/lib/', '-lv8',
                      '-Wl,--whole-archive <(V8_LIBBASE)',
                      '<(V8_PLTFRM)',
                      '-Wl,--no-whole-archive' ]
    }],
    [ 'OS=="linux" and component != "shared_library"', {
          'ldflags': [ '-L<(PRODUCT_DIR)/../nw/lib/', '-lnw',
                      #'-Wl,--whole-archive <(V8_LIBBASE)',
                      #'<(V8_PLTFRM)',
                      #'-Wl,--no-whole-archive'
                     ]
    }],
    [ 'OS=="mac" and component == "shared_library"', {
      'xcode_settings': {
        'OTHER_LDFLAGS': [
          '-L<(PRODUCT_DIR)/../nw/', '-lv8',
          '<(PRODUCT_DIR)/../nw/nwjs\ Framework.framework/nwjs\ Framework',
                  '-Wl,-force_load <(V8_LIBBASE)',
                  '-Wl,-force_load <(V8_PLTFRM)',
        ],
      },
      'postbuilds': [
        {
          'postbuild_name': 'Fix iculib Link',
          'action': [
            'install_name_tool',
            '-change',
            '/usr/local/lib/libicuuc.dylib',
            '@rpath/libicuuc.dylib',
            '${BUILT_PRODUCTS_DIR}/${EXECUTABLE_PATH}'
          ],
        },
        {
          'postbuild_name': 'Fix iculib Link2',
          'action': [
            'install_name_tool',
            '-change',
            '/usr/local/lib/libicui18n.dylib',
            '@rpath/libicui18n.dylib',
            '${BUILT_PRODUCTS_DIR}/${EXECUTABLE_PATH}'
          ],
        },
      ],
    }],
    [ 'OS=="mac" and component != "shared_library"', {
     'xcode_settings': {
       'OTHER_LDFLAGS': [
         '<(PRODUCT_DIR)/../nw/nwjs\ Framework.framework/nwjs\ Framework',
                 '-Wl,-force_load <(V8_LIBBASE)',
                 '-Wl,-force_load <(V8_PLTFRM)',
       ],
     },
    }],
    [ '(OS=="freebsd" or OS=="linux") and node_shared=="false" and coverage=="true"', {
      'ldflags': [ '-Wl,-z,noexecstack',
                   '-Wl,--whole-archive <(V8_BASE)',
                   '-Wl,--no-whole-archive',
                   '--coverage',
                   '-g',
                   '-O0' ],
       'cflags': [ '--coverage',
                   '-g',
                   '-O0' ],
       'cflags!': [ '-O3' ]
    }],
    [ 'OS=="mac" and node_shared=="false" and coverage=="true"', {
      'xcode_settings': {
        'OTHER_LDFLAGS': [
          '--coverage',
        ],
        'OTHER_CFLAGS+': [
          '--coverage',
          '-g',
          '-O0'
        ],
      }
    }],
    [ 'OS=="sunos"', {
      'ldflags': [ '-Wl,-M,/usr/lib/ld/map.noexstk' ],
    }],
  ],
}
