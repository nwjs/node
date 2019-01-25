{
  'variables': {
    'asan%': 0,
    'werror': '',                     # Turn off -Werror in V8 build.
    'visibility%': 'hidden',          # V8's visibility setting
    'target_arch%': 'ia32',           # set v8's target architecture
    'host_arch%': 'ia32',             # set v8's host architecture
    'want_separate_host_toolset%': 0, # V8 should not build target and host
    'library%': 'static_library',     # allow override to 'shared_library' for DLL/.so builds
    'component%': 'static_library',   # NB. these names match with what V8 expects
    'msvs_multi_core_compile': '0',   # we do enable multicore compiles, but not using the V8 way
    'enable_pgo_generate%': '0',
    'enable_pgo_use%': '0',
    'python%': 'python',

    'node_shared%': 'true',
    'force_dynamic_crt%': 0,
    'node_use_v8_platform%': 'true',
    'node_use_bundled_v8%': 'true',
    'node_debug_lib': 'false',
    'node_module_version%': '',
    'node_with_ltcg%': '',
    'node_use_pch%': 'false',

    'build_v8_with_gn': 'false',
    'openssl_no_asm': 1,
    'mac_product_name': 'nwjs',
    'enable_lto': 'false',

    'node_tag%': '',
    'uv_library%': 'static_library',

    'clang%': 0,

    'openssl_fips': '',
    'llvm_version': '6.0',

    # Reset this number to 0 on major V8 upgrades.
    # Increment by one for each non-official patch applied to deps/v8.
    'v8_embedder_string': '-node.16',

    # Enable disassembler for `--print-code` v8 options
    'v8_enable_disassembler': 1,
    'v8_host_byteorder': '<!(python -c "import sys; print sys.byteorder")',

    'v8_use_external_startup_data': 1,
    'v8_enable_i18n_support%': 1,
    #'icu_use_data_file_flag%': 1,
    'win_fastlink': 0,

    # Disable V8 untrusted code mitigations.
    # See https://github.com/v8/v8/wiki/Untrusted-code-mitigations
    'v8_untrusted_code_mitigations': 'false',

    # Some STL containers (e.g. std::vector) do not preserve ABI compatibility
    # between debug and non-debug mode.
    'disable_glibcxx_debug': 1,

    # Don't use ICU data file (icudtl.dat) from V8, we use our own.
    'icu_use_data_file_flag%': 0,
    'variables': {
      'building_nw%' : 0,
    },
    'building_nw%' : '<(building_nw)',

    'conditions': [
      ['target_arch=="arm64"', {
        # Disabled pending https://github.com/nodejs/node/issues/23913.
        'openssl_no_asm%': 1,
      }, {
        'openssl_no_asm%': 0,
      }],
      ['OS == "win"', {
        'os_posix': 0,
        'v8_postmortem_support%': 'false',
        'obj_dir': '<(PRODUCT_DIR)/obj',
        'v8_base': '<(PRODUCT_DIR)/lib/v8_libbase.lib',
        'clang_dir': 'third_party/llvm-build/Release+Asserts/',
      }, {
        'os_posix': 1,
        'v8_postmortem_support%': 'true',
        'clang_dir': '<!(cd <(DEPTH) && pwd -P)/third_party/llvm-build/Release+Asserts',
      }],
      ['OS=="linux" and target_arch=="ia32" and <(building_nw)==1', {
        'sysroot': '<!(cd <(DEPTH) && pwd -P)/build/linux/debian_sid_i386-sysroot',
      }],
      ['OS=="linux" and target_arch=="x64" and <(building_nw)==1', {
        'sysroot': '<!(cd <(DEPTH) && pwd -P)/build/linux/debian_sid_amd64-sysroot',
      }],
      ['OS== "mac"', {
        'obj_dir': '<(PRODUCT_DIR)/obj.target',
        #'v8_base': '<(PRODUCT_DIR)/libv8_base.a',
      }, {
        'conditions': [
          ['GENERATOR=="ninja"', {
            'obj_dir': '<(PRODUCT_DIR)/obj',
            'v8_base': '<(PRODUCT_DIR)/obj/deps/v8/src/libv8_base.a',
          }, {
            'obj_dir%': '<(PRODUCT_DIR)/obj.target',
            'v8_base%': '<(PRODUCT_DIR)/obj.target/deps/v8/src/libv8_base.a',
          }],
        ],
      }],
      ['build_v8_with_gn == "true"', {
        'conditions': [
          ['GENERATOR == "ninja"', {
            'v8_base': '<(PRODUCT_DIR)/obj/deps/v8/gypfiles/v8_monolith.gen/gn/obj/libv8_monolith.a',
          }, {
            'v8_base': '<(PRODUCT_DIR)/obj.target/v8_monolith/geni/gn/obj/libv8_monolith.a',
          }],
        ],
      }],
      ['openssl_fips != ""', {
        'openssl_product': '<(STATIC_LIB_PREFIX)crypto<(STATIC_LIB_SUFFIX)',
      }, {
        'openssl_product': '<(STATIC_LIB_PREFIX)openssl<(STATIC_LIB_SUFFIX)',
      }],
      ['OS=="mac"', {
        'clang%': 1,
      }],
    ],
  },

  'conditions': [
      [ 'clang==1 and OS == "linux" and building_nw==1', {
        'make_global_settings': [
          ['CC', '<(clang_dir)/bin/clang'],
          ['CXX', '<(clang_dir)/bin/clang++'],
          ['CC.host', '$(CC)'],
          ['CXX.host', '$(CXX)'],
        ],
      }],
      [ 'clang==1 and OS == "win" and building_nw==1', {
        'make_global_settings': [
          ['CC', 'third_party/llvm-build/Release+Asserts/bin/clang-cl'],
          ['CXX', 'third_party/llvm-build/Release+Asserts/bin/clang-cl'],
          ['CC.host', '$(CC)'],
          ['CXX.host', '$(CXX)'],
        ],
      }],
      [ 'OS == "win" and building_nw==1', {
        'make_global_settings': [
          ['LD', 'third_party/llvm-build/Release+Asserts/bin/lld-link.exe'],
        ],
      }],
  ],
  'target_defaults': {
    'default_configuration': 'Release',
    'variables': {
      'conditions': [
        ['OS=="win" and component=="shared_library"', {
          # See http://msdn.microsoft.com/en-us/library/aa652367.aspx
          'win_release_RuntimeLibrary%': '2', # 2 = /MD (nondebug DLL)
          'win_debug_RuntimeLibrary%': '3',   # 3 = /MDd (debug DLL)
        }, {
          # See http://msdn.microsoft.com/en-us/library/aa652367.aspx
          'win_release_RuntimeLibrary%': '0', # 0 = /MT (nondebug static)
          'win_debug_RuntimeLibrary%': '1',   # 1 = /MTd (debug static)
        }],
      ],
    },
    'configurations': {
      'Common_Base': {
        'abstract': 1,
        'msvs_settings':{
          'VCCLCompilerTool': {
            'AdditionalOptions': [
              '/bigobj',
              # Tell the compiler to crash on failures. This is undocumented
              # and unsupported but very handy.
              '/d2FastFail',
            ],
          },
          'VCLinkerTool': {
            # Add the default import libs.
            'AdditionalDependencies': [
              'kernel32.lib',
              'gdi32.lib',
              'winspool.lib',
              'comdlg32.lib',
              'advapi32.lib',
              'shell32.lib',
              'ole32.lib',
              'oleaut32.lib',
              'user32.lib',
              'uuid.lib',
              'odbc32.lib',
              'odbccp32.lib',
              'delayimp.lib',
              'credui.lib',
              'dbghelp.lib',
              'shlwapi.lib',
              'winmm.lib',
            ],
            'AdditionalOptions': [
              # Suggested by Microsoft Devrel to avoid
              #   LINK : fatal error LNK1248: image size (80000000) exceeds maximum allowable size (80000000)
              # which started happening more regularly after VS2013 Update 4.
              # Needs to be a bit lower for VS2015, or else errors out.
              '/maxilksize:0x7ff00000',
              # Tell the linker to crash on failures.
              '/fastfail',
            ],
          },
        },
        'conditions': [
          ['OS=="win" and win_fastlink==1 and MSVS_VERSION != "2013"', {
            'msvs_settings': {
              'VCLinkerTool': {
                # /PROFILE is incompatible with /debug:fastlink
                'Profile': 'false',
                'AdditionalOptions': [
                  # Tell VS 2015+ to create a PDB that references debug
                  # information in .obj and .lib files instead of copying
                  # it all.
                  '/DEBUG:FASTLINK',
                ],
              },
            },
          }],
          ['OS=="win" and component=="shared_library"', {
            'msvs_settings': {
              'VCCLCompilerTool': {
                'AdditionalOptions': [
                  '/Zc:dllexportInlines-',
                ],
              },
            },
          }],
          ['OS=="win" and MSVS_VERSION == "2015"', {
            'msvs_settings': {
              'VCCLCompilerTool': {
                'AdditionalOptions': [
                  # Work around crbug.com/526851, bug in VS 2015 RTM compiler.
                  '/Zc:sizedDealloc-',
                  # Disable thread-safe statics to avoid overhead and because
                  # they are disabled on other platforms. See crbug.com/587210
                  # and -fno-threadsafe-statics.
                  '/Zc:threadSafeInit-',
                ],
              },
            },
          }],
        ],
      },
      'Debug_Base': {
        'abstract': 1,
        'variables': {
          'v8_enable_handle_zapping': 1,
        },
        'defines': [ 'DEBUG', '_DEBUG', 'V8_ENABLE_CHECKS', '_HAS_ITERATOR_DEBUGGING=0' ],
        'cflags': [ '-g', '-O0' ],
        'conditions': [
          ['target_arch=="x64"', {
            'msvs_configuration_platform': 'x64',
          }],
          ['OS=="aix"', {
            'cflags': [ '-gxcoff' ],
            'ldflags': [ '-Wl,-bbigtoc' ],
          }],
          ['OS == "android"', {
            'cflags': [ '-fPIE' ],
            'ldflags': [ '-fPIE', '-pie' ]
          }],
        ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'RuntimeLibrary': '<(win_debug_RuntimeLibrary)', # static debug
            'Optimization': 0, # /Od, no optimization
            'MinimalRebuild': 'false',
            'OmitFramePointers': 'false',
            'BasicRuntimeChecks': 3, # /RTC1
            'MultiProcessorCompilation': 'true',
            'AdditionalOptions': [
              '/bigobj', # prevent error C1128 in VS2015
            ],
          },
          'VCLinkerTool': {
            'LinkIncremental': 2, # enable incremental linking
          },
        },
        'xcode_settings': {
          'GCC_OPTIMIZATION_LEVEL': '0', # stop gyp from defaulting to -Os
        },
      },
      'Release_Base': {
        'abstract': 1,
        'variables': {
          'v8_enable_handle_zapping': 0,
        },
        'cflags': [ '-O3' ],
        'conditions': [
          ['target_arch=="x64"', {
            'msvs_configuration_platform': 'x64',
          }],
          ['OS=="solaris"', {
            # pull in V8's postmortem metadata
            'ldflags': [ '-Wl,-z,allextract' ]
          }],
          ['OS!="mac" and OS!="win"', {
            'cflags': [ '-fno-omit-frame-pointer' ],
          }],
          ['OS=="linux"', {
            'variables': {
              'pgo_generate': ' -fprofile-generate ',
              'pgo_use': ' -fprofile-use -fprofile-correction ',
              'lto': ' -flto=4 -fuse-linker-plugin -ffat-lto-objects ',
            },
            'conditions': [
              ['enable_pgo_generate=="true"', {
                'cflags': ['<(pgo_generate)'],
                'ldflags': ['<(pgo_generate)'],
              },],
              ['enable_pgo_use=="true"', {
                'cflags': ['<(pgo_use)'],
                'ldflags': ['<(pgo_use)'],
              },],
              ['enable_lto=="true"', {
                'cflags': ['<(lto)'],
                'ldflags': ['<(lto)'],
              },],
            ],
          },],
          ['OS == "android"', {
            'cflags': [ '-fPIE' ],
            'ldflags': [ '-fPIE', '-pie' ]
          }],
          ['node_shared=="true_disable"', {
            'msvs_settings': {
             'VCCLCompilerTool': {
               'RuntimeLibrary': 2 # MultiThreadedDLL (/MD)
             }
            }
          }],
          ['node_shared=="false_disable"', {
            'msvs_settings': {
              'VCCLCompilerTool': {
                'RuntimeLibrary': 0 # MultiThreaded (/MT)
              }
            }
          }],
          ['node_with_ltcg=="true"', {
            'msvs_settings': {
              'VCCLCompilerTool': {
                'WholeProgramOptimization': 'true' # /GL, whole program optimization, needed for LTCG
              },
              'VCLibrarianTool': {
                'AdditionalOptions': [
                  '/LTCG:INCREMENTAL', # link time code generation
                ]
              },
              'VCLinkerTool': {
                'OptimizeReferences': 2, # /OPT:REF
                'EnableCOMDATFolding': 2, # /OPT:ICF
                'LinkIncremental': 1, # disable incremental linking
                'AdditionalOptions': [
                  '/LTCG:INCREMENTAL', # incremental link-time code generation
                ]
              }
            }
          }, {
            'msvs_settings': {
              'VCCLCompilerTool': {
                'WholeProgramOptimization': 'false'
              },
              'VCLinkerTool': {
                'LinkIncremental': 2 # enable incremental linking
              }
            }
          }]
        ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'RuntimeLibrary': '<(win_release_RuntimeLibrary)', # static release
            'Optimization': 3, # /Ox, full optimization
            'FavorSizeOrSpeed': 1, # /Ot, favor speed over size
            'InlineFunctionExpansion': 2, # /Ob2, inline anything eligible
            'OmitFramePointers': 'true',
            'EnableFunctionLevelLinking': 'true',
            'EnableIntrinsicFunctions': 'true',
            'RuntimeTypeInfo': 'false',
            'MultiProcessorCompilation': 'true',
            'AdditionalOptions': [
            ],
          }
        }
      },
      'Debug': {
        'inherit_from': ['Common_Base', 'Debug_Base'],
      },
      'Release': {
        'inherit_from': ['Common_Base', 'Release_Base'],
      },
      'conditions': [
        [ 'OS=="win"', {
              'Debug_x64': { 'inherit_from': ['Debug'] },
              'Release_x64': { 'inherit_from': ['Release'], },
        }],
      ],
    },
    # Forcibly disable -Werror.  We support a wide range of compilers, it's
    # simply not feasible to squelch all warnings, never mind that the
    # libraries in deps/ are not under our control.
    'cflags!': ['-Werror'],
    'msvs_settings': {
      'VCCLCompilerTool': {
        'StringPooling': 'true', # pool string literals
        'DebugInformationFormat': 1, # /Z7 embed info in .obj files
        'WarningLevel': 3,
        'BufferSecurityCheck': 'true',
        'ExceptionHandling': 0, # /EHsc
        'SuppressStartupBanner': 'true',
        'WarnAsError': 'false',
      },
      'VCLinkerTool': {
        'conditions': [
          ['target_arch=="ia32"', {
            'TargetMachine' : 1, # /MACHINE:X86
            'target_conditions': [
              ['_type=="executable"', {
                'AdditionalOptions': [ '/SubSystem:Console,"5.01"' ],
              }],
            ],
          }],
          ['target_arch=="x64"', {
            'TargetMachine' : 17, # /MACHINE:AMD64
            'target_conditions': [
              ['_type=="executable"', {
                'AdditionalOptions': [ '/SubSystem:Console,"5.02"' ],
              }],
            ],
          }],
        ],
        'GenerateDebugInformation': 'true',
        'GenerateMapFile': 'false', # /MAP
        'MapExports': 'false', # /MAPINFO:EXPORTS
        'RandomizedBaseAddress': 2, # enable ASLR
        'DataExecutionPrevention': 2, # enable DEP
        'AllowIsolation': 'true',
        'SuppressStartupBanner': 'true',
      },
    },
    # Disable warnings:
    # - "C4251: class needs to have dll-interface"
    # - "C4275: non-DLL-interface used as base for DLL-interface"
    #   Over 10k of these warnings are generated when compiling node,
    #   originating from v8.h. Most of them are false positives.
    #   See also: https://github.com/nodejs/node/pull/15570
    #   TODO: re-enable when Visual Studio fixes these upstream.
    #
    # - "C4267: conversion from 'size_t' to 'int'"
    #   Many any originate from our dependencies, and their sheer number
    #   drowns out other, more legitimate warnings.
    # - "C4244: conversion from 'type1' to 'type2', possible loss of data"
    #   Ususaly safe. Disable for `dep`, enable for `src`
    'msvs_disabled_warnings': [4351, 4355, 4800, 4251, 4275, 4244, 4267, 4595],
    'conditions': [
      ['asan == 1 and OS != "mac"', {
        'cflags+': [
          '-fno-omit-frame-pointer',
          '-fsanitize=address',
          '-DLEAK_SANITIZER'
        ],
        'cflags!': [ '-fomit-frame-pointer' ],
        'ldflags': [ '-fsanitize=address' ],
      }],
      ['asan == 1 and OS == "mac"', {
        'xcode_settings': {
          'OTHER_CFLAGS+': [
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-fsanitize=address',
            '-DLEAK_SANITIZER'
          ],
          'OTHER_CFLAGS!': [
            '-fomit-frame-pointer',
          ],
        },
        'target_conditions': [
          ['_type!="static_library"', {
            'xcode_settings': {'OTHER_LDFLAGS': ['-fsanitize=address']},
          }],
        ],
      }],
      ['OS == "win"', {
        'msvs_cygwin_shell': 0, # prevent actions from trying to use cygwin
        'defines': [
          'WIN32',
          # we don't really want VC++ warning us about
          # how dangerous C functions are...
          '_CRT_SECURE_NO_DEPRECATE',
          # ... or that C implementations shouldn't use
          # POSIX names
          '_CRT_NONSTDC_NO_DEPRECATE',
          # Make sure the STL doesn't try to use exceptions
          '_HAS_EXCEPTIONS=0',
          #'BUILDING_V8_SHARED=1',
          'BUILDING_UV_SHARED=1',
        ],
      }],
      [ 'OS in "linux freebsd openbsd solaris aix"', {
        'cflags': [ '-pthread' ],
        'ldflags': [ '-pthread' ],
      }],
      [ 'OS in "linux freebsd openbsd solaris android aix cloudabi"', {
        'cflags': [ '-Wall', '-Wextra', '-Wno-unused-parameter', ],
        'cflags_cc': [ '-fno-rtti', '-fno-exceptions', '-std=gnu++1y' ],
        'ldflags': [ '-rdynamic' ],
        'target_conditions': [
          # The 1990s toolchain on SmartOS can't handle thin archives.
          ['_type=="static_library" and OS=="solaris"', {
            'standalone_static_library': 1,
          }],
          ['OS=="openbsd"', {
            'cflags': [ '-I/usr/local/include' ],
            'ldflags': [ '-Wl,-z,wxneeded' ],
          }],
        ],
        'conditions': [
          [ 'target_arch=="ia32"', {
            'cflags': [ '-m32' ],
            'ldflags': [ '-m32' ],
          }],
          [ 'target_arch=="x32"', {
            'cflags': [ '-mx32' ],
            'ldflags': [ '-mx32' ],
          }],
          [ 'target_arch=="x64"', {
            'cflags': [ '-m64' ],
            'ldflags': [ '-m64' ],
          }],
          [ 'building_nw==1', {
            'cflags': [ '--sysroot=<(sysroot)', '-nostdinc++', '-isystem<(DEPTH)/buildtools/third_party/libc++/trunk/include', '-isystem<(DEPTH)/buildtools/third_party/libc++abi/trunk/include' ],
            'ldflags': [ '--sysroot=<(sysroot)','<!(<(DEPTH)/content/nw/tools/sysroot_ld_path.sh <(sysroot))', '-nostdlib++' ],
          }],
          [ 'target_arch=="ppc" and OS!="aix"', {
            'cflags': [ '-m32' ],
            'ldflags': [ '-m32' ],
          }],
          [ 'target_arch=="ppc64" and OS!="aix"', {
            'cflags': [ '-m64', '-mminimal-toc' ],
            'ldflags': [ '-m64' ],
          }],
          [ 'target_arch=="s390"', {
            'cflags': [ '-m31', '-march=z196' ],
            'ldflags': [ '-m31', '-march=z196' ],
          }],
          [ 'target_arch=="s390x"', {
            'cflags': [ '-m64', '-march=z196' ],
            'ldflags': [ '-m64', '-march=z196' ],
          }],
          [ 'OS=="solaris"', {
            'cflags': [ '-pthreads' ],
            'ldflags': [ '-pthreads' ],
            'cflags!': [ '-pthread' ],
            'ldflags!': [ '-pthread' ],
          }],
          [ 'node_shared=="true"', {
            'cflags': [ '-fPIC' ],
          }],
        ],
      }],
      [ 'OS=="aix"', {
        'variables': {
          # Used to differentiate `AIX` and `OS400`(IBM i).
          'aix_variant_name': '<!(uname -s)',
        },
        'cflags': [ '-maix64', ],
        'ldflags!': [ '-rdynamic', ],
        'ldflags': [
          '-Wl,-bbigtoc',
          '-maix64',
        ],
        'conditions': [
          [ '"<(aix_variant_name)"=="OS400"', {            # a.k.a. `IBM i`
            'ldflags': [
              '-Wl,-blibpath:/QOpenSys/pkgs/lib:/QOpenSys/usr/lib',
              '-Wl,-brtl',
            ],
          }, {                                             # else it's `AIX`
            'ldflags': [
              '-Wl,-blibpath:/usr/lib:/lib:/opt/freeware/lib/pthread/ppc64',
            ],
          }],
        ],
      }],
      ['OS=="android"', {
        'target_conditions': [
          ['_toolset=="target"', {
            'defines': [ '_GLIBCXX_USE_C99_MATH' ],
            'libraries': [ '-llog' ],
          }],
        ],
      }],
      ['OS=="mac"', {
        'defines': ['_DARWIN_USE_64_BIT_INODE=1'],
        'xcode_settings': {
          'ALWAYS_SEARCH_USER_PATHS': 'NO',
          'GCC_CW_ASM_SYNTAX': 'NO',                # No -fasm-blocks
          'GCC_DYNAMIC_NO_PIC': 'NO',               # No -mdynamic-no-pic
                                                    # (Equivalent to -fPIC)
          'GCC_ENABLE_CPP_EXCEPTIONS': 'NO',        # -fno-exceptions
          'GCC_ENABLE_CPP_RTTI': 'NO',              # -fno-rtti
          'GCC_ENABLE_PASCAL_STRINGS': 'NO',        # No -mpascal-strings
          'PREBINDING': 'NO',                       # No -Wl,-prebind
          'MACOSX_DEPLOYMENT_TARGET': '10.7',       # -mmacosx-version-min=10.7
          'USE_HEADERMAP': 'NO',
          'OTHER_CFLAGS': [
            '-fno-strict-aliasing',
          ],
          'WARNING_CFLAGS': [
            '-Wall',
            '-Wendif-labels',
            '-W',
            '-Wno-unused-parameter',
          ],
        },
        'target_conditions': [
          ['_type!="static_library"', {
            'xcode_settings': {
              'OTHER_LDFLAGS': [
                '-Wl,-no_pie',
                '-Wl,-search_paths_first',
              ],
            },
          }],
        ],
        'conditions': [
          ['target_arch=="ia32"', {
            'xcode_settings': {'ARCHS': ['i386']},
          }],
          ['target_arch=="x64"', {
            'xcode_settings': {'ARCHS': ['x86_64']},
          }],
          ['clang==1', {
            'xcode_settings': {
              'GCC_VERSION': 'com.apple.compilers.llvm.clang.1_0',
              'CLANG_CXX_LANGUAGE_STANDARD': 'gnu++1y',  # -std=gnu++1y
              'CLANG_CXX_LIBRARY': 'libc++',
            },
          }],
        ],
      }],
      ['OS=="freebsd" and node_use_dtrace=="true"', {
        'libraries': [ '-lelf' ],
      }],
      ['OS=="freebsd"', {
        'ldflags': [
          '-Wl,--export-dynamic',
        ],
      }]
    ],
  }
}
