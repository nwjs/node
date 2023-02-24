{
  'variables': {
    'v8_use_siphash%': 0,
    'v8_enable_shared_ro_heap%': 0,
    'icu_gyp_path%': '../icu/icu.gyp',
    'coverage': 'false',
    'node_report': 'false',
    'debug_node': 'false',
    'v8_trace_maps%': 0,
    'v8_enable_pointer_compression': 0,
    'v8_enable_31bit_smis_on_64bit_arch': 0,
    'openssl_quic': 'false',
    'node_shared_libuv': 'false',
    'node_no_browser_globals%': 'false',
    'node_snapshot_main%': '',
    'node_use_node_snapshot': 'false',
    'node_use_v8_platform%': 'true',
    'force_dynamic_crt%': 0,
    'ossfuzz' : 'false',
    'node_use_bundled_v8': 'false',
    'node_shared': 'true',
    'v8_enable_inspector': 0,
    'debug_http2': 0,
    'debug_nghttp2': 0,
    'node_enable_d8': 'false',
    'node_use_node_code_cache': 'false',
    'enable_lto': 'false',
    'node_module_version%': '',
    'node_shared_brotli%': 'false',
    'node_shared_zlib%': 'false',
    'node_shared_http_parser%': 'false',
    'node_shared_cares%': 'false',
    'node_shared_libuv%': 'false',
    'node_shared_nghttp2%': 'false',
    'node_use_openssl': 'true',
    'node_shared_openssl': 'false',
    'openssl_fips': '',
    'openssl_is_fips': 'false',
    'node_use_large_pages': 'false',
    'node_v8_options%': '',
    'node_enable_v8_vtunejit%': 'false',
    'node_core_target_name%': 'nodebin',
    'node_lib_target_name%': 'node',
    'node_intermediate_lib_type%': 'shared_library',
    'node_builtin_modules_path%': '',
    # We list the deps/ files out instead of globbing them in js2c.py since we
    # only include a subset of all the files under these directories.
    # The lengths of their file names combined should not exceed the
    # Windows command length limit or there would be an error.
    # See https://docs.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation
    'node_tag%': '',
    'node_release_urlbase%': '',
    'node_byteorder%': 'little',
    'python%': 'python3',
    'icu_small%': 'false',
    'v8_postmortem_support%' : 'false',
    'V8_LIBBASE%': '<(PRODUCT_DIR)/../nw/obj/v8/libv8_libbase.a',
    'V8_PLTFRM%': '<(PRODUCT_DIR)/../nw/obj/v8/libv8_libplatform.a',
    'LIBCXX%': '<(PRODUCT_DIR)/../nw/obj/buildtools/third_party/libc++/libcpp.a',
    'LIBCXXABI%': '<(PRODUCT_DIR)/../nw/obj/buildtools/third_party/libc++abi/libc++abi.a',
    'library_files': [
'lib/constants.js',
'lib/assert.js',
'lib/internal/constants.js',
'lib/internal/assert.js',
'lib/internal/crypto/keys.js',
'lib/internal/crypto/webcrypto.js',
'lib/internal/crypto/diffiehellman.js',
'lib/internal/crypto/pbkdf2.js',
'lib/internal/crypto/ec.js',
'lib/internal/crypto/random.js',
'lib/internal/crypto/sig.js',
'lib/internal/crypto/x509.js',
'lib/internal/crypto/hashnames.js',
'lib/internal/crypto/scrypt.js',
'lib/internal/crypto/cipher.js',
'lib/internal/crypto/hkdf.js',
'lib/internal/crypto/keygen.js',
'lib/internal/crypto/hash.js',
'lib/internal/crypto/aes.js',
'lib/internal/crypto/util.js',
'lib/internal/crypto/cfrg.js',
'lib/internal/crypto/mac.js',
'lib/internal/crypto/rsa.js',
'lib/internal/crypto/certificate.js',
'lib/internal/socketaddress.js',
'lib/internal/dns/utils.js',
'lib/internal/dns/promises.js',
'lib/internal/stream_base_commons.js',
'lib/internal/legacy/processbinding.js',
'lib/internal/querystring.js',
'lib/internal/linkedlist.js',
'lib/internal/async_hooks.js',
'lib/internal/v8_prof_processor.js',
'lib/internal/trace_events_async_hooks.js',
'lib/internal/cli_table.js',
'lib/internal/child_process.js',
'lib/internal/inspector_async_hook.js',
'lib/internal/repl/utils.js',
'lib/internal/repl/await.js',
'lib/internal/repl/history.js',
'lib/internal/fixed_queue.js',
'lib/internal/watchdog.js',
'lib/internal/source_map/prepare_stack_trace.js',
'lib/internal/source_map/source_map.js',
'lib/internal/source_map/source_map_cache.js',
'lib/internal/error_serdes.js',
'lib/internal/net.js',
'lib/internal/v8_prof_polyfill.js',
'lib/internal/v8/startup_snapshot.js',
'lib/internal/console/global.js',
'lib/internal/console/constructor.js',
'lib/internal/blocklist.js',
'lib/internal/debugger/inspect_repl.js',
'lib/internal/debugger/inspect_client.js',
'lib/internal/debugger/inspect.js',
'lib/internal/cluster/utils.js',
'lib/internal/cluster/child.js',
'lib/internal/cluster/worker.js',
'lib/internal/cluster/primary.js',
'lib/internal/cluster/round_robin_handle.js',
'lib/internal/cluster/shared_handle.js',
'lib/internal/assert/assertion_error.js',
'lib/internal/assert/calltracker.js',
'lib/internal/blob.js',
'lib/internal/worker.js',
'lib/internal/child_process/serialization.js',
'lib/internal/process/esm_loader.js',
'lib/internal/process/per_thread.js',
'lib/internal/process/policy.js',
'lib/internal/process/pre_execution.js',
'lib/internal/process/promises.js',
'lib/internal/process/report.js',
'lib/internal/process/task_queues.js',
'lib/internal/process/signal.js',
'lib/internal/process/worker_thread_only.js',
'lib/internal/process/execution.js',
'lib/internal/process/warning.js',
'lib/internal/encoding.js',
'lib/internal/priority_queue.js',
'lib/internal/modules/package_json_reader.js',
'lib/internal/modules/esm/fetch_module.js',
'lib/internal/modules/esm/formats.js',
'lib/internal/modules/esm/handle_process_exit.js',
'lib/internal/modules/esm/loader.js',
'lib/internal/modules/esm/module_map.js',
'lib/internal/modules/esm/resolve.js',
'lib/internal/modules/esm/translators.js',
'lib/internal/modules/esm/module_job.js',
'lib/internal/modules/esm/get_format.js',
'lib/internal/modules/esm/create_dynamic_module.js',
'lib/internal/modules/esm/initialize_import_meta.js',
'lib/internal/modules/esm/assert.js',
'lib/internal/modules/esm/load.js',
'lib/internal/modules/esm/package_config.js',
'lib/internal/modules/esm/utils.js',
'lib/internal/modules/run_main.js',
'lib/internal/modules/helpers.js',
'lib/internal/modules/cjs/loader.js',
'lib/internal/util/colors.js',
'lib/internal/util/comparisons.js',
'lib/internal/util/types.js',
'lib/internal/util/iterable_weak_map.js',
'lib/internal/util/inspector.js',
'lib/internal/util/inspect.js',
'lib/internal/util/debuglog.js',
'lib/internal/util/parse_args/parse_args.js',
'lib/internal/util/parse_args/utils.js',
'lib/internal/histogram.js',
'lib/internal/main/check_syntax.js',
'lib/internal/main/print_help.js',
'lib/internal/main/worker_thread.js',
'lib/internal/main/eval_string.js',
'lib/internal/main/prof_process.js',
'lib/internal/main/eval_stdin.js',
'lib/internal/main/run_main_module.js',
'lib/internal/main/inspect.js',
'lib/internal/main/repl.js',
'lib/internal/fs/read_file_context.js',
'lib/internal/fs/utils.js',
'lib/internal/fs/promises.js',
'lib/internal/fs/dir.js',
'lib/internal/fs/watchers.js',
'lib/internal/fs/cp/cp-sync.js',
'lib/internal/fs/cp/cp.js',
'lib/internal/fs/rimraf.js',
'lib/internal/fs/sync_write_stream.js',
'lib/internal/fs/streams.js',
'lib/internal/readline/utils.js',
'lib/internal/readline/callbacks.js',
'lib/internal/readline/emitKeypressEvents.js',
'lib/internal/readline/promises.js',
'lib/internal/readline/interface.js',
'lib/internal/buffer.js',
'lib/internal/webstreams/readablestream.js',
'lib/internal/webstreams/transfer.js',
'lib/internal/webstreams/encoding.js',
'lib/internal/webstreams/queuingstrategies.js',
'lib/internal/webstreams/util.js',
'lib/internal/webstreams/writablestream.js',
'lib/internal/webstreams/transformstream.js',
'lib/internal/vm/module.js',
'lib/internal/idna.js',
'lib/internal/bootstrap/browser.js',
'lib/internal/bootstrap/loaders.js',
'lib/internal/bootstrap/node.js',
'lib/internal/main/environment.js',
'lib/internal/main/watch_mode.js',
'lib/internal/watch_mode/files_watcher.js',
'lib/internal/bootstrap/switches/is_main_thread.js',
'lib/internal/bootstrap/switches/does_own_process_state.js',
'lib/internal/bootstrap/switches/does_not_own_process_state.js',
'lib/internal/bootstrap/switches/is_not_main_thread.js',
'lib/internal/event_target.js',
'lib/internal/policy/sri.js',
'lib/internal/policy/manifest.js',
'lib/internal/util.js',
'lib/internal/webidl.js',
'lib/internal/abort_controller.js',
'lib/internal/http2/util.js',
'lib/internal/http2/compat.js',
'lib/internal/http2/core.js',
'lib/internal/socket_list.js',
'lib/internal/js_stream_socket.js',
'lib/internal/validators.js',
'lib/internal/per_context/messageport.js',
'lib/internal/per_context/primordials.js',
'lib/internal/per_context/domexception.js',
'lib/internal/tty.js',
'lib/internal/http.js',
'lib/internal/streams/utils.js',
'lib/internal/streams/legacy.js',
'lib/internal/streams/buffer_list.js',
'lib/internal/streams/readable.js',
'lib/internal/streams/destroy.js',
'lib/internal/streams/from.js',
'lib/internal/streams/duplex.js',
'lib/internal/streams/passthrough.js',
'lib/internal/streams/pipeline.js',
'lib/internal/streams/lazy_transform.js',
'lib/internal/streams/add-abort-signal.js',
'lib/internal/streams/end-of-stream.js',
'lib/internal/streams/transform.js',
'lib/internal/streams/state.js',
'lib/internal/streams/writable.js',
'lib/internal/streams/operators.js',
'lib/internal/dgram.js',
'lib/internal/errors.js',
'lib/internal/tls/secure-pair.js',
'lib/internal/tls/secure-context.js',
'lib/internal/freelist.js',
'lib/internal/heap_utils.js',
'lib/internal/worker/js_transferable.js',
'lib/internal/worker/io.js',
'lib/internal/url.js',
'lib/internal/perf/utils.js',
'lib/internal/perf/event_loop_delay.js',
'lib/internal/perf/event_loop_utilization.js',
'lib/internal/perf/nodetiming.js',
'lib/internal/perf/performance_entry.js',
'lib/internal/perf/usertiming.js',
'lib/internal/perf/performance.js',
'lib/internal/perf/timerify.js',
'lib/internal/perf/observe.js',
'lib/internal/repl.js',
'lib/internal/timers.js',
'lib/internal/freeze_intrinsics.js',
'lib/internal/options.js',
'lib/internal/promise_hooks.js',
'lib/internal/structured_clone.js',
'lib/string_decoder.js',
'lib/_http_client.js',
'lib/dns.js',
'lib/dns/promises.js',
'lib/_stream_passthrough.js',
'lib/crypto.js',
'lib/querystring.js',
'lib/async_hooks.js',
'lib/_http_incoming.js',
'lib/path/win32.js',
'lib/path/posix.js',
'lib/_stream_transform.js',
'lib/child_process.js',
'lib/_http_agent.js',
'lib/v8.js',
'lib/net.js',
'lib/path.js',
'lib/sys.js',
'lib/fs.js',
'lib/os.js',
'lib/domain.js',
'lib/_http_outgoing.js',
'lib/stream/web.js',
'lib/stream/promises.js',
'lib/stream/consumers.js',
'lib/_http_common.js',
'lib/assert/strict.js',
'lib/_stream_wrap.js',
'lib/_tls_wrap.js',
'lib/_stream_readable.js',
'lib/timers/promises.js',
'lib/util/types.js',
'lib/fs/promises.js',
'lib/readline.js',
'lib/_tls_common.js',
'lib/_stream_writable.js',
'lib/cluster.js',
'lib/buffer.js',
'lib/_stream_duplex.js',
'lib/punycode.js',
'lib/util.js',
'lib/dummystream.js',
'lib/inspector.js',
'lib/tty.js',
'lib/http.js',
'lib/http2.js',
'lib/tls.js',
'lib/dgram.js',
'lib/worker_threads.js',
'lib/process.js',
'lib/_http_server.js',
'lib/perf_hooks.js',
'lib/trace_events.js',
'lib/module.js',
'lib/https.js',
'lib/zlib.js',
'lib/events.js',
'lib/vm.js',
'lib/url.js',
'lib/console.js',
'lib/repl.js',
'lib/diagnostics_channel.js',
'lib/timers.js',
'lib/wasi.js',
'lib/stream.js',
      'lib/dummystream.js',
    ],
    'deps_files': [
      'deps/v8/tools/splaytree.mjs',
      'deps/v8/tools/codemap.mjs',
      'deps/v8/tools/consarray.mjs',
      'deps/v8/tools/csvparser.mjs',
      'deps/v8/tools/profile.mjs',
      'deps/v8/tools/profile_view.mjs',
      'deps/v8/tools/logreader.mjs',
      'deps/v8/tools/arguments.mjs',
      'deps/v8/tools/tickprocessor.mjs',
      'deps/v8/tools/sourcemap.mjs',
      'deps/v8/tools/tickprocessor-driver.mjs',
      'deps/acorn/acorn/dist/acorn.js',
      'deps/acorn/acorn-walk/dist/walk.js',
      'deps/cjs-module-lexer/lexer.js',
      'deps/cjs-module-lexer/dist/lexer.js',
      'deps/undici/undici.js', #nwjs: reverting ca5be26b318affe7ee63a4b9c0489393c7dae661
    ],
    'node_mksnapshot_exec': '<(PRODUCT_DIR)/<(EXECUTABLE_PREFIX)node_mksnapshot<(EXECUTABLE_SUFFIX)',
    'conditions': [
      ['GENERATOR == "ninja"', {
        'node_text_start_object_path': 'src/large_pages/node_text_start.node_text_start.o'
      }, {
        'node_text_start_object_path': 'node_text_start/src/large_pages/node_text_start.o'
      }],
      [ 'node_shared=="true"', {
        'node_target_type%': 'shared_library',
        'conditions': [
          ['OS=="aix"', {
            # For AIX, always generate static library first,
            # It needs an extra step to generate exp and
            # then use both static lib and exp to create
            # shared lib.
            'node_intermediate_lib_type': 'static_library',
          }, {
            'node_intermediate_lib_type': 'shared_library',
          }],
        ],
      }, {
        'node_target_type%': 'executable',
      }],
      [ 'OS=="win" and '
        'node_use_openssl=="true" and '
        'node_shared_openssl=="false"', {
        'use_openssl_def%': 1,
      }, {
        'use_openssl_def%': 0,
      }],
    ],
  },

  'target_defaults': {
    # Putting these explicitly here so not to depend on `common.gypi`.
    # `common.gypi` need to be more general because it is used to build userland native addons.
    # Refs: https://github.com/nodejs/node-gyp/issues/1118
    'cflags': [ '-Wall', '-Wextra', '-Wno-unused-parameter', ],
    'xcode_settings': {
      'WARNING_CFLAGS': [
        '-Wall',
        '-Wendif-labels',
        '-W',
        '-Wno-unused-parameter',
        '-Werror=undefined-inline',
        '-Werror=extra-semi',
      ],
    },

    # Relevant only for x86.
    # Refs: https://github.com/nodejs/node/pull/25852
    # Refs: https://docs.microsoft.com/en-us/cpp/build/reference/safeseh-image-has-safe-exception-handlers
    'msvs_settings': {
      'VCLinkerTool': {
        'ImageHasSafeExceptionHandlers': 'false',
      },
    },

    'conditions': [
      ['OS=="aix"', {
        'ldflags': [
          '-Wl,-bnoerrmsg',
        ],
      }],
      ['OS == "linux" and llvm_version != "0.0"', {
        'libraries': ['-latomic'],
      }],
    ],
  },
  'includes': [
    '../../build/util/version.gypi',
  ],

  'targets': [
    {
      'target_name': 'node_text_start',
      'type': 'none',
      'conditions': [
        [ 'OS in "linux freebsd solaris" and '
          'target_arch=="x64"', {
          'type': 'static_library',
          'sources': [
            'src/large_pages/node_text_start.S'
          ]
        }],
      ]
    },
    {
      'target_name': '<(node_core_target_name)',
      'type': 'executable',

      'defines': [
        'NODE_ARCH="<(target_arch)"',
        'NODE_PLATFORM="<(OS)"',
        'NODE_WANT_INTERNALS=1',
      ],

      'includes': [
        'node.gypi'
      ],

      'include_dirs': [
        'src',
        'deps/v8/include',
        'deps/postject'
      ],

      'sources': [
        'src/node_main.cc'
      ],

      'dependencies': [
        'deps/histogram/histogram.gyp:histogram',
        'deps/uvwasi/uvwasi.gyp:uvwasi',
      ],

      'msvs_settings': {
        'VCLinkerTool': {
          'GenerateMapFile': 'true', # /MAP
          'MapExports': 'true', # /MAPINFO:EXPORTS
          'RandomizedBaseAddress': 2, # enable ASLR
          'DataExecutionPrevention': 2, # enable DEP
          'AllowIsolation': 'true',
          # By default, the MSVC linker only reserves 1 MiB of stack memory for
          # each thread, whereas other platforms typically allow much larger
          # stack memory sections. We raise the limit to make it more consistent
          # across platforms and to support the few use cases that require large
          # amounts of stack memory, without having to modify the node binary.
          'StackReserveSize': 0x800000,
        },
      },

      # - "C4244: conversion from 'type1' to 'type2', possible loss of data"
      #   Ususaly safe. Disable for `dep`, enable for `src`
      'msvs_disabled_warnings!': [4244],

      'conditions': [
        [ 'error_on_warn=="true"', {
          'cflags': ['-Werror'],
          'xcode_settings': {
            'WARNING_CFLAGS': [ '-Werror' ],
          },
        }],
        [ 'node_intermediate_lib_type=="static_library" and '
            'node_shared=="true" and OS=="aix"', {
          # For AIX, shared lib is linked by static lib and .exp. In the
          # case here, the executable needs to link to shared lib.
          # Therefore, use 'node_aix_shared' target to generate the
          # shared lib and then executable.
          'dependencies': [ 'node_aix_shared' ],
        }, {
          'dependencies': [ '<(node_lib_target_name)' ],
          'conditions': [
            ['OS=="win" and node_shared=="true"', {
              'dependencies': ['generate_node_def'],
              'msvs_settings': {
                'VCLinkerTool': {
                  'ModuleDefinitionFile': '<(PRODUCT_DIR)/<(node_core_target_name).def',
                },
              },
            }],
          ],
        }],
        [ 'node_intermediate_lib_type=="static_library" and node_shared=="false"', {
          'xcode_settings': {
            'OTHER_LDFLAGS': [
              '-Wl,-force_load,<(PRODUCT_DIR)/<(STATIC_LIB_PREFIX)<(node_core_target_name)<(STATIC_LIB_SUFFIX)',
              '-Wl,-force_load,<(PRODUCT_DIR)/<(STATIC_LIB_PREFIX)v8_base_without_compiler<(STATIC_LIB_SUFFIX)',
            ],
          },
          'msvs_settings': {
            'VCLinkerTool': {
              'AdditionalOptions': [
                '/WHOLEARCHIVE:<(node_lib_target_name)<(STATIC_LIB_SUFFIX)',
                '/WHOLEARCHIVE:<(STATIC_LIB_PREFIX)v8_base_without_compiler<(STATIC_LIB_SUFFIX)',
              ],
            },
          },
          'conditions': [
            ['OS != "aix" and OS != "mac" and OS != "ios"', {
              'ldflags': [
                '-Wl,--whole-archive',
                '<(obj_dir)/<(STATIC_LIB_PREFIX)<(node_core_target_name)<(STATIC_LIB_SUFFIX)',
                '<(obj_dir)/tools/v8_gypfiles/<(STATIC_LIB_PREFIX)v8_base_without_compiler<(STATIC_LIB_SUFFIX)',
                '-Wl,--no-whole-archive',
              ],
            }],
            [ 'OS=="win"', {
              'sources': [ 'src/res/node.rc' ],
            }],
          ],
        }],
        [ 'node_shared=="true"', {
          'xcode_settings': {
            'OTHER_LDFLAGS': [ '-Wl,-rpath,@loader_path', '-Wl,-rpath,@loader_path/../lib'],
          },
          'conditions': [
            ['OS=="linux"', {
               'ldflags': [
                 '-Wl,-rpath,\\$$ORIGIN/../lib'
               ],
            }],
          ],
        }],
        [ 'enable_lto=="true"', {
          'xcode_settings': {
            'OTHER_LDFLAGS': [
              # man ld -export_dynamic:
              # Preserves all global symbols in main executables during LTO.
              # Without this option, Link Time Optimization is allowed to
              # inline and remove global functions. This option is used when
              # a main executable may load a plug-in which requires certain
              # symbols from the main executable.
              '-Wl,-export_dynamic',
            ],
          },
        }],
        ['OS=="win"', {
          'libraries': [
            'Dbghelp.lib',
            'winmm.lib',
            'Ws2_32.lib',
          ],
        }],
        ['node_with_ltcg=="true"', {
          'msvs_settings': {
            'VCCLCompilerTool': {
              'WholeProgramOptimization': 'true'   # /GL, whole program optimization, needed for LTCG
            },
            'VCLibrarianTool': {
              'AdditionalOptions': [
                '/LTCG:INCREMENTAL',               # link time code generation
              ],
            },
            'VCLinkerTool': {
              'OptimizeReferences': 2,             # /OPT:REF
              'EnableCOMDATFolding': 2,            # /OPT:ICF
              'LinkIncremental': 1,                # disable incremental linking
              'AdditionalOptions': [
                '/LTCG:INCREMENTAL',               # incremental link-time code generation
              ],
            }
          }
        }, {
          'msvs_settings': {
            'VCCLCompilerTool': {
              'WholeProgramOptimization': 'false'
            },
            'VCLinkerTool': {
              'LinkIncremental': 2                 # enable incremental linking
            },
          },
         }],
         ['node_use_node_snapshot=="true"', {
          'dependencies': [
            'node_mksnapshot',
          ],
          'conditions': [
            ['node_snapshot_main!=""', {
              'actions': [
                {
                  'action_name': 'node_mksnapshot',
                  'process_outputs_as_sources': 1,
                  'inputs': [
                    '<(node_mksnapshot_exec)',
                    '<(node_snapshot_main)',
                  ],
                  'outputs': [
                    '<(SHARED_INTERMEDIATE_DIR)/node_snapshot.cc',
                  ],
                  'action': [
                    '<(node_mksnapshot_exec)',
                    '--build-snapshot',
                    '<(node_snapshot_main)',
                    '<@(_outputs)',
                  ],
                },
              ],
            }, {
              'actions': [
                {
                  'action_name': 'node_mksnapshot',
                  'process_outputs_as_sources': 1,
                  'inputs': [
                    '<(node_mksnapshot_exec)',
                  ],
                  'outputs': [
                    '<(SHARED_INTERMEDIATE_DIR)/node_snapshot.cc',
                  ],
                  'action': [
                    '<@(_inputs)',
                    '<@(_outputs)',
                  ],
                },
              ],
            }],
          ],
          }, {
          'sources': [
            'src/node_snapshot_stub.cc'
          ],
        }],
        [ 'OS in "linux freebsd" and '
          'target_arch=="x64"', {
          'dependencies': [ 'node_text_start' ],
          'ldflags+': [
            '<(obj_dir)/<(node_text_start_object_path)'
          ]
        }],

        ['node_fipsinstall=="true"', {
          'variables': {
            'openssl-cli': '<(PRODUCT_DIR)/<(EXECUTABLE_PREFIX)openssl-cli<(EXECUTABLE_SUFFIX)',
            'provider_name': 'libopenssl-fipsmodule',
            'opensslconfig': './deps/openssl/nodejs-openssl.cnf',
            'conditions': [
              ['GENERATOR == "ninja"', {
	        'fipsmodule_internal': '<(PRODUCT_DIR)/lib/<(provider_name).so',
                'fipsmodule': '<(PRODUCT_DIR)/obj/lib/openssl-modules/fips.so',
                'fipsconfig': '<(PRODUCT_DIR)/obj/lib/fipsmodule.cnf',
                'opensslconfig_internal': '<(PRODUCT_DIR)/obj/lib/openssl.cnf',
             }, {
	        'fipsmodule_internal': '<(PRODUCT_DIR)/obj.target/deps/openssl/<(provider_name).so',
                'fipsmodule': '<(PRODUCT_DIR)/obj.target/deps/openssl/lib/openssl-modules/fips.so',
                'fipsconfig': '<(PRODUCT_DIR)/obj.target/deps/openssl/fipsmodule.cnf',
                'opensslconfig_internal': '<(PRODUCT_DIR)/obj.target/deps/openssl/openssl.cnf',
             }],
            ],
          },
          'actions': [
            {
              'action_name': 'fipsinstall',
              'process_outputs_as_sources': 1,
              'inputs': [
                '<(fipsmodule_internal)',
              ],
              'outputs': [
                '<(fipsconfig)',
              ],
              'action': [
                '<(openssl-cli)', 'fipsinstall',
                '-provider_name', '<(provider_name)',
                '-module', '<(fipsmodule_internal)',
                '-out', '<(fipsconfig)',
                #'-quiet',
              ],
            },
            {
              'action_name': 'copy_fips_module',
              'inputs': [
                '<(fipsmodule_internal)',
              ],
              'outputs': [
                '<(fipsmodule)',
              ],
              'action': [
                'python', 'tools/copyfile.py',
                '<(fipsmodule_internal)',
                '<(fipsmodule)',
              ],
            },
            {
              'action_name': 'copy_openssl_cnf_and_include_fips_cnf',
              'inputs': [ '<(opensslconfig)', ],
              'outputs': [ '<(opensslconfig_internal)', ],
              'action': [
                'python', 'tools/enable_fips_include.py',
                '<(opensslconfig)',
                '<(opensslconfig_internal)',
                '<(fipsconfig)',
              ],
            },
          ],
         }, {
           'variables': {
              'opensslconfig_internal': '<(obj_dir)/deps/openssl/openssl.cnf',
              'opensslconfig': './deps/openssl/nodejs-openssl.cnf',
           },
           'actions': [
             {
               'action_name': 'reset_openssl_cnf',
               'inputs': [ '<(opensslconfig)', ],
               'outputs': [ '<(opensslconfig_internal)', ],
               'action': [
                 '<(python)', 'tools/copyfile.py',
                 '<(opensslconfig)',
                 '<(opensslconfig_internal)',
               ],
             },
           ],
         }],
      ],
    }, # node_core_target_name
    {
      'target_name': '<(node_lib_target_name)',
      'type': '<(node_intermediate_lib_type)',
      'includes': [
        'node.gypi',
      ],
      'msvs_disabled_warnings': [4146, 4267, 4003, 4065, 4477],

      'xcode_settings': {
        'WARNING_CFLAGS': [ '-Wno-error=deprecated-declarations' ],
      },

      'include_dirs': [
        'src',
        'deps/postject',
        '<(SHARED_INTERMEDIATE_DIR)' # for node_natives.h
        '../../v8', # include/v8_platform.h
        '../../v8/include'
      ],
      'dependencies': [
        'deps/base64/base64.gyp:base64',
        'deps/googletest/googletest.gyp:gtest_prod',
        'deps/histogram/histogram.gyp:histogram',
        'deps/uvwasi/uvwasi.gyp:uvwasi',
        'deps/simdutf/simdutf.gyp:simdutf',
        'deps/ada/ada.gyp:ada',
      ],

      'direct_dependent_settings': {
        'include_dirs': [
          '../../v8/include',
          'deps/uv/include',
          'deps/cares/include',
        ],
        'defines': [
          'BUILDING_NW_NODE=1',
          'V8_REVERSE_JSARGS',
        ],

      },

      'sources': [
        'src/api/async_resource.cc',
        'src/api/callback.cc',
        'src/api/embed_helpers.cc',
        'src/api/encoding.cc',
        'src/api/environment.cc',
        'src/api/exceptions.cc',
        'src/api/hooks.cc',
        'src/api/utils.cc',
        'src/async_wrap.cc',
        'src/base_object.cc',
        'src/cares_wrap.cc',
        'src/cleanup_queue.cc',
        'src/connect_wrap.cc',
        'src/connection_wrap.cc',
        'src/debug_utils.cc',
        'src/env.cc',
        'src/fs_event_wrap.cc',
        'src/handle_wrap.cc',
        'src/heap_utils.cc',
        'src/histogram.cc',
        'src/js_native_api.h',
        'src/js_native_api_types.h',
        'src/js_native_api_v8.cc',
        'src/js_native_api_v8.h',
        'src/js_native_api_v8_internals.h',
        'src/js_stream.cc',
        'src/json_utils.cc',
        'src/js_udp_wrap.cc',
        'src/module_wrap.cc',
        'src/node.cc',
        'src/node_snapshot_stub.cc',
        'src/node_api.cc',
        'src/node_binding.cc',
        'src/node_blob.cc',
        'src/node_buffer.cc',
        'src/node_builtins.cc',
        'src/node_config.cc',
        'src/node_constants.cc',
        'src/node_contextify.cc',
        'src/node_credentials.cc',
        'src/node_dir.cc',
        'src/node_env_var.cc',
        'src/node_errors.cc',
        'src/node_external_reference.cc',
        'src/node_file.cc',
        'src/node_http_parser.cc',
        'src/node_http2.cc',
        'src/node_i18n.cc',
        'src/node_main_instance.cc',
        'src/node_messaging.cc',
        'src/node_metadata.cc',
        'src/node_options.cc',
        'src/node_os.cc',
        'src/node_perf.cc',
        'src/node_platform.cc',
        'src/node_postmortem_metadata.cc',
        'src/node_process_events.cc',
        'src/node_process_methods.cc',
        'src/node_process_object.cc',
        'src/node_realm.cc',
        'src/node_report.cc',
        'src/node_report_module.cc',
        'src/node_report_utils.cc',
        'src/node_sea.cc',
        'src/node_serdes.cc',
        'src/node_shadow_realm.cc',
        'src/node_snapshotable.cc',
        'src/node_sockaddr.cc',
        'src/node_stat_watcher.cc',
        'src/node_symbols.cc',
        'src/node_task_queue.cc',
        'src/node_trace_events.cc',
        'src/node_types.cc',
        'src/node_url.cc',
        'src/node_util.cc',
        'src/node_v8.cc',
        'src/node_wasi.cc',
        'src/node_wasm_web_api.cc',
        'src/node_watchdog.cc',
        'src/node_worker.cc',
        'src/node_zlib.cc',
        'src/pipe_wrap.cc',
        'src/process_wrap.cc',
        'src/signal_wrap.cc',
        'src/spawn_sync.cc',
        'src/stream_base.cc',
        'src/stream_pipe.cc',
        'src/stream_wrap.cc',
        'src/string_bytes.cc',
        'src/string_decoder.cc',
        'src/tcp_wrap.cc',
        'src/timers.cc',
        'src/timer_wrap.cc',
        #'src/tracing/agent.cc',
        #'src/tracing/node_trace_buffer.cc',
        #'src/tracing/node_trace_writer.cc',
        #'src/tracing/trace_event.cc',
        #'src/tracing/traced_value.cc',
        'src/tty_wrap.cc',
        'src/udp_wrap.cc',
        'src/util.cc',
        'src/uv.cc',
        # headers to make for a more pleasant IDE experience
        'src/aliased_buffer.h',
        'src/aliased_struct.h',
        'src/aliased_struct-inl.h',
        'src/async_wrap.h',
        'src/async_wrap-inl.h',
        'src/base_object.h',
        'src/base_object-inl.h',
        'src/base64.h',
        'src/base64-inl.h',
        'src/callback_queue.h',
        'src/callback_queue-inl.h',
        'src/cleanup_queue.h',
        'src/cleanup_queue-inl.h',
        'src/connect_wrap.h',
        'src/connection_wrap.h',
        'src/debug_utils.h',
        'src/debug_utils-inl.h',
        'src/env_properties.h',
        'src/env.h',
        'src/env-inl.h',
        'src/handle_wrap.h',
        'src/histogram.h',
        'src/histogram-inl.h',
        'src/js_stream.h',
        'src/json_utils.h',
        'src/large_pages/node_large_page.cc',
        'src/large_pages/node_large_page.h',
        'src/memory_tracker.h',
        'src/memory_tracker-inl.h',
        'src/module_wrap.h',
        'src/node.h',
        'src/node_api.h',
        'src/node_api_types.h',
        'src/node_binding.h',
        'src/node_blob.h',
        'src/node_buffer.h',
        'src/node_builtins.h',
        'src/node_constants.h',
        'src/node_context_data.h',
        'src/node_contextify.h',
        'src/node_dir.h',
        'src/node_errors.h',
        'src/node_exit_code.h',
        'src/node_external_reference.h',
        'src/node_file.h',
        'src/node_file-inl.h',
        'src/node_http_common.h',
        'src/node_http_common-inl.h',
        'src/node_http2.h',
        'src/node_http2_state.h',
        'src/node_i18n.h',
        'src/node_internals.h',
        'src/node_main_instance.h',
        'src/node_mem.h',
        'src/node_mem-inl.h',
        'src/node_messaging.h',
        'src/node_metadata.h',
        'src/node_mutex.h',
        'src/node_object_wrap.h',
        'src/node_options.h',
        'src/node_options-inl.h',
        'src/node_perf.h',
        'src/node_perf_common.h',
        'src/node_platform.h',
        'src/node_process.h',
        'src/node_process-inl.h',
        'src/node_realm.h',
        'src/node_realm-inl.h',
        'src/node_report.h',
        'src/node_revert.h',
        'src/node_root_certs.h',
        'src/node_sea.h',
        'src/node_shadow_realm.h',
        'src/node_snapshotable.h',
        'src/node_snapshot_builder.h',
        'src/node_sockaddr.h',
        'src/node_sockaddr-inl.h',
        'src/node_stat_watcher.h',
        'src/node_union_bytes.h',
        'src/node_url.h',
        'src/node_util.h',
        'src/node_version.h',
        'src/node_v8.h',
        'src/node_v8_platform-inl.h',
        'src/node_wasi.h',
        'src/node_watchdog.h',
        'src/node_worker.h',
        'src/pipe_wrap.h',
        'src/req_wrap.h',
        'src/req_wrap-inl.h',
        'src/spawn_sync.h',
        'src/stream_base.h',
        'src/stream_base-inl.h',
        'src/stream_pipe.h',
        'src/stream_wrap.h',
        'src/string_bytes.h',
        'src/string_decoder.h',
        'src/string_decoder-inl.h',
        'src/string_search.h',
        'src/tcp_wrap.h',
        'src/tracing/agent.h',
        'src/tracing/node_trace_buffer.h',
        'src/tracing/node_trace_writer.h',
        'src/tracing/trace_event.h',
        'src/tracing/trace_event_common.h',
        'src/tracing/traced_value.h',
        'src/timer_wrap.h',
        'src/timer_wrap-inl.h',
        'src/tty_wrap.h',
        'src/udp_wrap.h',
        'src/util.h',
        'src/util-inl.h',
        # Dependency headers
        #'deps/v8/include/v8.h',
        'deps/postject/postject-api.h'
        # javascript files to make for an even more pleasant IDE experience
        '<@(library_files)',
        '<@(deps_files)',
        # node.gyp is added by default, common.gypi is added for change detection
        'common.gypi',
      ],

      'variables': {
        'openssl_system_ca_path%': '',
        'openssl_default_cipher_list%': '',
      },

      'cflags': ['-Werror=unused-result'],

      'defines': [
        'NODE_ARCH="<(target_arch)"',
        'NODE_PLATFORM="<(OS)"',
        'NODE_WANT_INTERNALS=1',
        # Warn when using deprecated V8 APIs.
        'V8_DEPRECATION_WARNINGS=1',
        'BUILDING_NW_NODE=1',
        'V8_REVERSE_JSARGS',
        '_ALLOW_ITERATOR_DEBUG_LEVEL_MISMATCH',
        'V8_SHARED',
        'USING_V8_SHARED',
        'V8_USE_EXTERNAL_STARTUP_DATA',
        'NODE_OPENSSL_SYSTEM_CERT_PATH="<(openssl_system_ca_path)"',
      ],

      # - "C4244: conversion from 'type1' to 'type2', possible loss of data"
      #   Ususaly safe. Disable for `dep`, enable for `src`
      'msvs_disabled_warnings!': [4244],

      'conditions': [
        [ 'OS=="win" or OS=="linux"', {
          'include_dirs': [
            '<(PRODUCT_DIR)/../../buildtools/third_party/libc++/trunk/include',
            '<(PRODUCT_DIR)/../../buildtools/third_party/libc++',
          ],
        }],
        [ 'openssl_default_cipher_list!=""', {
          'defines': [
            'NODE_OPENSSL_DEFAULT_CIPHER_LIST="<(openssl_default_cipher_list)"'
           ]
        }],
        [ 'error_on_warn=="true"', {
          'cflags': ['-Werror'],
          'xcode_settings': {
            'WARNING_CFLAGS': [ '-Werror' ],
          },
        }],
        [ 'node_builtin_modules_path!=""', {
          'defines': [ 'NODE_BUILTIN_MODULES_PATH="<(node_builtin_modules_path)"' ]
        }],
        [ 'node_shared=="true"', {
          'sources': [
            'src/node_snapshot_stub.cc',
          ]
        }],
        [ 'node_shared=="true" and node_module_version!="" and OS!="win"', {
          'product_extension': '<(shlib_suffix)',
          'xcode_settings': {
            'LD_DYLIB_INSTALL_NAME':
              '@rpath/lib<(node_core_target_name).<(shlib_suffix)'
          },
        }],
        [ 'node_use_node_code_cache=="true"', {
          'defines': [
            'NODE_USE_NODE_CODE_CACHE=1',
          ],
        }],
        ['node_shared=="true" and OS=="aix"', {
          'product_name': 'node_base',
        }],
        [ 'v8_enable_inspector==1', {
          'includes' : [ 'src/inspector/node_inspector.gypi' ],
        }, {
          'defines': [ 'HAVE_INSPECTOR=0' ]
        }],
        [ 'OS=="win"', {
          'conditions': [
            [ 'node_intermediate_lib_type!="static_library"', {
              'sources': [
                'src/res/node-nw.rc',
              ],
            }],
            [ 'component == "shared_library"', {
              'libraries': [ 'Winmm', 'ws2_32', '-lpsapi.lib', '<(PRODUCT_DIR)/../nw/obj/v8/v8_libbase.lib', '<(PRODUCT_DIR)/../nw/obj/v8/v8_libplatform.lib', '<(PRODUCT_DIR)/../nw/nw.dll.lib', '<(PRODUCT_DIR)/../nw/libc++.dll.lib'],
            }, {
              'libraries': [ 'Winmm', 'ws2_32', '-lpsapi.lib', '<(PRODUCT_DIR)/../nw/obj/v8/v8_libbase.lib', '<(PRODUCT_DIR)/../nw/obj/v8/v8_libplatform.lib', '<(PRODUCT_DIR)/../nw/nw.dll.lib', '<(PRODUCT_DIR)/../nw/obj/buildtools/third_party/libc++/libcpp.lib'],
            }],
          ],
        }],
        [ 'node_use_openssl=="true"', {
          'sources': [
            'src/crypto/crypto_aes.cc',
            'src/crypto/crypto_bio.cc',
            'src/crypto/crypto_common.cc',
            'src/crypto/crypto_dsa.cc',
            'src/crypto/crypto_hkdf.cc',
            'src/crypto/crypto_pbkdf2.cc',
            'src/crypto/crypto_sig.cc',
            'src/crypto/crypto_timing.cc',
            'src/crypto/crypto_cipher.cc',
            'src/crypto/crypto_context.cc',
            'src/crypto/crypto_ec.cc',
            'src/crypto/crypto_hmac.cc',
            'src/crypto/crypto_random.cc',
            'src/crypto/crypto_rsa.cc',
            'src/crypto/crypto_spkac.cc',
            'src/crypto/crypto_util.cc',
            'src/crypto/crypto_clienthello.cc',
            'src/crypto/crypto_dh.cc',
            'src/crypto/crypto_hash.cc',
            'src/crypto/crypto_keys.cc',
            'src/crypto/crypto_keygen.cc',
            'src/crypto/crypto_scrypt.cc',
            'src/crypto/crypto_tls.cc',
            'src/crypto/crypto_aes.cc',
            'src/crypto/crypto_x509.cc',
            'src/crypto/crypto_bio.h',
            'src/crypto/crypto_clienthello-inl.h',
            'src/crypto/crypto_dh.h',
            'src/crypto/crypto_hmac.h',
            'src/crypto/crypto_rsa.h',
            'src/crypto/crypto_spkac.h',
            'src/crypto/crypto_util.h',
            'src/crypto/crypto_cipher.h',
            'src/crypto/crypto_common.h',
            'src/crypto/crypto_dsa.h',
            'src/crypto/crypto_hash.h',
            'src/crypto/crypto_keys.h',
            'src/crypto/crypto_keygen.h',
            'src/crypto/crypto_scrypt.h',
            'src/crypto/crypto_tls.h',
            'src/crypto/crypto_clienthello.h',
            'src/crypto/crypto_context.h',
            'src/crypto/crypto_ec.h',
            'src/crypto/crypto_hkdf.h',
            'src/crypto/crypto_pbkdf2.h',
            'src/crypto/crypto_sig.h',
            'src/crypto/crypto_random.h',
            'src/crypto/crypto_timing.h',
            'src/crypto/crypto_x509.h',
            'src/node_crypto.cc',
            'src/node_crypto.h'
          ],
        }],
        [ 'OS in "linux freebsd mac solaris" and '
          'target_arch=="x64" and '
          'node_target_type=="executable"', {
          'defines': [ 'NODE_ENABLE_LARGE_CODE_PAGES=1' ],
        }],
        [ 'use_openssl_def==1', {
          # TODO(bnoordhuis) Make all platforms export the same list of symbols.
          # Teach mkssldef.py to generate linker maps that UNIX linkers understand.
          'variables': {
            'mkssldef_flags': [
              # Categories to export.
              '-CAES,BF,BIO,DES,DH,DSA,EC,ECDH,ECDSA,ENGINE,EVP,HMAC,MD4,MD5,'
              'PSK,RC2,RC4,RSA,SHA,SHA0,SHA1,SHA256,SHA512,SOCK,STDIO,TLSEXT,'
              'UI,FP_API,TLS1_METHOD,TLS1_1_METHOD,TLS1_2_METHOD,SCRYPT,OCSP,'
              'NEXTPROTONEG,RMD160,CAST,DEPRECATEDIN_1_1_0,DEPRECATEDIN_1_2_0,'
              'DEPRECATEDIN_3_0',
              # Defines.
              '-DWIN32',
              # Symbols to filter from the export list.
              '-X^DSO',
              '-X^_',
              '-X^private_',
              # Base generated DEF on zlib.def
              '-Bdeps/zlib/win32/zlib.def'
            ],
          },
          'conditions': [
            ['openssl_is_fips!=""', {
              'variables': { 'mkssldef_flags': ['-DOPENSSL_FIPS'] },
            }],
          ],
          'actions': [
            {
              'action_name': 'mkssldef',
              'inputs': [
                'deps/openssl/openssl/util/libcrypto.num',
                'deps/openssl/openssl/util/libssl.num',
              ],
              'outputs': ['<(SHARED_INTERMEDIATE_DIR)/openssl.def'],
              'process_outputs_as_sources': 1,
              'action': [
                '<(python)',
                'tools/mkssldef.py',
                '<@(mkssldef_flags)',
                '-o',
                '<@(_outputs)',
                '<@(_inputs)',
              ],
            },
          ],
        }],
        [ 'debug_nghttp2==1', {
          'defines': [ 'NODE_DEBUG_NGHTTP2=1' ]
        }],
      ],
      'actions': [
        {
          'action_name': 'node_js2c',
          'process_outputs_as_sources': 1,
          'inputs': [
            # Put the code first so it's a dependency and can be used for invocation.
            'tools/js2c.py',
            '<@(library_files)',
            '<@(deps_files)',
            'config.gypi'
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/node_javascript.cc',
          ],
          'action': [
            '<(python)',
            'tools/js2c.py',
            '--directory',
            'lib',
            '--target',
            '<@(_outputs)',
            'config.gypi',
            '<@(deps_files)',
          ],
        },
      ],
    }, # node_lib_target_name
    { # fuzz_env
      'target_name': 'fuzz_env',
      'type': 'executable',
      'dependencies': [
        '<(node_lib_target_name)',
        'deps/histogram/histogram.gyp:histogram',
        'deps/uvwasi/uvwasi.gyp:uvwasi',
      ],
      'includes': [
        'node.gypi'
      ],
      'include_dirs': [
        'src',
        'tools/msvs/genfiles',
        'deps/v8/include',
        'deps/cares/include',
        'deps/uv/include',
        'deps/uvwasi/include',
        'test/cctest',
      ],
      'defines': [
        'NODE_ARCH="<(target_arch)"',
        'NODE_PLATFORM="<(OS)"',
        'NODE_WANT_INTERNALS=1',
      ],
      'sources': [
        'src/node_snapshot_stub.cc',
        'test/fuzzers/fuzz_env.cc',
      ],
      'conditions': [
        ['OS=="linux"', {
          'ldflags': [ '-fsanitize=fuzzer' ]
        }],
        # Ensure that ossfuzz flag has been set and that we are on Linux
        [ 'OS!="linux" or ossfuzz!="true"', {
          'type': 'none',
        }],
      ],
    }, # fuzz_env
    {
      'target_name': 'cctest',
      'type': 'executable',

      'dependencies': [
        '<(node_lib_target_name)',
        'deps/base64/base64.gyp:base64',
        'deps/googletest/googletest.gyp:gtest',
        'deps/googletest/googletest.gyp:gtest_main',
        'deps/histogram/histogram.gyp:histogram',
        'deps/uvwasi/uvwasi.gyp:uvwasi',
        'deps/simdutf/simdutf.gyp:simdutf',
        'deps/ada/ada.gyp:ada',
      ],

      'includes': [
        'node.gypi'
      ],

      'include_dirs': [
        'src',
        'tools/msvs/genfiles',
        '../../v8/include',
        'deps/cares/include',
        'deps/uv/include',
        'deps/uvwasi/include',
        'test/cctest',
      ],

      'defines': [
        'NODE_ARCH="<(target_arch)"',
        'NODE_PLATFORM="<(OS)"',
        'NODE_WANT_INTERNALS=1',
      ],

      'sources': [
        'src/node_snapshot_stub.cc',
        'test/cctest/node_test_fixture.cc',
        'test/cctest/node_test_fixture.h',
        'test/cctest/test_aliased_buffer.cc',
        'test/cctest/test_base64.cc',
        'test/cctest/test_base_object_ptr.cc',
        'test/cctest/test_node_postmortem_metadata.cc',
        'test/cctest/test_environment.cc',
        'test/cctest/test_linked_binding.cc',
        'test/cctest/test_node_api.cc',
        'test/cctest/test_per_process.cc',
        'test/cctest/test_platform.cc',
        'test/cctest/test_report.cc',
        'test/cctest/test_json_utils.cc',
        'test/cctest/test_sockaddr.cc',
        'test/cctest/test_traced_value.cc',
        'test/cctest/test_util.cc',
      ],

      'conditions': [
        [ 'node_use_openssl=="true"', {
          'defines': [
            'HAVE_OPENSSL=1',
          ],
          'sources': [
            'test/cctest/test_crypto_clienthello.cc',
            'test/cctest/test_node_crypto.cc',
          ]
        }],
        ['v8_enable_inspector==1', {
          'sources': [
            'test/cctest/test_inspector_socket.cc',
            'test/cctest/test_inspector_socket_server.cc'
          ],
          'defines': [
            'HAVE_INSPECTOR=1',
          ],
        }, {
           'defines': [
             'HAVE_INSPECTOR=0',
           ]
        }],
        ['OS=="solaris"', {
          'ldflags': [ '-I<(SHARED_INTERMEDIATE_DIR)' ]
        }],
        # Skip cctest while building shared lib node for Windows
        [ 'OS=="win" and node_shared=="true"', {
          'type': 'none',
        }],
        [ 'node_shared=="true"', {
          'xcode_settings': {
            'OTHER_LDFLAGS': [ '-Wl,-rpath,@loader_path', ],
          },
        }],
        ['OS=="win"', {
          'libraries': [
            'Dbghelp.lib',
            'winmm.lib',
            'Ws2_32.lib',
          ],
        }],
      ],
    }, # cctest

    {
      'target_name': 'embedtest',
      'type': 'executable',

      'dependencies': [
        '<(node_lib_target_name)',
        'deps/histogram/histogram.gyp:histogram',
        'deps/uvwasi/uvwasi.gyp:uvwasi',
        'deps/ada/ada.gyp:ada',
      ],

      'includes': [
        'node.gypi'
      ],

      'include_dirs': [
        'src',
        'tools/msvs/genfiles',
        'deps/v8/include',
        'deps/cares/include',
        'deps/uv/include',
        'deps/uvwasi/include',
        'test/embedding',
      ],

      'sources': [
        'src/node_snapshot_stub.cc',
        'test/embedding/embedtest.cc',
      ],

      'conditions': [
        ['OS=="solaris"', {
          'ldflags': [ '-I<(SHARED_INTERMEDIATE_DIR)' ]
        }],
        # Skip cctest while building shared lib node for Windows
        [ 'OS=="win" and node_shared=="true"', {
          'type': 'none',
        }],
        [ 'node_shared=="true"', {
          'xcode_settings': {
            'OTHER_LDFLAGS': [ '-Wl,-rpath,@loader_path', ],
          },
        }],
        ['OS=="win"', {
          'libraries': [
            'Dbghelp.lib',
            'winmm.lib',
            'Ws2_32.lib',
          ],
        }],
      ],
    }, # embedtest

    {
      'target_name': 'overlapped-checker',
      'type': 'executable',

      'conditions': [
        ['OS=="win"', {
          'sources': [
            'test/overlapped-checker/main_win.c'
          ],
        }],
        ['OS!="win"', {
          'sources': [
            'test/overlapped-checker/main_unix.c'
          ],
        }],
      ]
    }, # overlapped-checker
    {
      'target_name': 'node_mksnapshot',
      'type': 'executable',

      'dependencies': [
        '<(node_lib_target_name)',
        'deps/histogram/histogram.gyp:histogram',
        'deps/uvwasi/uvwasi.gyp:uvwasi',
        'deps/ada/ada.gyp:ada',
      ],

      'includes': [
        'node.gypi'
      ],

      'include_dirs': [
        'src',
        'tools/msvs/genfiles',
        'deps/v8/include',
        'deps/cares/include',
        'deps/uv/include',
        'deps/uvwasi/include',
      ],

      'defines': [ 'NODE_WANT_INTERNALS=1' ],

      'sources': [
        'src/node_snapshot_stub.cc',
        'tools/snapshot/node_mksnapshot.cc',
      ],

      'conditions': [
        [ 'node_use_openssl=="true"', {
          'defines': [
            'HAVE_OPENSSL=1',
          ],
        }],
        [ 'node_use_node_code_cache=="true"', {
          'defines': [
            'NODE_USE_NODE_CODE_CACHE=1',
          ],
        }],
        ['v8_enable_inspector==1', {
          'defines': [
            'HAVE_INSPECTOR=1',
          ],
        }],
        ['OS=="win"', {
          'libraries': [
            'Dbghelp.lib',
            'winmm.lib',
            'Ws2_32.lib',
          ],
        }],
      ],
    }, # node_mksnapshot
  ], # end targets

  'conditions': [
    ['OS=="aix" and node_shared=="true"', {
      'targets': [
        {
          'target_name': 'node_aix_shared',
          'type': 'shared_library',
          'product_name': '<(node_core_target_name)',
          'ldflags': ['--shared'],
          'product_extension': '<(shlib_suffix)',
          'includes': [
            'node.gypi'
          ],
          'dependencies': ['<(node_lib_target_name)'],
          'include_dirs': [
            'src',
            'deps/v8/include',
          ],
          'sources': [
            '<@(library_files)',
            '<@(deps_files)',
            'common.gypi',
          ],
          'direct_dependent_settings': {
            'ldflags': [ '-Wl,-brtl' ],
          },
        },
      ]
    }], # end aix section
    ['OS=="win" and node_shared=="true"', {
     'targets': [
       {
         'target_name': 'gen_node_def',
         'type': 'executable',
         'sources': [
           'tools/gen_node_def.cc'
         ],
       },
       {
         'target_name': 'generate_node_def',
         'dependencies': [
           'gen_node_def',
           '<(node_lib_target_name)',
         ],
         'type': 'none',
         'actions': [
           {
             'action_name': 'generate_node_def_action',
             'inputs': [
               '<(PRODUCT_DIR)/<(node_lib_target_name).dll'
             ],
             'outputs': [
               '<(PRODUCT_DIR)/<(node_core_target_name).def',
             ],
             'action': [
               '<(PRODUCT_DIR)/gen_node_def.exe',
               '<@(_inputs)',
               '<@(_outputs)',
             ],
           },
         ],
       },
     ],
   }], # end win section
  ], # end conditions block
}
