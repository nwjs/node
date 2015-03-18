# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'variables': {
    'is_clang': 1,
    'gcc_version': 0,
    'openssl_no_asm%': 0,
    'llvm_version%': 0,
    'gas_version%': 0,
    'openssl_fips%': 'false',
    'conditions': [
      ['OS=="mac"', { 'openssl_no_asm%': 1 } ],
    ],
  },
  'targets': [
    {
      'target_name': 'openssl',
      'type': 'static_library',
      'includes': ['openssl.gypi'],
      'sources': ['<@(openssl_sources)'],
      'sources/': [
        ['exclude', 'md2/.*$'],
        ['exclude', 'store/.*$']
      ],
      'conditions': [
        # FIPS
        ['openssl_fips != ""', {
          'defines': [
            'OPENSSL_FIPS',
          ],
          'include_dirs': [
            '<(openssl_fips)/include',
          ],

          # Trick fipsld, it expects to see libcrypto.a
          'product_name': 'crypto',

          'direct_dependent_settings': {
            'defines': [
              'OPENSSL_FIPS',
            ],
            'include_dirs': [
              '<(openssl_fips)/include',
            ],
          },
        }],
        [ 'node_byteorder=="big"', {
            # Define Big Endian
            'defines': ['B_ENDIAN']
          }, {
            # Define Little Endian
           'defines':['L_ENDIAN']
        }],
        ['openssl_no_asm!=0', {
          # Disable asm
          'defines': [
            'OPENSSL_NO_ASM',
          ],
          'sources': ['<@(openssl_sources_no_asm)'],
        }, {
          # "else if" was supported in https://codereview.chromium.org/601353002
          'conditions': [
            ['target_arch=="arm"', {
              'defines': ['<@(openssl_defines_asm)'],
              'sources': ['<@(openssl_sources_arm_void_gas)'],
            }, 'target_arch=="ia32" and OS=="mac"', {
              'defines': [
                '<@(openssl_defines_asm)',
                '<@(openssl_defines_ia32_mac)',
              ],
              'sources': ['<@(openssl_sources_ia32_mac_gas)'],
            }, 'target_arch=="ia32" and OS=="win"', {
              'defines': [
                '<@(openssl_defines_asm)',
                '<@(openssl_defines_ia32_win)',
              ],
              'sources': ['<@(openssl_sources_ia32_win_masm)'],
            }, 'target_arch=="ia32"', {
              # Linux or others
              'defines': [
                '<@(openssl_defines_asm)',
                '<@(openssl_defines_ia32_elf)',
              ],
              'sources': ['<@(openssl_sources_ia32_elf_gas)'],
            }, 'target_arch=="x64" and OS=="mac"', {
              'defines': [
                '<@(openssl_defines_asm)',
                '<@(openssl_defines_x64_mac)',
              ],
              'sources': ['<@(openssl_sources_x64_mac_gas)'],
            }, 'target_arch=="x64" and OS=="win"', {
              'defines': [
                '<@(openssl_defines_asm)',
                '<@(openssl_defines_x64_win)',
              ],
              'sources': ['<@(openssl_sources_x64_win_masm)'],
            }, 'target_arch=="x64"', {
              # Linux or others
              'defines': [
                '<@(openssl_defines_asm)',
                '<@(openssl_defines_x64_elf)',
              ],
              'sources': ['<@(openssl_sources_x64_elf_gas)'],
            }, 'target_arch=="arm64"', {
              'defines': ['<@(openssl_defines_arm64)',],
              'sources': ['<@(openssl_sources_arm64_linux64_gas)'],
            }, {
              # Other architectures don't use assembly.
              'defines': ['OPENSSL_NO_ASM'],
              'sources': ['<@(openssl_sources_no_asm)'],
            }],
          ],
        }], # end of conditions of openssl_no_asm
        ['OS=="win"', {
          'defines' : ['<@(openssl_defines_all_win)'],
          'includes': ['masm_compile.gypi',],
        }, {
          'defines' : ['<@(openssl_defines_all_non_win)']
        }]
      ],
      'include_dirs': ['<@(openssl_include_dirs)'],
      'direct_dependent_settings': {
        'include_dirs': [
          'openssl/include'
        ],
        'defines': [
          'HMAC_Update=node_HMAC_Update',
          'MD5_Update=node_MD5_Update',
          'SHA512_Update=node_SHA512_Update',
          'SHA384_Update=node_SHA384_Update',
          'SHA256_Update=node_SHA256_Update',
          'SHA224_Update=node_SHA224_Update',
          'SHA1_Update=node_SHA1_Update',
          'HMAC_Init=node_HMAC_Init',
        ],
      },
      'defines': [
        'HMAC_Update=node_HMAC_Update',
          'MD5_Update=node_MD5_Update',
          'SHA512_Update=node_SHA512_Update',
          'SHA384_Update=node_SHA384_Update',
          'SHA256_Update=node_SHA256_Update',
          'SHA224_Update=node_SHA224_Update',
          'SHA1_Update=node_SHA1_Update',
        'HMAC_Init=node_HMAC_Init',
      ],
    },
    {
      # openssl-cli target
      'includes': ['openssl-cli.gypi',],
    }
  ],
  'target_defaults': {
    'includes': ['openssl.gypi'],
    'include_dirs': ['<@(openssl_default_include_dirs)'],
    'defines': ['<@(openssl_default_defines_all)'],
    'conditions': [
      ['OS=="win"', {
        'defines': ['<@(openssl_default_defines_win)'],
        'link_settings': {
          'libraries': ['<@(openssl_default_libraries_win)'],
        },
      }, {
        'defines': ['<@(openssl_default_defines_not_win)'],
        'cflags': ['-Wno-missing-field-initializers'],
        'conditions': [
          ['OS=="mac"', {
            'defines': ['<@(openssl_default_defines_mac)'],
          }, {
            'defines': ['<@(openssl_default_defines_linux_others)'],
          }],
        ]
      }],
      ['is_clang==1 or gcc_version>=43', {
        'cflags': ['-Wno-error=unused-command-line-argument', '-Wno-error=parentheses-equality'],
      }],
      ['OS=="solaris"', {
        'defines': ['__EXTENSIONS__'],
      }],
    ],
  },
}

# Local Variables:
# tab-width:2
# indent-tabs-mode:nil
# End:
# vim: set expandtab tabstop=2 shiftwidth=2:
