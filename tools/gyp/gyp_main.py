#!/usr/bin/env python3

# Copyright (c) 2009 Google Inc. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import subprocess
import sys


def IsCygwin():
    # Function copied from pylib/gyp/common.py
    try:
        out = subprocess.Popen(
            "uname", stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        stdout, _ = out.communicate()
        return "CYGWIN" in stdout.decode("utf-8")
    except Exception:
        return False


def UnixifyPath(path):
    try:
        if not IsCygwin():
            return path
        out = subprocess.Popen(
            ["cygpath", "-u", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        stdout, _ = out.communicate()
        return stdout.decode("utf-8")
    except Exception:
        return path


# Make sure we're using the version of pylib in this repo, not one installed
# elsewhere on the system. Also convert to Unix style path on Cygwin systems,
# else the 'gyp' library will not be found
path = UnixifyPath(sys.argv[0])
sys.path.insert(0, os.path.join(os.path.dirname(path), "pylib"))
sys.path.insert(1, os.path.join(os.path.dirname(path), '..', 'v8_gypfiles'))
import gyp  # noqa: E402

def UseChromiumClangOnMac():
    # nwjs: when building node as part of nw (building_nw=1) on macOS, node
    # must be compiled with Chromium's clang: libnode.dylib is linked against
    # Chromium's libc++ (see the OS=="mac" block in common.gypi), whose
    # headers and ABI (libc++ ABI v2) Apple clang cannot handle. Locate the
    # compiler in the Chromium checkout this script lives in, so builders do
    # not need to configure any absolute compiler path.
    if sys.platform != 'darwin':
        return
    defines = {}
    for item in os.environ.get('GYP_DEFINES', '').split():
        key, sep, value = item.partition('=')
        if sep:
            defines[key] = value
    if defines.get('building_nw') != '1':
        return
    # <src>/third_party/node-nw/tools/gyp/gyp_main.py -> <src>
    src_root = os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     '..', '..', '..', '..'))
    llvm_bin = os.path.join(src_root, 'third_party', 'llvm-build',
                            'Release+Asserts', 'bin')
    clang = os.path.join(llvm_bin, 'clang')
    clangxx = os.path.join(llvm_bin, 'clang++')
    if not (os.access(clang, os.X_OK) and os.access(clangxx, os.X_OK)):
        sys.stderr.write('gyp_main.py: WARNING: Chromium clang not found in %s;'
                         ' keeping CC_target/CXX_target from the environment.'
                         ' Building node as part of nw on macOS requires'
                         ' Chromium clang.\n' % llvm_bin)
        return
    arch = {'ia32': 'i386', 'x64': 'x86_64',
            'arm64': 'arm64'}.get(defines.get('target_arch', 'x64'), 'x86_64')
    os.environ['CC_target'] = clang + ' -arch ' + arch
    os.environ['CXX_target'] = clangxx + ' -arch ' + arch


if __name__ == "__main__":
    UseChromiumClangOnMac()
    sys.exit(gyp.script_main())
