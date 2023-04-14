'use strict';

const { RegExpPrototypeExec } = primordials;

const {
  prepareMainThreadExecution,
  markBootstrapComplete,
} = require('internal/process/pre_execution');

const { NativeModule } = require('internal/bootstrap/loaders');

if (process.__nwjs) {
prepareMainThreadExecution(true);
markBootstrapComplete();
    var Module = require('module');
    var module = new Module('.', null);
    global.process.mainModule = module;
    module._compile('global.module = module;\n' +
                    'global.require = global.__nw_require = require;\n', 'nw-emulate-node');
    if (process.argv[1]) {
      Module.runMain();
    }
} else {
prepareMainThreadExecution(true);
markBootstrapComplete();
RegExpPrototypeExec(/^/, '');
// Note: this loads the module through the ESM loader if the module is
// determined to be an ES module. This hangs from the CJS module loader
// because we currently allow monkey-patching of the module loaders
// in the preloaded scripts through require('module').
// runMain here might be monkey-patched by users in --require.
// XXX: the monkey-patchability here should probably be deprecated.
require('internal/modules/cjs/loader').Module.runMain(process.argv[1]);
}
