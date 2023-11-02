'use strict';

const { RegExpPrototypeExec } = primordials;

const {
  prepareMainThreadExecution,
  markBootstrapComplete,
} = require('internal/process/pre_execution');
const { getOptionValue } = require('internal/options');

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
const mainEntry = prepareMainThreadExecution(true);

markBootstrapComplete();

// Necessary to reset RegExp statics before user code runs.
RegExpPrototypeExec(/^/, '');

if (getOptionValue('--experimental-default-type') === 'module') {
  require('internal/modules/run_main').executeUserEntryPoint(mainEntry);
} else {
  /**
   * To support legacy monkey-patching of `Module.runMain`, we call `runMain` here to have the CommonJS loader begin
   * the execution of the main entry point, even if the ESM loader immediately takes over because the main entry is an
   * ES module or one of the other opt-in conditions (such as the use of `--import`) are met. Users can monkey-patch
   * before the main entry point is loaded by doing so via scripts loaded through `--require`. This monkey-patchability
   * is undesirable and is removed in `--experimental-default-type=module` mode.
   */
  require('internal/modules/cjs/loader').Module.runMain(mainEntry);
}
}
