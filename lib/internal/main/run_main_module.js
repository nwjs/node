'use strict';

const {
  prepareMainThreadExecution
} = require('internal/bootstrap/pre_execution');

const { NativeModule } = require('internal/bootstrap/loaders');

const CJSModule = require('internal/modules/cjs/loader').Module;

if (process.__nwjs) {
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

// Note: this loads the module through the ESM loader if
// --experimental-loader is provided or --experimental-modules is on
// and the module is determined to be an ES module
CJSModule.runMain(process.argv[1]);
}
