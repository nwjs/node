'use strict';

const {
  prepareMainThreadExecution
} = require('internal/bootstrap/pre_execution');

const { NativeModule } = require('internal/bootstrap/loaders');

// Expand process.argv[1] into a full path.
const path = require('path');
if (process.argv[1])
  process.argv[1] = path.resolve(process.argv[1]);

prepareMainThreadExecution();

const CJSModule = require('internal/modules/cjs/loader');

markBootstrapComplete();

if (process.__nwjs) {
    var Module = NativeModule.require('module');
    var module = new Module('.', null);
    global.process.mainModule = module;
    module._compile('global.module = module;\n' +
                    'global.require = global.__nw_require = require;\n', 'nw-emulate-node');
    if (process.argv[1]) {
      Module.runMain();
    }
} else {

// Note: this actually tries to run the module as a ESM first if
// --experimental-modules is on.
// TODO(joyeecheung): can we move that logic to here? Note that this
// is an undocumented method available via `require('module').runMain`
CJSModule.runMain();
}
