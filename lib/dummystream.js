module.exports = DummyStream;

var W = require('_stream_writable');
var util = require('util');
util.inherits(DummyStream, W);

function DummyStream() {
  W.apply(this, arguments);
  this.buffer = [];
  this.written = 0;
}

DummyStream.prototype._write = function(chunk, encoding, cb) {
    this.buffer.push(chunk.toString());
    this.written += chunk.length;
    cb();
};
