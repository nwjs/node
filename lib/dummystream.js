module.exports = DummyStream;

const { Writable } = require('stream');
var util = require('util');
util.inherits(DummyStream, Writable);

function DummyStream() {
  Writable.apply(this, arguments);
  this.buffer = [];
  this.written = 0;
}

DummyStream.prototype._write = function(chunk, encoding, cb) {
    this.buffer.push(chunk.toString());
    this.written += chunk.length;
    cb();
};

DummyStream.prototype.destroy = function() {
};
