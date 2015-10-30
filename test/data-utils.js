'use strict'

// (c) 2015 Michael Keller, minesworld-technologies.com , published under MIT license

var stream = require('stream'),
    util= require('util');

//
    
function Timeout(name, ms, errfunc) {
  if (undefined === ms || 0 > ms) {
    this.renew = function(b, n) {};
    this.clear = function() {};
    return;
  }

  var lastRenew = Date.now(),
      lastNumber,
      lastBytes;

  var intervalID = setInterval(function() {
        var d = Date.now() - lastRenew;
        if (ms <= d) errfunc(name, d, lastNumber, lastBytes);
      }, 500);
  
  this.renew = function(b, n) {
    var d = Date.now() - lastRenew;
    if (ms <= d) errfunc(name, d, lastNumber, lastBytes);
    lastBytes = b;
    lastNumber = n;

    lastRenew = Date.now();
  };

  this.clear = function() {
    clearInterval(intervalID);
  }

  this.renew();
}

exports.Timeout = Timeout;
    
//

function ChunkGenerator(name, maxNumber, maxSize) {
  this.name = name;
  this.maxNumber = maxNumber;
  this.maxSize = maxSize;
  this.number = 0;
  this.generated = 0;
  this.remainder = '';
  this.atEnd = false;
}

ChunkGenerator.prototype.next = function() {
  if (this.atEnd) return null;
  
  var chunk;
  
  if (this.maxSize) {
    // random chunkSize with max 
  }
  else {
    // single line
    chunk = new Buffer('' + (this.number++) + "\n", 'ascii');
  }
  
  this.atEnd = (0 === this.remainder.length && this.maxNumber <= this.number);
  this.generated += chunk.length;
  
  return chunk;
}

exports.ChunkGenerator = ChunkGenerator;

//

function ChunkVerifier(name, maxNumber) {
  this.name = name;
  this.maxNumber = maxNumber;
  this.number = 0;
  this.checked = 0;
  this.remainder = '';
  this.atEnd = false;
}

ChunkVerifier.prototype.verify = function(chunk) {
  if (null === chunk) {
    return this.atEnd || new Error('ChunkVerifier.next(null) but not .atEnd');
  }
  if (this.atEnd) {
    return new Error('ChunkVerifier.next(' + chunk.length + ') called after .atEnd');
  }
  
  var data = chunk.toString('ascii'),
      lines = data.split("\n"),
      hasRemainder = (data[-1] != "\n");
  
  var line, index, number;

  for (var i = 0; i < lines.length; i++) {
    if (0 === i && 0 < this.remainder.length) {
      line = this.remainder + lines[i];
      this.remainder = '';      
    }
    else {
      line = lines[i];
    }
    
    if (i < lines.length - 1 || false === hasRemainder)
    {
      // console.error("verify " + line);
      
      try {
        number = parseInt(line);
      }
      catch(exception) {
        return exception;
      }
    
      if (number !== this.number) {
        return new Error("'" + line + "' different from " + this.number + ' at chunk ' + this.checked);
      }
      this.number += 1;
    }
    else {
      this.remainder = line;
    }
  }
  
  this.atEnd = (0 === this.remainder.length && this.maxNumber <= this.number);
  this.checked += chunk.length;
  
  return null; // no error
}

exports.ChunkVerifier = ChunkVerifier;

//

function StreamOfNumberLines(generator,options) {
  stream.Readable.call(this, options);

  this.generator = generator;
  this.atEnd = false;
}

util.inherits(StreamOfNumberLines, stream.Readable);

StreamOfNumberLines.prototype._read = function(size) {
  if (this.generator.atEnd) {
    if (this.atEnd) {
      throw new Error('StreamOfNumberLines _read after .atEnd');
    }
    
    this.atEnd = true;
    this.emit('willpush', null);
    return this.push(null);
  }
  var chunk = this.generator.next();
  this.emit('willpush', chunk);
  this.push(chunk);
};

exports.StreamOfNumberLines = StreamOfNumberLines;  

//

function NumberLineStreamVerifier(verifier, options) {
  stream.Writable.call(this, options);
  
  this.verifier = verifier;
}

util.inherits(NumberLineStreamVerifier, stream.Writable);

NumberLineStreamVerifier.prototype._write = function(chunk, encoding, callback) {
  this.emit('verify', chunk);
  
  var err = this.verifier.verify(chunk);
  
  if (err) {
    return callback(err);
  }
  
  callback();
}

exports.NumberLineStreamVerifier = NumberLineStreamVerifier;  

//

function VerifyingNumberLinesStream(verifier, options) {
  stream.Transform.call(this, options);
  
  this.verifier = verifier;
}

util.inherits(VerifyingNumberLinesStream, stream.Transform);

VerifyingNumberLinesStream.prototype._transform = function(chunk, encoding, callback) {
  var err = this.verifier.verify(chunk);
  
  if (err) {
    return callback(err);
  }
  
  this.push(chunk);
  callback();
}

exports.VerifyingNumberLinesStream = VerifyingNumberLinesStream;  

