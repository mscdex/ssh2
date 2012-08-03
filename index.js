var addon = require('./build/Debug/ssh2');
var EventEmitter = require('events').EventEmitter;

addon.Session.prototype.__proto__ = EventEmitter.prototype;

module.exports = addon;