var Connection = require('./Connection')
var util = require('util')

function Tunnel(){
    this.tunnel = null;
    Connection.call(this);
}

util.inherits(Tunnel, Connection)

Tunnel.prototype.connect = function(options){
    var self = this;
    if(options.tunnel){
        var tunnelOptions = util._extend({}, options.tunnel); // clone
        this.tunnel = new Tunnel();
        this.tunnel.on('ready', function () {
            self.emit('tunnel:ready', options.tunnel.host);
            var ncCmd = 'nc ' + options.host + ' 22';
            self.tunnel.exec(ncCmd, function (err, stream) {
                if (err) return self.emit('error', err);
                var innerOptions = util._extend({}, options)
                innerOptions.sock = stream;
                delete(innerOptions.host)
                Tunnel.super_.prototype.connect.call(self,innerOptions);
            });
        });
        self.tunnel.on('error', function (err) {
            self.emit('tunnel:error', err, options.tunnel.host);
        });

        self.on('error', function(err) {
            self.end();
            self.tunnel.end();
        });
        self.on('end', function() {
            self.tunnel.end();
        });
        self.on('close', function(had_error) {
            self.tunnel.end();
        });
        self.tunnel.connect(tunnelOptions);
    } else {
        Tunnel.super_.prototype.connect.call(this,options)
    };
}

module.exports = Tunnel;

