/**
 * Test throwing errors if clients call connect on an established socket
 * (Refer to issue #161)
 *
 * @author: Mond Wan
 * @email: mondwan.1015@gmail.com
 * @last-modified: 2014-07-20 15:04
 */

var Q = require('q');
var Connection = require('../lib/Connection');
var util = require('util');

var c = new Connection();
var status = "READY";
var validation = false;

var connect = function () {
    var deferred = Q.defer();

    c.once("ready", function () {
        //console.log('Connection::Ready');
        c.removeAllListeners("error");
        status = "READY";
        deferred.resolve(c);
    });
    c.once("error", function (err) {
        c.removeAllListeners("ready");
        status = "ERROR";
        deferred.reject(err);
    });
    //c.once('keyboard-interactive', function (

    c.connect({
        host: 'localhost',
        port: 22,
        username: 'mond',
        //debug: console.log,
        password: "mondwan"
    });

    return deferred.promise;
};

var send = function (cmd) {
    var deferred = Q.defer();

    if (status !== "READY") {
        deferred.reject(new Error("Oops. Socket is closed"));
    } else {
        c.exec(cmd, function (err, stream) {
            if (err) {
                deferred.reject(err);
                return;
            }
            stream.setEncoding("utf8");

            var results = [];
            stream.on("data", function (data) {
                //console.log("connection::data");
                results.push(data);
            });
            stream.on("exit", function (code, signal) {
                deferred.resolve({
                    code: code,
                    signal: signal,
                    results: results
                });
            });
        });
    }

    return deferred.promise;
};

var disconnect = function () {
    var deferred = Q.defer();

    c.once("close", function (err) {
        //console.log("Connection::close");
        //status = "CLOSED";
        if (err) {
            deferred.reject(err);
        } else {
            deferred.resolve(true);
        }
    });
    c.end();
    return deferred.promise;
};

connect().then(function () {
    return send('echo "Command 1"');
}).then(function (res) {
    //console.log(util.format("send().respone()"), res);
}).then(function () {
    return disconnect();
}).then(function () {
    return send('echo "Command 2"');
}).catch(function (err) {
    if (err.message === 'Socket end prematurely') {
        validation = true;
    }
}).finally(function () {
    if (!validation) {
        throw new Error("Should throw error on calling exec() on a closed socket");
    }
}).done();
