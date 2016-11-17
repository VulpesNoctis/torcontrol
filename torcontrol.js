/**
 * Modified by VulpesNoctis on 02.02.2016.
 * Original at https://github.com/atd-schubert/node-tor-control
 */

'use strict';

var net = require('net');
var fs = require('fs');
var EventEmitter = require('events').EventEmitter;

var stream = require('stream');

/**
 * Tor control class
 * @link https://gitweb.torproject.org/torspec.git/tree/control-spec.txt
 * @param {{}} [opts] - Options
 * @param {string} [opts.host="localhost"] - Host address to tor-control (default localhost)
 * @param {number} [opts.port=9051] - Port of tor-control
 * @param {string} [opts.password=""] - Password for auth
 * @param {string} [opts.cookie] - Path to cookie for auth
 * @param {string} [opts.path] - Connect by path (alternative way to opts.host and opts.port)
 * @constructor
 */
var TorControl = function TorControl(opts) {
    var self = this;

    EventEmitter.apply(this);

    opts = opts || {};

    if (!opts.hasOwnProperty('path')) {
        opts.port = opts.port || 9051;
        opts.host = opts.host || 'localhost';
    }

    if(!opts.hasOwnProperty('password')) {
        if(opts.hasOwnProperty('cookie')) {
            var cookie_data = fs.readFileSync(opts.cookie);
            opts.password = cookie_data.toString('hex');
        }
        else {
            opts.password = '';
        }
    }
    else {
        var password_data = new Buffer(opts.password, 'binary');
        opts.password = password_data.toString('hex'); //To hash
    }

    if (!opts.hasOwnProperty('persistent')) {
        opts.persistent = false;
    }

    this.events = [];

    this.connect = function connectTorControl(params, cb) {

        params = params || opts;

        if (this.connection) {
            if (cb) {
                return cb(null, this.connection);
            }
            return;
        }

        if (!params.hasOwnProperty('path')) {
            if (opts.hasOwnProperty('path')) {
                params.path = opts.path;
            } else {
                params.host = params.host || opts.host;
                params.port = params.port || opts.port;
            }
        }

        this.connection = net.connect(params);

        var parseMessage = function (str_data) {
            var code = parseInt(str_data.substr(0, 3), 10),
                lineType = str_data.substr(3, 1),
                content = str_data.substr(4),
                body = '';

            switch (lineType) {
                case ' ':           // ' ' OneLine message, terminated by '/\r?\n/'
                case '-':           // '-' mid-line, multiple lines terminated after a OneLine
                    var end = content.search(/\r?\n/);
                    if(end === -1) {
                        return null;
                    }
                    body = content.substr(0, end);

                    if(lineType === '-') {
                        var nextLines = parseMessage(content.substr(end).replace(/\r?\n/, ''));

                        if(nextLines) {
                            body += '\n' + nextLines.body;
                        }
                    }
                    break;
                case '+':           // '+' MultiLine message, terminated by "650 OK\r\n" 
                    var end = content.search(/[0-9]{3} [A-Z].\r?\n/);

                    if(end === -1) {
                        return null;
                    }

                    var lineArray = content.substr(0, end).split(/\r?\n/);
                    lineArray.forEach(function(line) {
                        if(line.substr(0,2) === '..') {
                            line = line.substr(1);
                        }

                        body += line + '\n';
                    });
                    break;
                default:
                    return null;
            }
            // We could check if there is data left to parse, but thats not necessary now, since we get only one message at a time

            return {
                statusCode: code,
                lineType: lineType,
                body: body
            };
        };

        // piping events
        this.connection.on('data', function (data) {
            var message = parseMessage(data.toString());

            if(message) {
                if(message.statusCode === 650) {
                    self.emit('tor-event', message.body);
                }

                self.emit('tor-message', message);
            }

            self.emit('data', data);
        });
        this.connection.on('end', function () {
            self.connection = null;
            self.emit('end');
        });

        this.on('tor-event', function (event_data) {
            var eventNameEnd = event_data.search(/ /);

            if(eventNameEnd < 2) { //Not found or to short for a valid event name
                return;
            }

            var eventName = event_data.substr(0, eventNameEnd).toUpperCase(),
                eventBody = event_data.substr(eventNameEnd+1);

            if(self.knownEvents.indexOf(eventName) === -1) {
                return;
            }

            self.emit(eventName, eventBody);
        });

        if (cb) {
            this.connection.once('data', function (data) {
                data = data.toString();
                if (data.substr(0, 3) === '250') {
                    if(self.events && self.events.length) {
                        this.resubscribeEvents(function () {
                            if (err) {
                                return console.error(err);
                            }
                            else {
                                console.log('Resubscribed to events: ' + this.events.join(' '));
                            }
                        });
                    }
                    return cb(null, self.connection);
                }
                return cb(new Error('Authentication failed with message: ' + data));
            });
        }

        this.connection.write('AUTHENTICATE ' + (params.password || opts.password) + '\r\n'); // Chapter 3.5
        return this;
    };

    this.disconnect = function disconnectTorControl(cb, force) {
        //this.clearTorEvents(); //Just reattach on connect

        if (!this.connection) {
            if (cb) {
                return cb();
            }
            return;
        }
        if (cb) {
            this.connection.once('end', function () {
                return cb();
            });
        }
        if (force) {
            return this.connection.end();
        }
        this.connection.write('QUIT\r\n');
        return this;
    };

    this.isPersistent = function isTorControlPersistent() {
        return !!opts.persistent;
    };
    this.setPersistent = function setTorControlPersistent(value) {
        opts.persistent = !!value;
        return this;
    };

};

TorControl.prototype = {
    '__proto__': EventEmitter.prototype,
    sendCommand: function sendCommandToTorControl(command, cb, keepConnection) {
        var self = this,
            tryDisconnect = function (callback) {
                if (keepConnection || self.isPersistent() || !self.connection) {
                    return callback();
                }
                return self.disconnect(callback);
            };
        return this.connect(null, function (err, connection) {
            if (err) {
                return cb(err);
            }
            var handleResponse = function (data) {
                return tryDisconnect(function () {
                    var messages = [],
                        arr,
                        i;
                    if (cb) {
                        data = data.toString();

                        var code = parseInt(data.substr(0, 3), 10);

                        if (/250 OK\r?\n/.test(data)) {
                            arr = data.split(/\r?\n/);

                            for (i = 0; i < arr.length; i += 1) {
                                if (arr[i] !== '') {
                                    messages.push(arr[i].substr(4));
                                }
                            }
                            return cb(null, {
                                code: 250,
                                messages: messages,
                                data: data
                            });
                        }

                        if(code === 650) { // Async events may intersect us, just skip and wait for the next message
                            return connection.once('data', handleResponse);
                        }

                        return cb(new Error(data), {
                            code: code,
                            message: data.substr(4),
                            data: data
                        });
                    }
                });
            };
            connection.once('data', handleResponse);
            connection.write(command + '\r\n');
        });
    },

    // Config
    setConf: function setConf(request, cb) { // Chapter 3.1
        return this.sendCommand('SETCONF ' + request, cb);
    },
    resetConf: function resetConf(request, cb) { // Chapter 3.2
        return this.sendCommand('RESETCONF ' + request, cb);
    },
    getConf: function getConf(request, cb) { // Chapter 3.3
        return this.sendCommand('GETCONF ' + request, cb);
    },
    getEvents: function getEvents(request, cb) { // Chapter 3.4
        return this.sendCommand('GETEVENTS ' + request, cb);
    },
    saveConf: function saveConf(request, cb) { // Chapter 3.6
        return this.sendCommand('SAVECONF ' + request, cb);
    },

    // Signals:
    signal: function sendSignalToTorCOntrol(signal, cb, keepConnection) { // Chapter 3.7
        return this.sendCommand('SIGNAL ' + signal, cb, keepConnection);
    },
    signalReload: function sendSignalReload(cb) {
        return this.signal('RELOAD', cb, true);
    },
    signalHup: function sendSignalHup(cb) {
        return this.signal('HUP', cb);
    },
    signalShutdown: function sendSignalShutdown(cb) {
        return this.signal('SHUTDOWN', cb, true);
    },
    signalDump: function sendSignalDump(cb) {
        return this.signal('DUMP', cb);
    },
    signalUsr1: function sendSignalUsr1(cb) {
        return this.signal('USR1', cb);
    },
    signalDebug: function sendSignalDegug(cb) {
        return this.signal('DEBUG', cb);
    },
    signalUsr2: function sendSignalUsr2(cb) {
        return this.signal('USR2', cb);
    },
    signalHalt: function sendSignalHalt(cb) {
        return this.signal('HALT', cb, true);
    },
    signalTerm: function sendSignalTerm(cb) {
        return this.signal('TERM', cb, true);
    },
    signalInt: function sendSignalInt(cb) {
        return this.signal('INT', cb);
    },
    signalNewnym: function sendSignalNewNym(cb) {
        return this.signal('NEWNYM', cb);
    },
    signalCleardnscache: function sendSignalClearDnsCache(cb) {
        return this.signal('CLEARDNSCACHE', cb);
    },
    
    // AddHiddenService
    // No Auth for now
    addOnion: function (privateKey, flags, port, cb) {
        var checkFlag = function(flag) {
            return ['DiscardPK', 
                    'Detach', 
                    'BasicAuth', 
                    'NonAnonymous'].indexOf(flag) != -1; //TODO: Error if this is false
        }
        
        var flagstr = '';
        var portstr = ' Port=';
        
        if (! port ) {
            return 0; //TODO: Error
        }
        else if ( Number.isInteger(port) ) {
            portstr += port;
        }
        else if ( (typeof port === 'object') && port.virtport && port.target) {
            if (! Number.isInteger(port.virtport) ) {
                return 0; //TODO: Error        
            }
            portstr += port.virtport + ',' + port.target;
        }
        else {
            return 0; //TODO: Error
        }
        
        if (! privateKey) {
            privateKey = 'NEW:BEST';
        }
        else {
            privateKey = 'RSA1024:' + privateKey;   
        }
        
        if (flags) {
            flagstr = ' Flag=';
            if(Array.isArray(flags)) {
                for(var i = 0; i < flags.length; i++) {
                    flagstr += checkFlag(flags[i]) ? flags[i] : '';
                }
            }
            else {
                flagstr += checkFlag(flags) ? flags : '';
            }
        }

        return this.sendCommand('ADD_ONION ' + privateKey + flagstr + portstr, cb):
    },
    
    // MapAddress
    mapAddress: function mapAddress(address, cb) { // Chapter 3.8
        return this.sendCommand('MAPADDRESS ' + address, cb);
    },

    // GetInfo
    getInfo: function (request, cb) { // Chapter 3.9
        if (!Array.prototype.isPrototypeOf(request)) {
            request = [request];
        }
        return this.sendCommand('GETINFO ' + request.join(' '), cb);
    },

    //Events
    subscribeEvents: function (events, cb) {
        return this.sendCommand('SETEVENTS ' + events, cb);
    },

    resubscribeEvents: function (cb) {
        this.subscribeEvents(this.events.join(' '), cb);
    },

    addTorEvent: function(event, cb) {
        if(this.events.indexOf(event) !== -1) {
            //Already suscribed
            return cb();
        }
        else {
            var self = this;

            return this.subscribeEvents(this.events.concat(event).join(' '), function(err, status) {
                if(!err) {
                    self.events.push(event);
                }
                cb(err, status);
            });
        }
    },
    
    clearTorEvents: function() {
        var self = this;
        this.subscribeEvents('');
        
        this.events.forEach(function(event) { //This isn't necessary since we could reattach on reconnect
            self.removeAllListeners(event)
        });

        this.events = []; //Reset events
    },

    onTor: function (eventType, listener, cb) {
        var self = this;
        eventType = eventType.toUpperCase();

        this.addTorEvent(eventType, function(err) {
            if(err) {
                if(cb) {
                    return cb(err);
                }
            }
            else {
                // suscribed, now attach to event
                self.on.apply(self, [eventType, listener]);
                if(cb) {
                    return cb();
                }
            }
        });
    },

    //HSFetch
    hsfetch: function (query, servers, cb) {
        var server_string = '';

        if(typeof servers !== 'undefined' && servers !== null) {
            if(Array.isArray(servers)) {
                servers.forEach(function(server) {
                    server_string += ' SERVER='+server;
                });
            }
            else if(typeof servers === "string") {
                server_string = ' SERVER='+servers;
            }
        }

        return this.sendCommand('HSFETCH ' + query + server_string, cb);
    },

    // Circuit
    extendCircuit: function (id, superspec, purpose, cb) { // Chapter 3.10
        var str = 'EXTENDCIRCUIT ' + id;
        if (superspec) {
            str += ' ' + superspec;
        }
        if (purpose) {
            str += ' ' + purpose;
        }
        return this.sendCommand(str, cb);
    },
    setCircuitPurpose: function (id, purpose, cb) { // Chapter 3.11
        return this.sendCommand('SETCIRCUITPURPOSE ' + id + ' purpose=' + purpose, cb);
    },


    setRouterPurpose: function (nicknameOrKey, purpose, cb) { // Chapter 3.12
        return this.sendCommand('SETROUTERPURPOSE ' + nicknameOrKey + ' ' + purpose, cb);
    },
    attachStream: function (streamId, circuitId, hop, cb) { // Chapter 3.13
        var str = 'ATTACHSTREAM ' + streamId + ' ' + circuitId;

        if (hop) {
            str += ' ' + hop;
        }

        return this.sendCommand(str, cb);
    },

    // Alias
    getNewCircuit: function sendSignalNewNym(cb) {
        return this.sendSignalNewNym(cb);
    },


    /**
     * @type {stream}
     */
    connection: null,

    // Methods with usage of private vars (opts)
    /**
     * @type {function}
     */
    connect: null,
    /**
     * @type {function}
     */
    disconnect: null,
    /**
     * @type {function}
     */
    isPersistent: null,
    /**
     * @type {function}
     */
    setPersistent: null,

    /**
     * @type {Array}
     */
    events: null,

    /**
     * @type {Array}
     */
    knownEvents: [
        'CIRC',
        'CIRC_MINOR',
        'STREAM',
        'ORCONN',
        'BW',
        'DEBUG',
        'INFO',
        'NOTICE',
        'WARN',
        'ERR',
        'NEWDESC',
        'ADDRMAP',
        'AUTHDIR_NEWDESCS',
        'DESCCHANGED',
        'NS',
        'STATUS_GENERAL',
        'STATUS_CLIENT',
        'STATUS_SERVER',
        'GUARD',
        'STREAM_BW',
        'CLIENTS_SEEN',
        'NEWCONSENSUS',
        'BUILDTIMEOUT_SET',
        'SIGNAL',
        'CONF_CHANGED',
        'CONN_BW',
        'CELL_STATS',
        'TB_EMPTY',
        'CIRC_BW',
        'TRANSPORT_LAUNCHED',
        'HS_DESC',
        'HS_DESC_CONTENT',
        'NETWORK_LIVENESS',
        'HSDIR_DESC_CONTENT',
        'HSDIR_DESC_REQUEST'
    ]
};

module.exports = TorControl;
