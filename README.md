# torcontrol
Extension of Node.js torcontrol library

A node library to communicate with tor-control

*For basic information about tor-control please read the
[specs](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)*

## How to use

```js
var TorControl = require('torcontrol.js');

var control = new TorControl({
    // password: 'password',                     // Your password for tor-control
    cookie: '/tmp/tor_cookie',                // Optional replacement for password - cookie auth
    port: '9151',                             // Optional port to connect to
    persistent: true                         // Keep connection (persistent)
});

control.signalNewnym(function (err, status) { // Get a new circuit
   if (err) {
      return console.error(err);
   }
   console.log(status.messages[0]); // --> "OK"
});

control.getInfo(['version', 'events/names'], function (err, status) { // Get info like describe in chapter 3.9 in tor-control specs.
   if (err) {
      return console.error(err);
   }
   console.log(status.messages.join(' - '));
});

control.onTor('HS_DESC_CONTENT', function(data) { // Listen to tor events
    console.log("HS_DESC_CONTENT received");
    console.log(data);
}, function (err) {
    if(err) {
        console.log(err);
    }
});

control.hsfetch('facebookcorewwwi', null, function(err, status) { // Use HSFETCH to get HS descriptors
 if (err) {
    return console.error(err);
 }
 console.log(status.messages.join(' - '));
 });

```

NOT all commands from spec are supported. For further information take a look at the source-code and the specs.
