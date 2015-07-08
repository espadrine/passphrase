#!/usr/bin/env node
var entropy = (+process.argv[2]) || 64;
var nins = (+process.argv[3]) || 1;
var passphrase = require('./main.js');
passphrase({entropy:entropy, insertions:nins}, function(_, s, entr) {
  if (_ != null) { console.error(_); return; }
  console.log('Entropy:', entr);
  console.log(s);
});
