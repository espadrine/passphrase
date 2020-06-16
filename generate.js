#!/usr/bin/env node
var entropy = (+process.argv[2]) || 77;
var nins = (+process.argv[3]) || 0;
var passphrase = require('./main.js');
passphrase({entropy:entropy, insertions:nins}, function(e, s, entr) {
  if (e != null) { console.error(e); return; }
  console.warn('Entropy:', entr);
  console.log(s);
});
