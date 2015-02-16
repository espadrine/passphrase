var entropy = (+process.argv[2]) || 64;
var passphrase = require('./main.js');
passphrase(entropy, function(_, s, entr) {
  if (_ != null) { console.error(_); return; }
  console.log('Entropy:', entr);
  console.log(s);
});
