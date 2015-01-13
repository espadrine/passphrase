// Produce a passphrase.

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

// Read the word file.
var notEmpty = function(line) { return line && line.length > 0; };
var words = fs.readFileSync(path.join(__dirname, 'words-en'), {encoding:'utf8'})
    .split('\n').filter(notEmpty);
var wordCount = words.length;

var log2 = function(n) { return Math.log(n) / Math.log(2); };

// We require a number of words that is a power of 2,
// to ensure that wordEntropy is a discrete integer.
var wordEntropy = log2(wordCount)|0;
wordCount = Math.pow(2, wordEntropy)|0;
words = words.slice(0, wordCount);

// entropy: requested lower bound of passphrase entropy; number in bits.
// cb: callback, as function(err, string, actual entropy).
var passphrase = function(entropy, cb) {
  if (entropy == null) { entropy = 64; }
  if (entropy < 0) { cb(Error('Negative entropy')); return; }

  // How many words fill this entropy?
  // (We discretize everything by rounding up.)
  var n = ((entropy / wordEntropy)|0) + 1;

  // Actual entropy, given the number of words.
  var aentr = wordEntropy * n;

  // Generate enough bytes to fill the exact entropy.
  // Each word is indexed by a 32-bit integer (4 bytes).
  crypto.randomBytes(n << 2, function(err, buf) {
    if (err != null) { cb(err); return; }
    var words = [];
    for (var i = 0; i < (4 * n); i += 4) {
      words.push(password(buf, i));
    }
    var phrase = words.join(' ');
    cb(null, phrase, aentr);
  });
};

var filledUInt32 = 0xffffffff;
var wordIndexMask = filledUInt32 >>> ((32 - wordEntropy)|0);

var password = function(buf, i) {
  var index = buf.readUInt32LE(i);
  return words[(index & wordIndexMask) >>> 0];
};

module.exports = passphrase;
