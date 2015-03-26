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

var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]{};\'\\:"|,./<>?`~ ';
var smallestWord = words.reduce(function(acc, word) {
  if (word.length < acc.length) { return word; }
  else { return acc; }
});
var charEntropy = (log2(chars.length)|0);

// entropy: requested lower bound of passphrase entropy; number in bits.
// cb: callback, as function(err, string, actual entropy).
var passphrase = function(entropy, cb) {
  var nsub = 3;  // Number of substitutions.
  if (typeof entropy === 'object') {
    nsub = entropy.substitutions;
    entropy = entropy.entropy;
  }
  if (entropy == null) { entropy = 64; }
  if (entropy < 0) { cb(Error('Negative entropy')); return; }

  // How many words fill this entropy?
  // (We discretize everything by rounding up.)
  var n = ((entropy / wordEntropy)|0) + 1;

  // Reduce needed number of words based on substitution entropy.
  entropy -= ((nsub * (charEntropy + (log2(n * smallestWord.length)|0)))|0);
  n = ((entropy / wordEntropy)|0) + 1;

  // Generate enough bytes to fill the exact entropy.
  // Each word is indexed by a 32-bit integer (4 bytes).
  crypto.randomBytes(n << 2, function(err, buf) {
    if (err != null) { cb(err); return; }
    var words = [];
    for (var i = 0; i < (4 * n); i += 4) {
      words.push(password(buf, i));
    }
    var phrase = words.join(' ');
    var phraseLen = phrase.length;

    substitute(phrase, nsub, function(err, phrase) {
      if (err != null) { cb(err); return; }

      // Actual entropy, given the number of words.
      var aentr = wordEntropy * n
        + nsub * (charEntropy + (log2(phraseLen)|0));

      cb(null, phrase, aentr);
    });
  });
};

var filledUInt32 = 0xffffffff;
var wordIndexMask = filledUInt32 >>> ((32 - wordEntropy)|0);

var password = function(buf, i) {
  var index = buf.readUInt32LE(i);
  return words[(index & wordIndexMask) >>> 0];
};

var substitute = function(phrase, nsub, cb) {
  phrase = '' + phrase;
  var phraseLen = phrase.length;

  if (nsub === 0) { cb(null, phrase); return; }

  // The passphrase location is indexed by a 32-bit integer (4 bytes).
  // That index is scaled down to the size of the passphrase.
  // We assume the passphrase's length is < 4294967296.
  // We add one byte to select the character.
  crypto.randomBytes(5, function(err, buf) {
    if (err != null) { cb(err); return; }
    var index = randUInt32(buf.readUInt32LE(0), phraseLen);
    var cindex = randByte(buf[4], chars.length - 1);
    var char = chars[cindex];
    // We disallow a substitution without change.
    if (char === phrase[index]) {
      substitute(phrase, nsub, cb);
    } else {
      phrase = phrase.slice(0, index) + char + phrase.slice(index + 1);
      substitute(phrase, nsub - 1, cb);
    }
  });
};

// Get a random index in [0, length] given a 32-bit random number.
// length must be below 4294967296.
function randUInt32(rand, length) {
  return ((rand / 4294967295 * length)|0);
}

// Get a random index in [0, length] given a random byte.
// length must be below 256.
function randByte(rand, length) {
  return ((rand / 255 * length)|0);
}

module.exports = passphrase;
