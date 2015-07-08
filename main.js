// Produce a passphrase.

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

// Read the word file.
var notEmpty = function(line) { return line && line.length > 0; };
var words = fs.readFileSync(path.join(__dirname, 'words-en'), {encoding:'utf8'})
    .split('\n').filter(notEmpty);

var log2 = function(n) { return Math.log(n) / Math.log(2); };

var wordEntropy = log2(words.length)|0;

var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]{};\'\\:"|,./<>?`~';
var smallestWord = words.reduce(function(acc, word) {
  if (word.length < acc.length) { return word; }
  else { return acc; }
});
var charEntropy = (log2(chars.length)|0);

// entropy: requested lower bound of passphrase entropy; number in bits.
// cb: callback, as function(err, string, actual entropy).
var passphrase = function(entropy, cb) {
  var nsub = 0;  // Number of substitutions.
  var nins = 0;  // Number of insertions.
  if (typeof entropy === 'object') {
    nsub = (entropy.substitutions|0) || 0;
    nins = (entropy.insertions|0) || 0;
    entropy = (entropy.entropy|0);
  }
  if (entropy == null) { entropy = 64; }
  if (entropy < 0) { cb(Error('Negative entropy')); return; }

  // How many words fill this entropy?
  // (We discretize everything by rounding up.)
  var n = ((entropy / wordEntropy)|0) + 1;

  // Reduce needed number of words based on substitution entropy.
  entropy -= ((nsub * (charEntropy + (log2(n * smallestWord.length)|0)))|0);
  n = ((entropy / wordEntropy)|0) + 1;
  // Reduce needed number of words based on insertion entropy.
  entropy -= ((nins * (charEntropy + (log2(n * smallestWord.length)|0)))|0);
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

      insert(phrase, nins, function(err, phrase) {
        if (err != null) { cb(err); return; }

        // Actual entropy, given the number of words.
        var aentr = wordEntropy * n
          + nsub * (charEntropy + (log2(phraseLen)|0));

        cb(null, phrase, aentr);
      });
    });
  });
};

var password = function(buf, i) {
  var rand = buf.readUInt32LE(i);
  return words[randUInt32(rand, words.length - 1)];
};

var substitute = function(phrase, nsub, cb, _nerr, _indices) {
  phrase = '' + phrase;
  var phraseLen = phrase.length;

  if (nsub <= 0) { cb(null, phrase); return; }
  _indices = _indices || [];
  _nerr = _nerr || 0;

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
    if (char === phrase[index] || _indices.indexOf(index) >= 0) {
      _nerr++;
      if (_nerr > 1000) {
        cb(new Error('Cannot perform substitution.'));
      } else {
        substitute(phrase, nsub, cb, _nerr, _indices);
      }
    } else {
      phrase = phrase.slice(0, index) + char + phrase.slice(index + 1);
      _indices.push(index);
      substitute(phrase, nsub - 1, cb, _nerr, _indices);
    }
  });
};

var insert = function(phrase, nins, cb) {
  phrase = '' + phrase;
  var phraseLen = phrase.length;

  if (nins <= 0) { cb(null, phrase); return; }

  // The passphrase location is indexed by a 32-bit integer (4 bytes).
  // That index is scaled down to the size of the passphrase.
  // We assume the passphrase's length is < 4294967296.
  // We add one byte to select the character.
  crypto.randomBytes(5, function(err, buf) {
    if (err != null) { cb(err); return; }
    var index = randUInt32(buf.readUInt32LE(0), phraseLen);
    var cindex = randByte(buf[4], chars.length - 1);
    var char = chars[cindex];
    phrase = phrase.slice(0, index) + char + phrase.slice(index);
    insert(phrase, nins - 1, cb);
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
