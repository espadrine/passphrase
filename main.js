// Produce a passphrase.

(function(root, factory) {

  // Platform-specific hooks.

  if (typeof module === 'object' && module.exports) {
    // Node.js.
    var fs = require('fs');
    var path = require('path');
    var crypto = require('crypto');

    // Read the word file.
    var notEmpty = function(line) { return line && line.length > 0; };
    var words = fs.readFileSync(path.join(__dirname, 'words-en'), {encoding:'utf8'})
        .split('\n').filter(notEmpty);

    module.exports = factory({words: words, rand: crypto.randomBytes});

  } else {
    // Browser environment.

    // Take a number of bytes, and a callback
    // with a random Uint8Array buffer.
    //
    // nbytes: number of bytes to feed.
    // cb: callback; function(error, buffer),
    //     where either the error or the buffer is null.
    var rand = function(nbytes, cb) {
      var buf = new Uint8Array(nbytes);
      try {
        // While the browser function is synchronous,
        // we provide an async wrapper to have a common interface with Node.js.
        root.crypto.getRandomValues(buf);
      } catch(e) {
        return cb(e, null);
      }
      cb(null, buf);
    };

    // If you are reading this because this function was undefined,
    // you probably used the main.js file; please use the browser.js file.
    INSERT_WORDS_HERE();
    root.passphrase = factory({words: words, rand: rand});
  }

}(this, function(dependencies) {
  var words = dependencies.words;
  var rand = dependencies.rand;

  // Platform-independent code.

  var log2 = function(n) { return Math.log(n) / Math.log(2); };

  var wordEntropy = log2(words.length);

  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]{};\'\\:"|,./<>?`~';
  var smallestWord = words.reduce(function(acc, word) {
    if (word.length < acc.length) { return word; }
    else { return acc; }
  });
  var charEntropy = log2(chars.length);

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
    rand(n << 2, function(err, buf) {
      if (err != null) { cb(err); return; }
      var words = [];
      for (var i = 0; i < (4 * n); i += 4) {
        words.push(password(buf, i));
      }
      var phrase = words.join(' ');
      var phraseLen = phrase.length;
      // Actual entropy, given the number of words.
      var aentr = wordEntropy * n;

      substitute(phrase, nsub, function(err, phrase, entr) {
        if (err != null) { cb(err); return; }
        aentr += entr;

        insert(phrase, nins, function(err, phrase, entr) {
          if (err != null) { cb(err); return; }
          aentr += entr;

          cb(null, phrase, aentr|0);
        });
      });
    });
  };

  var password = function(buf, i) {
    var rand = readUInt32LE(buf, i);
    return words[randUInt32(rand, words.length - 1)];
  };

  // Substitute nsub characters in the phrase.
  // The callback cb is a function(err, phrase, entropy).
  var substitute = function(phrase, nsub, cb, _nerr, _indices, _entr) {
    phrase = String(phrase);
    var phraseLen = phrase.length;
    _indices = _indices || [];
    _nerr = _nerr || 0;
    _entr = _entr || 0;

    if (nsub <= 0) { cb(null, phrase, _entr); return; }

    // The passphrase location is indexed by a 32-bit integer (4 bytes).
    // That index is scaled down to the size of the passphrase.
    // We assume the passphrase's length is < 4294967296.
    // We add one byte to select the character.
    rand(5, function(err, buf) {
      if (err != null) { cb(err); return; }
      var index = randUInt32(readUInt32LE(buf, 0), phraseLen);
      var cindex = randByte(buf[4], chars.length - 1);
      var char = chars[cindex];
      // We disallow a substitution without change.
      if (char === phrase[index] || _indices.indexOf(index) >= 0) {
        _nerr++;
        if (_nerr > 1000) {
          cb(new Error('Cannot perform substitution.'));
        } else {
          substitute(phrase, nsub, cb, _nerr, _indices, _entr);
        }
      } else {
        phrase = phrase.slice(0, index) + char + phrase.slice(index + 1);
        _indices.push(index);
        // Newly added entropy from this substitution.
        var nentr = charEntropy + log2(phraseLen + 1);
        substitute(phrase, nsub - 1, cb, _nerr, _indices, _entr + nentr);
      }
    });
  };

  // Insert nins random characters at random positions in the phrase.
  var insert = function(phrase, nins, cb, _nentr) {
    phrase = '' + phrase;
    var phraseLen = phrase.length;
    _nentr = _nentr || 0;

    if (nins <= 0) { cb(null, phrase, _nentr); return; }

    // The passphrase location is indexed by a 32-bit integer (4 bytes).
    // That index is scaled down to the size of the passphrase.
    // We assume the passphrase's length is < 4294967296.
    // We add one byte to select the character.
    rand(5, function(err, buf) {
      if (err != null) { cb(err); return; }
      var index = randUInt32(readUInt32LE(buf, 0), phraseLen);
      var cindex = randByte(buf[4], chars.length - 1);
      var char = chars[cindex];
      phrase = phrase.slice(0, index) + char + phrase.slice(index);
      // Newly added entropy from this insertion.
      var nentr = charEntropy + log2(phraseLen + 1);
      insert(phrase, nins - 1, cb, _nentr + nentr);
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

  // Read a Uint8Array buf starting at index i,
  // consume 4 bytes, and return the Uint32 at that location in little endian.
  var readUInt32LE = function(buf, i) {
    return (buf[i + 0] <<  0) |
           (buf[i + 1] <<  8) |
           (buf[i + 2] << 16) |
           (buf[i + 3] << 24) & ~(1 << 31);
  };

  return passphrase;
}));
