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

    var rand = function(nbytes) {
      return new Promise(function(resolve, reject) {
        crypto.randomBytes(nbytes, function(err, buf) {
          if (err !== null) { return reject(err); }
          resolve(buf);
        });
      });
    };

    module.exports = factory({words: words, rand: rand});

  } else {
    // Browser environment.

    // Take a number of bytes of randomness to generate.
    // Returns a promise with a random Uint8Array buffer.
    var rand = function(nbytes) {
      return new Promise(function(resolve, reject) {
        var buf = new Uint8Array(nbytes);
        try {
          // While the browser function is synchronous,
          // we provide an async wrapper to have a common interface with Node.js.
          root.crypto.getRandomValues(buf);
        } catch(e) {
          return reject(e);
        }
        resolve(buf);
      });
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
  var passphraseGen = function(entropy, cb) {
    var nins = 0;  // Number of insertions.
    if (typeof entropy === 'object') {
      nins = (entropy.insertions|0) || 0;
      entropy = (entropy.entropy|0);
    }
    if (entropy == null) { entropy = 77; }
    if (entropy < 0) { cb(Error('Negative entropy')); return; }

    // How many words fill this entropy?
    // (We discretize everything by rounding up.)
    var n = ((entropy / wordEntropy)|0) + 1;

    // Reduce needed number of words based on insertion entropy.
    entropy -= ((nins * (charEntropy + (log2(n * smallestWord.length)|0)))|0);
    n = ((entropy / wordEntropy)|0) + 1;

    randPhrase(n)
    .then(function(state) { return randInserts(state, nins); })
    .then(function(state) { cb(null, state.passphrase, state.entropy); })
    .catch(cb);
  };

  var randPhrase = function(nwords) {
    return new Promise(function(resolve, reject) {
      var wordgen = [];
      for (var i = 0; i < nwords; i++) {
        wordgen.push(randWord());
      }
      return Promise.all(wordgen).then(function(words) {
        resolve({
          passphrase: words.map(function(w) { return w.passphrase; }).join('-'),
          entropy: words.reduce(function(acc, w) { return acc + w.entropy; }, 0)
        });
      });
    });
  };

  // Return a promise of a single randomly picked word.
  var randWord = function() {
    return new Promise(function(resolve, reject) {
      return randInt(words.length).then(function(wordIndex) {
        resolve({passphrase: words[wordIndex], entropy: wordEntropy});
      });
    });
  };

  // Insert random characters at random positions in the phrase.
  var randInserts = function(state, nins) {
    var p = Promise.resolve(state);
    for (var i = 0; i < nins; i++) {
      p = p.then(randInsert);
    }
    return p;
  };

  // Insert a random character at a random position in the phrase.
  var randInsert = function(state) {
    return new Promise(function(resolve, reject) {
      phrase = String(state.passphrase);
      entr = state.entropy || 0;

      // Pick an insert position, including the end.
      return randInt(phrase.length + 1).then(function(idx) {
        // Pick a character to insert.
        return randChar().then(function(state) {
          resolve({
            passphrase: phrase.slice(0, idx) + state.passphrase
                      + phrase.slice(idx),
            entropy: state.entropy + entr,
          });
        });
      });
    });
  };

  var randChar = function() {
    return new Promise(function(resolve, reject) {
      return randInt(chars.length).then(function(idx) {
        resolve({passphrase: chars[idx], entropy: charEntropy});
      });
    });
  };

  // Return a random integer below max excluded, 0 included.
  var randInt = function(max) {
    return new Promise(function(resolve, reject) {
      var nbits = Math.ceil(log2(max));
      var nbytes = Math.ceil(nbits/8);
      return rand(nbytes).then(function(buf) {
        // Reduce the last byte to fit in the minimum power of two
        // required for the max.
        var extraBits = nbytes * 8 - nbits;
        buf[nbytes-1] &= 0xff >>> extraBits;
        // Convert to a number.
        var n = buf[0];
        for (var i = 1; i < nbytes; i++) {
          n |= buf[i] << (8*i);
        }
        // Reject the number if too high.
        if (n < max) { resolve(n); }
        else { return randInt(max).then(resolve).catch(reject); }
      });
    });
  };

  return passphraseGen;
}));
