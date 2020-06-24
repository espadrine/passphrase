*Generate cryptographically secure passphrases at a set entropy.*

## Node.js

```js
var passphrase = require('passphrase');
var entropy = 90;
passphrase(entropy, function(_, phrase, actualEntropy) {
  console.log('My passphrase is:', phrase);
});
```

## Browser

Link to the browser.js file, and the passphrase function is in global scope.

## Details

[Blog article][].

[Blog article]: https://espadrine.github.io/blog/posts/memorable-passwords.html
