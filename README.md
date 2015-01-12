```js
var passphrase = require('passphrase');
var entropy = 90;
passphrase(entropy, function(_, phrase, actualEntropy) {
  console.log('My passphrase is:', phrase);
});
```
