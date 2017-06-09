# sm.js

SM series cryptography in javascript implementation.


## Usage 

### SM2 public key algorithm

Generate a key pair

```js
var sm2 = require('sm.js').sm2;

var curve = new sm2();
var key = curve.genKeyPair();

```

Generate signature for a message

```js
var msg = 'abc';
var signature = key.sign(msg);
```

Verify a signature

```js
if (key.verify(msg, signature.r, signature.s)) {
	console.log('PASS');
}
```

### SM3 hash algorithm

```js
var sm3 = require('sm.js').sm3;

var msg = 'abc';
var hash = new sm3();
var digest = hash.sum(msg);
```

