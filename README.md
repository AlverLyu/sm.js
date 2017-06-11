# sm.js

SM series cryptography in javascript implementation.

SM2 signature and SM3 hash are implemented.

## install

`sm.js` is available in npm.

```sh
npm install sm.js
```

## Usage 

### SM2 key pair

Generate a key pair

```js
var sm2 = require('sm.js').sm2;

var key = sm2.genKeyPair();
```

The public key can be converted to a string or a byte array, for storing or
transmitting on network.

```js
var pubKeyString = key.pubToString();
var pubKeyBytes = key.pubToBytes('compress');
```

Note that there are 3 conversion modes: compress, nocompress and mex.
The default mode is nocompress.

To parse the public key string/array, simply use the key pair constructor

```
var key = new sm2.SM2KeyPair(pubKeyString);
```


### SM2 signature

The key pair can be used to sign message or verify the signature.

```js
var msg = 'abc';
var signature = key.sign(msg);

if (key.verify(msg, signature.r, signature.s)) {
	console.log('PASS');
}
```

Note that `key.pri` should not be null when signing, as well as `key.pub` for
verifying.

`sign` will combine the input message with extra infos(a constant ID, the curve
parameters and the public key), and use SM3 as the hash algorithm. While there
is a function pair `signRaw` and `verifyRaw` which do not use the extra infos.
Also there is a function pair `signDigest` and `verifyDigest` use the message
digest as the input, allowing for custom hashing.


### SM3 hash algorithm

The sm3 module is used to generate digest using SM3 hash algorithm.

```js
var sm3 = require('sm.js').sm3;

var msg = 'abc';
var hash = new sm3();
var digest = hash.sum(msg);
```

