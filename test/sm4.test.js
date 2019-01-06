var SM42 = require('../lib/sm4');

var sm4Config = {
  // encrypt/decypt main key; cannot be omitted
  key: '31323334353637383837363534333231',

  // optional; can be 'cbc' or 'ecb'
  mode: 'cbc', // default

  // optional; when use cbc mode, it's necessary
  iv: '31313131313131313131313131313131', // default is null

  padding: 'none',
}

var sm4 = new SM42(sm4Config)

var plaintext = '32323232323232323232323232323232'
var ciphertext = sm4.encrypt(plaintext)
console.log('ciphertext', ciphertext)
var plaintext2 = sm4.decrypt(ciphertext)
console.log('plaintext', plaintext2)