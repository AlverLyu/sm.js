/**
 * Utils for SM2 and SM3 module
 */

var utils = exports
var BN = require('bn.js');
var crypto = require('crypto');

utils.strToBytes = strToBytes;
utils.hashToBN = hashToBN;
utils.random = random;
utils.padStart = padStart;
utils.hexToBytes = hexToBytes
utils.bytesTohex = bytesTohex

function strToBytes(s) {
  var ch, st, re = [];
  for (var i = 0; i < s.length; i++ ) {
    ch = s.charCodeAt(i);  // get char
    st = [];                 // set up "stack"
    do {
      st.push( ch & 0xFF );  // push byte to stack
      ch = ch >> 8;          // shift value down by 1 byte
    }
    while ( ch );
    // add stack contents to result
    // done because chars have "wrong" endianness
    re = re.concat( st.reverse() );
  }
  return re;
}

function hashToBN(hash) {
  if (typeof hash == 'string') {
    return new BN(hash, 16);
  } else {
    var hex = '';
    for (var i = 0; i < hash.length; i++) {
      var b = hash[i].toString(16);
      if (b.length == 1) {
        hex += '0';
      }
      hex += b;
    }
    return new BN(hex, 16);
  }
}

/**
 * Pads supplied string with character to fill the desired length.
 * 
 * @param {*} str String to pad
 * @param {*} length Desired length of result string
 * @param {*} padChar Character to use as padding
 */
function padStart(str, length, padChar) {
  if (str.length >= length) {
      return str;
  } else {
      return padChar.repeat(length - str.length) + str;
  }
}

/**
 * Generate cryptographic random value.
 *
 * @param {Number} n: byte length of the generated value
 */
function random(n) {
  try {
    return crypto.randomBytes(n).toString('hex');
  } catch (e) {
    // crypto.randomBytes may unavailable in some browsers
    var randomArr = new Array(n);
    for (var i = 0; i < n; i++) {
      randomArr[i] = Math.floor(Math.random() * 256);
    }
    return  randomArr
  }
}

function hexToBytes(hex) {
  var hexChars = '0123456789ABCDEFabcdef';
  if (hex.length % 2 === 1) hex = '0' + hex;

  var bytes = new Array(hex.length / 2);
  for (var i = 0; i < hex.length; i += 2) {
    if (hexChars.indexOf(hex.substring(i, i + 1)) === -1) break;
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesTohex(bytes) {
  var hexChars = '0123456789abcdef';
  var hexString = new Array(bytes.length * 2);

  for (var i = 0; i < bytes.length; i++) {
    hexString[2 * i] = hexChars.charAt((bytes[i] >> 4) & 0x0f);
    hexString[2 * i + 1] = hexChars.charAt(bytes[i] & 0x0f);
  }
  return hexString.join('');
}
