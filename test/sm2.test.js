var sm2 = require('../lib/sm2');

var key = sm2.genKeyPair();
var result = key.encrypt('313233343536', 'hex');

console.warn('pri', key.pri.toString(16, 32));
console.warn('pub x', key.pub.getX().toString(16, 32));
console.warn('pub y', key.pub.getY().toString(16, 32));
console.warn('pub', key.pubToString());
console.warn('c1', result.slice(0, 128));
console.warn('c3', result.slice(128, 192));
console.warn('c2', result.slice(192));

console.warn('dec', key.decrypt(result, 'hex'));

var key2 = sm2.SM2KeyPair(null, key.pri.toString(16, 32))
console.warn('dec 2', key2.decrypt(result, 'hex'));


var key3 = sm2.SM2KeyPair(key.pubToString())
var result3 = key.encrypt('313233343536', 'hex');
console.warn('enc 3', result3);
console.warn('dec 3', key.decrypt(result3, 'hex'));

var key4 = sm2.SM2KeyPair('04284F6A1A1479FADB063452ED3060CD98A34583BB448954990C239EEC414A41C5A076705E52BC4F6297F667938F99D05C3994834E6639E6DF775F45B2310F50F6')
console.warn('ver 4', key4.verifyRaw(
  [...Buffer.from('00000000fa2ed2f822d673ea829c852fdfdb3326d8392c3836b43cdf57667998a8dce0d9409c35098ba7b46175b3a5fab8dff6718bceb3d442cb55dc79bad11bf3541e8a', 'hex')],
  'b405ad77a936a2ceffb622d47a4e769ffa16f231d7f7130126cd655b02746731',
  'bc486fc3f12d3130633cb4c9c55aac8c6d56d9abf4ca91b0f1f2bd2480d292f2'
));
console.warn('ver 4', key4.verifyDigest(
  'C34A4011F41E774069ADEC370137DD4F282445DF58D909F0A4DEF68D6E86DBC7',
  'b405ad77a936a2ceffb622d47a4e769ffa16f231d7f7130126cd655b02746731',
  'bc486fc3f12d3130633cb4c9c55aac8c6d56d9abf4ca91b0f1f2bd2480d292f2'
));