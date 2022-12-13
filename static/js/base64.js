// var lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// (function (exports) {
//   'use strict'

//   var Arr = (typeof Uint8Array !== 'undefined')
//     ? Uint8Array
//     : Array

//   var PLUS = '+'.charCodeAt(0)
//   var SLASH = '/'.charCodeAt(0)
//   var NUMBER = '0'.charCodeAt(0)
//   var LOWER = 'a'.charCodeAt(0)
//   var UPPER = 'A'.charCodeAt(0)
//   var PLUS_URL_SAFE = '-'.charCodeAt(0)
//   var SLASH_URL_SAFE = '_'.charCodeAt(0)

//   function decode (elt) {
//     var code = elt.charCodeAt(0)
//     if (code === PLUS || code === PLUS_URL_SAFE) return 62 // '+'
//     if (code === SLASH || code === SLASH_URL_SAFE) return 63 // '/'
//     if (code < NUMBER) return -1 // no match
//     if (code < NUMBER + 10) return code - NUMBER + 26 + 26
//     if (code < UPPER + 26) return code - UPPER
//     if (code < LOWER + 26) return code - LOWER + 26
//   }

//   function b64ToByteArray (b64) {
//     var i, j, l, tmp, placeHolders, arr

//     if (b64.length % 4 > 0) {
//       throw new Error('Invalid string. Length must be a multiple of 4')
//     }

//     // the number of equal signs (place holders)
//     // if there are two placeholders, than the two characters before it
//     // represent one byte
//     // if there is only one, then the three characters before it represent 2 bytes
//     // this is just a cheap hack to not do indexOf twice
//     var len = b64.length
//     placeHolders = b64.charAt(len - 2) === '=' ? 2 : b64.charAt(len - 1) === '=' ? 1 : 0

//     // base64 is 4/3 + up to two characters of the original data
//     arr = new Arr(b64.length * 3 / 4 - placeHolders)

//     // if there are placeholders, only get up to the last complete 4 chars
//     l = placeHolders > 0 ? b64.length - 4 : b64.length

//     var L = 0

//     function push (v) {
//       arr[L++] = v
//     }

//     for (i = 0, j = 0; i < l; i += 4, j += 3) {
//       tmp = (decode(b64.charAt(i)) << 18) | (decode(b64.charAt(i + 1)) << 12) | (decode(b64.charAt(i + 2)) << 6) | decode(b64.charAt(i + 3))
//       push((tmp & 0xFF0000) >> 16)
//       push((tmp & 0xFF00) >> 8)
//       push(tmp & 0xFF)
//     }

//     if (placeHolders === 2) {
//       tmp = (decode(b64.charAt(i)) << 2) | (decode(b64.charAt(i + 1)) >> 4)
//       push(tmp & 0xFF)
//     } else if (placeHolders === 1) {
//       tmp = (decode(b64.charAt(i)) << 10) | (decode(b64.charAt(i + 1)) << 4) | (decode(b64.charAt(i + 2)) >> 2)
//       push((tmp >> 8) & 0xFF)
//       push(tmp & 0xFF)
//     }

//     return arr
//   }

//   function uint8ToBase64 (uint8) {
//     var i
//     var extraBytes = uint8.length % 3 // if we have 1 byte left, pad 2 bytes
//     var output = ''
//     var temp, length

//     function encode (num) {
//       return lookup.charAt(num)
//     }

//     function tripletToBase64 (num) {
//       return encode(num >> 18 & 0x3F) + encode(num >> 12 & 0x3F) + encode(num >> 6 & 0x3F) + encode(num & 0x3F)
//     }

//     // go through the array every three bytes, we'll deal with trailing stuff later
//     for (i = 0, length = uint8.length - extraBytes; i < length; i += 3) {
//       temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2])
//       output += tripletToBase64(temp)
//     }

//     // pad the end with zeros, but make sure to not forget the extra bytes
//     switch (extraBytes) {
//       case 1:
//         temp = uint8[uint8.length - 1]
//         output += encode(temp >> 2)
//         output += encode((temp << 4) & 0x3F)
//         output += '=='
//         break
//       case 2:
//         temp = (uint8[uint8.length - 2] << 8) + (uint8[uint8.length - 1])
//         output += encode(temp >> 10)
//         output += encode((temp >> 4) & 0x3F)
//         output += encode((temp << 2) & 0x3F)
//         output += '='
//         break
//       default:
//         break
//     }

//     return output
//   }

//   exports.toByteArray = b64ToByteArray
//   exports.fromByteArray = uint8ToBase64
// }(typeof exports === 'undefined' ? (this.base64js = {}) : exports))
/*
 * Base64URL-ArrayBuffer
 * https://github.com/herrjemand/Base64URL-ArrayBuffer
 *
 * Copyright (c) 2017 Yuriy Ackermann <ackermann.yuriy@gmail.com>
 * Copyright (c) 2012 Niklas von Hertzen
 * Licensed under the MIT license.
 * 
 */
(function(){
  'use strict';

  let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  // Use a lookup table to find the index.
  let lookup = new Uint8Array(256);
  for (let i = 0; i < chars.length; i++) {
      lookup[chars.charCodeAt(i)] = i;
  }

  let encode = function(arraybuffer) {
      let bytes = new Uint8Array(arraybuffer),
      i, len = bytes.length, base64url = '';

      for (i = 0; i < len; i+=3) {
          base64url += chars[bytes[i] >> 2];
          base64url += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
          base64url += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
          base64url += chars[bytes[i + 2] & 63];
      }

      if ((len % 3) === 2) {
          base64url = base64url.substring(0, base64url.length - 1);
      } else if (len % 3 === 1) {
          base64url = base64url.substring(0, base64url.length - 2);
      }

      return base64url;
  };

  let decode = function(base64string) {
      let bufferLength = base64string.length * 0.75,
      len = base64string.length, i, p = 0,
      encoded1, encoded2, encoded3, encoded4;

      let bytes = new Uint8Array(bufferLength);

      for (i = 0; i < len; i+=4) {
          encoded1 = lookup[base64string.charCodeAt(i)];
          encoded2 = lookup[base64string.charCodeAt(i+1)];
          encoded3 = lookup[base64string.charCodeAt(i+2)];
          encoded4 = lookup[base64string.charCodeAt(i+3)];

          bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
          bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
          bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
      }

      return bytes.buffer
  };

  let methods = {
      'decode': decode,
      'encode': encode
  }

  /**
   * Exporting and stuff
   */
  if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
      module.exports = methods;

  } else {
      if (typeof define === 'function' && define.amd) {
          define([], function() {
              return methods
          });
      } else {
          window.base64url = methods;
      }
  }
})();