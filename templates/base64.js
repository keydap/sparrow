// Copyright (c) 2012 Niklas von Hertzen Licensed under the MIT license.
// taken from https://github.com/niklasvh/base64-arraybuffer and made some cosmetic changes

let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

// Use a lookup table to find the index.
let lookup = new Uint8Array(256)
for (var i = 0; i < chars.length; i++) {
  lookup[chars.charCodeAt(i)] = i
}

function decodeUrlBase64 (base64) {
  var len = base64.length
  var bufferLength = len * 0.75
  var i = 0
  var p = 0

  var arraybuffer = new ArrayBuffer(bufferLength)
  var bytes = new Uint8Array(arraybuffer)

  for (i = 0; i < len; i += 4) {
    var encoded1 = lookup[base64.charCodeAt(i)]
    var encoded2 = lookup[base64.charCodeAt(i + 1)]
    var encoded3 = lookup[base64.charCodeAt(i + 2)]
    var encoded4 = lookup[base64.charCodeAt(i + 3)]

    bytes[p++] = (encoded1 << 2) | (encoded2 >> 4)
    bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2)
    bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63)
  }

  return arraybuffer
}
