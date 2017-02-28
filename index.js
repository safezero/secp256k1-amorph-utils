const secp256k1 = require('secp256k1')
const arguguard = require('arguguard')
const Amorph = require('amorph')
const amorphBufferPlugin = require('amorph-buffer')
const crypto = require('crypto')

Amorph.loadPlugin(amorphBufferPlugin)
Amorph.ready()

exports.generatePrivateKey = function generatePrivateKey() {
  let privateKeyBuffer
  do {
    privateKeyBuffer = crypto.randomBytes(32)
  } while (!secp256k1.privateKeyVerify(privateKeyBuffer))
  return new Amorph(privateKeyBuffer, 'buffer')
}

exports.verifyPrivateKey = function verifyPrivateKey(privateKey) {
  arguguard('verifyPrivateKey', [Amorph], arguments)
  return secp256k1.privateKeyVerify(privateKey.to('buffer'))
}

exports.verifyPublicKey = function verifyPrivateKey(publicKey) {
  arguguard('verifyPrivateKey', [Amorph], arguments)
  return secp256k1.publicKeyVerify(publicKey.to('buffer'))
}

exports.derivePublicKey = function derivePublicKey(privateKey, isCompressed) {
  arguguard('derivePublicKey', [Amorph, 'boolean'], arguments)
  return new Amorph(secp256k1.publicKeyCreate(privateKey.to('buffer'), isCompressed), 'buffer')
}

exports.convertPublicKey = function convertPublicKey(publicKey, isCompressed) {
  arguguard('convertPublicKey', [Amorph, 'boolean'], arguments)
  return new Amorph(secp256k1.publicKeyConvert(publicKey.to('buffer'), isCompressed), 'buffer')
}

exports.deriveEcdhKey = function deriveEcdhKey(privateKey, publicKey, isCompressed, isHashed) {
  arguguard('deriveECDHSharedKey', [Amorph, Amorph, 'boolean', 'boolean'], arguments)
  const ecdhKeyBuffer = isHashed ?
    secp256k1.ecdh(publicKey.to('buffer'), privateKey.to('buffer'), isCompressed)
    : secp256k1.ecdhUnsafe(publicKey.to('buffer'), privateKey.to('buffer'), isCompressed)
  return new Amorph(ecdhKeyBuffer, 'buffer')
}
