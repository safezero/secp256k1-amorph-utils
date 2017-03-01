const secp256k1 = require('secp256k1')
const arguguard = require('arguguard')
const Amorph = require('amorph')
const amorphBufferPlugin = require('amorph-buffer')
const amorphBnPlugin = require('amorph-bn')
const random = require('random-amorph')
const EC = require('elliptic').ec

Amorph.loadPlugin(amorphBufferPlugin)
Amorph.loadPlugin(amorphBnPlugin)
Amorph.ready()

const ec = exports.ec = new EC('secp256k1')

exports.generatePrivateKey = function generatePrivateKey() {
  let privateKey
  do {
    privateKey = random(32)
  } while (!secp256k1.privateKeyVerify(privateKey.to('buffer')))
  return privateKey
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

exports.deriveLinkedPublicKey = function deriveLinkedPublicKey(link, publicKey, isCompressed) {
  arguguard('deriveLinkedPublicKey', [Amorph, Amorph, 'boolean'], arguments)
  const publicKeyPointBn = ec.keyFromPublic(publicKey.to('hex'), 'hex').pub
  const linkedPublicKeyPoint = ec.g.mul(link.to('bn')).add(publicKeyPointBn)
  return new Amorph(linkedPublicKeyPoint.encode('hex', isCompressed), 'hex')
}

exports.deriveLinkedPrivateKey = function deriveLinkedPrivateKey(link, privateKey) {
  arguguard('deriveLinkedPrivateKey', [Amorph, Amorph], arguments)
  const privateKeyBn = privateKey.to('bn').add(link.to('bn')).mod(ec.n)
  return new Amorph(privateKeyBn, 'bn')
}
