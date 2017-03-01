const utils = require('./')
const crypto = require('crypto')
const Amorph = require('amorph')
const chai = require('chai')
const chaiAmorph = require('chai-amorph')
const random = require('random-amorph')

chai.use(chaiAmorph)
chai.should()

describe('utils', () => {
  let privateKey
  let uncompressedPublicKey
  let compresedPublicKey

  it('should generate private key', () => {
    privateKey = utils.generatePrivateKey()
  })
  it('private key should be 32 bytes', () => {
    privateKey.to('array').should.have.length(32)
  })
  it('privateKey should verify', () => {
    utils.verifyPrivateKey(privateKey).should.equal(true)
  })
  it('should derive public keys', () => {
    uncompressedPublicKey = utils.derivePublicKey(privateKey, false)
    compressedPublicKey = utils.derivePublicKey(privateKey, true)
  })
  it('public keys should have correct length', () => {
    uncompressedPublicKey.to('array').should.have.length(65)
    compressedPublicKey.to('array').should.have.length(33)
  })
  it('public keys should veriy', () => {
    utils.verifyPublicKey(uncompressedPublicKey).should.equal(true)
    utils.verifyPublicKey(compressedPublicKey).should.equal(true)
  })
  it('should cross convert public keys', () => {
    utils.convertPublicKey(uncompressedPublicKey, true).should.amorphEqual(compressedPublicKey)
    utils.convertPublicKey(compressedPublicKey, false).should.amorphEqual(uncompressedPublicKey)
  })
  describe('ecdh', () => {
    [true, false].forEach((isCompressed) => {
      describe(`isCompressed:${isCompressed}`, () => {
        [true, false].forEach((isHashed) => {
          describe(`isHashed:${isHashed}`, () => {
            it('should derive mirrors', () => {
              const alicePrivateKey = utils.generatePrivateKey()
              const alicePublicKey = utils.derivePublicKey(alicePrivateKey, true)
              const bobPrivateKey = utils.generatePrivateKey()
              const bobPublicKey = utils.derivePublicKey(bobPrivateKey, false)
              utils.deriveEcdhKey(alicePrivateKey, bobPublicKey, isCompressed, isHashed).should.amorphEqual(
                utils.deriveEcdhKey(bobPrivateKey, alicePublicKey, isCompressed, isHashed)
              )
            })
          })
        })
      })
    })
  })
  describe('linked keys', () => {
    [true, false].forEach((isCompressed) => {
      describe(`isCompressed:${isCompressed}`, () => {
        const link = random(32)
        let linkedPublicKey
        let linkedPrivateKey
        it('should derive linkedPrivateKey from privateKey', () => {
          linkedPrivateKey = utils.deriveLinkedPrivateKey(link, privateKey)
        })
        it('should derive linkedPublicKey from publicKey', () => {
          linkedPublicKey = utils.deriveLinkedPublicKey(link, compressedPublicKey, isCompressed)
        })
        it('should be able to derive linkedPublicKey from linkedPrivateKey', () => {
          utils.derivePublicKey(linkedPrivateKey, isCompressed).should.amorphEqual(linkedPublicKey)
        })
      })
    })
  })
})
