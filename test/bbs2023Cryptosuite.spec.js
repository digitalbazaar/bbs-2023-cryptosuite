/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bbs2023Cryptosuite from '../lib/index.js';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {bls12381MultikeyKeyPair} from './mock-data.js';
import {expect} from 'chai';

const {
  createDiscloseCryptosuite,
  createSignCryptosuite,
  createVerifyCryptosuite,
  requiredAlgorithm: algorithm
} = bbs2023Cryptosuite;

describe.only('bbs-2023 cryptosuite', () => {
  describe('exports', () => {
    it('should have proper exports', async () => {
      should.exist(bbs2023Cryptosuite);
      bbs2023Cryptosuite.createDiscloseCryptosuite.should.be.a('function');
      bbs2023Cryptosuite.createSignCryptosuite.should.be.a('function');
      bbs2023Cryptosuite.createVerifyCryptosuite.should.be.a('function');
    });
  });

  describe('createSignCryptosuite', () => {
    it('should have proper exports', async () => {
      const cryptosuite = await createSignCryptosuite();
      should.exist(cryptosuite);
      cryptosuite.name.should.equal('bbs-2023');
      cryptosuite.requiredAlgorithm.should.equal('BBS-BLS12-381-SHA-256');
      cryptosuite.createVerifier.should.be.a('function');
      cryptosuite.createVerifyData.should.be.a('function');
      cryptosuite.createProofValue.should.be.a('function');
      cryptosuite.options.should.be.an('object');
    });
  });

  describe('createDiscloseCryptosuite', () => {
    it('should have proper exports', async () => {
      const cryptosuite = await createDiscloseCryptosuite();
      should.exist(cryptosuite);
      cryptosuite.name.should.equal('bbs-2023');
      cryptosuite.requiredAlgorithm.should.equal('BBS-BLS12-381-SHA-256');
      cryptosuite.createVerifier.should.be.a('function');
      cryptosuite.createVerifyData.should.be.a('function');
      cryptosuite.createProofValue.should.be.a('function');
      cryptosuite.derive.should.be.a('function');
      cryptosuite.options.should.be.an('object');
    });
  });

  describe('createVerifyCryptosuite', () => {
    it('should have proper exports', async () => {
      const cryptosuite = await createVerifyCryptosuite();
      should.exist(cryptosuite);
      cryptosuite.name.should.equal('bbs-2023');
      cryptosuite.requiredAlgorithm.should.equal('BBS-BLS12-381-SHA-256');
      cryptosuite.createVerifier.should.be.a('function');
      cryptosuite.createVerifyData.should.be.a('function');
    });
  });

  describe('createVerifier()', () => {
    it('should fail with a sign cryptosuite', async () => {
      const cryptosuite = await createSignCryptosuite();
      let verifier;
      let error;
      const keyPair = await Bls12381Multikey.from({
        ...bls12381MultikeyKeyPair
      }, {algorithm});
      keyPair.type = 'BadKeyType';
      try {
        verifier = await cryptosuite.createVerifier({
          verificationMethod: keyPair
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.exist;
      expect(verifier).to.not.exist;
      error.message.should.equal(
        'This cryptosuite must only be used with "sign".');
    });

    it('should fail with a disclose cryptosuite', async () => {
      const cryptosuite = await createDiscloseCryptosuite();
      let verifier;
      let error;
      const keyPair = await Bls12381Multikey.from({
        ...bls12381MultikeyKeyPair
      }, {algorithm});
      keyPair.type = 'BadKeyType';
      try {
        verifier = await cryptosuite.createVerifier({
          verificationMethod: keyPair
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.exist;
      expect(verifier).to.not.exist;
      error.message.should.equal(
        'This cryptosuite must only be used with "derive".');
    });

    it('should pass with BBS Multikey', async () => {
      const cryptosuite = await createVerifyCryptosuite();
      let verifier;
      let error;
      try {
        verifier = await cryptosuite.createVerifier({
          verificationMethod: {...bls12381MultikeyKeyPair}
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.not.exist;
      expect(verifier).to.exist;
      verifier.algorithm.should.equal('BBS-BLS12-381-SHAKE-256');
      verifier.id.should.equal(bls12381MultikeyKeyPair.id);
      verifier.verify.should.be.a('function');
    });

    it('should fail w/ unsupported key type', async () => {
      const cryptosuite = await createVerifyCryptosuite();
      let verifier;
      let error;
      const keyPair = await Bls12381Multikey.from({
        ...bls12381MultikeyKeyPair
      }, {algorithm});
      keyPair.type = 'BadKeyType';
      try {
        verifier = await cryptosuite.createVerifier({
          verificationMethod: keyPair
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.exist;
      expect(verifier).to.not.exist;
      error.message.should.equal(
        '"key" must be a Multikey with type "Multikey".');
    });
  });
});
