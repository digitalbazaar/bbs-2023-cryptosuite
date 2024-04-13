/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bbs2023Cryptosuite from '../lib/index.js';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {
  alumniCredential,
  bls12381MultikeyKeyPair
} from './mock-data.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {expect} from 'chai';
import jsigs from 'jsonld-signatures';
import {klona} from 'klona';
import {loader} from './documentLoader.js';

const {
  createDiscloseCryptosuite,
  createSignCryptosuite
} = bbs2023Cryptosuite;

const algorithm = Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256;

const {purposes: {AssertionProofPurpose}} = jsigs;

const documentLoader = loader.build();

describe('sign()', () => {
  it('should sign a document using `signer.multisign`', async () => {
    const cryptosuite = createSignCryptosuite();
    const unsignedCredential = klona(alumniCredential);
    const keyPair = await Bls12381Multikey.from({
      ...bls12381MultikeyKeyPair
    }, {algorithm});
    const date = '2023-03-01T21:29:24Z';
    const suite = new DataIntegrityProof({
      signer: keyPair.signer(), date, cryptosuite
    });

    let error;
    let signedCredential;
    try {
      signedCredential = await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    } catch(e) {
      error = e;
    }

    expect(error).to.not.exist;
    expect(signedCredential.proof).to.exist;
    expect(signedCredential.proof['@context']).to.not.exist;
  });

  it('should sign a document using `signer.sign()`', async () => {
    const cryptosuite = createSignCryptosuite();
    const unsignedCredential = klona(alumniCredential);
    const keyPair = await Bls12381Multikey.from({
      ...bls12381MultikeyKeyPair
    }, {algorithm});
    const date = '2023-03-01T21:29:24Z';
    const signer = keyPair.signer();
    delete signer.multisign;
    const suite = new DataIntegrityProof({signer, date, cryptosuite});

    let error;
    let signedCredential;
    try {
      signedCredential = await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    } catch(e) {
      error = e;
    }

    expect(error).to.not.exist;
    expect(signedCredential.proof).to.exist;
    expect(signedCredential.proof['@context']).to.not.exist;
  });

  it('should sign a document using with alg=Bls12381G2', async () => {
    const cryptosuite = createSignCryptosuite();
    const unsignedCredential = klona(alumniCredential);
    const keyPair = await Bls12381Multikey.from({
      ...bls12381MultikeyKeyPair
    }, {algorithm});
    const date = '2023-03-01T21:29:24Z';
    const signer = keyPair.signer();
    delete signer.multisign;
    signer.algorithm = 'Bls12381G2';
    const suite = new DataIntegrityProof({signer, date, cryptosuite});

    let error;
    let signedCredential;
    try {
      signedCredential = await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    } catch(e) {
      error = e;
    }

    expect(error).to.not.exist;
    expect(signedCredential.proof).to.exist;
    expect(signedCredential.proof['@context']).to.not.exist;
  });

  it('should fail to sign with a disclose cryptosuite', async () => {
    const cryptosuite = createDiscloseCryptosuite();
    const unsignedCredential = klona(alumniCredential);

    const keyPair = await Bls12381Multikey.from({
      ...bls12381MultikeyKeyPair
    }, {algorithm});
    const date = '2023-03-01T21:29:24Z';
    const suite = new DataIntegrityProof({
      signer: keyPair.signer(), date, cryptosuite
    });

    let error;
    try {
      await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    } catch(e) {
      error = e;
    }

    expect(error).to.exist;
    error.message.should.equal(
      'This cryptosuite must only be used with "derive".');
  });

  it('should fail to sign with undefined term', async () => {
    const cryptosuite = createSignCryptosuite();
    const unsignedCredential = klona(alumniCredential);
    unsignedCredential.undefinedTerm = 'foo';

    const keyPair = await Bls12381Multikey.from({
      ...bls12381MultikeyKeyPair
    }, {algorithm});
    const date = '2023-03-01T21:29:24Z';
    const suite = new DataIntegrityProof({
      signer: keyPair.signer(), date, cryptosuite
    });

    let error;
    try {
      await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    } catch(e) {
      error = e;
    }

    expect(error).to.exist;
    expect(error.name).to.equal('jsonld.ValidationError');
  });

  it('should fail to sign with relative type URL', async () => {
    const cryptosuite = createSignCryptosuite();
    const unsignedCredential = klona(alumniCredential);
    unsignedCredential.type.push('UndefinedType');

    const keyPair = await Bls12381Multikey.from({
      ...bls12381MultikeyKeyPair
    }, {algorithm});
    const date = '2023-03-01T21:29:24Z';
    const suite = new DataIntegrityProof({
      signer: keyPair.signer(), date, cryptosuite
    });

    let error;
    try {
      await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    } catch(e) {
      error = e;
    }

    expect(error).to.exist;
    expect(error.name).to.equal('jsonld.ValidationError');
  });

  it('should fail to sign with incorrect signer algorithm', async () => {
    const cryptosuite = createSignCryptosuite();
    const keyPair = await Bls12381Multikey.from({
      ...bls12381MultikeyKeyPair
    }, {algorithm});
    const date = '2023-03-01T21:29:24Z';
    const signer = keyPair.signer();
    signer.algorithm = 'wrong-algorithm';

    let error;
    try {
      new DataIntegrityProof({signer, date, cryptosuite});
    } catch(e) {
      error = e;
    }

    const errorMessage = `The signer's algorithm "${signer.algorithm}" ` +
      'is not a supported algorithm for the cryptosuite. The supported ' +
      `algorithms are: "${cryptosuite.requiredAlgorithm.join(', ')}".`;

    expect(error).to.exist;
    expect(error.message).to.equal(errorMessage);
  });
});
