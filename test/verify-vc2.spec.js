/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bbs2023Cryptosuite from '../lib/index.js';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {
  bls12381MultikeyKeyPair,
  employeeCredential
} from './mock-data.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {expect} from 'chai';
import jsigs from 'jsonld-signatures';
import {klona} from 'klona';
import {loader} from './documentLoader.js';

const {
  createDiscloseCryptosuite,
  createSignCryptosuite,
  createVerifyCryptosuite
} = bbs2023Cryptosuite;

const algorithm = Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256;

const {purposes: {AssertionProofPurpose}} = jsigs;

const documentLoader = loader.build();

describe('verify VCDM 2.0 example VC', () => {
  let signedEmployeeCredential;
  let revealedEmployeeCredential;
  before(async () => {
    const cryptosuite = createSignCryptosuite({
      mandatoryPointers: [
        '/issuer',
        '/type',
        '/validFrom',
        '/validUntil'
      ]
    });
    const unsignedCredential = klona(employeeCredential);

    const keyPair = await Bls12381Multikey.from({
      ...bls12381MultikeyKeyPair
    }, {algorithm});
    const date = unsignedCredential.validFrom;
    const suite = new DataIntegrityProof({
      signer: keyPair.signer(), date, cryptosuite
    });

    signedEmployeeCredential = await jsigs.sign(unsignedCredential, {
      suite,
      purpose: new AssertionProofPurpose(),
      documentLoader
    });

    {
      const cryptosuite = createDiscloseCryptosuite({
        selectivePointers: [
          '/credentialSubject/employer/name'
        ]
      });
      const suite = new DataIntegrityProof({cryptosuite});
      revealedEmployeeCredential = await jsigs.derive(
        signedEmployeeCredential, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });
    }
  });

  it('should verify', async () => {
    const cryptosuite = createVerifyCryptosuite();
    const suite = new DataIntegrityProof({cryptosuite});
    const result = await jsigs.verify(revealedEmployeeCredential, {
      suite,
      purpose: new AssertionProofPurpose(),
      documentLoader
    });

    expect(result.verified).to.be.true;
  });

  it('should fail w/modified mandatory property',
    async () => {
      const cryptosuite = createVerifyCryptosuite();
      const suite = new DataIntegrityProof({cryptosuite});
      const signedCredentialCopy = klona(revealedEmployeeCredential);
      // modify `validUntil`
      signedCredentialCopy.validUntil = '2032-01-01T00:00:00Z';

      const result = await jsigs.verify(signedCredentialCopy, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      expect(result.verified).to.be.false;
      const {error} = result.results[0];

      expect(result.verified).to.be.false;
      expect(error.name).to.equal('Error');
      expect(error.message).to.include('Invalid signature');
    });

  it('should fail w/added message to mandatory reveal', async () => {
    const cryptosuite = createVerifyCryptosuite();
    const suite = new DataIntegrityProof({cryptosuite});
    const signedCredentialCopy = klona(revealedEmployeeCredential);
    // intentionally add data (should fail even if it's the same as original)
    // because signature count is different
    signedCredentialCopy.credentialSubject.jobTitle =
      signedEmployeeCredential.credentialSubject.jobTitle;

    const result = await jsigs.verify(signedCredentialCopy, {
      suite,
      purpose: new AssertionProofPurpose(),
      documentLoader
    });

    expect(result.verified).to.be.false;
    const {error} = result.results[0];

    expect(result.verified).to.be.false;
    expect(error.name).to.equal('Error');
    expect(error.message).to.include('Number of disclosed messages');
  });

  it('should fail w/modified selective property',
    async () => {
      const cryptosuite = createVerifyCryptosuite();
      const suite = new DataIntegrityProof({cryptosuite});
      const signedCredentialCopy = klona(revealedEmployeeCredential);
      // modify `employer.name`
      signedCredentialCopy.credentialSubject.employer.name = 'Invalid';

      const result = await jsigs.verify(signedCredentialCopy, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      expect(result.verified).to.be.false;
      const {error} = result.results[0];

      expect(result.verified).to.be.false;
      expect(error.message).to.include('Invalid signature');
    });

  it('should fail w/same message disclosure count but different data',
    async () => {
      const cryptosuite = createVerifyCryptosuite();
      const suite = new DataIntegrityProof({cryptosuite});
      const signedCredentialCopy = klona(revealedEmployeeCredential);
      // intentionally add data (should fail even if it's the same as
      // original) because message disclosure count is different
      signedCredentialCopy.credentialSubject.jobTitle =
        signedEmployeeCredential.credentialSubject.jobTitle;
      // intentionally delete `employer` to keep message disclosure count equal
      delete signedCredentialCopy.credentialSubject.employer;

      const result = await jsigs.verify(signedCredentialCopy, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      expect(result.verified).to.be.false;
      const {error} = result.results[0];

      expect(result.verified).to.be.false;
      expect(error.name).to.equal('Error');
      // should NOT fail due to bad signature count, but due to bad signature
      expect(error.message).to.not.include('Number of disclosed messages');
      expect(error.message).to.include('Invalid signature');
    });
});
