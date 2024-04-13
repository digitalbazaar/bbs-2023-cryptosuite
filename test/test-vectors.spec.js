/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bbs2023Cryptosuite from '../lib/index.js';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {expect} from 'chai';
import jsigs from 'jsonld-signatures';
import {loader} from './documentLoader.js';

import * as testVectors from './test-vectors.js';

const {
  createDiscloseCryptosuite,
  createVerifyCryptosuite
} = bbs2023Cryptosuite;

const algorithm = Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256;

const {purposes: {AssertionProofPurpose}} = jsigs;

const documentLoader = loader.build();

describe('test vectors', () => {
  before(async () => {
    const {keyMaterial} = testVectors;
    const keyPair = await Bls12381Multikey.fromRaw({
      algorithm,
      secretKey: h2b(keyMaterial.privateKeyHex),
      publicKey: h2b(keyMaterial.publicKeyHex)
    });
    keyPair.controller = `did:key:${keyPair.publicKeyMultibase}`;
    keyPair.id = `${keyPair.controller}#${keyPair.publicKeyMultibase}`;
  });

  it('should derive and verify proof', async () => {
    const {signedSDBase} = testVectors;

    // generate reveal doc
    const discloseCryptosuite = createDiscloseCryptosuite({
      selectivePointers: [
        '/credentialSubject/boards/0',
        '/credentialSubject/boards/1'
      ]
    });

    let error;
    let revealed;
    try {
      revealed = await jsigs.derive(signedSDBase, {
        suite: new DataIntegrityProof({cryptosuite: discloseCryptosuite}),
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    } catch(e) {
      error = e;
    }

    expect(error).to.not.exist;

    const expected = {
      '@context': signedSDBase['@context'],
      type: signedSDBase.type,
      credentialSubject: {
        // `sailNumber` and sails `1` and `2` are mandatory in test vector
        sailNumber: signedSDBase.credentialSubject.sailNumber,
        sails: [
          signedSDBase.credentialSubject.sails[1],
          signedSDBase.credentialSubject.sails[2]
        ],
        boards: signedSDBase.credentialSubject.boards.slice(0, 2)
      }
    };
    revealed['@context'].should.deep.equal(expected['@context']);
    revealed.type.should.deep.equal(expected.type);
    revealed.credentialSubject.should.deep.equal(expected.credentialSubject);
    expect(revealed.proof).to.exist;
    expect(revealed.proof['@context']).to.not.exist;
    revealed.proof.should.not.deep.equal(signedSDBase.proof);

    // verify reveal doc
    const result = await jsigs.verify(revealed, {
      suite: new DataIntegrityProof({cryptosuite: createVerifyCryptosuite()}),
      purpose: new AssertionProofPurpose(),
      documentLoader
    });

    expect(result.verified).to.be.true;
  });

  it('should verify derived proof', async () => {
    const {derivedRevealDocument} = testVectors;

    const cryptosuite = createVerifyCryptosuite();
    const suite = new DataIntegrityProof({cryptosuite});
    const result = await jsigs.verify(derivedRevealDocument, {
      suite,
      purpose: new AssertionProofPurpose(),
      documentLoader
    });

    expect(result.verified).to.be.true;
  });
});

// hex => bytes
function h2b(hex) {
  if(hex.length === 0) {
    return new Uint8Array();
  }
  return Uint8Array.from(hex.match(/.{1,2}/g).map(h => parseInt(h, 16)));
}
