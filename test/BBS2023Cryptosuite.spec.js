/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {expect} from 'chai';

import jsigs from 'jsonld-signatures';
const {purposes: {AssertionProofPurpose}} = jsigs;

import {
  credential,
  // ...
} from './mock-data.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
// FIXME
//import ...
import {
  cryptosuite as bbs2023CryptoSuite
} from '../lib/index.js';

import {loader} from './documentLoader.js';

const documentLoader = loader.build();

describe('BBS2023Cryptosuite', () => {
  describe('exports', () => {
    it('it should have proper exports', async () => {
      should.exist(bbs2023CryptoSuite);
      bbs2023CryptoSuite.name.should.equal('bbs-2023');
      bbs2023CryptoSuite.requiredAlgorithm.should.equal('FIXME');
      bbs2023CryptoSuite.canonize.should.be.a('function');
      bbs2023CryptoSuite.createVerifier.should.be.a('function');
    });
  });

  describe('canonize()', () => {
    it('should canonize using URDNA2015 w/ n-quads', async () => {
      const unsignedCredential = {...credential};

      let result;
      let error;
      try {
        result = await bbs2023CryptoSuite.canonize(
          unsignedCredential, {documentLoader});
      } catch(e) {
        error = e;
      }

      expect(error).to.not.exist;
      expect(result).to.exist;
      /* eslint-disable max-len */
      const expectedResult = `<http://example.edu/credentials/1872> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org#AlumniCredential> .
<http://example.edu/credentials/1872> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.edu/credentials/1872> <https://www.w3.org/2018/credentials#credentialSubject> <https://example.edu/students/alice> .
<http://example.edu/credentials/1872> <https://www.w3.org/2018/credentials#issuanceDate> "2010-01-01T19:23:24Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.edu/credentials/1872> <https://www.w3.org/2018/credentials#issuer> <https://example.edu/issuers/565049> .
<https://example.edu/students/alice> <https://schema.org#alumniOf> "Example University" .\n`;
      /* eslint-enable max-len */
      result.should.equal(expectedResult);
    });
  });

  // FIXME
});
