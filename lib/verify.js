/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {concatBuffers, parseDisclosureProofValue} from './proofValue.js';
import {
  createLabelMapFunction,
  hashCanonizedProof,
  hashMandatory,
  labelReplacementCanonicalizeJsonLd,
  stringToUtf8Bytes
} from '@digitalbazaar/di-sd-primitives';
import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';

export function createVerifyCryptosuite({expectedPresentationHeader} = {}) {
  const options = {expectedPresentationHeader};
  return {
    name,
    requiredAlgorithm,
    createVerifier,
    createVerifyData: _createVerifyData,
    options,
    results: {lastParsedProof: null}
  };
}

export async function createVerifier({verificationMethod}) {
  const key = await Bls12381Multikey.from(verificationMethod);
  const verifier = key.verifier();
  return {
    algorithm: verifier.algorithm,
    id: verifier.id,
    // `data` includes `signature` in this cryptosuite
    async verify({data}) {
      return _multiverify({verifier, data});
    }
  };
}

async function _createVerifyData({
  cryptosuite, document, proof, documentLoader
}) {
  if(cryptosuite?.name !== name) {
    throw new TypeError(`"cryptosuite.name" must be "${name}".`);
  }
  const {expectedPresentationHeader} = cryptosuite.options;
  if(expectedPresentationHeader &&
    !(expectedPresentationHeader instanceof Uint8Array)) {
    throw new TypeError(
      '"cryptosuite.options.expectedPresentationHeader" must be a Uint8Array.');
  }

  // 1. Generate `proofHash` in parallel.
  const options = {documentLoader};
  const proofHashPromise = hashCanonizedProof({document, proof, options})
    .catch(e => e);

  // 2. Parse disclosure `proof` to get parameters to verify.
  const {
    bbsProof, labelMap, mandatoryIndexes, selectiveIndexes, presentationHeader
  } = await parseDisclosureProofValue({proof});

  // 3. Check expected presentation header, if any.
  if(expectedPresentationHeader) {
    if(!(presentationHeader.length === expectedPresentationHeader.length &&
      presentationHeader.every(
        (e, i) => e === expectedPresentationHeader[i]))) {
      // presentation header does not match expected value
      return false;
    }
  } else {
    // store last parsed presentation header
    cryptosuite.results.lastParsedProof = {presentationHeader};
  }

  // 4. Canonicalize document using label map.
  const labelMapFactoryFunction = await createLabelMapFunction({labelMap});
  const nquads = await labelReplacementCanonicalizeJsonLd(
    {document, labelMapFactoryFunction, options});

  // 5. Separate N-Quads into mandatory and non-mandatory.
  const mandatory = [];
  const nonMandatory = [];
  for(const [index, nq] of nquads.entries()) {
    if(mandatoryIndexes.includes(index)) {
      mandatory.push(nq);
    } else {
      nonMandatory.push(nq);
    }
  }

  // 6. Hash any mandatory N-Quads.
  const {mandatoryHash} = await hashMandatory({mandatory});

  // 7. Return data used by cryptosuite to verify.
  const proofHash = await proofHashPromise;
  if(proofHash instanceof Error) {
    throw proofHash;
  }
  return {
    bbsProof, proofHash, nonMandatory, mandatoryHash, selectiveIndexes,
    presentationHeader
  };
}

async function _multiverify({verifier, data} = {}) {
  // 1. Deserialize `data` into named components.
  const {
    bbsProof: proof, proofHash, nonMandatory, mandatoryHash, selectiveIndexes,
    presentationHeader
  } = data;

  // 2. Set `bbsHeader` to the concatenation of `proofHash` and `mandatoryHash`.
  const header = concatBuffers([proofHash, mandatoryHash]);

  // 3. Set `verificationResult` to the result of BBS `ProofVerify` passing
  //   the appropriate params.
  const disclosedMessages = nonMandatory.map(stringToUtf8Bytes);
  if(disclosedMessages.length !== selectiveIndexes.length) {
    throw new Error(
      `Number of disclosed messages (${disclosedMessages.length}) does not ` +
      `equal number of "selectiveIndexes" (${selectiveIndexes.length}).`);
  }
  // build sparse `messages` array using selective indexes
  const messages = [];
  for(const [i, message] of disclosedMessages.entries()) {
    messages[selectiveIndexes[i]] = message;
  }
  return verifier.multiverify({proof, header, presentationHeader, messages});
}
