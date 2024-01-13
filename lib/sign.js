/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  canonicalizeAndGroup,
  createHmac,
  hashCanonizedProof,
  hashMandatory,
  stringToUtf8Bytes
} from '@digitalbazaar/di-sd-primitives';
import {concatBuffers, serializeBaseProofValue} from './proofValue.js';
import {createShuffledIdLabelMapFunction} from './sdFunctions.js';
import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';

export function createSignCryptosuite({mandatoryPointers = []} = {}) {
  const options = {mandatoryPointers};
  return {
    name,
    requiredAlgorithm,
    createVerifier: _throwSignUsageError,
    createVerifyData: _createSignData,
    createProofValue: _createBaseProofValue,
    options
  };
}

async function _createBaseProofValue({verifyData, dataIntegrityProof}) {
  const {signer} = dataIntegrityProof;
  const {
    proofHash, mandatoryPointers, mandatoryHash, nonMandatory, hmacKey
  } = verifyData;

  // 1. Set BBS header to the concatenation of `proofHash` and `mandatoryHash`.
  const bbsHeader = concatBuffers([proofHash, mandatoryHash]);

  // 2. Set BBS messages to all non-mandatory messages using UTF-8 encoding.
  const messages = nonMandatory.map(stringToUtf8Bytes);

  // 3. Create BBS signature.
  const {publicKey} = signer;
  const bbsSignature = await signer.multisign({header: bbsHeader, messages});

  // 4. Generate `proofValue`.
  const proofValue = serializeBaseProofValue({
    bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers
  });
  return proofValue;
}

async function _createSignData({
  cryptosuite, document, proof, documentLoader
}) {
  if(cryptosuite?.name !== name) {
    throw new TypeError(`"cryptosuite.name" must be "${name}".`);
  }
  if(!(cryptosuite.options && typeof cryptosuite.options === 'object')) {
    throw new TypeError(`"cryptosuite.options" must be an object.`);
  }
  const {mandatoryPointers = []} = cryptosuite.options;
  if(!Array.isArray(mandatoryPointers)) {
    throw new TypeError(
      `"cryptosuite.options.mandatoryPointers" must be an array.`);
  }

  // 0. Remove `created` from proof if present.
  // FIXME: implement `updateProof` or another method to ensure `created`
  // is not set once some API is exposed via `data-integrity`
  delete proof.created;

  // 1. Generate `proofHash` in parallel.
  const options = {documentLoader};
  const proofHashPromise = hashCanonizedProof({document, proof, options})
    .catch(e => e);

  // 2. Create HMAC label replacement function to randomize bnode labels.
  const hmac = await createHmac({key: null});
  const labelMapFactoryFunction = createShuffledIdLabelMapFunction({hmac});

  // 3. Canonicalize document with randomized bnode labels and group N-Quads
  //  by mandatory pointers.
  const {
    groups: {mandatory: mandatoryGroup}
  } = await canonicalizeAndGroup({
    document,
    labelMapFactoryFunction,
    groups: {mandatory: mandatoryPointers},
    options
  });
  const mandatory = [...mandatoryGroup.matching.values()];
  const nonMandatory = [...mandatoryGroup.nonMatching.values()];

  // 4. Hash any mandatory N-Quads.
  const {mandatoryHash} = await hashMandatory({mandatory});

  // 5. Export HMAC key.
  const hmacKey = await hmac.export();

  // 6. Return data used by cryptosuite to sign.
  const proofHash = await proofHashPromise;
  if(proofHash instanceof Error) {
    throw proofHash;
  }
  return {proofHash, mandatoryPointers, mandatoryHash, nonMandatory, hmacKey};
}

function _throwSignUsageError() {
  throw new Error('This cryptosuite must only be used with "sign".');
}
