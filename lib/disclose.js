/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {
  canonicalize,
  canonicalizeAndGroup,
  createHmac,
  selectJsonLd,
  stringToUtf8Bytes,
  stripBlankNodePrefixes
} from '@digitalbazaar/di-sd-primitives';
import {
  parseBaseProofValue,
  serializeDisclosureProofValue
} from './proofValue.js';
import {createShuffledIdLabelMapFunction} from './sdFunctions.js';
import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';

export function createDiscloseCryptosuite({
  proofId, selectivePointers = [], presentationHeader = new Uint8Array()
} = {}) {
  const options = {proofId, selectivePointers, presentationHeader};
  return {
    name,
    requiredAlgorithm,
    createVerifier: _throwDeriveUsageError,
    createVerifyData: _throwDeriveUsageError,
    createProofValue: _throwDeriveUsageError,
    derive: _derive,
    options
  };
}

async function _createDisclosureData({
  cryptosuite, document, proof, documentLoader
}) {
  if(cryptosuite?.name !== name) {
    throw new TypeError(`"cryptosuite.name" must be "${name}".`);
  }
  if(!(cryptosuite.options && typeof cryptosuite.options === 'object')) {
    throw new TypeError(`"cryptosuite.options" must be an object.`);
  }
  if(!(cryptosuite.options.presentationHeader instanceof Uint8Array)) {
    throw new TypeError(
      '"cryptosuite.options.presentationHeader" must be a Uint8Array.');
  }

  // 1. Parse base `proof` to get parameters for disclosure proof.
  const {
    bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers
  } = await parseBaseProofValue({proof});

  // 2. Ensure mandatory and / or selective data will be disclosed.
  const {selectivePointers = []} = cryptosuite.options;
  if(!(mandatoryPointers?.length > 0 || selectivePointers?.length > 0)) {
    throw new Error('Nothing selected for disclosure.');
  }

  // 3. Create HMAC label replacement function from `hmacKey` to randomize
  //   bnode identifiers.
  const hmac = await createHmac({key: hmacKey});
  const labelMapFactoryFunction = createShuffledIdLabelMapFunction({hmac});

  // 4. Canonicalize document with randomized bnode labels and group N-Quads
  //  by mandatory, selective, and combined pointers.
  const options = {documentLoader};
  const combinedPointers = mandatoryPointers.concat(selectivePointers);
  const {
    groups: {
      mandatory: mandatoryGroup,
      selective: selectiveGroup,
      combined: combinedGroup,
    },
    labelMap
  } = await canonicalizeAndGroup({
    document,
    labelMapFactoryFunction,
    groups: {
      mandatory: mandatoryPointers,
      selective: selectivePointers,
      combined: combinedPointers
    },
    options
  });

  // 5. Convert absolute indexes of mandatory N-Quads to indexes relative to
  // the combined output to be revealed.
  let relativeIndex = 0;
  const mandatoryIndexes = [];
  for(const absoluteIndex of combinedGroup.matching.keys()) {
    if(mandatoryGroup.matching.has(absoluteIndex)) {
      mandatoryIndexes.push(relativeIndex);
    }
    relativeIndex++;
  }

  // 6. Convert absolute indexes of selective N-Quads to indexes relative to
  // the non-mandatory messages as these are the indexes used in BBS.
  relativeIndex = 0;
  const selectiveIndexes = [];
  for(const absoluteIndex of mandatoryGroup.nonMatching.keys()) {
    if(selectiveGroup.matching.has(absoluteIndex)) {
      selectiveIndexes.push(relativeIndex);
    }
    relativeIndex++;
  }

  // 7. Set `bbsMessages` to an array with the UTF-8 encoding of each
  // non-mandatory message.
  const bbsMessages = [...mandatoryGroup.nonMatching.values()]
    .map(stringToUtf8Bytes);

  // 8. Produce reveal document using combination of mandatory and selective
  //   pointers.
  const revealDoc = selectJsonLd({document, pointers: combinedPointers});

  // 9. Canonicalize deskolemized N-Quads for the combined group to generate
  //   the canonical blank node labels a verifier will see.
  let canonicalIdMap = new Map();
  await canonicalize(
    combinedGroup.deskolemizedNQuads.join(''),
    {...options, inputFormat: 'application/n-quads', canonicalIdMap});
  // implementation-specific bnode prefix fix
  canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap);

  // 10. Produce a blank node label map from the canonical blank node labels
  //   the verifier will see to the HMAC labels.
  const verifierLabelMap = new Map();
  for(const [inputLabel, verifierLabel] of canonicalIdMap) {
    verifierLabelMap.set(verifierLabel, labelMap.get(inputLabel));
  }

  // 11. Generate BBS proof.
  const importedKey = await Bls12381Multikey.fromRaw({
    algorithm: Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256, publicKey
  });
  const {presentationHeader} = cryptosuite.options;
  const bbsProof = await importedKey.deriveProof({
    signature: bbsSignature, header: bbsHeader, messages: bbsMessages,
    presentationHeader, disclosedMessageIndexes: selectiveIndexes
  });

  // 12. Return data used by cryptosuite to disclose.
  return {
    bbsProof, labelMap: verifierLabelMap,
    mandatoryIndexes, selectiveIndexes, presentationHeader,
    revealDoc
  };
}

async function _derive({
  cryptosuite, document, purpose, proofSet,
  documentLoader, dataIntegrityProof
}) {
  // find matching base `proof` in `proofSet`
  const {options: {proofId}} = cryptosuite;
  const baseProof = await _findProof({proofId, proofSet, dataIntegrityProof});

  // ensure `purpose` matches `baseProof`
  if(baseProof.proofPurpose !== purpose.term) {
    throw new Error(
      'Base proof purpose does not match purpose for derived proof.');
  }

  // generate data for disclosure
  const {
    bbsProof, labelMap,
    mandatoryIndexes, selectiveIndexes, presentationHeader,
    revealDoc
  } = await _createDisclosureData(
    {cryptosuite, document, proof: baseProof, documentLoader});

  // create new disclosure proof
  const newProof = {...baseProof};
  newProof.proofValue = await serializeDisclosureProofValue({
    bbsProof, labelMap, mandatoryIndexes, selectiveIndexes,
    presentationHeader
  });

  // attach proof to reveal doc w/o context
  delete newProof['@context'];
  revealDoc.proof = newProof;
  return revealDoc;
}

async function _findProof({proofId, proofSet, dataIntegrityProof}) {
  let proof;
  if(proofId) {
    proof = proofSet.find(p => p.id === proofId);
  } else {
    // no `proofId` given, so see if a single matching proof exists
    for(const p of proofSet) {
      if(await dataIntegrityProof.matchProof({proof: p})) {
        if(proof) {
          // already matched
          throw new Error(
            'Multiple matching proofs; a "proofId" must be specified.');
        }
        proof = p;
      }
    }
  }
  if(!proof) {
    throw new Error(
      'No matching base proof found from which to derive a disclosure proof.');
  }
  return proof;
}

function _throwDeriveUsageError() {
  throw new Error('This cryptosuite must only be used with "derive".');
}
