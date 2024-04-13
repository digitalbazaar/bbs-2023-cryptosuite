/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';

export const requiredAlgorithm = [
  Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256,
  'Bls12381G2'
];
