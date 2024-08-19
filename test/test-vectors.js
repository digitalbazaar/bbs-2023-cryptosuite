/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
/* Note: This file contains data generated from the vc-di-bbs specification
test vectors. */

/* eslint-disable max-len */
/* eslint-disable quote-props */
/* eslint-disable quotes */
export const keyMaterial = {
  // eslint-disable-next-line quotes
  "publicKeyHex": "a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f",
  "privateKeyHex": "66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0",
  "hmacKeyString": "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
};

// public key above converted to multikey format + controller doc:
export const publicKey = {
  '@context': 'https://w3id.org/security/multikey/v1',
  id: 'did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ',
  type: 'Multikey',
  controller: 'did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ',
  publicKeyMultibase: 'zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ'
};
export const controllerDoc = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/multikey/v1'
  ],
  id: publicKey.controller,
  assertionMethod: [publicKey]
};

export const signedSDBase = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    {
      "@vocab": "https://windsurf.grotto-networking.com/selective#"
    }
  ],
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "https://vc.example/windsurf/racecommittee",
  "credentialSubject": {
    "sailNumber": "Earth101",
    "sails": [
      {
        "size": 5.5,
        "sailName": "Kihei",
        "year": 2023
      },
      {
        "size": 6.1,
        "sailName": "Lahaina",
        "year": 2023
      },
      {
        "size": 7,
        "sailName": "Lahaina",
        "year": 2020
      },
      {
        "size": 7.8,
        "sailName": "Lahaina",
        "year": 2023
      }
    ],
    "boards": [
      {
        "boardName": "CompFoil170",
        "brand": "Wailea",
        "year": 2022
      },
      {
        "boardName": "Kanaha Custom",
        "brand": "Wailea",
        "year": 2019
      }
    ]
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "bbs-2023",
    "created": "2023-08-15T23:36:38Z",
    "verificationMethod": "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
    "proofPurpose": "assertionMethod",
    "proofValue": "u2V0ChVhQgzH1WtRY_lwyJCCyy4BvmiDqayuKKdUXEAJtcazl2ggAZLSIgY78daQ5UlvQMUUIIqajMtp4GSbhk2C5AWZDESTvzz0GD7x1DGEixxTAf3FYQDpbvyXTTZCxjDXNI1e-am9CMB6U_J5S936Tt3PFYUvfVV3gX4mIF-MTAbrBh9DD_ysD4svbSttNVowX3pYfmhhYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-FZy9pc3N1ZXJ4HS9jcmVkZW50aWFsU3ViamVjdC9zYWlsTnVtYmVyeBovY3JlZGVudGlhbFN1YmplY3Qvc2FpbHMvMXggL2NyZWRlbnRpYWxTdWJqZWN0L2JvYXJkcy8wL3llYXJ4Gi9jcmVkZW50aWFsU3ViamVjdC9zYWlscy8y"
  }
};

export const derivedRevealDocument = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    {
      "@vocab": "https://windsurf.grotto-networking.com/selective#"
    }
  ],
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "https://vc.example/windsurf/racecommittee",
  "credentialSubject": {
    "sailNumber": "Earth101",
    "sails": [
      {
        "size": 6.1,
        "sailName": "Lahaina",
        "year": 2023
      },
      {
        "size": 7,
        "sailName": "Lahaina",
        "year": 2020
      }
    ],
    "boards": [
      {
        "year": 2022,
        "boardName": "CompFoil170",
        "brand": "Wailea"
      },
      {
        "boardName": "Kanaha Custom",
        "brand": "Wailea",
        "year": 2019
      }
    ]
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "bbs-2023",
    "created": "2023-08-15T23:36:38Z",
    "verificationMethod": "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
    "proofPurpose": "assertionMethod",
    "proofValue": "u2V0DhVkCEJgxugaFJpT7ROtWzZ9mWBMw2Uk2caOtXtKGEMJVDFv9psrafLrzfprwyHOk7GgTv4V9U5VDvEW6E0n-MjO0RvbEYZDECqhFbZgxLtdTXDAD46d691Ltb37hYt9OOKJorYfMWhD_ONzGYzgQ4IrFqA2s_m597DymX7HauNGw2iK48mBAI4xwC4MQ3pLJwuwRiy3msMzccvvdMynM97xymCnoSS0KeW9uCRMYhPb90N-AKNXvjwXZqpgXhyWYxWQhUm2-XbQFhs0rg6RUZS9xY35XkXq9IvRbtn1I_OvfVGRnGuwuhF-H-HwdDrk02z-54jENSD1nEQtfZBJ4J4iOjNklnqePZoMYTKTnGEW4A9k6NVT0V3cW-Tm9NvJut0B3G9XDUkfvSrwrDnAXIabo7fYqY686Ay34lc3gbQsVyowadQckkRj50Jb8xaP5o57BqHDvYZ76avYf2Tt0uCskMX3vWfmB_I7CtWM9jrhxGxCFUre250hkhQP-zfUqwKduyokwY2EmLMR2e7uE6QTRp1I7wZ1nvFAceJSWFr72VHCwZ_gXWdmin5wndcCIikYXtXAY7OER5izYNltHg_vlO87IRr9yS93cGW_O0FxZw167c1rqmoPw5SM825-7j9LjsAfuf2nK_DfEmT3fx0fXeTtI6kghMVS0WSYMKdpt1B3pU5ozUoVa-jmLK6_UfQfXZaYAAgEEAgMDBwQGBQCOAAECBQYICQoODxAREhOGAwQFCAkKRBEzd6o"
  }
};
/* eslint-enable quotes */
/* eslint-enable quote-props */
/* eslint-enable max-len */
