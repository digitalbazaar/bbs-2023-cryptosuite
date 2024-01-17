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
    "proofValue": "u2V0ChdhAWFCKn4dlQY9B3YMaAmVMTmD8bAcksNKyWcHAUF3Oh5chgdWwBLehP7jXMgyinO5h0H4D3s0RxzgDksDTqyXaI3B8BoqHsUQp7Z-Fjis2xIp_DthAWEA6W78l002QsYw1zSNXvmpvQjAelPyeUvd-k7dzxWFL36jkBckYFrsZd9sl_H-Bd6z6zLefgh7YBaRV5oVfM0te2EBYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj9hAWCAAESIzRFVmd4iZqrvM3e7_ABEiM0RVZneImaq7zN3u_4R4HS9jcmVkZW50aWFsU3ViamVjdC9zYWlsTnVtYmVyeBovY3JlZGVudGlhbFN1YmplY3Qvc2FpbHMvMXggL2NyZWRlbnRpYWxTdWJqZWN0L2JvYXJkcy8wL3llYXJ4Gi9jcmVkZW50aWFsU3ViamVjdC9zYWlscy8y"
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
    "proofValue": "u2V0DhdhAWQIQpfdWUrAhGTOffbGNFoN9ABqtEpgN2K2DsTEEEWkhb8LbeDm4Ac9K-Pw3ZkS6F6Dfk6NoLdOiElhEB093vHndQFWSkS6qWE1Y1fCwl39YPK3hnjWVI7T4o_Cm7ky9TFfTktJ-g3Czll_YIeyRYkdJ5i4CFBR0IlWvJ9TqoHNezMHG8ZeOgw5g_hnTMzKoZDkSMeRr8jVjwz84QpicLEz00SEFYUqsx_5vul1gy_afkJlVqIHDHuDw8F8xIdoO68mrdIDQAidoTfz43uAJetv8S2odynGrMMvnTh9UQHzME3E9UmtfN_YWvn--8RTzFqWwFzdThg7_iMnMaDRX5onQ6sVa4ihmDda8VZTos_6YWbtK5Dhe4wFqTwc9-uXE5jvTJ1U3a66V_QcFkWhYHJ1YPxMATUtHAxEwIIRowrUkBNYRVYE-4JU9tEl03lTEmFy_K4ucM-_UN1LrwzyK9toa_CcMfOgm8ZUlv2iRVb4JKwcjQ8tUlXBEUUms9J0DKEiibjzgBhFjSg01r24-j2Ibv06vCyH7mk9bLkchxQn4ZImntT8i7hwi4QSxrd9at9AdJa4qeV6Q95Nrckmj8QvmOVx81JY7ok1Co8VFmMHrFExVjfZhTQ1PVG_jK_Wae-qNzC5ITr-hx0uNw2AuWyjs81XeDDCyilODKQIMOpLX3_j71E_0SZcWppvVFlOQY0YApgACAQQCBwMGBAUFAI0AAQIFBgcICQoLDQ4PhgMECAsMDdhARBEzd6o"
  }
};
/* eslint-enable quotes */
/* eslint-enable quote-props */
/* eslint-enable max-len */
