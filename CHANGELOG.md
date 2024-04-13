# @digitalbazaar/bbs-2023-cryptosuite Changelog

## 1.2.0 - 2024-04-12

### Added
- Allow `Bls12381G2` to be specified as the signer algorithm to
  support better interop with keys that are not bound to a more
  fully specified algorithm.

## 1.1.1 - 2024-01-30

### Fixed 
- Encode `Map` objects in CBOR using the Map tag, not the object tag.

## 1.1.0 - 2024-01-17

### Added
- Support proof encodings that use CBOR tag 64 for Uint8Array instead
  of simpler major type 2 byte string.

## 1.0.0 - 2024-01-15

### Added
- Initial version.
