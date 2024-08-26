# @digitalbazaar/bbs-2023-cryptosuite Changelog

## 2.0.1 - 2024-08-dd

### Fixed
- Use `@digitalbazaar/di-sd-primitives@3.0.4` to get latest bug fixes.

## 2.0.0 - 2024-08-19

### Changed
- **BREAKING**: Use `@digitalbazaar/bls12-381-multikey@2` which is
  interoperable with IETF BBS draft 6 and no longer interoperable with
  any previous versions (the previous versions should be considered
  obsolete).

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
