# @digitalbazaar/bbs-2023-cryptosuite Changelog

## 1.1.1 - 2024-01-dd

### Fixed 
- Encode `Map` objects in CBOR using the Map tag, not the object tag.

## 1.1.0 - 2024-01-17

### Added
- Support proof encodings that use CBOR tag 64 for Uint8Array instead
  of simpler major type 2 byte string.

## 1.0.0 - 2024-01-15

### Added
- Initial version.
