# Changelog

## [0.3.0] - 2026-04-14

### Added

* X25519 interface - this is only intended to support rustls

* HKDF interface

* ED25519 interface - this is only intended to support rustls

* All getter methods are changed to return data as part of Ok()

### Changed

* API breakage: rename all getter functions to get_* (e.g. sk() -> get_sk())

## [0.2.2] - 2025-10-18

### Added

* AES-GCM

* AES-XTS

This release requires leancrypto 1.6.0.

## [0.2.1] - 2025-07-01

### Added

* ChaCha20-Poly1305

## [0.2.0] - 2025-06-26

### Added

* ML-DSA-ED448

* ML-KEM-X25519

* ML-KEM-X448

