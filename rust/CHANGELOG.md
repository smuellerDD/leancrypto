# Changelog

## [0.3.0] - 2026-04-14

This version requires leancrypto >= 1.8.0.

### Added

* X25519 interface - this is only intended to support rustls

* HKDF interface

* ED25519 interface - this is only intended to support rustls

* All getter methods are changed to return data as part of Ok()

* lcr_kyber_x25519 operation changed to provide non-KDF version usable for rustls

* PBKDF2 interface

* KBKDF interface

### Changed

* API breakage: rename all getter functions to get_* (e.g. sk() -> get_sk())

* API breakage: kyber_x25519 and kyber_x448 encapsulate and decapsulate changed - they now fill the raw shared secret buffer that must be obtained with a separate call

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

