# AGENTS.md

## Repoitory Overview

The leancrypto code contains different modules which are encapsulated into different directories.

The following modules are present:

* `aead`: Implements AEAD symmetric algorithms.

* `apps`: Applications provided with leancrypto

* `asn1`: ASN.1, X.509 and PKCS#7/CMS code

* `bike`: Code-based PQC algorithm of BIKE

* `build-scripts`: Scripts with pre-defined compile-time options

* `curve25519`: Curve25519 implementation including EdDSA and ECDH

* `curve448`: Curve448 implementation including EdDSA and ECDH

* `doc`: Doxygen generator

* `drng`: Deterministic random number generator including the seeded_rng implemenation with its link code to entropy sources.

* `efi`: Compilation support for EFI environment

* `hash`: hash implemenations of SHA2, SHA3, Ascon, Poly1305

* `hmac`: HMAC implementation

* `hqc`: Code-based PQC algorithm of HQC

* `internal`: Support code

* `kdf`: Different key derivation functions

* `kmac`: SP800-185 KMAC

* `linux_kernel`: Linux kernel compilation support and code to register leancrypto with the kernel crypto API

* `ml-dsa`: FIPS 204 ML-DSA PQC algorithm

* `ml-kem`: FIPS 203 ML-KEM PQC algorithm

* `otp`: One-Time-Pad algorithms

* `rust`: Rust wrapper to make the leancrypto API available to Rust

* `rustls`: rustls provider using leancrypto

* `slh-dsa`: FIPS 205 SLH-DSA algorithm

* `sym`: symmetric encryption algorithms with their block chaining modes

## Module Directories

The individual module directories have a common structure:

* `api`: Header files used in other parts of leancrypto or defining official APIs

* `doc`: Algorithm specifications

* `src`: Actual implementation

* `tests`: Unit tests for the implementation

## Before making changes

- Read the relevant source code and existing tests before proposing changes.

- Do not make unrelated refactors.

- Prefer existing abstractions over introducing new ones.

- Apply the coding rules in `coding-guidelines.md`

## Automated checks

Before completing a review, inspect the results of:

- `meson test -C build --suite regression`

## Code Review

When reviewing a change or pull request:

1. Read `code-review.md`

2. Inspect the complete diff, not just changed items.

3. Track changed behavior into its callers and consumers.

4. Check tests for the changed behavior.

5. Look for security, correctness, compatibility, and data-integrity issues.

6. Report only actionable findings supported by evidence.

Do not report:

- stylistic preferences already enforced by tooling

- hypothetical problems without a plausible execution path

- issues unrelated to the change

### Review Output

- **Severity** Critical / High / Medium / Low

- **Confidence level** High / Medium / Low

- **Location** file and line

- **Problem** concise description

- **Impact** what can happen

- **Evidence** concrete failure scenario

- **Recommendation** suggested fix, when appropriate

Order findings by severity.

Do not report more than one finding for the same underlying defect.

### Summary

After findings, provide:

- what was reviewed

- what validation was performed

- any remaining uncertainty

If there are no actionable findings, explicitly state: "No actionable findings."
