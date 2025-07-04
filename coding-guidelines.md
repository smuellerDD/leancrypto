# Code Structure

Due to the fact that leancrypto is compiled for many different execution environments, the compilation process must consider the specifics of each target execution environment. The leancrypto code implements target-specific code in independent source code files. Depending on the target environment, the source code files are or are not compiled.

## Modules

The leancrypto code contains different modules which are encapsulated into different directories.

The following modules are present:

* `aead`: Implements AEAD symmetric algorithms.

* `apps`: Applications provided with leancrypto

* `asn1`: ASN.1, X.509 and PKCS#7/CMS code

* `bike`: Code-based PQC algorithm of BIKE

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

* `slh-dsa`: FIPS 205 SLH-DSA algorithm

* `sym`: symmetric encryption algorithms with their block chaining modes

## Module Directories

The individual module directories have a common structure:

* `api`: Header files used in other parts of leancrypto or defining official APIs

* `doc`: Algorithm specifications

* `src`: Actual implementation

* `tests`: Unit tests for the implementation

## Coding Guidelines

Code changes should follow these guidelines:

* KNF code format (use `addon/clang-format-helper.sh`)

* All externally visible symbols are prefixed with `lc_`.

* All externally visible macros are prefixed with `LC_`.

* All header files defining external APIs must have a name starting with `lc_` and cannot include internal header files.

* Ifdef's in the C code should be reduced to an absolute minimum. Conditional compilation is defined by the build environment. If a C file that can be conditionally compiled provides services to other C files, the associated header file shall contain ifdef'ed NOOP functions.
