# Lean Crypto Library

This crypto library provides algorithm implementations which have the following
properties:

* minimal dependencies: only POSIX environment needed,

* extractable: the algorithms can be extracted and compiled as part of a
  separate project,

* stack-only support: all algorithms can be allocated on stack if needed. In
  addition, allocation functions for a usage on heap is also supported, and

* minimizing footprint when statically linking by applying dead-code stripping.

The following subsections outline the different cryptographic algorithm support.

## Library Build

If you want to build the leancrypto shared library, use the provided `Meson`
build system:

1. Setup: `meson setup builddir`

2. Compile: `meson compile -C builddir`

3. Test: `meson test -C builddir`

4. Install: `meson install -C builddir`

## Library Build for Linux Kernel

To build the leancrypto Linux kernel module, use the `Makefile` in the
directory `linux_kernel`:

1. cd `linux_kernel`

2. make

3. the leancrypto library is provided with `leancrypto.ko`

Note, the compiled test kernel module of `leancrypto_test.ko` is only provided
for regression testing and is not required for production use. Insert the
kernel module and check `dmesg` for the results. Unload the kernel module
afterwards.

## Library Build for Other Environments

If you need leancrypto to work in other environments like small embedded
systems, you need:

1. Adjust the build system as needed to compile and link it

2. Adjust the file `ext_headers.h` to point to the right header files and
   locations.

3. set the flag `LC_MEM_ON_HEAP` if your environment only has a limited stack
   size. When set, functions with large memory requirements use the heap
   instead of the stack for this memory.

An example on the approach is given with the Linux kernel support found
in the directory `linux_kernel`.

# Cryptographic Algorithms

Leancrypto offers various cryptographic algorithms:

* Authenticated Encryption with Associated Data

  * cSHAKE-based AEAD algorithm - algorithm devised with leancrypto,
    see `cshake_crypt.c` for full specification

  * hash-based AEAD algorithm -  algorithm devised with leancrypto,
    see `hash_crypt.c` for full specification

  * KMAC-based AEAD algorithm - algorithm devised with leancrypto,
    see `kmac_crypt.c` for full specification

  * AES-based AEAD algorithm - see `symhmac_crypt.c` for full specification

* Pseudo Random Number Generators

  * cSHAKE-based PRNG - see `cshake_drng.c` for full specification

  * KMAC-based PRNG - see `kmac_drng.c` for full specification

  * SP800-90A Hash and HMAC DRBG

  * ChaCha20-based PRNG - see https://www.chronox.de/lrng.html for specification

* Message Digest algorithms

  * SHA2-256, SHA2-512

  * SHA3-224, SHA3-256, SHA3-384, SHA3-512

  * SHAKE-128, SHAKE-256

  * cSHAKE-128, cSHAKE-256

* Keyed Message Digest algorithms

  * HMAC

  * KMAC

* Key Derivation Functions

  * HKDF

  * SP800-108 KDF (counter, feedback, double pipelining mode)

  * PBKDF2

* Key Encapsulation Mechanism

  * Kyber Key Encapsulation Mechanism (KEM)

  * Kyber Key Exchange Mechanism (KEX)

  * Kyber Integrated Encryption Schema (IES) - algorithm devised with
    leancrypto, see `kyber_ies.c` for full specification

* One Time Pad algorithms

  * HOTP

  * TOTP

* Signature algorithm

  * Dilithium

* Symmetric algorithms

  * AES: ECB, CBC, CTR, KW

  * ChaCha20

# API Documentation

The complete API documentation is provided in the different header files
`lc_*.h`.

# Testing

## Functional Testing

The command `meson test -C build` performs a full regression testing of all
algorithms and all code paths.

When using the code coverage analysis support enabled by
`meson setup build -Db_coverage=true` followed by `meson test -C build` and
`ninja coverage-html -C build`, it is shown that almost all code paths in the
library are covered (the test code contains error code paths which are not
all tested, naturally).

To perform testing of the Linux kernel module of leancrypto, insmod the
module `leancrypto_test.ko` and review the kernel log via `dmesg`. Once the
test is complete, the test kernel module can be removed from the kernel.

## Memory Leak Testing

Using valgrind, the memory leak testing can be applied. Valgrind shows now
leaks possible for any code path.

## ASAN Testing

Using ASAN address testing, some issues were reported which were all assessed
to not present a security hazard. If you still have ideas how to fix all ASAN
reports, please file a bug report.

## Clang Static Code Analysis

Using the clan-scan tool with the command `ninja -C build/ scan-build` shows no
issues.

## ACVP Testing

ACVP certificate: A770

https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=13214

The test harness is available at https://github.com/smuellerDD/acvpparser

All algorithms were tested with NIST's ACVP service without obtaining an
official certificate. Currently not tested: ARMv8 Neon (pending).

# Author

Stephan Müller <smueller@chronox.de>
