# Lean Crypto Library

The leancrypto library is a cryptographic library that exclusively contains
only PQC-resistant cryptographic algorithms. The algorithm implementations
have the following properties:

* minimal dependencies: only minimal POSIX environment needed - function calls
  are abstracted into helper code that may need to be replaced for other
  environments (see the Linux kernel support in `linux_kernel` for replacing the
  POSIX calls)

* extractable: the algorithms can be extracted and compiled as part of a
  separate project,

* flexible: you can disable algorithms on an as-needed basis using
  `meson configure`,

* fully thread-safe when using different cipher contexts for an invocation:
  there is no global state maintained for the algorithms,

* stack-only support: all algorithms can be allocated on stack if needed. In
  addition, allocation functions for a usage on heap is also supported,

* size: minimizing footprint when statically linking by supporting dead-code
  stripping, and

* performance: provide optimized code invoked with minimal overhead, thus
  significantly faster than other libraries like OpenSSL.

## Library Build

If you want to build the leancrypto shared library, use the provided `Meson`
build system:

1. Setup: `meson setup build`

2. Compile: `meson compile -C build`

3. Test: `meson test -C build`

4. Install: `meson install -C build`

## Library Build for Linux Kernel

The leancrypto library can also be built as an independent Linux kernel module.
This kernel module offers the same APIs and functions as the user space version
of the library. This implies that a developer wanting to develop kernel and
user space users of cryptographic mechanisms do not need to adjust to a new
API.

Note: The user space and kernel space versions of leancrypto are fully
independent of each other. Neither requires the presence of the other for full
operation.

To build the leancrypto Linux kernel module, use the `Makefile` in the
directory `linux_kernel`:

1. cd `linux_kernel`

2. make

3. the leancrypto library is provided with `leancrypto.ko`

Note, the compiled test kernel modules are only provided for regression testing
and are not required for production use. Insert the kernel modules and check
`dmesg` for the results. Unload the kernel modules afterwards.

The API specified by the header files installed as part of the
`meson install -C build` command for the user space library is applicable to
the kernel module as well. When compiling kernel code, the flag `-DLINUX_KERNEL`
needs to be set.

## Library Build for Other Environments

If you need leancrypto to work in other environments like small embedded
systems, you need:

1. Adjust the build system as needed to compile and link it

2. Adjust the file `ext_headers.h` to point to the right header files and
   locations.

3. set the flag `LC_MEM_ON_HEAP` if your environment only has a limited stack
   size. When set, functions with large memory requirements use the heap
   instead of the stack for this memory. The maximum stack size used by a
   function is 2048 bytes and is verified by a compiler check.

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

Using valgrind, the memory leak testing can be applied. Valgrind shows no
leaks possible for any code path.

## ASAN Testing

Using ASAN address testing with the help of meson, no issues were identified.

## Clang Static Code Analysis

Using the clang-scan tool with the command `ninja -C build/ scan-build` shows no
issues.

## Linux Hints

Linux offers the `memfd_secret(2)` system call which would be used by
`leancrypto` for secure memory allocation, if it is available. This system call,
however, is only available when the kernel is booted with `securemem.enable=1`.
With this option enabled, according to the kernel documentation suspend is
disabled as long as one or more memory with `memfd_secret` is in use.

If the `memfd_secret` is not available, `leancrypto` will use `mlock` to
protect memory with sensitive data.

## ACVP Testing

ACVP certificates covering all ciphers and their implementations testable by NIST:

- [A3770 non-accelerated C cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36380)

- [A3771 AVX2 accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36381)

- [A3772 4-way SIMD accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36382)

- [A3773 AVX512 accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36383)

- [A3774 AES-NI accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36384)

- [A3775 RISC-V assembler cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36385)

- [A3776 ARMv8 assembler cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36386)

- [A3777 ARMv8 Crypto Extensions cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36387)

- [A3778 ARMv7 NEON cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36388)

The testing covered the following platforms:

- x86_64 systems: Intel Tiger Lake i7, Intel Alder Lake i7, AMD Ryzen 9 5950X

- RISC-V system: SiFive Unmatched board with U74 SiFive Freedom U740 SoC

- ARMv7: NXP Cortex-A7 i.MX6ULZ

- ARMv8: Apple M2, Broadcom BCM2711

The test harness is available at https://github.com/smuellerDD/acvpparser
covering all algorithm implementations of algorithms that are testable.

# Author

Stephan Müller <smueller@chronox.de>
