# Lean Crypto Library

The leancrypto library is a cryptographic library that exclusively contains
only PQC-resistant cryptographic algorithms. It is lean in every of its
properties listed in the following:

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
  stripping,

* performance: provide optimized code invoked with minimal overhead,

* testable: all algorithm implementations are directly accessible via their
  data structures at runtime, and

* side-channel-resistant: A valgrind-based dynamic side channel analysis is
  applied to find time-variant code paths based on secret data.

## Status

Type                  | Service               | Status
---                   | ---                   | ---
Linux User Space      | GitHub                | [![Linux user space CI](https://github.com/smuellerDD/leancrypto/actions/workflows/userspace-test.yml/badge.svg)](https://github.com/smuellerDD/leancrypto/actions/workflows/userspace-test.yml)
Linux Kernel Space    | GitHub                | [![Build Status Linux Kernel Space](https://github.com/smuellerDD/leancrypto/actions/workflows/linux-kernelspace-test.yml/badge.svg?branch=master)](https://github.com/smuellerDD/leancrypto/actions/workflows/linux-kernelspace-test.yml)
macOS User Space      | GitHub                | [![Build Status macOS User Space](https://github.com/smuellerDD/leancrypto/actions/workflows/macos-test.yml/badge.svg?branch=master)](https://github.com/smuellerDD/leancrypto/actions/workflows/macos-test.yml)
Small Stack           | GitHub                | [![Build Status Small Stack](https://github.com/smuellerDD/leancrypto/actions/workflows/small-stack-test.yml/badge.svg?branch=master)](https://github.com/smuellerDD/leancrypto/actions/workflows/small-stack-test.yml)
ASAN Address Check    | GitHub                | [![Build Status ASAN Address](https://github.com/smuellerDD/leancrypto/actions/workflows/asan-address-test.yml/badge.svg?branch=master)](https://github.com/smuellerDD/leancrypto/actions/workflows/asan-address-test.yml)
CodeQL Scan           | GitHub                | [![CodeQL](https://github.com/smuellerDD/leancrypto/actions/workflows/codeql.yml/badge.svg?branch=master)](https://github.com/smuellerDD/leancrypto/actions/workflows/codeql.yml)
Codacy Scan           | GitHub                | [![Codacy](https://github.com/smuellerDD/leancrypto/actions/workflows/codacy.yml/badge.svg?branch=master)](https://github.com/smuellerDD/leancrypto/actions/workflows/codacy.yml)
Windows User Space    | GitHub                | [![Windows user space CI](https://github.com/smuellerDD/leancrypto/actions/workflows/windows-test.yml/badge.svg?branch=master)](https://github.com/smuellerDD/leancrypto/actions/workflows/windows-test.yml)
Side-Channel Analysis | GitHub                | [![Side-Channels](https://github.com/smuellerDD/leancrypto/actions/workflows/timecop.yml/badge.svg?branch=master)](https://github.com/smuellerDD/leancrypto/actions/workflows/timecop.yml)
Static Code Analysis | GitHub                | [![Static Code Analysis](https://github.com/smuellerDD/leancrypto/actions/workflows/clang-scan.yml/badge.svg?branch=master)](https://github.com/smuellerDD/leancrypto/actions/workflows/clang-scan.yml)

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

For more details, see `linux_kernel/README.md`.

## Library Build for EFI Environment

The `leancrypto` library is designed to run without any dependencies and thus
can be used in environments like (U)EFI. To compile it for the EFI environment,
configure the compilation with the following command:

```
meson setup build -Defi=enabled -Dpkcs7_generator=disabled -Dx509_generator=disabled
meson compile -C build
meson compile -C build pkcs7_trust_tester.efi
```

The PKCS#7 message generator and X.509 certificate generator are assumed to be
not required and thus use POSIX service functions that are not available in EFI.

The compilation uses the [GNU-EFI](https://wiki.osdev.org/GNU-EFI) environment
and generates:

1. The static library `leancrypto.a` that could be bound into an EFI
   application compiled externally to the build environment.

2. A test application in `build/efi/tests/pkcs7_trust_tester.efi` which is
   statically linked with `leancrypto.a` and implements the test
   "PKCS7 Trust Validation - PKCS#7 with trust chain" from
   `asn1/tests/meson.build`. This application is a UEFI application:
   
   ```
   $ file ./build/efi/tests/pkcs7_trust_tester.efi
   ./build/efi/tests/pkcs7_trust_tester.efi: PE32+ executable for EFI (application), x86-64 (stripped to external PDB), 7 sections
   ```
   
Naturally, all other options offered by the meson build enviornment can be
toggled for EFI support as well allowing `leancrypto` to be configured to
implement the exact algorithms required.

When programming with `leancrypto` in the EFI environment, the following
considerations must be applied:

* Only stack support is currently provided. All memory allocations using heap
  will fail with `ENOMEM` as an appropriate implementation of `free` and
  `posix_memalign` is not available in `internal/api/ext_headers.h`. If you want
  heap support, feel free to provide patches for these functions.
  
* The API specified by the header files installed as part of the
  `meson install -C build` command for the user space library is applicable to
  the EFI environment as well.

## Library Build for Windows

The `leancrypto` library can be built on Windows using
[MSYS2](https://www.msys2.org/). Once `MSYS2` is installed along with `meson`
and the `mingw` compiler, the standard compilation procedure outlined above
for `meson` can be used.

The support for full assembler acceleration is enabled.

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

## Library Build Using Profile Guided Optimization

Using profile guided optimization with GCC is a two phase operation. First,
et up `leancrypto` with profile measurements enabled and compile it.

```
meson setup build -Db_pgo=generate
meson compile -C build
```

Then execute the test environment with the regression test suite to create
representative input:

```
meson test -C build --suite regression
```

Once that is done the compiler flags are changed to use the generated
nformation and rebuild.

```
meson configure build -Db_pgo=use
meson compile -C build
```

Note, it is possible that for some source code files, no profiling data is
creeated due to them not being excercised in the test. This should be ignored
as the affected code is either auxiliary code or test code.

After these steps the resulting `leancrypto` library binary is fully optimized.

# Cryptographic Algorithms

Leancrypto offers various cryptographic algorithms:

* Authenticated Encryption with Associated Data

  * Ascon 128 AEAD and Ascon 128a AEAD

  * Ascon Keccak 256, and 512 AEAD, full specification provided with `aead/doc/Ascon-Keccak.pdf`

  * cSHAKE-based AEAD algorithm - algorithm devised with leancrypto,
    full specification provided with `aead/doc/KMAC_cSHAKE_AEAD_algorithm.pdf`

  * hash-based AEAD algorithm -  algorithm devised with leancrypto,
    see `hash_crypt.c` for full specification

  * KMAC-based AEAD algorithm - algorithm devised with leancrypto,
    full specification provided with `aead/doc/KMAC_cSHAKE_AEAD_algorithm.pdf`

  * AES-based AEAD algorithm using SHA2 - see `symhmac_crypt.c` for full
    specification

  * AES-based AEAD algorithm using Keccak-based KMAC - see `symkmac_crypt.c` for
    full specification

* Pseudo Random Number Generators

  * XDRBG using either SHAKE-256 or Ascon-128 providing either 256 bits or 128 bits cryptographic strength respectively - see `drng/doc/ToSC2024_1_01.pdf` for full specification and proof

  * cSHAKE-based PRNG - see `cshake_drng.c` for full specification - it complies with the XDRBG specification given in `drng/doc/ToSC2024_1_01.pdf`

  * KMAC-based PRNG - see `kmac_drng.c` for full specification - it complies with the XDRBG specification given in `drng/doc/ToSC2024_1_01.pdf`

  * SHAKE-based PRNG

  * SP800-90A Hash and HMAC DRBG

  * ChaCha20-based PRNG - see https://www.chronox.de/lrng for specification

* Message Digest algorithms

  * SHA2-256, SHA2-512

  * SHA3-224, SHA3-256, SHA3-384, SHA3-512

  * SHAKE-128, SHAKE-256

  * cSHAKE-128, cSHAKE-256

  * Ascon 128 / 128a

  * Ascon XOF / XOFa

* Keyed Message Digest algorithms

  * HMAC

  * KMAC

* Key Derivation Functions

  * HKDF

  * SP800-108 KDF (counter, feedback, double pipelining mode)

  * PBKDF2

* Key Encapsulation Mechanism

  * ML-KEM (Kyber) Key Encapsulation Mechanism (KEM)

  * ML-KEM (Kyber) Key Exchange Mechanism (KEX)

  * ML-KEM (Kyber) Integrated Encryption Schema (IES) - algorithm devised with
    leancrypto, see `kyber_ies.c` for full specification

  * ML-KEM (Kyber) hybrid KEM / KEX with Curve25519

  * BIKE Key Encapsulation Mechanism (KEM)

* One-Time Password (OTP) algorithms

  * HMAC-based One-Time Password Algorithm (HOTP)

  * Time-based One-Time Password Algorithm  (TOTP)

* Signature algorithms

  * ML-DSA (Dilithium)

  * ML-DSA (Dilithium) hybrid signature operation with Curve25519

  * SLH-DSA (Sphincs Plus)

* Symmetric algorithms

  * AES: ECB, CBC, CTR, KW

  * ChaCha20

# API Documentation

The complete API documentation is provided in the different header files
`lc_*.h`.

The Doxygen documentation is automatically compiled if the Doxygen binary is
found during the compilation run.

The various header files contain data structures which are provided
solely for the purpose that appropriate memory on stack can be allocated.
These data structures do not constitute an API in the sense that calling
applications should access member variables directly. If access to member
variables is desired, proper accessor functions are available. This implies
that changes to the data structures in newer versions of the library are not
considered as API changes!

## X.509 and PKCS#7 Support

The library offers an X.509 and PKCS#7 support with `lc_x509_parser.h`,
`lc_x509_generator.h`, `lc_pkcs7_parser.h`, and `lc_pkcs7_generator.h`.

X.509 support includes:

* X.509 parsing

* X.509 generation

The operations are offered via APIs as well as via the `lc_x509_generator`
application.

The following services are offered with the PKCS#7 support:

* Parsing PKCS#7 messages:

    - Signature verification

    - Enforcement of key usage / EKU, time stamps

    - Certificate chain validation

    - Trust store handling

* Generating PKCS#7 messages:

    - Signature generation

    - Certificate chain

The operations are offered via APIs as well as via the `lc_pkcs7_generator`
application.

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
module `leancrypto.ko` followed by insmoding all remaining kernel modules found
in the `linux_kernel` directory and review the kernel log via `dmesg`. After
completion of testing, these modules can be removed.

## Memory Leak Testing

Using valgrind, the memory leak testing can be applied. Valgrind shows no
leaks possible for any code path.

For the Linux kernel, kmemleak can be applied showing no leaks during test
execution.

## ASAN Testing

Using ASAN address testing with the help of meson, no issues were identified.

Similarly, KASAN can be used for the same type of testing inside the Linux
kernel where no issues were identified.

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

The testing covered the following platforms:

- x86_64 systems: Intel Tiger Lake i7, Intel Alder Lake i7, Intel Meteor Lake Ultra 7, AMD Ryzen 9 5950X

- RISC-V system: SiFive Unmatched board with U74 SiFive Freedom U740 SoC

- ARMv7: NXP Cortex-A7 i.MX6ULZ

- ARMv8: Apple M2, Broadcom BCM2711, Broadcom BCM2712

The test harness is available at https://github.com/smuellerDD/acvpparser
covering all algorithm implementations of algorithms that are testable.

## Version 0.6.0

- [A3770 non-accelerated C cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36380)

- [A3771 AVX2 accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36381)

- [A3772 4-way SIMD accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36382)

- [A3773 AVX512 accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36383)

- [A3774 AES-NI accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36384)

- [A3775 RISC-V assembler cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36385)

- [A3776 ARMv8 assembler cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36386)

- [A3777 ARMv8 Crypto Extensions cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36387)

- [A3778 ARMv7 NEON cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=36388)

## Version 0.7.0

- [A4405 non-accelerated C cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37015)

- [A4409 AVX2 accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37019)

- [A4410 4-way SIMD accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37020)

- [A4413 AVX512 accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37023)

- [A4411 AES-NI accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37021)

- [A4408 RISC-V assembler cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37018)

- [A4407 ARMv8 assembler cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37017)

- [A4412 ARMv8 Crypto Extensions cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37022)

- [A4406 ARMv7 NEON cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37016)

## Version 0.8.0

- [A4850 non-accelerated C cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37460)

- [A4866 AVX2 accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37476)

- [A4867 Intel 4-way SIMD accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37477)

- [A4864 AVX512 accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37474)

- [A4865 AES-NI accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37475)

- [A4851 RISC-V assembler cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37461)

- [A4852 ARMv8 assembler cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37462)

- [A4853 ARMv8 Crypto Extensions cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37463)

- [A4854 ARMv8 2-way SIMD accelerated cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37464)

- [A4860 ARMv7 NEON cipher implementations](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?validation=37470)

## Version 1.0.0

[CAVP Certificates](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search?searchMode=implementation&product=leancrypto&productType=-1&dateFrom=08%2F13%2F2024&ipp=25)

## Version 1.0.1

[CAVP certificates](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search?searchMode=implementation&product=leancrypto&productType=-1&dateFrom=08%2F15%2F2024&dateTo=08%2F17%2F2024&ipp=25)

## Version 1.1.0

[CAVP Certificates](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search?searchMode=implementation&product=leancrypto&productType=-1&dateFrom=10%2F15%2F2024&dateTo=10%2F24%2F2024&ipp=25)

# Author

Stephan Müller <smueller@chronox.de>
