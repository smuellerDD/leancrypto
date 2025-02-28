# Leancrypto and FIPS 140

Leancrypto intends to implement all FIPS 140 requirements, albeit sometimes in its own ways. This document gives an overview of the FIPS 140 compliance.

## Status

The following status regarding FIPS 140 compliance is achieved:

* leancrypto compiled as ELF binary (e.g. Linux): fully FIPS 140 compliant

* other binary types (e.g. Apple, Windows, EFI): FIPS 140 compliance achieved for all aspects except the integrity test. See section [Integrity Test](#Integrity-Test) for details.

## General Approach

The `leancrypto` library always is compiled as a FIPS 140 module. To achieve that, it is compiled into two binaries:

1. `leancrypto-fips.[so|a]` contains the FIPS 140 compliant code, all FIPS-approved algorithms and defines the FIPS 140 physical / logical boundary. This means that this library forms the "FIPS module".

2. `leancrypto.[so|a]` contains the full leancrypto code base including the FIPS 140 code and FIPS-non-approved algorithms.

When a caller wants to request services from the FIPS module, the caller MUST link to `leancrypto-fips`.

The compilation provides both libraries to allow developers to choose even at startup time of the consuming application whether the FIPS module version of leancrypto is used. Both are API-identical with the exception that the `leancrypto-fips` only contains FIPS-approved algorithms and activates FIPS-approved functionality.

NOTE: Due to time constraints, the Linux kernel variant is not split up into FIPS-approved and -non-approved code. Albeit technically it is simple to ensure the Linux kernel variant of leancrypto compiles the FIPS module, this is not yet offered.

## Available Services

Leancrypto allows the de-selection of algorithms at compile time with the various `meson` options. This is also allowed for the FIPS-approved version of leancrypto.

When de-selecting algorithms at compile time, the respective services are reduced by this set of services.

## List of Cryptographic Algorithms

Leancrypto offers approved cryptographic algorithms as defined by the [ACVP-Proxy definition](https://github.com/smuellerDD/acvpproxy/blob/master/lib/module_implementations/definition_impl_leancrypto.c). This definition also covers all implementations of the cryptographic algorithm.

NOTE: The reference of "C" implementations in the ACVP Proxy may be a bit deceiving for ML-KEM and ML-DSA as for some platforms, assembler accelerations are natively used by the C code (ARMv7 and RISCV). Yet, the reference is correct as the caller interacts with the implementation that does not require specific CPU instructions.

NOTE2: The referenced ACVP proxy definitions explicitly exclude SHA LDT tests. This is *only* due to the fact that for the release testing of leancrypto, some test systems do not have more than 1GB of RAM which means that a linear buffer of 1GB or more cannot be allocated. There is *no* cryptographic limitation in leancrypto preventing the testing of LDT test vectors. Thus, if your platform has more RAM, you SHOULD enable the LDT testing.

## Service Indicator

The `leancrypto-fips` FIPS module implements a global service indicator. This implies that all algorithms are FIPS-approved and the fact that the FIPS module is active is the indicator that FIPS-approved services are available.

## Cryptographic Algorithm Self Test

Each cryptographic algorithm has its own power-up self test which is executed before this algorithm is used for the first time.

The caller may trigger a complete new round of self tests, i.e. all algorithms will perform a new self test before the next use, when using the API of `lc_rerun_selftests`.

When a self-test fails, `leancrypto-fips` aborts and terminates itself as well as the calling application.

Leancrypto provides multiple implementations of one algorithm. Furthermore, it contains a "selector" heuristic which selects the fastest implementation at the time when using the algorithm at runtime. This heuristic depends on the detection of CPU mechanisms required by the accelerated algorithm implementations. Considering that on one given CPU (i.e. execution environment) the heuristic will always select the same algorithm, the self test is executed only once for the selected implementation.

## Integrity Test

NOTE: The integrity test is only supported for ELF binaries only so far. To change that, perform the following steps:

* Create a suitable replacement for `fips_integrity_checker.c` and compile it (search for "FIPS 140 Integrity check" in the `internal/src/meson.build`).

* If applicable, add the required compilation options for `libleancrypto-fips` in the main meson.build (search for "FIPS 140 Integrity check").

The integrity test uses SHA3-256. Due to the architecture of leancrypto, the selected message digest is executed after its self test is performed.

### ELF Binary Integrity Test

The FIPS 140 integrity test on the `leancrypto-fips` library instance is implemented as follows but only for the `libleancrypto-fips.[so|a]` variants.

First, a `libleancrypto-real.a` is compiled which contains all FIPS approved algorithm code, the self tests and auxiliary code required to comply with all FIPS requirements. The only exception is the file `fips_integrity_checker.c` which contains the constructor starting up the integrity test and the integrity check control values.

The `libleancrypto-real.a` is linked together with `fips_integrity_checker_elf.c` into `libleancrypto-fips.[so|a]` using the linker script `fips_integrity_check.ld`. This linker script adds a start and end pointers for the text and rodata ELF segments. Both segments contains all code and readonly data (e.g. self test data) from `libleancrypto-real.a` and the `fips_integrity_checker_elf.c`, i.e. all FIPS module code / data. The only exception is the integrity check control value which are placed into a different section. This approach now allows to calculate the integrity of the text and rodata segments by the start/end pointers added by the linker script and adjust the integrity control values after compilation.

The following ELF sections are covered by the integrity check in their entirety:

* .init section (covering the constructors)

* .text section (covering the entire code)

* .rodata section (covering the constant data) is currently not covered due to technical limitations - it is not required to be covered as this section contains the self-test values as well as the static data for the algorithms. Considering that each algorithm is subject to a power-on test before first use and the fact that the .text section is covered by an integrity test, the consistency of the .rodata section is implicitly verified by the self-tests.

The sizes of the sections covered by the integrity check can be shown by invoking the command `leancrypto-fips-raw-generator` that is created during compile time. When invoking it, it reports that the used integrity check values are wrong followed by the used start/end pointers of the sections and their length. The lengths can be compared to the sizes reported by `readelf -WS libleancrypto-fips.so`. The sizes reported by the `leancrypto-fips-raw-generator` tool may be a bit larger than the real segment sizes because the start/end markers of the sections encapsulate the section meta data.

## Pairwise Consistency Test

The PCT is automatically enabled for the following algorithms:

* ML-KEM

* hybrid ML-KEM - only the ML-KEM key pair generation

* ML-DSA

* hybrid ML-DSA - only the ML-DSA key pair generation

* SLH-DSA

* ED25519

## Initialization

Leancrypto utilizes the "constructor" functionality from the underlying platform to automatically perform initialization operations at startup time before the consuming application can interact with leancrypto. This constructor usage is defined with the macro `LC_CONSTRUCTOR`.

For environments where no constructor is offered, such as the EFI environment or the Linux kernel, the function `lc_init` is provided. This function must be registered such that it is triggered during load time of the library before a consumer can use the services offered by leancrypto. For example, the Linux kernel code `linux_kernel/leancrypto_kernel.c` which would be part of a FIPS module invokes `lc_init` automatically during loading of the `leancrypto.ko` kernel module.

## Random Number Generator and Entropy Source

Leancrypto offers a fully seeded RNG instance that can readily be used everywhere where a FIPS-approved random number generator is required by using `lc_seeded_rng`.

Leancrypto does not implement any entropy source. Yet, it implements support for several entropy sources that can be selected at compile time:

* `builtin`: This option uses the underlying operating system's default entropy sources as implemented in `drng/src/seeded_rng_*.c` such as the `getrandom` system call on Linux or `getentropy` system call on BSD / macOS.

* `cpu`: This option uses the CPU entropy sources as implemented in `drng/src/es_cpu`, such as RDSEED on Intel x86 systems. This option is the default when compiling leancrypto for the EFI environment.

* `esdm`: This option uses the [ESDM](http://chronox.de/esdm/index.html) as entropy source.

NOTE: The default RNG used by leancrypto is the XDRBG. At the time of writing (beginning 2025), it is not yet FIPS-approved. However, SP800-90A is subject to revision at the time of writing and it is planned to add the XDRBG as an approved algorithm. Therefore, leancrypto selects XDRBG as default. If that shall be changed, the macros `LC_SEEDED_RNG_CTX_SIZE` and `LC_SEEDED_RNG_CTX` found in `drng/src/seeded_rng.c` must be set to either the Hash DRBG or HMAC DRBG at compile time.

## API and Usage Documentation

The documentation of the API as well as the usage of leancrypto, including the FIPS module variant, is provided with Doxygen. Either the [online version](https://leancrypto.org/leancrypto/doxygen/html/index.html) is used or Doxygen is present during compile time to automatically generate the guidance out of the source code. The resulting documentation is found in `<meson-build-directory>/doc`.

## ACVP Testing

ACVP-Testing is provided with the [ACVP-Parser](https://github.com/smuellerDD/acvpparser). This parser offers the testing of the user space as well as the kernel space variant of leancrypto.

The mentioned ACVP-Parser was used to obtain all certificates listed on the [leancrypto CAVP website](https://leancrypto.org/leancrypto/cavp_certificates).

## Random Notes

ECDH 25519 is compiled as part of the FIPS module, but is non-approved. This is considered acceptable because the algorithm is not available via an API. Instead, the algorithm is used as part of the hybrid ML-KEM which use it as follows: Hybrid ML-KEM performs an SP800-108 KDF (KMAC256) using the concatenated output of ML-KEM and ECDH 25519 to generate the final shared secret. This is approved as per SP800-56C rev 2 chapter 2.
