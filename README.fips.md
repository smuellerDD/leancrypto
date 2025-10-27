# Leancrypto and FIPS 140

Leancrypto intends to implement all FIPS 140 requirements, albeit sometimes in its own ways. This document gives an overview of the FIPS 140 compliance.

## Status

The following status regarding FIPS 140 compliance is achieved:

* leancrypto compiled as ELF binary (e.g. Linux): fully FIPS 140 compliant

* other binary types (e.g. Apple, Windows, EFI): FIPS 140 compliance achieved for all aspects except the integrity test. See section [Integrity Test](#Integrity-Test) for details.

## General Approach

The `leancrypto` library always is compiled as a FIPS 140 module. To achieve that, it is compiled into two binaries:

1. `leancrypto-fips.[so|a]` contains the FIPS 140 compliant code, as well as all approved and non-approved algorithms. It defines the FIPS 140 physical / logical boundary. This means that this library forms the "FIPS module".

2. `leancrypto.[so|a]` contains the identical implementatino to `leancrypto-fips` with the exception that the integrity test is not present.

When a caller wants to request services from the FIPS module, the caller MUST link to `leancrypto-fips`.

The compilation provides both libraries to allow developers to choose even at startup time of the consuming application whether the FIPS module version of leancrypto is used. Both are ABI and API-identical.

## Available Services

Leancrypto allows the de-selection of algorithms at compile time with the various `meson` options. This is also allowed for the FIPS-approved version of leancrypto.

When de-selecting algorithms at compile time, the respective services are reduced by this set of services.

## List of Cryptographic Algorithms

Leancrypto offers approved cryptographic algorithms as defined by the [ACVP-Proxy definition](https://github.com/smuellerDD/acvpproxy/blob/master/lib/module_implementations/definition_impl_leancrypto.c). This definition also covers all implementations of the cryptographic algorithm.

NOTE: The reference of "C" implementations in the ACVP Proxy may be a bit deceiving for ML-KEM and ML-DSA as for some platforms, assembler accelerations are natively used by the C code (ARMv7 and RISCV). Yet, the reference is correct as the caller interacts with the implementation that does not require specific CPU instructions.

NOTE2: The referenced ACVP proxy definitions explicitly exclude SHA LDT tests. This is **only** due to the fact that for the release testing of leancrypto, some test systems do not have more than 1GB of RAM which means that a linear buffer of 1GB or more cannot be allocated. There is *no* cryptographic limitation in leancrypto preventing the testing of LDT test vectors. Thus, if your platform has more RAM, you SHOULD enable the LDT testing.

## Service Indicator

The `leancrypto-fips` FIPS module implements a service indicator accessible with the API `lc_alg_status` where its input may be provided by the different calls of `lc_[aead|drng|hash|sym]_algorithm_type` and `lc_[aead|drng|hash|sym]_ctx_algorithm_type` or by specifying an algorithm type as documented for this API. The latter APIs allow the caller to obtain the service indicator for services that are provided by APIs offering a common interface for different algorithms. For APIs that only offer one algorithm / service, the `lc_alg_status` shall be used directly.

The API of `lc_status` provides the version information along with the status whether the FIPS mode is active. The information about the enabled FIPS mode can be obtained programmatically with the API call of `lc_alg_status(LC_ALG_STATUS_LIB)`.

## Cryptographic Algorithm Self Test and Degraded Mode

Each cryptographic algorithm has its own power-up self test which is executed before this algorithm is used for the first time.

When a self-test fails, the offending algorithm is marked with a failed self test and all self tests for all other algorithms are triggered again. These new self tests execute only once the algorithm is used again. Thus, the `leancrypto-fips.so` enters a degraded mode of operation.

The precise steps of entering are:

1. The error indicator for the offending algorithm is set (which is consistent with entering the error state),

2. Trigger a (lazy) re-running of all algorithm CASTs (which is consistent with staying in the error state), and

3. Disabling the offending algorithm for further use, but leaving other algorithms unaffected (entering the degraded mode).

The caller may trigger a complete new round of self tests, i.e. all algorithms will perform a new self test before the next use, when using the API of `lc_rerun_selftests` and `lc_rerun_one_selftest`. These APIs trigger the exit from degraded mode. In FIPS mode, they trigger the re-execution of the integrity tests as well as the re-running of the known-answer tests for the specified algorithms. As the re-execution of the integrity test requires the gating of the module operation, all algorithms are first set into a failure state, followed by the integrity test, followed by setting the algorithm into a pending state triggering all self tests once again.

To re-perform the integrity test, the API `lc_fips_integrity_checker` is provided.

The status of the passed/failed self-tests is visible with the interfaces documented as part of [Service Indicator](#Service Indicator).

Leancrypto provides multiple implementations of one algorithm. Furthermore, it contains a "selector" heuristic which selects the fastest implementation at the time when using the algorithm at runtime. This heuristic depends on the detection of CPU mechanisms required by the accelerated algorithm implementations. Considering that on one given CPU (i.e. execution environment) the heuristic will always select the same algorithm, the self test is executed only once for the selected implementation.

## Integrity Test

The `leancrypto-fips.so` performs an integrity test using SHA3-256 at startup triggered by a constructor. If that check fails, the library aborts.

NOTE: The integrity test is only supported for ELF binaries only so far. To change that, perform the following steps:

* Create a suitable replacement for `fips_integrity_checker.c` and compile it (search for "FIPS 140 Integrity check" in the `internal/src/meson.build`).

* If applicable, add the required compilation options for `libleancrypto-fips` in the main meson.build (search for "FIPS 140 Integrity check").

The integrity test uses SHA3-256. Due to the architecture of leancrypto, the selected message digest is executed after its self test is performed.

### ELF Binary Integrity Test

The FIPS 140 integrity test on the `leancrypto-fips` library instance is implemented as follows but only for the `libleancrypto-fips.so` variant.

This is achieved with the following approach:

1. The `leancrypto-fips.so` library is build for the target platform. This contains a "placeholder" bit string in the ELF section `fips_integrity_data`.

2. A build-host executable derived from the leancrypto `sha3-256sum` is compiled.

3. The external tool of `objcopy` is used to extract the ELF sections subject to integrity test from `leancrypto-fips.so` using the script `addon/fips_integrity_checker_elf_generator.sh`.

4. The aforementioned script uses the build-host executable instance of `sha3-256sum` to generate a message digest of the extracted ELF sections.

5. The mentioned script uses `objcopy` to insert the newly generated digest into the ELF section `.lc_fips_integrity_data` of `leancrypto-fips.so` replacing the "placeholder" value found there.

The following ELF sections are covered by the integrity check in their entirety:

* .init section (covering the initialization steps)

* .lc_fips_rodata section

* .text section (covering the entire code - note, some static data provided with assembler files is also placed into the text section)

## Pairwise Consistency Test

The PCT is automatically enabled for the following algorithms:

* ML-KEM

* composite ML-KEM - only the ML-KEM key pair generation

* ML-DSA

* composite ML-DSA - only the ML-DSA key pair generation

* SLH-DSA

* ED25519

* ED448

## Initialization

Leancrypto utilizes the "constructor" functionality from the underlying platform to automatically perform initialization operations at startup time before the consuming application can interact with leancrypto. This constructor usage is defined with the macro `LC_CONSTRUCTOR`.

For environments where no constructor is offered, such as the EFI environment or the Linux kernel, the function `lc_init` is provided. This function must be registered such that it is triggered during load time of the library before a consumer can use the services offered by leancrypto. For example, the Linux kernel code `linux_kernel/leancrypto_kernel.c` which would be part of a FIPS module invokes `lc_init` automatically during loading of the `leancrypto.ko` kernel module.

NOTE: As the `lc_init` function is only useful in environments without constructor support (i.e. excluding the Linux user space) and knowing that the Linux user space currently only supports an integrity test, `lc_init` will not trigger an integrity test.

## Random Number Generator and Entropy Source

Leancrypto offers a fully seeded RNG instance that can readily be used everywhere where a FIPS-approved random number generator is required by using `lc_seeded_rng`.

Leancrypto does not implement any entropy source. Yet, it implements support for several entropy sources that can be selected at compile time:

* `builtin`: This option uses the underlying operating system's default entropy sources as implemented in `drng/src/seeded_rng_*.c` such as the `getrandom` system call on Linux or `getentropy` system call on BSD / macOS.

* `cpu`: This option uses the CPU entropy sources as implemented in `drng/src/es_cpu`, such as RDSEED on Intel x86 systems. This option is the default when compiling leancrypto for the EFI environment.

* `esdm`: This option uses the [ESDM](http://chronox.de/esdm/index.html) as entropy source.

* `jent`: This option uses the [Jitter RNG](http://chronox.de/jent/index.html) as entropy source.

NOTE: The default deterministic random number generator used by leancrypto (and thus by `lc_seeded_rng`) is the XDRBG-256. At the time of writing (September 2025), it is not yet FIPS-approved. However, SP800-90A is subject to revision at the time of writing and it is planned to add the XDRBG as an approved algorithm. Therefore, leancrypto selects XDRBG as default. If that shall be changed, the macros `LC_SEEDED_RNG_CTX_SIZE` and `LC_SEEDED_RNG_CTX` found in `drng/src/seeded_rng.c` must be set to either the Hash DRBG or HMAC DRBG at compile time.

## API and Usage Documentation

The documentation of the API as well as the usage of leancrypto, including the FIPS module variant, is provided with Doxygen. Either the [online version](https://leancrypto.org/leancrypto/doxygen/html/index.html) is used or Doxygen is present during compile time to automatically generate the guidance out of the source code. The resulting documentation is found in `<meson-build-directory>/doc`.

## ACVP Testing

ACVP-Testing is provided with the [ACVP-Parser](https://github.com/smuellerDD/acvpparser). This parser offers the testing of the user space as well as the kernel space variant of leancrypto.

The mentioned ACVP-Parser was used to obtain all certificates listed on the [leancrypto CAVP website](https://leancrypto.org/leancrypto/cavp_certificates).

## Functional Verification Testing

The functional verification testing is provided with the regression testing offered by the Meson build environment as well as with the Linux kernel compilation.

For Meson, execute `meson test -C build --suite regression`.

For the Linux kernel, execute: `for i in *.ko; do insmod $i; done`.

## Negative Testing

The Meson test framework offers also negative testing of:

* Failing of all power-up self tests

* Verification of health test status

The negative testing is performed with the following commands:

```
meson setup build -Dfips140_negative=enabled
meson compile -C build
meson test -C build --suite regression
```

NOTE: All tests which are marked with an `OK` during the `meson test` run are designed to cover the negative testing. All negative tests verify:

1. All CASTs are modified to fail. The tests verify that the CASTs fail.

2. Upon failure of the CASTs, each test verifies that the respective algorithm(s) triggered the failure have their service indicator set to the failure mode (i.e. verification of entering the degraded mode).

3. The `rerun_selftests_tester` verifies the negative behavior of FIPS integrity testing. It tests whether:
  a) immediately after initialization the library status is in error state,
  
  b) checking that in this error state the algorithms are in error state and thus not usable (all servies using cryptographic algorithms are unavailable),
  
  c) the invocation of a cryptographic service fails with the expected error code, and
  
  d) triggering a rerun of the self tests and verify that the library remains in error state.

## Random Notes

ECDH 25519 and ECDH 448 is compiled as part of the FIPS module, but is non-approved. This is considered acceptable because the algorithm is not available via an API. Instead, the algorithm is used as part of the hybrid ML-KEM which use it as follows: Hybrid ML-KEM performs an SP800-108 KDF (KMAC256) using the concatenated output of ML-KEM and ECDH 25519 to generate the final shared secret. This is approved as per SP800-56C rev 2 chapter 2.
