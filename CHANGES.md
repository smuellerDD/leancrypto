Changes 1.6.0-prerelease
* ASN.1: use stack for small generator for small use cases

* X.509: Updates required to support the shim boot loader

* X.509: add lc_gmtime to convert Epoch to time format

* ASN.1: added to Linux kernel

* AES-GCM added

* AES-XTS added

* Availability: remove assert() calls throughout the code - in case of a self test error, disable the algorithm. Instead of using assert, apply a centrally managed test manager that stores the test status. This implies that some initalization APIs like lc_hash_init, lc_sym_init, lc_hmac_init are changed such that they return an error code if self tests failed. Thus, the version is now changed as this is considered to be an ABI change. Although this sounds heavy, the test manager is relatively small and the runtime state should be smaller than the old approach considering the old approach uses one global 32 bit integer per self test to maintain the state. This is now replaced with a set of 32 bit atomic integers that hold a 3-bit field for each algorithm. This change also adds the API call of lc_rerun_one_selftest which allows triggering the reruning of a self test for one given algorithm.

* FIPS: Rearchitect integrity test control value generator: The build process now uses the host's objcopy to extract the ELF sections of interest into a separate file, use a build_machine compiled version of sha3-256sum to generate the digest of it and reinsert it into the leancrypto-fips.so. This now allows cross-compilation with FIPS integrity test support. There is no functional change to leancrypto though.

Changes 1.5.1
* add ChaCha20 Poly 1305 AEAD

* ChaCha20: add ARMv8 NEON, ARMv7 Neon, Intel AVX2, Intel AVX512, RISCV RVV/ZBB implementations

* RISC-V entropy source: make implementation consistent to spec

* Unify stack memory allocation

Changes 1.5.0
* Enable SHA3 CE 2x implementation for SLH-DSA and ML-DSA (performance increases 2 to 3 fold)

* Fix lookup of RDRAND support in CPUID

* Catch Y2038 issue on 32-bit systems that do not have 64 bit time_t support

* Start Python interface

* Add ED448 / X448 for use in hybrid PQC constructions, ED448 implementation verified with NIST ACVP

* Add ML-KEM-X448 and ML-DSA-ED448 support

* ASN.1: Add ML-DSA-ED448 certificate support

* RUST: Add ML-DSA-ED448 support

* Linux kernel: Add ML-KEM-X448 and ML-DSA-ED448 support

* Ascon AEAD: Bug fix when calculating the tag for plaintext that is not multiples of 128 bits

* Composite X.509 signatures: update implementation to match draft revision 5

* Add support for the Linux kernel updated scatterwalk API in 6.15 for leancrypto_kernel_aead_ascon.ko 

Changes 1.4.0
* ML-DSA: add signature generation rejection test cases and enable them during self tests

* add HQC following reference implementation (https://pqc-hqc.org/implementation.html (versions from 2025-02-19)) but derived from PQClean implementation. NOTE: HQC is not yet considered stable as the implementation currently does not exhibit the IND-CCA2 property. Moreover, the FIPS standardization of HQC is pending. Changes to the HQC algorithm until standardization will need to be expected. I.e. the versioning rules of the library do not apply to the HQC algorithm until being announced in the CHANGES.md file.

* ARMv8: properly save/restore SIMD registers v8 through v15 for ML-DSA/ML-KEM, X25519 and SHA3-CE (reported by Alexander Sosedkin)

* Rust: add wrapper allowing a native interaction with the leancrypto library - the API offered by the Rust wrappers is not yet defined to be stable and may change to the next version - i.e. the versioning rules of the library do not apply to the Rust API until being announced in the CHANGES.md file.

* Add "secure_execution" compile-time option

* Add HQC AVX2 implementation derived from https://pqc-hqc.org/

Changes 1.3.0
* Allow CPU entropy sources to be used as seed sources with meson option "seedsource=cpu"

* Ensure full clean run on vintage system without AVX2 (thanks to "David C. Rankin" <drankinatty@gmail.com>)

* EFI: compilation support on AARCH64 

* Meson: reduce number of object files to speed up compilation process

* Intel assembler: add endbr[64|32] to every function and ensure IBT is enabled

* ARMv8 assembler / ELF: add BTI and PAC support

* *Full FIPS 140 compliance*: Invoke PCT, add integrity test for ELF compilations, enable FIPS compilation by default

* ML-DSA: add external-mu support; new API: lc_dilithium_ctx_external_mu

* Add optional Jitter RNG entropy source

* Add SLH-DSA-Ascon-128[s|f]  (by default they are disabled, enable with meson configuration options `slh_dsa_ascon_128s` and `slh_dsa_ascon_128f`)

* ML-KEM: use common poly_tobytes / poly_compress including fix for kyberslash for ARMv8 (thus all ML-KEM implementations have proper protections against it)

* ML-KEM: reduce code duplication

* Big-Endian: fixes on X.509 key usage processing, ML-KEM modulus tester

Changes 1.2.0
* Locking für seeded_rng added to avoid requiring the caller providing a lock

* Addition of ASN.1 decoder, X.509 parser, PKCS#7 / CMS parser

* Addition of ASN.1 encoder, X.509 generator, PKCS#7 / CMS generator for ML-DSA, SLH-DSA, ML-DSA-ED25519

* ML-DSA-ED25519: Hybrid implementation changed to match definition https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html

* RISCV64: Keccak - add assembler and ZBB implementation

* RISCV64: ML-KEM - add assembler implementation

* RISCV64: ML-DSA - add assembler implementation

* Add FIPS 140 mode (as of now, it does not yet implement full FIPS 140 compliance)

* Ascon AEAD, Hash, XOF, Ascon-Keccak: Update to comply with SP800-232

* Dilithium AVX2: Add side channel analysis

* leancrypto passes X.509 IETF-Hackathon tests: https://ietf-hackathon.github.io/pqc-certificates/pqc_hackathon_results_certs_r4_automated_tests.html

* Add compilation support for (U)EFI environment

* RISCV64 RVV: ML-KEM, ML-DSA - add assembler implementation using RVV support

* Seeded DRNG: Require a reseed after 2**14 bytes to comply with AIS20/31 3.0 DRG.4 and the discussed upcoming changes to SP800-90A.

* SHA-512 / 384 / 256: Addition of AVX2, SHA_NI, SHA_NI-512, ARMv8 Neon, ARMv8 CE, RISCV ASM, RISCV ZBB acceleration

* Add lc_init API

* Intel non-AVX2 systems: remove all SIGILL causes by ensuring no AVX2 code is executed

* Linux kernel: support version 6.13 kernel crypto signature API

* Allow switching the central leancrypto seeded RNG instance with a caller-provided RNG

* ML-KEM: fix poly_frombytes to perform the loading operation modulo 3329 (instead of modulo 4096) - thanks to Daiki Ueno for reporting it

Changes 1.1.0
* ML-KEM remove modulus check of decapsulation key (not required by FIPS 203)

* ML-KEM: add key pair PCT API - leancrypto cannot invoke it itself as it does not know when both keys are provided from outside

* ML-DSA: add consistency with FIPS 204 - the signature changes as the input data handling is added (if you want to apply the old signature, use the new lc_dilithium_[sign|verify]_ctx API with ctx->ml_dsa_internal = 1)

* ML-DSA: add API to allow caller to provide a user context as allowed by FIPS 204, to invoke ML-DSA.Sign_internal, ML-DSA.Verify_internal and HashML-DSA

* ML-KEM: rename source code directory to ml-kem

* ML-DSA: rename source code directory to ml-dsa

* BIKE: Add NIST round 4 KEM candiate

* ML-DSA: Add support to retain the expanded key to increase the performance of signature operations by 15 to 20%

* ML-DSA: add key pair PCT API - leancrypto will not invoke it, but provides it for FIPS 140 support

* SLH-DSA: Add SLH-DSA-SHAKE-256s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-128f

* ML-DSA, ML-KEM, SLH-DSA, BIKE, Hash, AEAD, RNG, HMAC, HKDF, symmetric: move API implementation from H to C file - this implies that no RUST wrappers are needed

* Linux kernel: ML-DSA / SLH-DSA sigver input changed to be compliant to existing kernel structures: req->src SGL contains signature || msg, req->dst SGL is not processed

Changes 1.0.1

* fix: Kyber keygen - add LC_KYBER_K to initial hash (change is only relevant when storing keys as seed and for interoperability)

* fix: Dilithium keygen - add dimensions K and L (change is only relevant when storing keys as seed and for interoperability)

* small performance improvements for hasher apps

Changes 1.0.0

* enhancement: add Doxygen support - it is automatically compiled if Doxygen is present

* enhancement: add Dilithium-ED25519 stream mode operation (i.e. init/update/final)

* due to the Dilithium-ED25519 stream mode support, the Dilithium-ED25519 now used ED25519ph signature algorithm mode

* Dilithium API change: the stream mode uses struct lc_dilithium_ctx instead of lc_hash_ctx to reflect the newly added Dilithium-ED25519 API - the lc_dilithium_ctx can be allocated on the stack or heap using LC_DILITHIUM_CTX_ON_STACK or lc_dilithium_ctx_alloc

* enhancement: add Dilithium-ED25519 as Linux kernel akcipher algorithm

* enhancement: make Kyber-X25519 as Linux kernel kpp algorithm consistent with the standalone Kyber kpp implementation and add a tester

* seeded_rng: when using the ESDM as entropy source, use DRBG without prediction resistance. When having heavy respawning of applications, using the PR DRBG will strain the entropy source significantly.

* Dilithium: add edge case tests as referenced by https://github.com/usnistgov/ACVP/pull/1525.patch and https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/G8Zf0hC-uu0/m/Kb3qNJb0AwAJ

Changes 0.11.0

* security fix: fix possible leak of message in Kyber

* Kyber: reduce memory footprint, use common lc_memcmp_secure API

* Ascon-Keccak: include the tag length into the IV and thus implicitly authenticate the tag length (thanks to Markku-Juhani Saarinen to suggest this)

* Kyber: change standard API such that caller can select Kyber type

* Dilithium: change standard API such that caller can select Dilithium type

* security: addition of Timecop and instrumentation of tests to find side-channels

* enhancement: add Linux kernel crypto API support for Ascon / Ascon-Keccak

* fix: performance of seeded RNG by setting reseed threshold to 1MB

* fix: Linux kernel warning on return thunk

* enhancement: add ASM ARMv7 and ARMv8 implementation for X25519

* enhancement: add Ascon support for XDRBG

* enhancement: performance increase for XDRBG256

* enhancement: add ED25519ph to support Dilithium hybrid init/update/final handling

Changes 0.10.1

* enhancement: Linux kernel - Kyber: allow parallel compilation of all Kyber types including all optimizations

* enhancement: Linux kernel - Dilithium: allow parallel compilation of all Dilithium types including all optimizations

* add additional hardening compiler flags stipulated by openssf.org

Changes 0.10.0

* enhancement: add Sponge APIs

* enhancement: add Ascon Keccak 512 and 256

* update AEAD: add lc_aead_enc|dec_init and change all AEAD algo's tag calculation to now perform MAC(AAD || ciphertext) instead of MAC(ciphertext || AAD) - this brings it in line with all AEAD algorithms

* enhancement: add Ascon AEAD 128 and 128b

* rename API lc_shake to lc_xof

* enhancement: add Ascon Hash 128 and 128a

* enhancement: add Ascon XOF and XOFa

* enhancement: add Ascon 128/128a hasher apps

* large data tests can now execute on small systems by using smaller memory sizes

* remove riscv64 hash assembler directory: it is a duplicate of the riscv32 assembler code

* Kyber 768: Add AVX2, ARMv8, ARMv7 support

* Dilithium 65: Add AVX2, ARMv8, ARMv7 support

* Enable compilation of Kyber 1024, Kyber-768 and Kyber-512 at the same time (APIs starting with lc_kyber_768/lc_kex_768 refer to Kyber-768, APIs starting with lc_kyber_512/lc_kex_512 refer to Kyber-512, all others refer to Kyber-1024)

* Enable compilation of Dilithium 87, Dilithium-65 and Dilithium-44 at the same time (APIs starting with lc_dilithium_65 refer to Dilithium-768, APIs starting with lc_dilithium_44 refer to Dilithium-44, all others refer to Dilithium-87)

* enhancement: Windows is now supported as target platform using the MINGW compiler with full acceleration support

* Dilithium: update SampleInBall implementation following https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/y8ul-ZcVWI4 - implementation is fully checked against NIST ACVP Demo server

Changes 0.9.2

* fix: update "reduce memory footprint of Keccak state" to handle big-endian systems

* enhancement: Seed the lc_seeded_rng with (random.c || Jitter RNG)

Changes 0.9.1

* fix: move XOR-256 memory definitions to lc_memory_support.h as otherwise compilation of external applications and libraries fail due to missing xor256.h

Changes 0.9.0

* enhancement: X/ED25519: enable 128 bit mode on Intel for both, kernel and user
  space

* add Rust binding support

* enhancement: reduce memory footprint of Keccak state

* enhancement: add cSHAKE re-init support

* fix: KMAC-AEAD / cSHAKE-AEAD - ensure proper re-initialization

* enhancement: add RISC-V 64 bit Keccak - currently disabled due to a bug

* enhancement: compile Dilithium ARMv8 support in Linux kernel (excluding the SIMD Keccak operation)

* fix: fix ARM-CE detection logic

* fix: potential Kyber side channel

* fix: KMAC min MAC size is 32 bits

* enhancement: use accelerated XOR for KMAC/cSHAKE AEAD

* fix: enable poly_compress_avx for Linux kernel compilation when GCC >= 13 is present

* enhancement: add interface code to register leancrypto with Linux kernel crypto API

Changes 0.8.0:

* enhancement: add applications

* enhancement: add Dilithium ARMv8 support (including SHAKE 2x ARMv8 support)

* enhancement: add Dilithium ARMv7 support

* enhancement: add Kyber ARMv7 support

* reduce memory footprint of Dilithium and Kyber

* enhancement: Add Kyber-X25519 KEM, KEX, and IES

* enhancement: Add Dilithium-ED25519

* hardening: use -fzero-call-used-regs=used-gpr if available to counter ROP
  attacks

* fix: Add fork-detection for seeded_rng

* update XDRBG256 implementation based on latest draft

Changes 0.7.0:

* enhancement: add XDRBG256 - the SHAKE256-based DRNG discussed for SP800-90A
  inclusion (almost idential to cSHAKE/KMAC DRNG specified with leancrypto)

* enhancement: add SymKMAC AEAD algorithm - it uses 100 bytes less context than
  SymHMAC (it is less than 1024 bytes now), uses accelerated Keccak for KDF and
  authentication but is otherwise identical to SymHMAC

* Kyber: switch responder and initiator definitions

* enhancement: add ESDM seed source to seed lc_seeded_rng

* editorial: reformat code using clang-format and provided configuration file

* Dilithium: Update implementation to match FIPS 204 (draft from Aug 24, 2023)

* Kyber: Update implementation to match FIPS 203 (draft from Aug 24, 2023)

* enhancement: Dilithium and Kyber security strengths are selectable via Meson options

* Kyber KEM: Update shared secret KDF (as the KDF is now removed from FIPS 203,
  it can be adjusted to be more performant and consistent with SP800-108)

* Kyber KEX: Updated shared secret KDF to use SP800-108 compliant KMAC KDF

* enhancement: Add input parameter validatino to Kyber as specified in FIPS 203

* enhancement: consolidate all testing requiring an RNG to use selftest_rng

Changes 0.6.0:

* enhancement: Linux - add memfd_secret(2) support for secure memory allocation

* fix: documentation of lc_kyber_keypair

* enhancement: remove the rng_ctx parameter in all Kyber APIs except the key
  generation - internally lc_seeded_rng is used instead

* enhancement: use -Wmissing-prototypes and fix reported issues

* enhancement: provide standalone CBC, CTR, KW implementation

* enhancement: provide AESNI implementation

* enhancement: provide AES ARM CE implementation

* enhancement: provide AES RISC-V 64 assembler implementation

* enhancement: provide Linux kernel configuration option to enable startup
  health tests

* fix: apply fixes such that all self tests and regression tests pass when compiled for Linux kernel

* fix: properly zeroize memory when using the workspace memory

Changes 0.5.3:

* convert to safe min/max implementations

* enhancement: allow kernel modules to be compiled directly from installed user space headers

* enhancement: make ARMv8 code compile on macOS

- use O3 compiler optimization instead of Os - O3 is significantly faster especially for Kyber C implementation, yet both options work fine

Changes 0.5.2
* enhancement: add ARMv7 Neon assembler support for Keccak

* enhancement: add but disable ARMv8 Neon assembler support for Keccak (it is
  slower than optimized C)

* enhancement: add sign/update/final Dilithium APIs

* enhancement: add RISC-V assembler support for Keccak (yet disabled)

* enhancement: add ARMv8 assembler implementation of Kyber

* enhancement: add counter KDF RNG interface

* enhancement: add ARMv8 assembler and ARMv8 CE Keccak support

Changes 0.5.1:
* enhancement: add Linux kernel configuration options

* enhancement: add lc_rerun_selftests API

* enhancement: add AVX2 support for memcmp_secure

* fix: some comments

Changes 0.5.0:
* enhancement: add ability to compile leancrypto for the Linux kernel including
  all tests

* enhancement: make leancrypto generic such that it can be used in environments
  other than user space

* enhancement: add compile time option small_stack which ensures that
  leancrypto's stack usage is always less than 2048 (also verified by the
  compiler warning if it is bigger)

* enhancement: Add assembler accelerations for SHA3 (AVX2 and AVX512 are
  verified with NIST's ACVP service)

* bug fix: Fix the SHA-3 C implementation on big-endian system (one byte-swap
  missing)

* bug fix: SHAKE128 state had wrong size causing an overflow with the
  memset_secure in lc_hash_zero

* fix: remove compile-time warnings on 32 bit systems

* enhancement: SHAKE AVX2 4x implementation used by Kyber AVX2 implementation

* enhancement: Kyber AVX2 support

* enhancement: Dilithium AVX2 support

* leancrypto tested on macOS with an M2 system

* bug fix: Dilithium C on Big Endian had implicit type casts leading to
  endianess issues

* enhancement: add RPM SPEC file - successful build on OpenSUSE build service
  on x86_64, i586, aarch64, armv7l, armv6l, ppc64, ppc64le, riscv64

* rename memset_secure to lc_memset_secure preventing any possible name space clash

* enhancement: add self tests to all algorithms

* bug fix: ChaCha20 on BigEndian systems

Changes 0.4.0:
* simplify Kyber code

* add RNG context to HKDF

* add RNG context to KMAC

* add AES 128/192/256, ECB, CBC, CTR, KW

* add lc_seeded_rng

* add lc_aead API to provide common interface to AEAD algorithms

* add KyberIES

* change API to Kyber KEM: allow caller to specify size of generated key

* add leancrypto.h for ease of use

* add SymHMAC AEAD algorithm

* add cSHAKE 128

* add KMAC 128

Changes 0.3.0:
* Introduce lc_rng.h as a common interface to the random number generators

* add KMAC DRNG

* add cSHAKE DRNG

* add SHAKE-128

* add dilithium signature PQC schema - test vectors were generated by leancrypto, but compared with the reference implementation which calculate the same results

* add kyber KEM PQC schema - test vectors were generated by leancrypto, but compared with the reference implementation which calculate the same results

* add cSHAKE AEAD cipher

* KMAC-AEAD cipher: auth key is now set to 256 bits
