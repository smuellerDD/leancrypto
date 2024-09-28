Changes 1.1.0-prerelease
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
