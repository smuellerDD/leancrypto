Changes 0.10.0

* enhancement: add Sponge APIs

* enhancement: add Ascon Keccak 256/512 and 256/256

* update AEAD: add lc_aead_enc|dec_init and change all AEAD algo's tag calculation to now perform MAC(AAD || ciphertext) instead of MAC(ciphertext || AAD) - this brings it in line with all AEAD algorithms

* enhancement: add Ascon AEAD 128 and 128b

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
