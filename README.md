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

# Cryptographic Algorithms

Leancrypto offers various cryptographic algorithms.

## Authenticate Encryption with Associated Data

Did you know you can use hash to encrypt data?

The hash crypt implementations provide an authenticating stream cipher.

### KMAC Crypt

Encrypt and decrypt data by using KMAC as defined in SP800-185. The
authentication of the ciphertext is performed using KMAC as well. The algorithm
is fully defined in `aead/src/kmac_crypt.c`.

The implementation supports the use in one-shot and in stream mode. The
stream mode implies that repeatedly new data of arbitrary size can be inserted
into the state. See the description [SHA-2 Hash Crypt] as the KMAC hash
crypt follows the same principle.

### cSHAKE Crypt

Encrypt and decrypt data by using cSHAKE as defined in SP800-185. The
authentication of the ciphertext is performed using KMAC as well. The algorithm
is fully defined in `aead/src/cshake_crypt.c`.

The implementation supports the use in one-shot and in stream mode. The
stream mode implies that repeatedly new data of arbitrary size can be inserted
into the state. See the description [SHA-2 Hash Crypt] as the KMAC hash
crypt follows the same principle.

### SHA-2 Hash Crypt

The following properties are implemented with the algorithm:

* Key stream is generated using the SP800-90A Hash DRBG with SHA-512 core

* Key stream is generated with 64 byte blocks

* Key stream is XORed with the plaintext (encryption) or ciphertext
  (decryption)

* AEAD authentication is provided with HMAC SHA-512 with an Encrypt-Then-MAC
  approach to integrity-protect the plaintext and ciphertext including guards
  against malleable attacks.

* The algorithm supports an arbitrary key size. The security strength is equal
  to the key size, but at most 256 bits (the strength of SHA-512). The key is
  used to seed the DRBG instance for generating the key stream. The first step
  the freshly seeded DRBG does is to generate a 512 bit random value that
  becomes the key for the HMAC authenticator. The goal is simply to use two
  different values for the keystream and the authenticator.

* The implementation supports the use in one-shot and in stream mode. The
  stream mode implies that repeatedly new data of arbitrary size can be inserted
  into the state. The following calls are equal:

	- oneshot call:
```
	lc_hc_encrypt_oneshot(Plain_1 || ... || Plain_N, Ciphertext_1 || ... || Ciphertext_N, tag);
```

	- stream operation:

```
	lc_hc_encrypt(Plain_1, Ciphertext_1);
	...
	lc_hc_encrypt(Plain_N, Ciphertext_N);
	lc_hc_encrypt_tag(tag);
```

  Similarly for decryption, the oneshot and stream modes are supported as
  follows:

	- oneshot call:
```
	lc_hc_decrypt_oneshot(Ciphertext_1 || ... || Ciphertext_N, Plain_1 || ... || Plain_N, tag);
```

	- stream operation:

```
	lc_hc_decrypt(Ciphertext_1, Output_1);
	...
	lc_hc_decrypt(Ciphertext_N, Output_N);
	if (lc_hc_decrypt_authenticate(tag) < 0)
		... authentication failed ...
	else
		... authentication succeeded ...
```

## Hash

The following header files contain an implementation of `struct hash` which
can be used to perform the respective hashing operations. You only need to
include the following header files depending on the selected hash operation.

* `lc_sha256.h` provides the object `lc_sha256` of type `struct lc_hash`

* `lc_sha512.h` provides the object `lc_sha512` of type `struct lc_hash`

* `lc_sha3.h` provides the objects `lc_sha3_256`, `lc_sha3_384`, `lc_sha3_512`,
  `lc_shake256`, `lc_shake128`, and `lc_cshake256` of type `struct lc_hash`

The mentioned hash object have to be used with the hash API as documented in
`lc_hash.h` and the aforementioned header files. It is sufficient to only
include the object-specific header files as they include `lc_hash.h`.

See `lc_hash.h` for the API documentation.

## HMAC

The HMAC implementation is a wrapper to the hash. Thus include your chosen
hash header file as outlined in section [Hash] along with `lc_hmac.h`. You must
provide a reference to the hash object to the allocation functions of HMAC.
The HMAC API functions ensure that the hash context is allocated appropriately
and that the hash functions are invoked accordingly.

The HMAC API is documented in `hmac.h`.

## KMAC

The KMAC implementation is a wrapper to the cSHAKE hash. Include `lc_kmac.h`.
You must provide a reference to the `lc_cshake256` hash object to the allocation
functions of KMAC. The KMAC API functions ensure that the hash context is
allocated appropriately and that the hash functions are invoked accordingly.

The KMAC API is documented in `lc_kmac.h`.

## KEy Exchange Mechanism

The Kyber post-quantum cryptography (PQC) algorithm for key exchange is
provided. It offers an asymmetric cryptographic algorithm.

## Random Number Generation

Leancrypto offer different random number generator implementation which all
are used with the same API documented in `lc_rng.h`. The key is that the
caller must allocate the intended RNG implementation using the RNG-specific
allocation functions documented in the different RNG header files. After
successful allocation, the common API can be used.

The following RNGs are implemented

* Hash SP800-90A DRBG without PR, using SHA-512 core.

* HMAC SP800-90A DRBG without PR, using HMAC SHA-512 core.

* cSHAE-based deterministic random number generator - the specification is
  provided with `drng/src/cshake_rng.c`. This implementation has an equal
  security as the SP800-90A DRBGs but it is significantly faster.

* KMAC-based deterministic random number generator - the specification is
  provided with `drng/src/kmac_rng.c`.  This implementation has an equal
  security as the SP800-90A DRBGs but it is significantly faster.

* ChaCha20-based deterministic random number generator.

## Key Derivation Funcation

The KDF API is documented in `kdf/api/*.h`. The following algorithms are
available:

* SP800-108 counter KDF, feedbac KDF, double-pipeline KDF.

* RFC5869 HKDF

## One-Time Pad

The cryptographic algorithms of HOTP and TOTP are available and documented in
`otp/api/*.h`.

## Signature

The Dilithium post-quantum cryptography (PQC) algorithm for digital signatures
is provided. It offers an asymmetric cryptographic algorithm.

## Symmetric Algorithms

The symmetric algorithm API is documented in `sym/api/lc_sym.h`.

# ACVP Testing

ACVP certificate: A770

https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=13214

The test harness is available at https://github.com/smuellerDD/acvpparser

# Author

Stephan Müller <smueller@chronox.de>
