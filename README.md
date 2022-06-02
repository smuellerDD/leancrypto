# Lean Crypto Library

This crypto library provides algorithm implementations which have the following
properties:

* minimal dependencies: only POSIX environment needed

* extractable: the algorithms can be extracted and compiled as part of a
  separate project

* stack-only support: all algorithms can be allocated on stack if needed. In
  addition, allocation functions for a usage on heap is also supported.

The following subsections outline the different cryptographic algorithm support.

## Library Build

If you want to build the leancrypto shared library, use the provided `Meson`
build system:

1. Setup: `meson setup builddir`

2. Compile: `meson compile -C builddir`

3. Test: `meson test -C builddir`

4. Install: `meson install -C builddir`

## Hash

The following header files contain an implementation of `struct hash` which
can be used to perform the respective hashing operations. You only need to
include the following header files depending on the selected hash operation.

* `sha256.h` provides the object `sha256` of type `struct hash`

* `sha512.h` provides the object `sha512` of type `struct hash`

* `sha3.h` provides the objects `sha3_256`, `sha3_384`, `sha3_512`, `shake`,
  and `cshake` of type `struct hash`

The mentioned hash object have to be used with the hash API as documented in
`hash.h`. It is sufficient to only include the object-specific header files
as they include `hash.h`.

See `hash.h` for the API documentation.

## HMAC

The HMAC implementation is a wrapper to the hash. Thus include your chosen
hash header file as outlined in section [Hash] along with `hmac.h`. You must
provide a reference to the hash object to the allocation functions of HMAC.
The HMAC API functions ensure that the hash context is allocated appropriately
and that the hash functions are invoked accordingly.

The HMAC API is documented in `hmac.h`.

## SP800-90A DRBG

The DRBG implementation is a wrapper to the hash. As specific context sizes
depending on the type of chosen hash need to be defined, the DRBG takes
care of properly wrapping the hash. Thus you only need to include the
DRBG-specific header file as follows:

* `hash_drbg_sha512.h`: SP800-90A Hash DRBG with derivation function

* `hmac_drbg_sha512.h`: SP800-90A HMAC DRBG

The DRBG API is documented in `drbg.h`.

Note, if you want to copy the DRBG, copy, the base `drbg.c` and `drbg.h`. For
any HMAC DRBG, also copy `hmac_drbg.h` and `hmac_drbg.c`. For any hash DRBG,
also copy `hash_drbg.h` and `hash_drbg.c`. Finally copy the specific header
file of the desired DRBG. You only need to include this header file into your
code.

NOTE: The `drbg.c` includes the specific DRBG header file. Update it as needed.
This is considered appropriate as it is expected to only have one type of DRBG
in use.

WARNING: The implementation only provides a full deterministic DRBG
implementation. It does NOT handle proper seeding. You MUST perform the seeding!

## Hash Crypt - AEAD Algorithm

Did you know you can use hash to encrypt data?

The hash crypt implementations provide an authenticating stream cipher.

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

### KMAC Hash Crypt

The following properties are implemented with the algorithm:

* Key stream is generated using KMAC-256

* Key stream is generated with 136 byte blocks (cSHAKE 256 block size)

* Key stream is XORed with the plaintext (encryption) or ciphertext
  (decryption)

* AEAD authentication is provided with KMAC-256 with an Encrypt-Then-MAC
  approach to integrity-protect the plaintext and ciphertext including guards
  against malleable attacks.

* The algorithm supports an arbitrary key size. The security strength is equal
  to the key size, but at most 256 bits (the strength of KMAC-256). The key is
  used to seed the KMAC instance for generating the key stream. The first step
  the freshly seeded KMAC does is to generate a 1088 bit random value that
  becomes the key for the KMAC authenticator. The goal is simply to use two
  different values for the keystream and the authenticator.

* The implementation supports the use in one-shot and in stream mode. The
  stream mode implies that repeatedly new data of arbitrary size can be inserted
  into the state. See the description [SHA-2 Hash Crypt] as the KMAC hash
  crypt follows the same principle.

# KMAC

The KMAC implementation is a wrapper to the cSHAKE hash. Include `kmac.h`.
You must provide a reference to the `cshake256` hash object to the allocation
functions of KMAC. The KMAC API functions ensure that the hash context is
allocated appropriately and that the hash functions are invoked accordingly.

The KMAC API is documented in `kmac.h`.

# KDF

The KDF API is documented in `kdf/api/*.h`.

# One-Time Pad

The cryptographic algorithms of HOTP and TOTP are available and documented in
`otp/api/*.h`.

# Symmetric Algorithms

The symmetric algorithm API is documented in `sym/api/lc_sym.h`.

# ACVP Testing

ACVP certificate: A770

https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=13214

# Author

Stephan Müller <smueller@chronox.de>
