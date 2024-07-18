# Leancrypto for the Linux Kernel

The leancrypto library is intended to provide the identical services for user
space as well as Linux kernel space. This shall allow developers to only have
one crypto provider which they need to maintain and learn to develop with.

The user space and kernel space versions of leancrypto are fully
independent of each other. Neither requires the presence of the other for full
operation.

Leancrypto therefore can be compiled into a separate Linux kernel module
called `leancrypto.ko`.

## Building

In the current directory, the support for building the leancrypto library is
provided. To build the leancrypto Linux kernel module, use the `Makefile` in the
directory `linux_kernel`:

1. make

2. the leancrypto library is provided with `leancrypto.ko`

## Test Modules

In addition to the `leancrypto.ko` kernel module, a large number of additional
kernel modules are compiled. They are all test modules for regression testing
and are not required and even not intended for production use. Insert the kernel
modules and check `dmesg` for the results. Unload the kernel modules afterwards.

The test modules almost all are the user space test application the `meson`
test framework uses too, but compiled into kernel modules. They invoke the
`leancrypto` API to demonstrate that the identical code is supported in user
as well as user space.

In addition to the standard leancrypto test code, the following test modules
are provided to validate the leancrypto integration into the kernel crypto API:

* `leancrypto_kernel_aead_ascon_tester.ko` invokes the Linux kernel crypto API
  of type `skcipher` to perform a Ascon and Ascon-Keccak encryption / decryption
  operation.

* `leancrypto_kernel_ascon_tester.ko` invokes the Linux kernel crypto API
  of type `shash` to perform a Ascon 128 and Ascon 128a message digest
  calculation.

* `leancrypto_kernel_dilithium_tester.ko` invokes the Linux kernel crypto API
  of type `akcipher` to perform a FIPS 204 (CRYSTALS Dilithium) signature
  generation and verification.

* `leancrypto_kernel_kmac_tester.ko` invokes the Linux kernel crypto API type
  `shash` to invoke KMAC256 XOF, a keyed message digest using FIPS 202 defined
  in SP800-185.

* `leancrypto_kernel_kyber_tester.ko` tests the Linux kernel crypto API type
  `kpp` to invoke FIPS 203 (CRYSTALS Kyber) key generation, encapsulation and
  decapsulation.

* `leancrypto_kernel_rng_tester.ko` invokes the Linux kernel crypto API type
  `rng` to utilize the XDRBG256 deterministic random number generator.

* `leancrypto_kernel_sha3_tester.ko` performs the testing of leancrypto's
  SHA-3 implementation which is registered as a `shash`.

## Leancrypto Registered with the Linux Kernel Crypto API

The `leancrypto.ko` offers its own API interface as discussed above. In
addition, it registers a subset of algorithms with the kernel crypto API to
allow other kernel users, that already use the kernel crypto API for its
purposes, to use the algorithms of the leancrypto library without further
changes. All algorithms adhere to the kernel crypto API standards and should
be usable out of the box.

For the CRYSTALS Kyber support, some special precautions need to be applied
considering that there are two modes of operation a user must be aware of:
acting as an Initiator or a Responder of a Kyber key agreement. This
consideration is identical to the one that needs to be applied for
(EC)Diffie-Hellman. The following listing enumerates the call sequence the
user must apply for the given mode. The following sequences for both, the
initiator and the responder is implemented in `leancrypto_kernel_kyber_tester.c`
as a reference.

* Acting as Initiator of a Kyber KEM operation:

	1. Generate new keypair: `crypto_kpp_set_secret(tfm, NULL, 0);`
	   Note, it is permissible to also set an externally-provided key here.

	2. Get public key:
		`crypto_kpp_generate_public_key(req->src = NULL, req->dst = PK)`

	3. Send the Kyber PK to the responder and retrieve the Kyber CT from the
	   responder.

	4. Calculate shared secret:
		`crypto_kpp_compute_shared_secret(req->src = CT, req->dst = SS)`

* Acting as Responder of a Kyber KEM operation:

	1. Generate new keypair: `crypto_kpp_set_secret(tfm, NULL, 0);`
	   Note, it is permissible to also set an externally-provided key here.

	2. Get the initiator PK to generate the CT and shared secret:
		`crypto_kpp_generate_public_key(req->src = PK, req->dst = CT)`

	3. Send CT to the initiator

	4. Get the shared secret that was already calculated in step 2:
		`crypto_kpp_compute_shared_secret(req->src = NULL, req->dst = SS)`

Please note that the leancrypto Kyber support allows specifying arbitrary sizes
of the shared secret (referenced as `SS` above). When the caller specifies a
length that is not equal to 32 bytes, the leancrypto built-in KDF is applied to
generate the shared secret of appropriate size.

## Leancrypto Kernel Support Configuration

The kernel-compilation of leancrypto is equally flexible as the user space part
and thus can still be called "lean". It allows at compile time to enable or
disable algorithms as needed.

Unfortunately, the Linux kernel build system's graphical configuration tools
cannot be used for out-of-tree modules. Thus, if changes to the set of
algorithms is intended, the file `Kbuild.config` must be modified as follows:

The file `Kbuild.config` contains a configuration of the services. Simply
comment out the respective symbols that are not desired to be present. The
`Kbuild.config` file contains a description of each option including its
dependencies, if any. You MUST adhere to the specified dependencies as
otherwise the compilation will fail due to missing symbols.
