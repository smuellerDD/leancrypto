/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef LC_KYBER_H
#define LC_KYBER_H

#include "ext_headers.h"
#include "lc_aead.h"
#include "lc_rng.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Kyber 512:  K == 2
 * Kyber 768:  K == 3
 * Kyber 1024: K == 4
 */
#ifndef LC_KYBER_K
#define LC_KYBER_K 4	/* Change this for different security strengths */
#endif

#define LC_KYBER_N 256
#define LC_KYBER_Q 3329

#define LC_KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define LC_KYBER_SSBYTES  32   /* size in bytes of shared key */

#define LC_KYBER_POLYBYTES		384
#define LC_KYBER_POLYVECBYTES	(LC_KYBER_K * LC_KYBER_POLYBYTES)

#if LC_KYBER_K == 2
#define LC_KYBER_ETA1 3
#define LC_KYBER_POLYCOMPRESSEDBYTES    128
#define LC_KYBER_POLYVECCOMPRESSEDBYTES (LC_KYBER_K * 320)
#elif LC_KYBER_K == 3
#define LC_KYBER_ETA1 2
#define LC_KYBER_POLYCOMPRESSEDBYTES    128
#define LC_KYBER_POLYVECCOMPRESSEDBYTES (LC_KYBER_K * 320)
#elif LC_KYBER_K == 4
#define LC_KYBER_ETA1 2
#define LC_KYBER_POLYCOMPRESSEDBYTES    160
#define LC_KYBER_POLYVECCOMPRESSEDBYTES (LC_KYBER_K * 352)
#endif

#define LC_KYBER_ETA2 2

#define LC_KYBER_INDCPA_MSGBYTES       (LC_KYBER_SYMBYTES)
#define LC_KYBER_INDCPA_PUBLICKEYBYTES					       \
	(LC_KYBER_POLYVECBYTES + LC_KYBER_SYMBYTES)
#define LC_KYBER_INDCPA_SECRETKEYBYTES (LC_KYBER_POLYVECBYTES)
#define LC_KYBER_INDCPA_BYTES						       \
	(LC_KYBER_POLYVECCOMPRESSEDBYTES + LC_KYBER_POLYCOMPRESSEDBYTES)

#define LC_KYBER_PUBLICKEYBYTES  (LC_KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define LC_KYBER_SECRETKEYBYTES						       \
	(LC_KYBER_INDCPA_SECRETKEYBYTES + LC_KYBER_INDCPA_PUBLICKEYBYTES +     \
	 2 * LC_KYBER_SYMBYTES)
#define LC_KYBER_CIPHERTEXTBYTES (LC_KYBER_INDCPA_BYTES)

#define LC_CRYPTO_SECRETKEYBYTES  LC_KYBER_SECRETKEYBYTES
#define LC_CRYPTO_PUBLICKEYBYTES  LC_KYBER_PUBLICKEYBYTES
#define LC_CRYPTO_CIPHERTEXTBYTES LC_KYBER_CIPHERTEXTBYTES
#define LC_CRYPTO_BYTES           LC_KYBER_SSBYTES

/************************************* KEM ************************************/
/**
 * @brief Kyber secret key
 */
struct lc_kyber_sk {
	uint8_t sk[LC_KYBER_SECRETKEYBYTES];
};

/**
 * @brief Kyber public key
 */
struct lc_kyber_pk {
	uint8_t pk[LC_KYBER_PUBLICKEYBYTES];
};

/**
 * @brief Kyber ciphertext
 */
struct lc_kyber_ct {
	uint8_t ct[LC_CRYPTO_CIPHERTEXTBYTES];
};

/**
 * @brief Kyber shared secret
 */
struct lc_kyber_ss {
	uint8_t ss[LC_KYBER_SSBYTES];
};

/**
 * @brief lc_kyber_keypair - Generates public and private key for
 *			     IND-CCA2-secure Kyber key encapsulation mechanism
 *
 * @param [out] pk pointer to already allocated output public key
 * @param [out] sk pointer to already allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kyber_keypair(struct lc_kyber_pk *pk,
		     struct lc_kyber_sk *sk,
		     struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kyber_enc - Key encapsulation
 *
 * Generates cipher text and shared secret for given public key.
 *
 * @param [out] ct pointer to output cipher text to used for decapsulation
 * @param [out] ss pointer to output shared secret that will be also produced
 *		   during decapsulation
 * @param [in] ss_len length of shared secret to be generated
 * @param [in] pk pointer to input public key
 * @param [in] rng_ctx pointer to seeded random number generator context
 *
 * Returns 0 (success) or < 0 on error
 */
int lc_kyber_enc(struct lc_kyber_ct *ct,
		 uint8_t *ss, size_t ss_len,
		 const struct lc_kyber_pk *pk,
		 struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kyber_dec - Key decapsulation
 *
 * Generates shared secret for given cipher text and private key
 *
 * @param [out] ss pointer to output shared secret that is the same as produced
 *		   during encapsulation
 * @param [in] ss_len length of shared secret to be generated
 * @param [in] ct pointer to input cipher text generated during encapsulation
 * @param [in] sk pointer to input private key
 *
 * @return 0
 *
 * On failure, ss will contain a pseudo-random value.
 */
int lc_kyber_dec(uint8_t *ss, size_t ss_len,
		 const struct lc_kyber_ct *ct,
		 const struct lc_kyber_sk *sk);

/************************************* KEX ************************************/

/**
 * Unilaterally authenticated key exchange
 *
 * The key exchange provides a shared secret between two communication parties.
 * Only the initiator authenticates the key exchange with his private key.
 *
 * 		Alice (initiator)		Bob (responder)
 *
 * Step 1	generate keypair
 *		Result:
 *			public key pk_i
 *			secret key sk_i
 *
 * Step 2	send public key
 * 		pk_i ------------------------->	pk_i
 *
 * Step 3					initiate key exchange
 *						Result:
 *							Public key pk_e_r
 *							Cipher text ct_e_r
 *							KEM shared secret tk
 *							Secret key sk_e
 *
 * Step 4					send kex data
 *		Public key pk_e_r <------------	Public key pk_e_r
 *		Cipher text ct_e_r <-----------	Cipher text ct_e_r
 *
 * Step 5	calculate shared secret
 *		Result:
 *			Cipher text ct_e_i
 *			Shared secret SS
 *
 * Step 6	send kex data
 *		Cipher text ct_e_i ----------->	Cipher text ct_e_i
 *
 * Step 7					calculate shared secret
 *						Result:
 * 							Shared secret SS
 */

/**
 * @brief lc_kex_uake_responder_init - Initialize unilaterally authenticated
 *				       key exchange
 *
 * @param [out] pk_e_r responder's ephemeral public key to be sent to the
 *		       initiator
 * @param [out] ct_e_r responder's ephemeral cipher text to be sent to the
 *		       initator
 * @param [out] tk KEM shared secret data to be used for the responder's shared
 *		   secret generation
 * @param [out] sk_e responder's ephemeral secret key to be used for the
 *		     responder's shared secret generation
 * @param [in] pk_i initiator's public key
 * @param [in] rng_ctx pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_uake_responder_init(struct lc_kyber_pk *pk_e_r,
			       struct lc_kyber_ct *ct_e_r,
			       struct lc_kyber_ss *tk,
			       struct lc_kyber_sk *sk_e,
			       const struct lc_kyber_pk *pk_i,
			       struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kex_uake_initiator_ss - Initiator's shared secret generation
 *
 * @param [out] ct_e_i intiator's ephemeral cipher text to be sent to the
 *		       responder
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] pk_e_r responder's ephemeral public key
 * @param [in] ct_e_r responder's ephemeral cipher text
 * @param [in] sk_i initator's secret key
 * @param [in] rng_ctx pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_uake_initiator_ss(struct lc_kyber_ct *ct_e_i,
			     uint8_t *shared_secret,
			     size_t shared_secret_len,
			     const uint8_t *kdf_nonce,
			     size_t kdf_nonce_len,
			     const struct lc_kyber_pk *pk_e_r,
			     const struct lc_kyber_ct *ct_e_r,
			     const struct lc_kyber_sk *sk_i,
			     struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kex_uake_responder_ss - Responder's shared secret generation
 *
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] ct_e_i intiator's ephemeral cipher text
 * @param [in] tk KEM shared secret data that was generated during the
 *		  responder's initialization
 * @param [in] sk_e responder's ephemeral secret that was generated during the
 *		    responder's initialization
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_uake_responder_ss(uint8_t *shared_secret,
			     size_t shared_secret_len,
			     const uint8_t *kdf_nonce,
			     size_t kdf_nonce_len,
			     const struct lc_kyber_ct *ct_e_i,
			     const struct lc_kyber_ss *tk,
			     const struct lc_kyber_sk *sk_e);


/**
 * Authenticated key exchange
 *
 * The key exchange provides a shared secret between two communication parties.
 * The initiator and responder authenticates the key exchange with their private
 * keys.
 *
 * 		Alice (initiator)		Bob (responder)
 *
 * Step 1	generate keypair		generate keypair
 *		Result:				Result:
 *			public key pk_i			public key pk_r
 *			secret key sk_i			secret key sk_r
 *
 * Step 2	send public key			send public key
 * 		pk_i ------------------------->	pk_i
 *		pk_r <------------------------- pk_r
 *
 * Step 3					initiate key exchange
 *						Result:
 *							Public key pk_e_r
 *							Cipher text ct_e_r
 *							KEM shared secret tk
 *							Secret key sk_e
 *
 * Step 4					send kex data
 *		Public key pk_e_r <------------	Public key pk_e_r
 *		Cipher text ct_e_r <-----------	Cipher text ct_e_r
 *
 * Step 5	calculate shared secret
 *		Result:
 *			Cipher text ct_e_i_1
 *			Cipher text ct_e_i_2
 *			Shared secret SS
 *
 * Step 6	send kex data
 *		Cipher text ct_e_i_1 --------->	Cipher text ct_e_i_1
 *		Cipher text ct_e_i_2 --------->	Cipher text ct_e_i_2
 *
 * Step 7					calculate shared secret
 *						Result:
 * 							Shared secret SS
 */

/**
 * @brief lc_kex_ake_responder_init - Initialize authenticated key exchange
 *
 * @param [out] pk_e_r responder's ephemeral public key to be sent to the
 *		       initiator
 * @param [out] ct_e_r responder's ephemeral cipher text to be sent to the
 *		       initator
 * @param [out] tk KEM shared secret data to be used for the responder's shared
 *		   secret generation
 * @param [out] sk_e responder's ephemeral secret key to be used for the
 *		     responder's shared secret generation
 * @param [in] pk_i initiator's public key
 * @param [in] rng_ctx pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_ake_responder_init(struct lc_kyber_pk *pk_e_r,
			      struct lc_kyber_ct *ct_e_r,
			      struct lc_kyber_ss *tk,
			      struct lc_kyber_sk *sk_e,
			      const struct lc_kyber_pk *pk_i,
			      struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kex_ake_initiator_ss - Initiator's shared secret generation
 *
 * @param [out] ct_e_i_1 intiator's ephemeral cipher text to be sent to the
 *			 responder
 * @param [out] ct_e_i_2 intiator's ephemeral cipher text to be sent to the
 *			 responder
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] pk_e_r responder's ephemeral public key
 * @param [in] ct_e_r responder's ephemeral cipher text
 * @param [in] sk_i initator's secret key
 * @param [in] pk_r responder's public key
 * @param [in] rng_ctx pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_ake_initiator_ss(struct lc_kyber_ct *ct_e_i_1,
			    struct lc_kyber_ct *ct_e_i_2,
			    uint8_t *shared_secret,
			    size_t shared_secret_len,
			    const uint8_t *kdf_nonce,
			    size_t kdf_nonce_len,
			    const struct lc_kyber_pk *pk_e_r,
			    const struct lc_kyber_ct *ct_e_r,
			    const struct lc_kyber_sk *sk_i,
			    const struct lc_kyber_pk *pk_r,
			    struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kex_ake_responder_ss - Responder's shared secret generation
 *
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] ct_e_i_1 intiator's ephemeral cipher text
 * @param [in] ct_e_i_2 intiator's ephemeral cipher text
 * @param [in] tk KEM shared secret data that was generated during the
 *		  responder's initialization
 * @param [in] sk_e responder's ephemeral secret that was generated during the
 *		    responder's initialization
 * @param [in] sk_r responder's secret key
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_ake_responder_ss(uint8_t *shared_secret,
			    size_t shared_secret_len,
			    const uint8_t *kdf_nonce,
			    size_t kdf_nonce_len,
			    const struct lc_kyber_ct *ct_e_i_1,
			    const struct lc_kyber_ct *ct_e_i_2,
			    const struct lc_kyber_ss *tk,
			    const struct lc_kyber_sk *sk_e,
			    const struct lc_kyber_sk *sk_r);

/************************************* IES ************************************/

/**
 * @brief lc_kyber_ies_enc - KyberIES encryption oneshot
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] pk Kyber public key of data owner
 * @param [out] ct Kyber ciphertext to be sent to the decryption operation
 * @param [in] plaintext Plaintext data to be encrypted
 * @param [out] ciphertext Buffer of equal size as plaintext that will be filled
 *			   with the encryption result
 * @param [in] datalen Length of the plaintext buffer
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [out] tag Buffer that will be filled with the authentication tag
 * @param [in] taglen Length of the tag buffer
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] rng_ctx Fully seeded random bit generator context.
 *
 * @return 0 on success, < 0 on error
 */
int lc_kyber_ies_enc(const struct lc_kyber_pk *pk,
		     struct lc_kyber_ct *ct,
		     const uint8_t *plaintext, uint8_t *ciphertext,
		     size_t datalen,
		     const uint8_t *aad, size_t aadlen,
		     uint8_t *tag, size_t taglen,
		     struct lc_aead_ctx *aead,
		     struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kyber_ies_enc_init - KyberIES encryption stream operation
 *				  initialization
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * The aead context is initialized such that it can be used with
 * lc_kyber_ies_enc_[update|final].
 *
 * @param [out] aead Allocated AEAD algorithm - the caller only needs to provide
 *		     an allocated but otherwise unused instance of an AEAD
 *		     algorithm. This allows the caller to define the AEAD
 *		     algorithm type. The caller must zeroize and release the
 *		     context after completion.
 * @param [in] pk Kyber public key of data owner
 * @param [out] ct Kyber ciphertext to be sent to the decryption operation
 * @param [in] rng_ctx Fully seeded random bit generator context.
 *
 * @return 0 on success, < 0 on error
 */
int lc_kyber_ies_enc_init(struct lc_aead_ctx *aead,
			  const struct lc_kyber_pk *pk, struct lc_kyber_ct *ct,
			  struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kyber_ies_enc_update - KyberIES encryption stream operation
 *				    add more data
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] plaintext Plaintext data to be encrypted
 * @param [out] ciphertext Buffer of equal size as plaintext that will be filled
 *			   with the encryption result
 * @param [in] datalen Length of the plaintext buffer
 */
static inline void
lc_kyber_ies_enc_update(struct lc_aead_ctx *aead,
			const uint8_t *plaintext, uint8_t *ciphertext,
			size_t datalen)
{
	lc_aead_enc_update(aead, plaintext, ciphertext, datalen);
}

/**
 * @brief lc_kyber_ies_enc_final - KyberIES encryption stream operation
 *				   finalization / integrity test
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [out] tag Buffer that will be filled with the authentication tag
 * @param [in] taglen Length of the tag buffer
 */
static inline void
lc_kyber_ies_enc_final(struct lc_aead_ctx *aead,
		       const uint8_t *aad, size_t aadlen,
		       uint8_t *tag, size_t taglen)
{
	lc_aead_enc_final(aead, aad, aadlen, tag, taglen);
}

/**
 * @brief lc_kyber_ies_dec - KyberIES decryption oneshot
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] sk Kyber secret key of data owner
 * @param [in] ct Kyber ciphertext received from the encryption operation
 * @param [in] ciphertext Ciphertext data to be encrypted
 * @param [out] plaintext Buffer of equal size as ciphertext that will be
 *			   filled with the decryption result
 * @param [in] datalen Length of the ciphertext buffer
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [in] tag Buffer with the authentication tag
 * @param [in] taglen Length of the tag buffer
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @return 0 on success, < 0 on error (-EBADMSG on integrity error)
 */
int lc_kyber_ies_dec(const struct lc_kyber_sk *sk,
		     const struct lc_kyber_ct *ct,
		     const uint8_t *ciphertext, uint8_t *plaintext,
		     size_t datalen,
		     const uint8_t *aad, size_t aadlen,
		     const uint8_t *tag, size_t taglen,
		     struct lc_aead_ctx *aead);

/**
 * @brief lc_kyber_ies_dec_init - KyberIES decryption stream operation
 *				  initialization
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * The aead context is initialized such that it can be used with
 * lc_kyber_ies_dec_[update|final].
 *
 * @param [out] aead Allocated AEAD algorithm - the caller only needs to provide
 *		     an allocated but otherwise unused instance of an AEAD
 *		     algorithm. This allows the caller to define the AEAD
 *		     algorithm type. The caller must zeroize and release the
 *		     context after completion.
 * @param [in] sk Kyber secret key of data owner
 * @param [in] ct Kyber ciphertext received from the encryption operation
 * @return 0 on success, < 0 on error
 */
int lc_kyber_ies_dec_init(struct lc_aead_ctx *aead,
			  const struct lc_kyber_sk *sk,
			  const struct lc_kyber_ct *ct);

/**
 * @brief lc_kyber_ies_dec_update - KyberIES decryption stream operation
 *				    add more data
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] ciphertext Ciphertext data to be encrypted
 * @param [out] plaintext Buffer of equal size as ciphertext that will be
 *			   filled with the decryption result
 * @param [in] datalen Length of the ciphertext buffer
 */
static inline void
lc_kyber_ies_dec_update(struct lc_aead_ctx *aead,
			const uint8_t *ciphertext, uint8_t *plaintext,
			size_t datalen)
{
	lc_aead_dec_update(aead, ciphertext, plaintext, datalen);
}

/**
 * @brief lc_kyber_ies_dec_final - KyberIES decryption stream operation
 *				   finalization / integrity test
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [in] tag Buffer with the authentication tag
 * @param [in] taglen Length of the tag buffer
 * @return 0 on success, < 0 on error (-EBADMSG on integrity error)
 */
static inline int
lc_kyber_ies_dec_final(struct lc_aead_ctx *aead,
		       const uint8_t *aad, size_t aadlen,
		       const uint8_t *tag, size_t taglen)
{
	return lc_aead_dec_final(aead, aad, aadlen, tag, taglen);
}

#ifdef __cplusplus
}
#endif

#endif /* LC_KYBER_H */
