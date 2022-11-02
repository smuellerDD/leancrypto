/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include <stdint.h>
#include <sys/types.h>

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
 * @brief crypto_kem_keypair - Generates public and private key for CCA-secure
 *			       Kyber key encapsulation mechanism
 *
 * @param pk [out] pointer to already allocated output public key
 * @param sk [out] pointer to already allocated output private key
 * @param rng_ctx [in] pointer to seeded random number generator context
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
 * @param ct [out] pointer to output cipher text to used for decapsulation
 * @param ss [out] pointer to output shared secret that will be also produced
 *		   during decapsulation
 * @param ss_len [in] length of shared secret to be generated
 * @param pk [in] pointer to input public key
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
 * @param ss [out] pointer to output shared secret that is the same as produced
 *		   during encapsulation
 * @param ss_len [in] length of shared secret to be generated
 * @param ct [in] pointer to input cipher text generated during encapsulation
 * @param sk [in] pointer to input private key
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
 * @param pk_e_r [out] responder's ephemeral public key to be sent to the
 *		       initiator
 * @param ct_e_r [out] responder's ephemeral cipher text to be sent to the
 *		       initator
 * @param tk [out] KEM shared secret data to be used for the responder's shared
 *		   secret generation
 * @param sk_e [out] responder's ephemeral secret key to be used for the
 *		     responder's shared secret generation
 * @param pk_i [in] initiator's public key
 * @param rng_ctx [in] pointer to seeded random number generator context
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
 * @param ct_e_i [out] intiator's ephemeral cipher text to be sent to the
 *		       responder
 * @param shared_secret [out] Shared secret between initiator and responder
 * @param shared_secret_len [in] Requested size of the shared secret
 * @param pk_e_r [in] responder's ephemeral public key
 * @param ct_e_r [in] responder's ephemeral cipher text
 * @param sk_i [in] initator's secret key
 * @param rng_ctx [in] pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_uake_initiator_ss(struct lc_kyber_ct *ct_e_i,
			     uint8_t *shared_secret,
			     size_t shared_secret_len,
			     const struct lc_kyber_pk *pk_e_r,
			     const struct lc_kyber_ct *ct_e_r,
			     const struct lc_kyber_sk *sk_i,
			     struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kex_uake_responder_ss - Responder's shared secret generation
 *
 * @param shared_secret [out] Shared secret between initiator and responder
 * @param shared_secret_len [in] Requested size of the shared secret
 * @param ct_e_i [in] intiator's ephemeral cipher text
 * @param tk [in] KEM shared secret data that was generated during the
 *		  responder's initialization
 * @param sk_e [in] responder's ephemeral secret that was generated during the
 *		    responder's initialization
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_uake_responder_ss(uint8_t *shared_secret,
			     size_t shared_secret_len,
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
 * @param pk_e_r [out] responder's ephemeral public key to be sent to the
 *		       initiator
 * @param ct_e_r [out] responder's ephemeral cipher text to be sent to the
 *		       initator
 * @param tk [out] KEM shared secret data to be used for the responder's shared
 *		   secret generation
 * @param sk_e [out] responder's ephemeral secret key to be used for the
 *		     responder's shared secret generation
 * @param pk_i [in] initiator's public key
 * @param rng_ctx [in] pointer to seeded random number generator context
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
 * @param ct_e_i_1 [out] intiator's ephemeral cipher text to be sent to the
 *			 responder
 * @param ct_e_i_2 [out] intiator's ephemeral cipher text to be sent to the
 *			 responder
 * @param shared_secret [out] Shared secret between initiator and responder
 * @param shared_secret_len [in] Requested size of the shared secret
 * @param pk_e_r [in] responder's ephemeral public key
 * @param ct_e_r [in] responder's ephemeral cipher text
 * @param sk_i [in] initator's secret key
 * @param pk_r [in] responder's public key
 * @param rng_ctx [in] pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_ake_initiator_ss(struct lc_kyber_ct *ct_e_i_1,
			    struct lc_kyber_ct *ct_e_i_2,
			    uint8_t *shared_secret,
			    size_t shared_secret_len,
			    const struct lc_kyber_pk *pk_e_r,
			    const struct lc_kyber_ct *ct_e_r,
			    const struct lc_kyber_sk *sk_i,
			    const struct lc_kyber_pk *pk_r,
			    struct lc_rng_ctx *rng_ctx);

/**
 * @brief lc_kex_ake_responder_ss - Responder's shared secret generation
 *
 * @param shared_secret [out] Shared secret between initiator and responder
 * @param shared_secret_len [in] Requested size of the shared secret
 * @param ct_e_i_1 [in] intiator's ephemeral cipher text
 * @param ct_e_i_2 [in] intiator's ephemeral cipher text
 * @param tk [in] KEM shared secret data that was generated during the
 *		  responder's initialization
 * @param sk_e [in] responder's ephemeral secret that was generated during the
 *		    responder's initialization
 * @param sk_r [in] responder's secret key
 *
 * @return 0 (success) or < 0 on error
 */
int lc_kex_ake_responder_ss(uint8_t *shared_secret,
			    size_t shared_secret_len,
			    const struct lc_kyber_ct *ct_e_i_1,
			    const struct lc_kyber_ct *ct_e_i_2,
			    const struct lc_kyber_ss *tk,
			    const struct lc_kyber_sk *sk_e,
			    const struct lc_kyber_sk *sk_r);

/************************************* IES ************************************/

/**
 * @brief lc_kyber_ies_enc - KyberIES encryption
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param pk [in] Kyber public key of data owner
 * @param ct [out] Kyber ciphertext to be sent to the decryption operation
 * @param plaintext [in] Plaintext data to be encrypted
 * @param ciphertext [out] Buffer of equal size as plaintext that will be filled
 *			   with the encryption result
 * @param datalen [in] Length of the plaintext buffer
 * @param aad [in] Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param aadlen [in] Length of the AAD buffer
 * @param tag [out] Buffer that will be filled with the authentication tag
 * @param taglen [in] Length of the tag buffer
 * @param aead [in] Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param rng_ctx [in] Fully seeded random bit generator context.
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
 * @brief lc_kyber_ies_dec - KyberIES decryption
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param sk [in] Kyber secret key of data owner
 * @param ct [int] Kyber ciphertext received from the encryption operation
 * @param ciphertext [in] Ciphertext data to be encrypted
 * @param plaintext [out] Buffer of equal size as ciphertext that will be
 *			   filled with the decryption result
 * @param datalen [in] Length of the ciphertext buffer
 * @param aad [in] Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param aadlen [in] Length of the AAD buffer
 * @param tag [in] Buffer with the authentication tag
 * @param taglen [in] Length of the tag buffer
 * @param aead [in] Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @return 0 on success, < 0 on error
 */
int lc_kyber_ies_dec(const struct lc_kyber_sk *sk,
		     const struct lc_kyber_ct *ct,
		     const uint8_t *ciphertext, uint8_t *plaintext,
		     size_t datalen,
		     const uint8_t *aad, size_t aadlen,
		     const uint8_t *tag, size_t taglen,
		     struct lc_aead_ctx *aead);

#ifdef __cplusplus
}
#endif

#endif /* LC_KYBER_H */
