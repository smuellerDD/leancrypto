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

#ifndef LC_DRBG_H
#define LC_DRBG_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/******************************************************************
 * Generic internal DRBG helper functions
 ******************************************************************/

/*
 * Concatenation Helper and string operation helper
 *
 * SP800-90A requires the concatenation of different data. To avoid copying
 * buffers around or allocate additional memory, the following data structure
 * is used to point to the original memory with its size. In addition, it
 * is used to build a linked list. The linked list defines the concatenation
 * of individual buffers. The order of memory block referenced in that
 * linked list determines the order of concatenation.
 */
struct lc_drbg_string {
	const uint8_t *buf;
	size_t len;
	struct lc_drbg_string *next;
};

enum lc_drbg_prefixes
{
	DRBG_PREFIX0 = 0x00,
	DRBG_PREFIX1,
	DRBG_PREFIX2,
	DRBG_PREFIX3
};

static inline void lc_drbg_string_fill(struct lc_drbg_string *string,
				       const uint8_t *buf, size_t len)
{
	string->buf = buf;
	string->len = len;
	string->next = NULL;
}

static inline size_t lc_drbg_max_request_bytes(void)
{
	/* SP800-90A requires the limit 2**19 bits, but we return bytes */
	return (1 << 16);
}

static inline size_t lc_drbg_max_addtl(void)
{
	/* SP800-90A requires 2**35 bytes additional info str / pers str */
#if (__BITS_PER_LONG == 32)
	/*
	 * SP800-90A allows smaller maximum numbers to be returned -- we
	 * return SIZE_MAX - 1 to allow the verification of the enforcement
	 * of this value in drbg_healthcheck_sanity.
	 */
	return (SIZE_MAX - 1);
#else
	return (1UL<<35);
#endif
}

/******************************************************************
 * Generic DRBG API
 ******************************************************************/

struct lc_drbg_state {
	void (*drbg_int_seed)(struct lc_drbg_state *drbg,
			      struct lc_drbg_string *seed);
	size_t (*drbg_int_generate)(struct lc_drbg_state *drbg,
				    uint8_t *buf, size_t buflen,
				    struct lc_drbg_string *addtl);
	void (*drbg_int_zero)(struct lc_drbg_state *drbg);
	unsigned int seeded:1;
};

#define _LC_DRBG_SET_CTX(name, seeder, generator, zeroer)		       \
	name->drbg_int_seed = seeder;					       \
	name->drbg_int_generate = generator;				       \
	name->drbg_int_zero = zeroer;					       \
	name->seeded = 0

/**
 * @brief Seeding or reseeding of the DRBG
 *
 * @param drbg [in] DRBG state struct
 * @param seedbuf [in] Buffer with seed data (when using a nonce, the nonce must
 *		       be concatenated past the seed by the caller)
 * @param seedlen [in] Length of seed buffer
 * @param persbuf [in] Personalization / additional information buffer - may be
 *		      NULL
 * @param perslen [in] Length of personalization / additional information buffer
 *
 * @return 0 on success, negative error value otherwise
 */
int lc_drbg_seed(struct lc_drbg_state *drbg,
		 const uint8_t *seedbuf, size_t seedlen,
		 const uint8_t *persbuf, size_t perslen);

/**
 * @brief DRBG generate function as required by SP800-90A - this function
 *	  generates random numbers of a size of at most 2^16 bytes.
 *
 * @param drbg [in] DRBG state handle
 * @param buf [out] Buffer where to store the random numbers -- the buffer must
 *		   already be pre-allocated by caller
 * @param buflen [in] Length of output buffer - this value defines the number of
 *		     random bytes pulled from DRBG
 * @param addtlbuf [in] Additional input that is mixed into state, may be NULL
 * @param addtllen [in] Additional input buffer length
 *
 * @return generated number of bytes on success, negative error value otherwise
 */
ssize_t lc_drbg_generate(struct lc_drbg_state *drbg,
			 uint8_t *buf, size_t buflen,
			 const uint8_t *addtlbuf, size_t addtllen);

/**
 * @brief DRBG uninstantiate function as required by SP800-90A - this function
 *	  frees all buffers and the DRBG handle
 *
 * @param drbg [in] DRBG state handle
 *
 * @return: 0 on success, < 0 on error
 */
void lc_drbg_zero_free(struct lc_drbg_state *drbg);

/**
 * @brief Zeroize DRBG context allocated with either DRBG_CTX_ON_STACK or
 *	  drbg_alloc
 */
static inline void lc_drbg_zero(struct lc_drbg_state *drbg)
{
	drbg->seeded = 0;
	drbg->drbg_int_zero(drbg);
}

/**
 * @brief Tests as defined in 11.3.2 in addition to the cipher tests: testing
 *	  of the error handling.
 *
 * @param drbg [in] DRBG state handle that is used solely for the testing. It
 *		    shall not be a production handle unless you call drbg_seed
 *		    on that handle afterwards.
 *
 * Note: testing of failing seed source as defined in 11.3.2 must be handled
 * by the caller.
 *
 * Note 2: There is no sensible way of testing the reseed counter
 * enforcement, so skip it.
 *
 * @return: 0 on success, < 0 on error
 */
int lc_drbg_healthcheck_sanity(struct lc_drbg_state *drbg);

#ifdef __cplusplus
}
#endif

#endif /* LC_DRBG_H */
