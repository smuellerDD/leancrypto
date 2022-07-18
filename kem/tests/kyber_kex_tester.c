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

#include <stdio.h>

#include "lc_kyber.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "ret_checkers.h"

static int
randombytes(void *_state,
	    const uint8_t *addtl_input, size_t addtl_input_len,
	    uint8_t *out, size_t outlen)
{
	unsigned int i;
	uint8_t buf[8];
	static uint64_t ctr = 0;

	(void)_state;
	(void)addtl_input;
	(void)addtl_input_len;

	for(i = 0; i < 8; ++i)
		buf[i] = (uint8_t)(ctr >> 8*i);

	ctr++;
	lc_shake(lc_shake128, buf, 8, out, outlen);

	return 0;
}

static int
randombytes_seed(void *_state,
		 const uint8_t *seed, size_t seedlen,
		 const uint8_t *persbuf, size_t perslen)
{
	(void)_state;
	(void)seed;
	(void)seedlen;
	(void)persbuf;
	(void)perslen;
	return 0;
}

static void randombytes_zero(void *_state)
{
	(void)_state;
}

static const struct lc_rng kyber_drng = {
	.generate	= randombytes,
	.seed		= randombytes_seed,
	.zero		= randombytes_zero,
};

int main(void)
{
	struct lc_kyber_pk pk_r;
	struct lc_kyber_sk sk_r;

	struct lc_kyber_pk pk_i;
	struct lc_kyber_sk sk_i;

	struct lc_kyber_pk pk_e_r;
	struct lc_kyber_ct ct_e_r, ct_e_i, ct_e_i_1, ct_e_i_2;
	struct lc_kyber_sk sk_e;

	struct lc_kyber_ss tk;

	uint8_t ss_r[LC_KYBER_SSBYTES], ss_i[LC_KYBER_SSBYTES],
		zero[LC_KYBER_SSBYTES];

	/*
	 * The testing is based on the fact that,
	 * - this "RNG" produces identical output
	 */
	struct lc_rng_ctx cshake_rng =
		{ .rng = &kyber_drng, .rng_state = NULL };

	unsigned int i;
	int ret;

	for(i = 0; i < LC_KYBER_SSBYTES; i++)
		zero[i] = 0;

	// Generate static key for Bob
	CKINT(lc_kyber_keypair(&pk_r, &sk_r, &cshake_rng));

	// Generate static key for Alice
	CKINT(lc_kyber_keypair(&pk_i, &sk_i, &cshake_rng));


	// Perform unilaterally authenticated key exchange

	// Run by Bob
	CKINT(lc_kex_uake_responder_init(&pk_e_r, &ct_e_r, &tk, &sk_e, &pk_i,
					 &cshake_rng));

	// Run by Alice
	CKINT(kex_uake_initiator_ss(&ct_e_i, ss_i, sizeof(ss_i), &pk_e_r,
				    &ct_e_r, &sk_i, &cshake_rng));

	// Run by Bob
	CKINT(kex_uake_responder_ss(ss_r, sizeof(ss_r), &ct_e_i, &tk, &sk_e));

	if (memcmp(ss_i, ss_r, sizeof(ss_r))) {
		printf("Error in UAKE\n");
		return 1;
	}

	if (!memcmp(ss_i, zero, sizeof(ss_i))) {
		printf("Error: UAKE produces zero key\n");
		return 1;
	}

	// Perform mutually authenticated key exchange

	// Run by Bob
	CKINT(lc_kex_uake_responder_init(&pk_e_r, &ct_e_r, &tk, &sk_e, &pk_i,
					 &cshake_rng));

	// Run by Alice
	CKINT(kex_ake_initiator_ss(&ct_e_i_1, &ct_e_i_2, ss_i, sizeof(ss_i),
				   &pk_e_r, &ct_e_r, &sk_i, &pk_r,
				   &cshake_rng));

	// Run by Bob
	CKINT(kex_ake_responder_ss(ss_r, sizeof(ss_r), &ct_e_i_1, &ct_e_i_2,
				   &tk, &sk_e, &sk_r));

	if (memcmp(ss_i, ss_r, sizeof(ss_r))){
		printf("Error in AKE\n");
		return 1;
	}

	if (!memcmp(ss_i, zero, sizeof(ss_i))) {
		printf("Error: AKE produces zero key\n");
		return 1;
	}

out:
	return ret;
}
