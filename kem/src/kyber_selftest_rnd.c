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

#include "kyber_selftest.h"
#include "lc_kyber.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"

static int randombytes(void *_state, const uint8_t *addtl_input,
		       size_t addtl_input_len, uint8_t *out, size_t outlen)
{
	struct rand_state *state = _state;

	(void)addtl_input;
	(void)addtl_input_len;

	lc_hash_set_digestsize(state->rng_hash_ctx, outlen);
	lc_hash_final(state->rng_hash_ctx, out);

	return 0;
}

static int randombytes_seed(void *_state, const uint8_t *seed, size_t seedlen,
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

const struct lc_rng kyber_drng = {
	.generate = randombytes,
	.seed = randombytes_seed,
	.zero = randombytes_zero,
};
