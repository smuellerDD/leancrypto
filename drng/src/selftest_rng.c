/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers_internal.h"
#include "selftest_rng.h"

/*
 * The selftest DRNG is a SHAKE128 state that is initialized to a zero state.
 * The Keccak squeeze operation generates data from the SHAKE state.
 */

static int selftest_rng_gen(void *_state, const uint8_t *addtl_input,
			    size_t addtl_input_len, uint8_t *out, size_t outlen)
{
	struct lc_hash_ctx *state = _state;

	(void)addtl_input;
	(void)addtl_input_len;

	lc_hash_set_digestsize(state, outlen);
	lc_hash_final(state, out);

	return 0;
}

static int selftest_rng_seed(void *_state, const uint8_t *seed, size_t seedlen,
			     const uint8_t *persbuf, size_t perslen)
{
	struct lc_hash_ctx *state = _state;

	if (!state)
		return -EINVAL;

	(void)seed;
	(void)seedlen;
	(void)persbuf;
	(void)perslen;

	lc_hash_init(state);

	return 0;
}

static void selftest_rng_zero(void *_state)
{
	struct lc_hash_ctx *state = _state;

	if (!state)
		return;

	lc_hash_zero(state);
}

static const struct lc_rng _lc_selftest_drng = {
	.generate = selftest_rng_gen,
	.seed = selftest_rng_seed,
	.zero = selftest_rng_zero,
};
const struct lc_rng *lc_selftest_drng = &_lc_selftest_drng;
