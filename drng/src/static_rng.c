/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "static_rng.h"

static int lc_static_rng_gen(void *_state, const uint8_t *addtl_input,
			     size_t addtl_input_len, uint8_t *out,
			     size_t outlen)
{
	struct lc_static_rng_data *state = _state;

	(void)addtl_input;
	(void)addtl_input_len;

	if (outlen > state->seedlen)
		return -EINVAL;

	memcpy(out, state->seed, outlen);
	state->seed += outlen;
	state->seedlen -= outlen;

	/*
	 * The used seed is not cleared out as this is the responsibility of
	 * the owner of the seed buffer.
	 */

	return 0;
}

static int lc_static_rng_seed(void *_state, const uint8_t *seed, size_t seedlen,
			      const uint8_t *persbuf, size_t perslen)
{
	(void)_state;
	(void)seed;
	(void)seedlen;
	(void)persbuf;
	(void)perslen;
	return 0;
}

static void lc_static_rng_zero(void *_state)
{
	(void)_state;
}

static const struct lc_rng _lc_static_drng = {
	.generate = lc_static_rng_gen,
	.seed = lc_static_rng_seed,
	.zero = lc_static_rng_zero,
};
const struct lc_rng *lc_static_drng = &_lc_static_drng;
