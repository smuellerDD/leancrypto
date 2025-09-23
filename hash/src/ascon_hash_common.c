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

#include "ascon_hash_common.h"
#include "ascon_selftest.h"
#include "compare.h"

static inline void ascon_ctx_init(struct lc_ascon_hash *ctx)
{
	ctx->msg_len = 0;
	ctx->squeeze_more = 0;
	ctx->offset = 0;
}

static void ascon_256_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 12;
	ctx->digestsize = LC_ASCON_HASH_DIGESTSIZE;

	/*
	 * Values are generated with:
	 *
	 * ctx->state[0] = 0x0000080100cc0002;
	 * ctx->state[1] = 0;
	 * ctx->state[2] = 0;
	 * ctx->state[3] = 0;
	 * ctx->state[4] = 0;
	 * ascon_c_permutation(ctx->state, 12);
	 */
	ctx->state[0] = 0x9b1e5494e934d681;
	ctx->state[1] = 0x4bc3a01e333751d2;
	ctx->state[2] = 0xae65396c6b34b81a;
	ctx->state[3] = 0x3c7fd4a4d56a4db3;
	ctx->state[4] = 0x1a5c464906c5976d;
}

int ascon_256_init_nocheck(void *_state)
{
	struct lc_ascon_hash *ctx = _state;

	if (!ctx)
		return -EINVAL;

	ascon_256_init_common(ctx);

	return 0;
}

int ascon_256_init(void *_state)
{
	ascon_256_selftest_common(lc_ascon_256);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ASCON256);

	return ascon_256_init_nocheck(_state);
}

static void ascon_128a_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 8;
	ctx->digestsize = LC_ASCON_HASH_DIGESTSIZE;

	/*
	 * This hash function is not defined and should never be used directly!
	 *
	 * Its only purpose is the use in the Ascon AEAD algorithm.
	 */
	ctx->state[0] = 0;
	ctx->state[1] = 0;
	ctx->state[2] = 0;
	ctx->state[3] = 0;
	ctx->state[4] = 0;
}

int ascon_128a_init(void *_state)
{
	struct lc_ascon_hash *ctx = _state;

	if (!ctx)
		return -EINVAL;

	ascon_128a_init_common(ctx);

	return 0;
}

static void ascon_xof_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 12;
	ctx->digestsize = 0;

	/*
	 * Values are generated with:
	 *
	 * ctx->state[0] = 0x0000080000cc0003;
	 * ctx->state[1] = 0;
	 * ctx->state[2] = 0;
	 * ctx->state[3] = 0;
	 * ctx->state[4] = 0;
	 * ascon_c_permutation(ctx->state, 12);
	 */
	ctx->state[0] = 0xda82ce768d9447eb;
	ctx->state[1] = 0xcc7ce6c75f1ef969;
	ctx->state[2] = 0xe7508fd780085631;
	ctx->state[3] = 0x0ee0ea53416b58cc;
	ctx->state[4] = 0xe0547524db6f0bde;
}

int ascon_xof_init_nocheck(void *_state)
{
	struct lc_ascon_hash *ctx = _state;

	ascon_xof_init_common(ctx);

	return 0;
}

int ascon_xof_init(void *_state)
{
	ascon_xof_selftest_common(lc_ascon_xof);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ASCONXOF);

	return ascon_xof_init_nocheck(_state);
}

static void ascon_cxof_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 12;
	ctx->digestsize = 0;

	/*
	 * Values are generated with:
	 *
	 * ctx->state[0] = 0x0000080000cc0004;
	 * ctx->state[1] = 0;
	 * ctx->state[2] = 0;
	 * ctx->state[3] = 0;
	 * ctx->state[4] = 0;
	 * ascon_c_permutation(ctx->state, 12);
	 */
	ctx->state[0] = 0x675527c2a0e8de03;
	ctx->state[1] = 0x43d12d7dc0377bbc;
	ctx->state[2] = 0xe9901dec426e81b5;
	ctx->state[3] = 0x2ab14907720780b6;
	ctx->state[4] = 0x8f3f1d02d432bc46;
}

int ascon_cxof_init_nocheck(void *_state)
{
	struct lc_ascon_hash *ctx = _state;

	if (!ctx)
		return -EINVAL;

	ascon_cxof_init_common(ctx);

	return 0;
}

int ascon_cxof_init(void *_state)
{
	ascon_cxof_selftest_common(lc_ascon_xof);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ASCONXOF);

	return ascon_cxof_init_nocheck(_state);
}

size_t ascon_digestsize(void *_state)
{
	(void)_state;
	return LC_ASCON_HASH_DIGESTSIZE;
}

void ascon_xof_set_digestsize(void *_state, size_t digestsize)
{
	struct lc_ascon_hash *ctx = _state;

	ctx->digestsize = digestsize;
}

size_t ascon_xof_get_digestsize(void *_state)
{
	struct lc_ascon_hash *ctx = _state;

	return ctx->digestsize;
}
