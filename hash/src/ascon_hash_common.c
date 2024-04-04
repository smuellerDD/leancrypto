/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

static inline void ascon_ctx_init(struct lc_ascon_hash *ctx)
{
	ctx->msg_len = 0;
	ctx->squeeze_more = 0;
	ctx->offset = 0;
}

static void ascon_128_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 12;
	ctx->digestsize = LC_ASCON_HASH_DIGESTSIZE;

	ctx->state[0] = 0xee9398aadb67f03d;
	ctx->state[1] = 0x8bb21831c60f1002;
	ctx->state[2] = 0xb48a92db98d5da62;
	ctx->state[3] = 0x43189921b8f8e3e8;
	ctx->state[4] = 0x348fa5c9d525e140;
}

void ascon_128_init(void *_state)
{
	struct lc_ascon_hash *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	ascon_128_selftest_common(lc_ascon_128, &tested, "Ascon 128 C");
	ascon_128_init_common(ctx);
}

static void ascon_128a_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 8;
	ctx->digestsize = LC_ASCON_HASH_DIGESTSIZE;

	ctx->state[0] = 0x01470194fc6528a6;
	ctx->state[1] = 0x738ec38ac0adffa7;
	ctx->state[2] = 0x2ec8e3296c76384c;
	ctx->state[3] = 0xd6f6a54d7f52377d;
	ctx->state[4] = 0xa13c42a223be8d87;
}

void ascon_128a_init(void *_state)
{
	struct lc_ascon_hash *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	ascon_128a_selftest_common(lc_ascon_128a, &tested, "Ascon 128a C");
	ascon_128a_init_common(ctx);
}

static void ascon_xof_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 12;
	ctx->digestsize = 0;

	ctx->state[0] = 0xb57e273b814cd416;
	ctx->state[1] = 0x2b51042562ae2420;
	ctx->state[2] = 0x66a3a7768ddf2218;
	ctx->state[3] = 0x5aad0a7a8153650c;
	ctx->state[4] = 0x4f3e0e32539493b6;
}

void ascon_xof_init(void *_state)
{
	struct lc_ascon_hash *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	ascon_xof_selftest_common(lc_ascon_xof, &tested, "Ascon XOF C");
	ascon_xof_init_common(ctx);
}

static void ascon_xofa_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 8;
	ctx->digestsize = 0;

	ctx->state[0] = 0x44906568b77b9832;
	ctx->state[1] = 0xcd8d6cae53455532;
	ctx->state[2] = 0xf7b5212756422129;
	ctx->state[3] = 0x246885e1de0d225b;
	ctx->state[4] = 0xa8cb5ce33449973f;
}

void ascon_xofa_init(void *_state)
{
	struct lc_ascon_hash *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	ascon_xofa_selftest_common(lc_ascon_xofa, &tested, "Ascon XOFa C");
	ascon_xofa_init_common(ctx);
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
