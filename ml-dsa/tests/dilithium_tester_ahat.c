/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

#include "dilithium_type.h"
#include "dilithium_signature_c.h"

static int dilithium_tester_ahat(struct lc_dilithium_ctx *ctx, int reset)
{
	struct workspace {
		struct lc_dilithium_sk sk;
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sig sig;
		uint8_t msg[10];
	};
	unsigned int i;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	int ret = 0;

	CKINT(lc_dilithium_keypair_c(&ws->pk, &ws->sk, lc_seeded_rng));

	for (i = 0; i < 10000; i++) {
		if (reset)
			ctx->ahat_expanded = 0;
		CKINT_LOG(lc_dilithium_sign_ctx_c(&ws->sig, ctx, ws->msg,
						  sizeof(ws->msg), &ws->sk,
						  lc_seeded_rng),
			  "Sign failed - ret %d\n", ret);

		if (reset)
			ctx->ahat_expanded = 0;
		CKINT_LOG(lc_dilithium_verify_ctx_c(&ws->sig, ctx, ws->msg,
						    sizeof(ws->msg), &ws->pk),
			  "Verify failed - ret %u\n", ret);
	}

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

/*
 * This test app is not meant to have small stack support
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-larger-than="

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	struct lc_dilithium_ctx *ctx_heap;
	int ret = 0;

#ifdef LC_DILITHIUM_TYPE_65
	LC_DILITHIUM_65_CTX_ON_STACK_AHAT(ctx);

	CKINT(lc_dilithium_65_ctx_alloc(&ctx_heap));
#elif defined(LC_DILITHIUM_TYPE_44)
	LC_DILITHIUM_44_CTX_ON_STACK_AHAT(ctx);

	CKINT(lc_dilithium_44_ctx_alloc(&ctx_heap));
#else
	LC_DILITHIUM_87_CTX_ON_STACK_AHAT(ctx);

	CKINT(lc_dilithium_87_ctx_alloc(&ctx_heap));
#endif

	(void)argc;
	(void)argv;

	ret += dilithium_tester_ahat(ctx, argc > 1);
	ret += dilithium_tester_ahat(ctx_heap, argc > 1);

out:
	lc_dilithium_ctx_zero(ctx);
	lc_dilithium_ctx_zero_free(ctx_heap);
	return ret;
}

#pragma GCC diagnostic pop
