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
#include "lc_dilithium.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

#ifdef LC_DILITHIUM_TYPE_65
#define DILITHIUM_TYPE LC_DILITHIUM_65
#elif defined(LC_DILITHIUM_TYPE_44)
#define DILITHIUM_TYPE LC_DILITHIUM_44
#else
#define DILITHIUM_TYPE LC_DILITHIUM_87
#endif

static int dilithium_tester_official(void)
{
	struct workspace {
		struct lc_dilithium_sk sk;
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sig sig;
		uint8_t msg[10];
	};
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	int ret = 0;

	/* One-shot */
	CKINT(lc_dilithium_keypair(&ws->pk, &ws->sk, lc_seeded_rng,
				   DILITHIUM_TYPE));
	CKINT(lc_dilithium_sign(&ws->sig, ws->msg, sizeof(ws->msg), &ws->sk,
				lc_seeded_rng));
	CKINT(lc_dilithium_verify(&ws->sig, ws->msg, sizeof(ws->msg), &ws->pk));

	/* Stream operation */
	CKINT_LOG(lc_dilithium_sign_init(hash_ctx, &ws->sk),
		  "Sign init failed - ret %d\n", ret);
	CKINT_LOG(lc_dilithium_sign_update(hash_ctx, ws->msg, sizeof(ws->msg)),
		  "Sign update failed - ret %u\n", ret);
	CKINT_LOG(lc_dilithium_sign_final(&ws->sig, hash_ctx, &ws->sk,
					  lc_seeded_rng),
		  "Sign final failed - ret %u\n", ret);

	CKINT_LOG(lc_dilithium_verify_init(hash_ctx, &ws->pk),
		  "Verify init failed - ret %u\n", ret);
	CKINT_LOG(lc_dilithium_verify_update(hash_ctx, ws->msg,
					     sizeof(ws->msg)),
		  "Verify update failed - ret %u\n", ret);
	CKINT_LOG(lc_dilithium_verify_final(&ws->sig, hash_ctx, &ws->pk),
		  "Signature verification stream operatino fialed - ret: %d\n",
		  ret);

out:
	LC_RELEASE_MEM(ws);
	lc_hash_zero(hash_ctx);
	;
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return !!dilithium_tester_official();
}
