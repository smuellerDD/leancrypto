/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/sphincs/sphincsplus
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "build_bug_on.h"
#include "compare.h"
#include "cpufeatures.h"
#include "helper.h"
#include "lc_rng.h"
#include "lc_memcmp_secure.h"
#include "signature_domain_separation.h"
#include "small_stack_support.h"
#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_fors.h"
#include "sphincs_hash.h"
#include "sphincs_internal.h"
#include "sphincs_merkle.h"
#include "sphincs_pct.h"
#include "sphincs_selftest.h"
#include "sphincs_thash.h"
#include "sphincs_utils.h"
#include "sphincs_wots.h"
#include "timecop.h"
#include "ret_checkers.h"
#include "visibility.h"

#include "avx2/sphincs_fors_avx2.h"
#include "avx2/sphincs_merkle_avx2.h"
#include "avx2/sphincs_wots_avx2.h"

#if defined(LC_HOST_AARCH64)
#include "armv8/sphincs_fors_armv8.h"
#include "armv8/sphincs_merkle_armv8.h"
#include "armv8/sphincs_wots_armv8.h"
#endif

struct lc_sphincs_siggen_func_ctx {
	merkle_sign_f merkle_sign;
	fors_sign_f fors_sign;
};

static const struct lc_sphincs_siggen_func_ctx f_ctx_c = {
	.merkle_sign = sphincs_merkle_sign_c,
	.fors_sign = fors_sign_c,
};

static const struct lc_sphincs_siggen_func_ctx f_ctx_avx2 __maybe_unused = {
	.merkle_sign = sphincs_merkle_sign_avx2,
	.fors_sign = fors_sign_avx2,
};

#if defined(LC_HOST_AARCH64)
static const struct lc_sphincs_siggen_func_ctx f_ctx_armv8 __maybe_unused = {
	.merkle_sign = sphincs_merkle_sign_armv8,
	.fors_sign = fors_sign_armv8,
};
#endif

static const struct lc_sphincs_siggen_func_ctx *lc_sphincs_siggen_get_ctx(void)
{
	enum lc_cpu_features feat __maybe_unused = lc_cpu_feature_available();

#if (defined(LC_HOST_X86_64) && !defined(LC_SPHINCS_TYPE_128F_ASCON) &&        \
     !defined(LC_SPHINCS_TYPE_128S_ASCON))
	if (feat & LC_CPU_FEATURE_INTEL_AVX2) {
		return &f_ctx_avx2;
	} else
#endif /* LC_HOST_X86_64 */
#if (defined(LC_HOST_AARCH64) && !defined(LINUX_KERNEL) &&                     \
     !defined(LC_SPHINCS_TYPE_128F_ASCON) &&                                   \
     !defined(LC_SPHINCS_TYPE_128S_ASCON))
		/*
		 * TODO See issue in Kbuild.slh-dsa - enable NEON intrinsics
		 * for the Linux kernel.
		 */
		if (feat & LC_CPU_FEATURE_ARM_NEON) {
			return &f_ctx_armv8;
		}
#endif /* LC_HOST_AARCH64 */

	return &f_ctx_c;
}

/**
 * Returns an array containing a detached signature.
 */
int lc_sphincs_sign_ctx_nocheck(struct lc_sphincs_sig *sig,
				struct lc_sphincs_ctx *ctx, const uint8_t *m,
				size_t mlen, const struct lc_sphincs_sk *sk,
				struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		uint64_t tree;
		uint32_t idx_leaf;
		uint32_t wots_addr[8];
		uint32_t tree_addr[8];
		uint8_t optrand[LC_SPX_N];
		uint8_t root[LC_SPX_N];
		uint8_t mhash[LC_SPX_FORS_MSG_BYTES];
	};
	uint32_t i;
	const struct lc_sphincs_siggen_func_ctx *f_ctx = lc_sphincs_siggen_get_ctx();
	spx_ctx ctx_int;
	const uint8_t *sk_prf = sk->sk_prf;
	const uint8_t *pk = sk->pk;
	uint8_t *wots_sig = sig->sight;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);

	/*
	 * Timecop: secret key is sensitive
	 */
	poison(sk, 2 * LC_SPX_N);

	ctx_int.sk_seed = sk->sk_seed;
	ctx_int.pub_seed = pk;

	set_type(ws->wots_addr, LC_SPX_ADDR_TYPE_WOTS);
	set_type(ws->tree_addr, LC_SPX_ADDR_TYPE_HASHTREE);

	if (rng_ctx) {
		CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->optrand,
				      sizeof(ws->optrand)));
	} else {
		memcpy(ws->optrand, pk, sizeof(ws->optrand));
	}

	/* Compute the digest randomization value. */
	CKINT(gen_message_random(sig->r, sk_prf, ws->optrand, m, mlen, ctx));

	/*
	 * Timecopy: signature randomness part is not sensitive.
	 */
	unpoison(sig->r, LC_SPX_N);

	/* Derive the message digest and leaf index from R, PK and M. */
	CKINT(hash_message(ws->mhash, &ws->tree, &ws->idx_leaf, sig->r, pk, m,
			   mlen, ctx));

	set_tree_addr(ws->wots_addr, ws->tree);
	set_keypair_addr(ws->wots_addr, ws->idx_leaf);

	/* Sign the message hash using FORS. */
	CKINT(f_ctx->fors_sign(sig->sigfors, ws->root, ws->mhash, &ctx_int,
			       ws->wots_addr));

	/*
	 * Timecop:
	 *
	 * According to the original authors of the Sphincs+ code, ws->root
	 * is a public information (see
	 * https://github.com/sphincs/sphincsplus/issues/63#issuecomment-2694902727). This would imply we could call
	 * unpoison(ws->root, sizeof(ws->root)); at this point which would
	 * remove the Valgrind side channel complaints in the wots_gen_leaf
	 * functions. However, we try to err on the conservative side and
	 * do want to have as little side channels as possible. This implies
	 * that conditional code dependent on the ws->root is replaced.
	 */

	for (i = 0; i < LC_SPX_D; i++) {
		set_layer_addr(ws->tree_addr, i);
		set_tree_addr(ws->tree_addr, ws->tree);

		copy_subtree_addr(ws->wots_addr, ws->tree_addr);
		set_keypair_addr(ws->wots_addr, ws->idx_leaf);

		CKINT(f_ctx->merkle_sign(wots_sig, ws->root, &ctx_int,
					 ws->wots_addr, ws->tree_addr,
					 ws->idx_leaf));
		wots_sig += LC_SPX_WOTS_BYTES + LC_SPX_TREE_HEIGHT * LC_SPX_N;

		/* Update the indices for the next layer. */
		ws->idx_leaf = (ws->tree & ((1 << LC_SPX_TREE_HEIGHT) - 1));
		ws->tree = ws->tree >> LC_SPX_TREE_HEIGHT;
	}

out:
	unpoison(sk, sizeof(*sk));
	unpoison(sig, sizeof(*sig));

	if (ret && sig)
		lc_memset_secure(sig, 0, sizeof(struct lc_sphincs_sig));
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign_ctx, struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx, const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	sphincs_selftest_siggen();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SLHDSA_SIGGEN);

	return lc_sphincs_sign_ctx_nocheck(sig, ctx, m, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign, struct lc_sphincs_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	LC_SPHINCS_CTX_ON_STACK(sphincs_ctx);
	int ret = lc_sphincs_sign_ctx(sig, sphincs_ctx, m, mlen, sk, rng_ctx);

	lc_sphincs_ctx_zero(sphincs_ctx);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign_init, struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_sk *sk)
{
	int ret = 0;

	/*
	 * We do not need the SK here - but we leave it to have a consistent
	 * API with ML-DSA.
	 */
	(void)sk;

	CKNULL(ctx, -EINVAL);

	sphincs_selftest_siggen();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SLHDSA_SIGGEN);

	if (!ctx->sphincs_prehash_type) {
#if (LC_SPHINCS_NIST_CATEGORY == 1)
		ctx->sphincs_prehash_type = lc_sha3_256;
#elif (LC_SPHINCS_NIST_CATEGORY == 3)
		ctx->sphincs_prehash_type = lc_sha3_384;
#elif (LC_SPHINCS_NIST_CATEGORY == 5)
		ctx->sphincs_prehash_type = lc_sha3_512;
#else
#error "Unknown NIST category"
#endif
	}

	/*
	 * If the prehash type was set, we do not check it here, but the
	 * signature_domain_separation function will force the proper hash.
	 */

	/* Initialize the hash */
	LC_HASH_SET_CTX((&ctx->sphincs_hash_ctx), ctx->sphincs_prehash_type);

	CKINT(lc_hash_init(&ctx->sphincs_hash_ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign_update, struct lc_sphincs_ctx *ctx,
		      const uint8_t *m, size_t mlen)
{
	int ret = 0;

	CKNULL(ctx, -EINVAL);

	lc_hash_update(&ctx->sphincs_hash_ctx, m, mlen);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign_final, struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	uint8_t digest[LC_SHA3_512_SIZE_DIGEST];
	int ret;

	CKNULL(ctx, -EINVAL);

	/*
	 * Detect SHAKE algos and set the digest size following the
	 * specification.
	 */
	if (!lc_hash_digestsize(&ctx->sphincs_hash_ctx)) {
#if (LC_SPHINCS_NIST_CATEGORY == 1)
		CKINT(lc_hash_set_digestsize(&ctx->sphincs_hash_ctx, 32));
#elif (LC_SPHINCS_NIST_CATEGORY == 3)
		CKINT(lc_hash_set_digestsize(&ctx->sphincs_hash_ctx, 48));
#elif (LC_SPHINCS_NIST_CATEGORY == 5)
		CKINT(lc_hash_set_digestsize(&ctx->sphincs_hash_ctx, 64));
#else
#error "Unknown NIST category"
#endif
	}

	/* Should never happen */
	if (lc_hash_digestsize(&ctx->sphincs_hash_ctx) > sizeof(digest))
		return -EFAULT;

	lc_hash_final(&ctx->sphincs_hash_ctx, digest);

	ret = lc_sphincs_sign_ctx(sig, ctx, digest,
				  lc_hash_digestsize(&ctx->sphincs_hash_ctx),
				  sk, rng_ctx);

	/* Zeroize hash context in case of successful signature operation */
	if (!ret)
		lc_hash_zero(&ctx->sphincs_hash_ctx);

out:
	return ret;
}
