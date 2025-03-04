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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/sphincs/sphincsplus
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

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

#include "armv8/sphincs_fors_armv8.h"
#include "armv8/sphincs_merkle_armv8.h"
#include "armv8/sphincs_wots_armv8.h"

struct lc_sphincs_func_ctx {
	merkle_sign_f merkle_sign;
	merkle_gen_root_f merkle_gen_root;
	fors_sign_f fors_sign;
	fors_pk_from_sig_f fors_pk_from_sig;
	wots_pk_from_sig_f wots_pk_from_sig;
};

static const struct lc_sphincs_func_ctx f_ctx_c = {
	.merkle_sign = sphincs_merkle_sign_c,
	.merkle_gen_root = sphincs_merkle_gen_root_c,
	.fors_sign = fors_sign_c,
	.fors_pk_from_sig = fors_pk_from_sig_c,
	.wots_pk_from_sig = wots_pk_from_sig_c,
};

static const struct lc_sphincs_func_ctx f_ctx_avx2 __maybe_unused = {
	.merkle_sign = sphincs_merkle_sign_avx2,
	.merkle_gen_root = sphincs_merkle_gen_root_avx2,
	.fors_sign = fors_sign_avx2,
	.fors_pk_from_sig = fors_pk_from_sig_avx2,
	.wots_pk_from_sig = wots_pk_from_sig_avx2,
};

static const struct lc_sphincs_func_ctx f_ctx_armv8 __maybe_unused = {
	.merkle_sign = sphincs_merkle_sign_armv8,
	.merkle_gen_root = sphincs_merkle_gen_root_armv8,
	.fors_sign = fors_sign_armv8,
	.fors_pk_from_sig = fors_pk_from_sig_armv8,
	.wots_pk_from_sig = wots_pk_from_sig_armv8,
};

static const struct lc_sphincs_func_ctx *lc_sphincs_get_ctx(void)
{
	enum lc_cpu_features feat __maybe_unused = lc_cpu_feature_available();

#ifdef LC_HOST_X86_64
	if (feat & LC_CPU_FEATURE_INTEL_AVX2) {
		return &f_ctx_avx2;
	} else
#endif /* LC_HOST_X86_64 */
#if (defined(LC_HOST_AARCH64) && !defined(LINUX_KERNEL))
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

static int lc_sphincs_keypair_from_seed_internal(struct lc_sphincs_pk *pk,
						 struct lc_sphincs_sk *sk)
{
	const struct lc_sphincs_func_ctx *f_ctx = lc_sphincs_get_ctx();
	spx_ctx ctx;
	static int tested = 0;
	int ret;

	sphincs_selftest_keygen(&tested);

	/*
	 * Timecop: The SLH-DSA seed is sensitive.
	 */
	poison(sk, LC_SPX_SEEDBYTES);

	/* Initialize PUB_SEED of PK from SK . */
	memcpy(pk, sk->pk, LC_SPX_N);

	ctx.pub_seed = pk->pk;
	ctx.sk_seed = sk->sk_seed;

	/* Compute root node of the top-most subtree. */
	CKINT(f_ctx->merkle_gen_root(sk->pk + LC_SPX_N, &ctx));

	memcpy(pk->pk + LC_SPX_N, sk->pk + LC_SPX_N, LC_SPX_N);

	/*
	 * Timecop: Unmark the generated keys
	 */
	unpoison(sk, sizeof(*sk));
	unpoison(pk, sizeof(*pk));

	CKINT(lc_sphincs_pct_fips(pk, sk));

out:
	return ret;
}

/*
 * Generates an LC_SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
LC_INTERFACE_FUNCTION(int, lc_sphincs_keypair_from_seed,
		      struct lc_sphincs_pk *pk, struct lc_sphincs_sk *sk,
		      const uint8_t *seed, size_t seedlen)
{
	/*
	 * FIPS 205 does not allow key generation from seed, but we leave the
	 * API to allow a seamless transition from one to another algorithm
	 * usage.
	 */
#if 0
	int ret = 0;

	CKNULL(pk, -EINVAL);
	CKNULL(sk, -EINVAL);

	if (seedlen != LC_SPX_SEEDBYTES)
		return -EINVAL;

	/* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
	memcpy(sk, seed, LC_SPX_SEEDBYTES);

	CKINT(lc_sphincs_keypair_from_seed_internal(pk, sk));

out:
	return ret;
#else
	(void)pk;
	(void)sk;
	(void)seed;
	(void)seedlen;
	return -EOPNOTSUPP;
#endif
}

/*
 * Generates an LC_SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */

LC_INTERFACE_FUNCTION(int, lc_sphincs_keypair, struct lc_sphincs_pk *pk,
		      struct lc_sphincs_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKNULL(pk, -EINVAL);
	CKNULL(sk, -EINVAL);
	CKNULL(rng_ctx, -EINVAL);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, (uint8_t *)sk,
			      LC_SPX_SEEDBYTES));
	CKINT(lc_sphincs_keypair_from_seed_internal(pk, sk));

out:
	return ret;
}

/**
 * Returns an array containing a detached signature.
 */
LC_INTERFACE_FUNCTION(int, lc_sphincs_sign_ctx, struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx, const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_sk *sk,
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
	const struct lc_sphincs_func_ctx *f_ctx = lc_sphincs_get_ctx();
	spx_ctx ctx_int;
	const uint8_t *sk_prf = sk->sk_prf;
	const uint8_t *pk = sk->pk;
	uint8_t *wots_sig = sig->sight;
	static int tested = 0;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);

	sphincs_selftest_siggen(&tested);

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

	lc_hash_init(&ctx->sphincs_hash_ctx);

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
		lc_hash_set_digestsize(&ctx->sphincs_hash_ctx, 32);
#elif (LC_SPHINCS_NIST_CATEGORY == 3)
		lc_hash_set_digestsize(&ctx->sphincs_hash_ctx, 48);
#elif (LC_SPHINCS_NIST_CATEGORY == 5)
		lc_hash_set_digestsize(&ctx->sphincs_hash_ctx, 64);
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

/**
 * Verifies a detached signature and message under a given public key.
 */
LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_ctx,
		      const struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx, const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_pk *pk)
{
	struct workspace {
		uint64_t tree;
		uint32_t idx_leaf;
		uint32_t wots_addr[8];
		uint32_t tree_addr[8];
		uint32_t wots_pk_addr[8];
		uint8_t root[LC_SPX_N];
		uint8_t leaf[LC_SPX_N];
		uint8_t wots_pk[LC_SPX_WOTS_BYTES];
		uint8_t mhash[LC_SPX_FORS_MSG_BYTES];
	};
	unsigned int i;
	const struct lc_sphincs_func_ctx *f_ctx = lc_sphincs_get_ctx();
	spx_ctx ctx_int;
	const uint8_t *pub_root = pk->pk + LC_SPX_N;
	const uint8_t *wots_sig = sig->sight;
	static int tested = 0;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);

	sphincs_selftest_sigver(&tested);

	ctx_int.pub_seed = pk->pk;

	set_type(ws->wots_addr, LC_SPX_ADDR_TYPE_WOTS);
	set_type(ws->tree_addr, LC_SPX_ADDR_TYPE_HASHTREE);
	set_type(ws->wots_pk_addr, LC_SPX_ADDR_TYPE_WOTSPK);

	/* Derive the message digest and leaf index from R || PK || M. */
	/* The additional LC_SPX_N is a result of the hash domain separator. */
	CKINT(hash_message(ws->mhash, &ws->tree, &ws->idx_leaf, sig->r, pk->pk,
			   m, mlen, ctx));

	/* Layer correctly defaults to 0, so no need to set_layer_addr */
	set_tree_addr(ws->wots_addr, ws->tree);
	set_keypair_addr(ws->wots_addr, ws->idx_leaf);

	CKINT(f_ctx->fors_pk_from_sig(ws->root, sig->sigfors, ws->mhash,
				      &ctx_int, ws->wots_addr));

	/* For each subtree.. */
	for (i = 0; i < LC_SPX_D; i++) {
		set_layer_addr(ws->tree_addr, i);
		set_tree_addr(ws->tree_addr, ws->tree);

		copy_subtree_addr(ws->wots_addr, ws->tree_addr);
		set_keypair_addr(ws->wots_addr, ws->idx_leaf);

		copy_keypair_addr(ws->wots_pk_addr, ws->wots_addr);

		/*
		 * The WOTS public key is only correct if the signature was
		 * correct. Initially, root is the FORS pk, but on subsequent
		 * iterations it is the root of the subtree below the currently
		 * processed subtree.
		 */
		CKINT(f_ctx->wots_pk_from_sig(ws->wots_pk, wots_sig, ws->root,
					      &ctx_int, ws->wots_addr));
		wots_sig += LC_SPX_WOTS_BYTES;

		/* Compute the leaf node using the WOTS public key. */
		thash(ws->leaf, ws->wots_pk, LC_SPX_WOTS_LEN, pk->pk,
		      ws->wots_pk_addr);

		/* Compute the root node of this subtree. */
		compute_root(ws->root, ws->leaf, ws->idx_leaf, 0, wots_sig,
			     LC_SPX_TREE_HEIGHT, pk->pk, ws->tree_addr);
		wots_sig += LC_SPX_TREE_HEIGHT * LC_SPX_N;

		/* Update the indices for the next layer. */
		ws->idx_leaf = (ws->tree & ((1 << LC_SPX_TREE_HEIGHT) - 1));
		ws->tree = ws->tree >> LC_SPX_TREE_HEIGHT;
	}

	/* Check if the root node equals the root node in the public key. */
	if (lc_memcmp_secure(ws->root, sizeof(ws->root), pub_root, LC_SPX_N))
		ret = -EBADMSG;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify, const struct lc_sphincs_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_pk *pk)
{
	LC_SPHINCS_CTX_ON_STACK(sphincs_ctx);
	int ret = lc_sphincs_verify_ctx(sig, sphincs_ctx, m, mlen, pk);

	lc_sphincs_ctx_zero(sphincs_ctx);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_init, struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_pk *pk)
{
	/*
	 * We do not need the PK here - but we leave it to have a consistent
	 * API with ML-DSA.
	 */
	(void)pk;
	return lc_sphincs_sign_init(ctx, NULL);
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_update, struct lc_sphincs_ctx *ctx,
		      const uint8_t *m, size_t mlen)
{
	int ret = 0;

	CKNULL(ctx, -EINVAL);

	lc_hash_update(&ctx->sphincs_hash_ctx, m, mlen);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_final,
		      const struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_pk *pk)
{
	uint8_t digest[LC_SHA3_512_SIZE_DIGEST];
	int ret;

	CKNULL(ctx, -EINVAL);

	/*
	 * Catch SHAKE algos and set the digestsize following the
	 * specification.
	 */
	if (!lc_hash_digestsize(&ctx->sphincs_hash_ctx)) {
#if (LC_SPHINCS_NIST_CATEGORY == 1)
		lc_hash_set_digestsize(&ctx->sphincs_hash_ctx, 32);
#elif (LC_SPHINCS_NIST_CATEGORY == 3)
		lc_hash_set_digestsize(&ctx->sphincs_hash_ctx, 48);
#elif (LC_SPHINCS_NIST_CATEGORY == 5)
		lc_hash_set_digestsize(&ctx->sphincs_hash_ctx, 64);
#else
#error "Unknown NIST category"
#endif
	}

	/* Should never happen */
	if (lc_hash_digestsize(&ctx->sphincs_hash_ctx) > sizeof(digest))
		return -EFAULT;

	lc_hash_final(&ctx->sphincs_hash_ctx, digest);

	ret = lc_sphincs_verify_ctx(sig, ctx, digest,
				    lc_hash_digestsize(&ctx->sphincs_hash_ctx),
				    pk);

	/* Zeroize hash context in case of successful signature operation */
	if (!ret || ret == -EBADMSG)
		lc_hash_zero(&ctx->sphincs_hash_ctx);

out:
	return ret;
}
