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

#include "alignment.h"
#include "build_bug_on.h"
#include "compare.h"
#include "cpufeatures.h"
#include "helper.h"
#include "lc_rng.h"
#include "lc_memcmp_secure.h"
#include "lc_memcpy_secure.h"
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

struct lc_sphincs_keygen_func_ctx {
	merkle_gen_root_f merkle_gen_root;
};

static const struct lc_sphincs_keygen_func_ctx f_ctx_c = {
	.merkle_gen_root = sphincs_merkle_gen_root_c,
};

static const struct lc_sphincs_keygen_func_ctx f_ctx_avx2 __maybe_unused = {
	.merkle_gen_root = sphincs_merkle_gen_root_avx2,
};

#if defined(LC_HOST_AARCH64)
static const struct lc_sphincs_keygen_func_ctx f_ctx_armv8 __maybe_unused = {
	.merkle_gen_root = sphincs_merkle_gen_root_armv8,
};
#endif

static const struct lc_sphincs_keygen_func_ctx *lc_sphincs_keygen_get_ctx(void)
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

static int lc_sphincs_keypair_from_seed_internal(struct lc_sphincs_pk *pk,
						 struct lc_sphincs_sk *sk)
{
	struct workspace {
		uint8_t sk_seed_aligned[sizeof(sk->sk_seed)] __align(
			sizeof(uint64_t));
		uint8_t pk_aligned[sizeof(pk->pk)] __align(sizeof(uint64_t));
	};
	const struct lc_sphincs_keygen_func_ctx *f_ctx =
		lc_sphincs_keygen_get_ctx();
	spx_ctx ctx;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/*
	 * Timecop: The SLH-DSA seed is sensitive.
	 */
	poison(sk, LC_SPX_SEEDBYTES);

	/* Initialize PUB_SEED of PK from SK . */
	memcpy(pk, sk->pk, LC_SPX_N);

	/*
	 * When using the ctx in the AVX2 code path, it is type-casted into
	 * a 64 bit integer.
	 */
	if (aligned(sk->sk_seed, sizeof(uint64_t) - 1)) {
		ctx.sk_seed = sk->sk_seed;
	} else {
		lc_memcpy_secure(ws->sk_seed_aligned,
				 sizeof(ws->sk_seed_aligned), sk->sk_seed,
				 sizeof(sk->sk_seed));
		ctx.sk_seed = ws->sk_seed_aligned;
	}

	if (aligned(pk->pk, sizeof(uint64_t) - 1)) {
		ctx.pub_seed = pk->pk;
	} else {
		lc_memcpy_secure(ws->pk_aligned, sizeof(ws->pk_aligned), pk,
				 sizeof(sk->pk));
		ctx.pub_seed = ws->pk_aligned;
	}

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
	LC_RELEASE_MEM(ws);
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

	sphincs_selftest_keygen();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SLHDSA_KEYGEN);

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

LC_INTERFACE_FUNCTION(int, lc_sphincs_pk_from_sk, struct lc_sphincs_pk *pk,
		      const struct lc_sphincs_sk *sk)
{
	int ret = 0;

	CKNULL(pk, -EINVAL);
	CKNULL(sk, -EINVAL);

	BUILD_BUG_ON(sizeof(sk->pk) != sizeof(pk->pk));

	memcpy(pk->pk, sk->pk, sizeof(pk->pk));

out:
	return ret;
}

/*
 * Generates an LC_SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */

int lc_sphincs_keypair_nocheck(struct lc_sphincs_pk *pk,
			       struct lc_sphincs_sk *sk,
			       struct lc_rng_ctx *rng_ctx)
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

LC_INTERFACE_FUNCTION(int, lc_sphincs_keypair, struct lc_sphincs_pk *pk,
		      struct lc_sphincs_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	sphincs_selftest_keygen();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SLHDSA_KEYGEN);

	return lc_sphincs_keypair_nocheck(pk, sk, rng_ctx);
}
