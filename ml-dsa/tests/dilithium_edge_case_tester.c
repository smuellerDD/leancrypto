/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "compare.h"
#include "dilithium_edge_case_tester.h"
#include "ext_headers.h"
#include "lc_sha256.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

/*
 * Enable to generate keys / signatures.
 */
#undef GENERATE_KEYS

#ifdef GENERATE_KEYS
#if LC_DILITHIUM_MODE == 2
#include "dilithium_rejection_upstream_vectors_44.h"
#elif LC_DILITHIUM_MODE == 3
#include "dilithium_rejection_upstream_vectors_65.h"
#elif LC_DILITHIUM_MODE == 5
#include "dilithium_rejection_upstream_vectors_87.h"
#endif
#else
#if LC_DILITHIUM_MODE == 2
#include "dilithium_rejection_vectors_44.h"
#elif LC_DILITHIUM_MODE == 3
#include "dilithium_rejection_vectors_65.h"
#elif LC_DILITHIUM_MODE == 5
#include "dilithium_rejection_vectors_87.h"
#endif
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifdef GENERATE_KEYS
static void printf_bin(const uint8_t *data, size_t datalen, const char *label)
{
	size_t i;

	printf("\t\t.%s = {\n\t\t\t", label);
	for (i = 0; i < datalen; ++i) {
		printf("0x%02x, ", data[i]);
		if (i && !((i + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n");
}

static int dilithium_edge_tester_internal(
	const struct dilithium_rejection_testvector *tc,
	int (*_lc_dilithium_sign_ctx)(struct lc_dilithium_sig *sig,
				      struct lc_dilithium_ctx *ctx,
				      const uint8_t *m, size_t mlen,
				      const struct lc_dilithium_sk *sk,
				      struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sk sk;
		struct lc_dilithium_sig sig;
	};
	uint8_t digest[LC_SHA256_SIZE_DIGEST];
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha256);
	int ret = 0;

	ctx->ml_dsa_internal = 1;

	CKINT(lc_dilithium_keypair_from_seed(&ws->pk, &ws->sk, tc->seed,
					     sizeof(tc->seed)));

	/* SHA256(pk) */
	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, ws->pk.pk, sizeof(ws->pk.pk));
	lc_hash_update(hash_ctx, ws->sk.sk, sizeof(ws->sk.sk));
	lc_hash_final(hash_ctx, digest);
	lc_hash_zero(hash_ctx);
	ret = lc_compare(digest, tc->key_hash, LC_SHA256_SIZE_DIGEST,
			 "Key hash");
	if (ret)
		goto out;

	CKINT(_lc_dilithium_sign_ctx(&ws->sig, ctx, tc->msg, sizeof(tc->msg),
				     &ws->sk, NULL));

	/* SHA256(sig) */
	lc_hash(lc_sha256, ws->sig.sig, sizeof(ws->sig.sig), digest);
	ret = lc_compare(digest, tc->sig_hash, LC_SHA256_SIZE_DIGEST,
			 "Signature hash");
	if (ret)
		goto out;

	printf("\t{\n");
	printf_bin(tc->seed, sizeof(tc->seed), "seed");
	printf_bin(ws->pk.pk, sizeof(ws->pk.pk), "pk");
	printf_bin(ws->sk.sk, sizeof(ws->sk.sk), "sk");
	printf_bin(tc->key_hash, sizeof(tc->key_hash), "key_hash");
	printf_bin(tc->msg, sizeof(tc->msg), "msg");
	printf_bin(tc->sig_hash, sizeof(tc->sig_hash), "sig_hash");
	printf_bin(ws->sig.sig, sizeof(ws->sig.sig), "sig");
	printf("\t},\n");

out:
	LC_RELEASE_MEM(ws);
	return ret ? 1 : 0;
}

#else

static int dilithium_edge_tester_internal(
	const struct dilithium_rejection_testvector *tc,
	int (*_lc_dilithium_sign_ctx)(struct lc_dilithium_sig *sig,
				      struct lc_dilithium_ctx *ctx,
				      const uint8_t *m, size_t mlen,
				      const struct lc_dilithium_sk *sk,
				      struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_dilithium_sig sig;
	};
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	int ret = 0;

	ctx->ml_dsa_internal = 1;

	CKINT(_lc_dilithium_sign_ctx(&ws->sig, ctx, tc->msg, sizeof(tc->msg),
				     (struct lc_dilithium_sk *)tc->sk, NULL));
	ret = lc_compare(ws->sig.sig, tc->sig, sizeof(tc->sig), "Signature");
	if (ret)
		goto out;

out:
	LC_RELEASE_MEM(ws);
	return ret ? 1 : 0;
}
#endif

int dilithium_edge_tester(int (*_lc_dilithium_sign_ctx)(
	struct lc_dilithium_sig *sig, struct lc_dilithium_ctx *ctx,
	const uint8_t *m, size_t mlen, const struct lc_dilithium_sk *sk,
	struct lc_rng_ctx *rng_ctx))
{
	unsigned int i;
	int ret = 0;

#ifdef GENERATE_KEYS
	printf("#ifndef DILITHIUM_REJECTION_VECTORS_H\n"
	       "#define DILITHIUM_REJECTION_VECTORS_H\n"
	       "#include \"dilithium_type.h\"\n"
	       "struct dilithium_rejection_testvector {\n"
	       "\tuint8_t seed[LC_DILITHIUM_SEEDBYTES];\n"
	       "\tuint8_t pk[LC_DILITHIUM_PUBLICKEYBYTES];\n"
	       "\tuint8_t sk[LC_DILITHIUM_SECRETKEYBYTES];\n"
	       "\tuint8_t key_hash[LC_SHA256_SIZE_DIGEST];\n"
	       "\tuint8_t msg[32];\n"
	       "\tuint8_t sig_hash[LC_SHA256_SIZE_DIGEST];\n"
	       "\tuint8_t sig[LC_DILITHIUM_CRYPTO_BYTES];\n"
	       "};\n\n"
	       "static const struct\n"
	       "dilithium_rejection_testvector dilithium_rejection_testvectors[] =\n"
	       "{\n");
#endif

	for (i = 0; i < ARRAY_SIZE(dilithium_rejection_testvectors); i++)
		ret += dilithium_edge_tester_internal(
			&dilithium_rejection_testvectors[i],
			_lc_dilithium_sign_ctx);

#ifdef GENERATE_KEYS
	printf("};\n");
	printf("#endif\n");
#endif

	return ret;
}
