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
/*
 * This code checks the leancrypto implementation against the test vectors
 * provided with
 * https://github.com/post-quantum-cryptography/KAT/tree/main/MLDSA
 *
 * To execute; use the following commands:
 *
 * pure ML-DSA:
 *
 * for i in "*pure*"
 * do
 *	build/internal/tests/tester_kat -f $i
 *	if [ $? -ne 0 ]
 *		then echo $i FAILED
 *		break
 *	fi
 * done
 *
 *
 * ML-DSA.Sign_internal and ML-DSA.Verify_internal:
 *
 * for i in "*raw*"
 * do
 *	build/internal/tests/tester_kat --internal -f $i
 *	if [ $? -ne 0 ]
 *		then echo $i FAILED
 *		break
 *	fi
 * done
 *
 *
 * HashML-DSA:
 *
 * for i in "*hashed*"
 * do
 *	build/internal/tests/tester_kat --prehash -f $i
 *	if [ $? -ne 0 ]
 *		then echo $i FAILED
 *		break
 *	fi
 * done
 *
 */

#define _POSIX_C_SOURCE 200112L
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "binhexbin.h"
#include "compare.h"
#include "lc_dilithium.h"
#include "lc_sha256.h"
#include "lc_sha512.h"
#include "ret_checkers.h"
#include "static_rng.h"

struct lc_buffer {
	uint8_t *buf;
	size_t len;
};

#define LC_BUF_FREE_NULL(x)                                                    \
	if (x) {                                                               \
		free((x)->buf);                                                \
		(x)->buf = NULL;                                               \
		(x)->len = 0;                                                  \
	}

static char *get_val(char *str, const char *delim)
{
	char *ret = NULL;
	char *tmp = NULL;
	char *saveptr = NULL;

	ret = strtok_r(str, delim, &saveptr);
	if (!ret)
		return ret;
	/* get the string after the delimiter */
	ret = strtok_r(NULL, delim, &saveptr);
	if (!ret)
		return ret;

	while (*ret != '\0' && isblank(*ret))
		ret++;

	/* remove trailing \n or \r*/
	tmp = ret;
	tmp += strlen(tmp) - 1;
	while ((*tmp == '\n' || *tmp == '\r' || *tmp == ']' || isblank(*tmp)) &&
	       tmp >= ret) {
		*tmp = '\0';
		tmp--;
	}

	return ret;
}

static int get_binval(char *str, const char *delim, struct lc_buffer *buf)
{
	char *hex = NULL;

	if (buf->buf || buf->len) {
		printf("Buffer not empty, refusing to allocate new!\n");
		return -EFAULT;
	}

	hex = get_val(str, delim);

	if (strlen(hex))
		return hex2bin_alloc(hex, strlen(hex), &buf->buf, &buf->len);
	return 0;
}

static void lc_test_compare(const uint8_t *act, size_t actlen,
			    const uint8_t *exp, size_t explen, const char *info)
{
	if (actlen != explen) {
		printf("%s - Size mismatch: expected %zu, actual %zu\n", info,
		       explen, actlen);
	}

	lc_compare(act, exp, actlen, info);
}

struct lc_mldsa_kat {
	struct lc_buffer xi;
	struct lc_buffer rng;
	struct lc_buffer pk;
	struct lc_buffer sk;
	struct lc_buffer m;
	struct lc_buffer sig;
	struct lc_buffer ctx;
};

struct lc_mldsa_test_def {
	FILE *infile;
	int prehash;
	int internal;
};

static void lc_mldsa_kat(struct lc_mldsa_kat *kat)
{
	if (!kat)
		return;

	LC_BUF_FREE_NULL(&kat->xi);
	LC_BUF_FREE_NULL(&kat->rng);
	LC_BUF_FREE_NULL(&kat->pk);
	LC_BUF_FREE_NULL(&kat->sk);
	LC_BUF_FREE_NULL(&kat->m);
	LC_BUF_FREE_NULL(&kat->sig);
	LC_BUF_FREE_NULL(&kat->ctx);
}

static int lc_hash_msg(struct lc_buffer *msg, struct lc_dilithium_ctx *ctx,
		       enum lc_dilithium_type type)
{
	struct lc_buffer tmp = { 0 };
	int ret = 0;

	switch (type) {
	case LC_DILITHIUM_87:
		tmp.buf = malloc(LC_SHA512_SIZE_DIGEST);
		CKNULL(tmp.buf, -ENOMEM);
		tmp.len = LC_SHA512_SIZE_DIGEST;
		lc_hash(lc_sha512, msg->buf, msg->len, tmp.buf);
		lc_dilithium_ctx_hash(ctx, lc_sha512);
		break;
	case LC_DILITHIUM_65:
		tmp.buf = malloc(LC_SHA384_SIZE_DIGEST);
		CKNULL(tmp.buf, -ENOMEM);
		tmp.len = LC_SHA384_SIZE_DIGEST;
		lc_hash(lc_sha384, msg->buf, msg->len, tmp.buf);
		lc_dilithium_ctx_hash(ctx, lc_sha384);
		break;
	case LC_DILITHIUM_44:
		tmp.buf = malloc(LC_SHA256_SIZE_DIGEST);
		CKNULL(tmp.buf, -ENOMEM);
		tmp.len = LC_SHA256_SIZE_DIGEST;
		lc_hash(lc_sha256, msg->buf, msg->len, tmp.buf);
		lc_dilithium_ctx_hash(ctx, lc_sha256);
		break;
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EINVAL;
	}

	msg->buf = tmp.buf;
	msg->len = tmp.len;

out:
	return ret;
}

static int lc_exec_mldsa_verify_kat(const struct lc_mldsa_test_def *def,
				    struct lc_mldsa_kat *kat)
{
	struct lc_dilithium_pk pk;
	struct lc_dilithium_sig sig;
	struct lc_buffer msg = { .buf = kat->m.buf, .len = kat->m.len };
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(ctx);

	if (kat->m.len > kat->sig.len) {
		printf("Wrong data size\n");
		return -EINVAL;
	}

	CKINT_LOG(lc_dilithium_pk_load(&pk, kat->pk.buf, kat->pk.len),
		  "Loading of PK failed (size %zu)\n", kat->pk.len);
	CKINT_LOG(lc_dilithium_sig_load(&sig, kat->sig.buf,
					kat->sig.len - kat->m.len),
		  "Loading of signature failed (size %zu)\n",
		  kat->sig.len - kat->m.len);

	if (def->internal)
		lc_dilithium_ctx_internal(ctx);
	if (def->prehash) {
		CKINT(lc_hash_msg(&msg, ctx, lc_dilithium_pk_type(&pk)));
	}

	lc_dilithium_ctx_userctx(ctx, kat->ctx.buf, kat->ctx.len);

	CKINT(lc_dilithium_verify_ctx(&sig, ctx, msg.buf, msg.len, &pk));

out:
	if (msg.buf != kat->m.buf)
		free(msg.buf);
	return ret;
}

static int lc_exec_mldsa_sign_kat(const struct lc_mldsa_test_def *def,
				  struct lc_mldsa_kat *kat)
{
	struct lc_dilithium_pk pk = { 0 }, pk2 = { 0 };
	struct lc_dilithium_sk sk = { 0 };
	struct lc_dilithium_sig sig = { 0 };
	struct lc_static_rng_data static_data = {
		.seed = kat->rng.buf,
		.seedlen = kat->rng.len,
	};
	struct lc_buffer msg = { .buf = kat->m.buf, .len = kat->m.len };
	uint8_t *ptr;
	size_t plen;
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	LC_STATIC_DRNG_ON_STACK(sdrng, &static_data);

	if (kat->m.len > kat->sig.len) {
		printf("Wrong data size\n");
		return -EINVAL;
	}

	CKINT_LOG(lc_dilithium_pk_load(&pk2, kat->pk.buf, kat->pk.len),
		  "Loading of PK failed (size %zu)\n", kat->pk.len);

	CKINT_LOG(lc_dilithium_keypair_from_seed(&pk, &sk, kat->xi.buf,
						 kat->xi.len,
						 lc_dilithium_pk_type(&pk2)),
		  "Dilithium keypair generation failed: %d\n", ret);

	CKINT(lc_dilithium_pk_ptr(&ptr, &plen, &pk));
	lc_test_compare(ptr, plen, kat->pk.buf, kat->pk.len, "PK");
	CKINT(lc_dilithium_sk_ptr(&ptr, &plen, &sk));
	lc_test_compare(ptr, plen, kat->sk.buf, kat->sk.len, "SK");

	if (def->internal)
		lc_dilithium_ctx_internal(ctx);
	if (def->prehash) {
		CKINT(lc_hash_msg(&msg, ctx, lc_dilithium_pk_type(&pk)));
	}

	lc_dilithium_ctx_userctx(ctx, kat->ctx.buf, kat->ctx.len);

	CKINT(lc_dilithium_sign_ctx(&sig, ctx, msg.buf, msg.len, &sk,
				    kat->rng.len ? &sdrng : NULL));
	CKINT(lc_dilithium_sig_ptr(&ptr, &plen, &sig));
	lc_test_compare(ptr, plen, kat->sig.buf, kat->sig.len - kat->m.len,
			"SIG");

out:
	if (msg.buf != kat->m.buf)
		free(msg.buf);
	return ret;
}

static int lc_parse_mldsa_kat(const struct lc_mldsa_test_def *def)
{
	struct lc_mldsa_kat kat = { 0 };
	char buf[16384];
	int ret = 0;

	while (fgets(buf, sizeof(buf), def->infile)) {
		if (strstr(buf, "xi =")) {
			CKINT(get_binval(buf, "=", &kat.xi));
		}
		if (strstr(buf, "rng =")) {
			CKINT(get_binval(buf, "=", &kat.rng));
		}
		if (strstr(buf, "pk =")) {
			CKINT(get_binval(buf, "=", &kat.pk));
		}
		if (strstr(buf, "sk =")) {
			CKINT(get_binval(buf, "=", &kat.sk));
		}
		if (strstr(buf, "msg =")) {
			CKINT(get_binval(buf, "=", &kat.m));
		}
		if (strstr(buf, "sm =")) {
			CKINT(get_binval(buf, "=", &kat.sig));
		}
		if (strstr(buf, "ctx =")) {
			CKINT(get_binval(buf, "=", &kat.ctx));
		}

		if (strstr(buf, "count =")) {
			if (kat.xi.buf && kat.pk.buf && kat.sk.buf &&
			    kat.m.buf && kat.sig.buf) {
				printf("Starting testing\n");
				CKINT(lc_exec_mldsa_sign_kat(def, &kat));
				CKINT(lc_exec_mldsa_verify_kat(def, &kat));
			}

			printf("Starting testing for count %s\n",
			       get_val(buf, "="));

			lc_mldsa_kat(&kat);
			continue;
		}
	}

out:
	lc_mldsa_kat(&kat);
	return ret;
}

int main(int argc, char *argv[])
{
	struct lc_mldsa_test_def def = { 0 };
	int c = 0, ret;

	while (1) {
		int opt_index = 0;
		static struct option options[] = {
			{ "file", required_argument, 0, 'f' },
			{ "prehash", no_argument, 0, 0 },
			{ "internal", no_argument, 0, 0 },

			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "f:", options, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* file */
				if (def.infile) {
					printf("Cannot allocate infile twice\n");
					ret = -EINVAL;
					goto out;
				}
				def.infile = fopen(optarg, "r+");
				if (!def.infile) {
					ret = -errno;

					printf("Opening of file %s failed: %d\n",
					       optarg, ret);
					goto out;
				}
				break;
			case 1:
				/* prehash */
				def.prehash = 1;
				break;
			case 2:
				/* internal */
				def.internal = 1;
				break;

			default:
				ret = -EINVAL;
				goto out;
				break;
			}
			break;

		case 'f':
			/* file */
			if (def.infile) {
				printf("Cannot allocate infile twice\n");
				ret = -EINVAL;
				goto out;
			}
			def.infile = fopen(optarg, "r+");
			if (!def.infile) {
				ret = errno;

				printf("Opening of file %s failed: %d\n",
				       optarg, ret);
				goto out;
			}
			break;

		default:
			ret = -EINVAL;
			goto out;
			break;
		}
	}

	CKINT(lc_parse_mldsa_kat(&def));

out:
	if (def.infile)
		fclose(def.infile);

	return -ret;
}
