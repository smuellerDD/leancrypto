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

#include "compare.h"
#include "lc_kyber.h"
#include "lc_rng.h"
#include "small_stack_support.h"
#include "timecop.h"
#include "visibility.h"

static int kyber_official(enum lc_kyber_type type)
{
	struct workspace {
		struct lc_kyber_sk sk;
		struct lc_kyber_pk pk;
		struct lc_kyber_ct ct;
		uint8_t ss[5], ss2[5];
	};
	int ret = 1;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (lc_kyber_keypair(&ws->pk, &ws->sk, lc_seeded_rng, type))
		goto out;

	if (ws->pk.kyber_type != type || ws->sk.kyber_type != type) {
		printf("Kyber type error pk/sk\n");
		goto out;
	}

	/* modify type to get error */
	ws->pk.kyber_type = 123;
	if (lc_kyber_enc_kdf(&ws->ct, ws->ss, sizeof(ws->ss), &ws->pk) !=
	    -EOPNOTSUPP) {
		printf("Unexpected error enc 1\n");
		goto out;
	}

	/* positive operation */
	ws->pk.kyber_type = type;
	if (lc_kyber_enc_kdf(&ws->ct, ws->ss, sizeof(ws->ss), &ws->pk)) {
		printf("Unexpected error enc 2\n");
		goto out;
	}

	if (ws->ct.kyber_type != type) {
		printf("Kyber type error ct\n");
		goto out;
	}

	/* modify type to get error */
	ws->sk.kyber_type = 123;
	if (lc_kyber_dec_kdf(ws->ss2, sizeof(ws->ss2), &ws->ct, &ws->sk) !=
	   -EINVAL) {
		printf("Unexpected error dec 1\n");
		goto out;
	}

	/* positive operation */
	ws->sk.kyber_type = type;
	if (lc_kyber_dec_kdf(ws->ss2, sizeof(ws->ss2), &ws->ct, &ws->sk)) {
		printf("Unexpected error dec 2\n");
		goto out;
	}

	unpoison(ws->ss, sizeof(ws->ss));
	unpoison(ws->ss2, sizeof(ws->ss));
	if (memcmp(ws->ss, ws->ss2, sizeof(ws->ss))) {
		printf("Shared secrets do not match\n");
		goto out;
	}

	ret = 0;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret = 0;

	(void)argc;
	(void)argv;

#ifdef LC_KYBER_1024_ENABLED
	ret += kyber_official(LC_KYBER_1024);
#endif
#ifdef LC_KYBER_768_ENABLED
	ret += kyber_official(LC_KYBER_768);
#endif
#ifdef LC_KYBER_512_ENABLED
	ret += kyber_official(LC_KYBER_512);
#endif

	return ret;
}
