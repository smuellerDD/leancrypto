/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include "kyber_internal.h"
#include "lc_cshake256_drng.h"
#include "lc_kyber.h"
#include "lc_rng.h"
#include "small_stack_support.h"
#include "visibility.h"

static int kyber_invalid(void)
{
	struct workspace {
		struct lc_kyber_sk sk;
		struct lc_kyber_pk pk;
		struct lc_kyber_ct ct;
		uint8_t ss[5], ss2[5];
	};
	int ret = 1;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_CSHAKE256_DRNG_CTX_ON_STACK(rng);

	if (lc_rng_seed(rng, (uint8_t *)"123", 3, NULL, 0))
		goto out;

	if (lc_kyber_keypair(&ws->pk, &ws->sk, rng))
		goto out;

	/* modify the pub key */
	ws->pk.pk[0] = (uint8_t)((ws->pk.pk[0] + 0x01) & 0xff);
	if (lc_kyber_enc_kdf_internal(&ws->ct, ws->ss, sizeof(ws->ss), &ws->pk,
				      rng))
		goto out;
	if (lc_kyber_dec_kdf(ws->ss2, sizeof(ws->ss2), &ws->ct, &ws->sk))
		goto out;
	if (!memcmp(ws->ss, ws->ss2, sizeof(ws->ss)))
		goto out;

	/* revert modify the pub key */
	ws->pk.pk[0] = (uint8_t)((ws->pk.pk[0] - 0x01) & 0xff);
	/* modify the sec key */
	ws->sk.sk[0] = (uint8_t)((ws->sk.sk[0] + 0x01) & 0xff);
	if (lc_kyber_enc_kdf_internal(&ws->ct, ws->ss, sizeof(ws->ss), &ws->pk,
				      rng))
		goto out;
	if (lc_kyber_dec_kdf(ws->ss2, sizeof(ws->ss2), &ws->ct, &ws->sk))
		goto out;
	if (!memcmp(ws->ss, ws->ss2, sizeof(ws->ss)))
		goto out;

	/* revert modify the sec key */
	ws->sk.sk[0] = (uint8_t)((ws->sk.sk[0] - 0x01) & 0xff);
	if (lc_kyber_enc_kdf_internal(&ws->ct, ws->ss, sizeof(ws->ss), &ws->pk,
				      rng))
		goto out;
	/* modify the ct */
	ws->ct.ct[0] = (uint8_t)((ws->ct.ct[0] + 0x01) & 0xff);
	if (lc_kyber_dec_kdf(ws->ss2, sizeof(ws->ss2), &ws->ct, &ws->sk))
		goto out;
	if (!memcmp(ws->ss, ws->ss2, sizeof(ws->ss)))
		goto out;

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

	ret += kyber_invalid();

	return ret;
}
