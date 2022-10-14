/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

static int kyber_invalid(void)
{
	struct lc_kyber_sk sk;
	struct lc_kyber_pk pk;
	struct lc_kyber_ct ct;
	uint8_t ss[5], ss2[5];
	int ret = 0;

	if (lc_kyber_keypair(&pk, &sk, lc_seeded_rng))
		return 1;

	/* modify the pub key */
	pk.pk[0] = (pk.pk[0] + 0x01) & 0xff;
	if (lc_kyber_enc(&ct, ss, sizeof(ss), &pk, lc_seeded_rng))
		return 1;
	if (lc_kyber_dec(ss2, sizeof(ss2), &ct, &sk))
		return 1;
	if (!memcmp(ss, ss2, sizeof(ss)))
		return 1;

	/* revert modify the pub key */
	pk.pk[0] = (pk.pk[0] - 0x01) & 0xff;
	/* modify the sec key */
	sk.sk[0] = (sk.sk[0] + 0x01) & 0xff;
	if (lc_kyber_enc(&ct, ss, sizeof(ss), &pk, lc_seeded_rng))
		return 1;
	if (lc_kyber_dec(ss2, sizeof(ss2), &ct, &sk))
		return 1;
	if (!memcmp(ss, ss2, sizeof(ss)))
		return 1;

	/* revert modify the sec key */
	sk.sk[0] = (sk.sk[0] - 0x01) & 0xff;
	if (lc_kyber_enc(&ct, ss, sizeof(ss), &pk, lc_seeded_rng))
		return 1;
	/* modify the ct */
	ct.ct[0] = (ct.ct[0] + 0x01) & 0xff;
	if (lc_kyber_dec(ss2, sizeof(ss2), &ct, &sk))
		return 1;
	if (!memcmp(ss, ss2, sizeof(ss)))
		return 1;

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	(void)argc;
	(void)argv;

	ret += kyber_invalid();

	return ret;
}
