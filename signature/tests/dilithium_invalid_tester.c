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

#include "lc_dilithium.h"
#include "lc_rng.h"

static int dilithium_invalid(void)
{
	struct lc_dilithium_sk sk;
	struct lc_dilithium_pk pk;
	struct lc_dilithium_sig sig;
	uint8_t msg[] = { 0x01, 0x02, 0x03 };
	int ret = 0;

	if (lc_dilithium_keypair(&pk, &sk, lc_seeded_rng))
		return 1;

	if (lc_dilithium_sign(&sig, msg, sizeof(msg), &sk, lc_seeded_rng))
		return 1;

	/* modify the pub key */
	pk.pk[0] = (pk.pk[0] + 0x01) & 0xff;
	if (lc_dilithium_verify(&sig, msg, sizeof(msg), &pk) != -EBADMSG)
		return 1;

	/* revert modify the pub key */
	pk.pk[0] = (pk.pk[0] - 0x01) & 0xff;
	/* modify the sec key */
	sk.sk[0] = (sk.sk[0] + 0x01) & 0xff;

	if (lc_dilithium_sign(&sig, msg, sizeof(msg), &sk, lc_seeded_rng))
		return 1;

	if (lc_dilithium_verify(&sig, msg, sizeof(msg), &pk) != -EBADMSG)
		return 1;

	/* revert modify the sec key */
	sk.sk[0] = (sk.sk[0] - 0x01) & 0xff;

	if (lc_dilithium_sign(&sig, msg, sizeof(msg), &sk, lc_seeded_rng))
		return 1;

	/* modify the signature */
	sig.sig[0] = (sig.sig[0] + 0x01) & 0xff;
	if (lc_dilithium_verify(&sig, msg, sizeof(msg), &pk) != -EBADMSG)
		return 1;

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	(void)argc;
	(void)argv;

	ret += dilithium_invalid();

	return ret;
}
