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

#include "lc_cshake256_drng.h"
#include "lc_dilithium.h"
#include "small_stack_support.h"
#include "visibility.h"

static int dilithium_invalid(void)
{
	struct workspace {
		struct lc_dilithium_sk sk;
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sig sig;
	};
	uint8_t msg[] = { 0x01, 0x02, 0x03 };
	int ret = 1;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_CSHAKE256_DRNG_CTX_ON_STACK(rng);

	if (lc_rng_seed(rng, msg, sizeof(msg), NULL, 0))
		goto out;

	if (lc_dilithium_keypair(&ws->pk, &ws->sk, rng))
		goto out;

	if (lc_dilithium_sign(&ws->sig, msg, sizeof(msg), &ws->sk, rng))
		goto out;

	/* modify the pub key */
	ws->pk.pk[0] = (ws->pk.pk[0] + 0x01) & 0xff;
	if (lc_dilithium_verify(&ws->sig, msg, sizeof(msg), &ws->pk) != -EBADMSG)
		goto out;

	/* revert modify the pub key */
	ws->pk.pk[0] = (ws->pk.pk[0] - 0x01) & 0xff;
	/* modify the sec key */
	ws->sk.sk[0] = (ws->sk.sk[0] + 0x01) & 0xff;

	if (lc_dilithium_sign(&ws->sig, msg, sizeof(msg), &ws->sk, rng))
		goto out;

	if (lc_dilithium_verify(&ws->sig, msg, sizeof(msg), &ws->pk) !=
	    -EBADMSG)
		goto out;

	/* revert modify the sec key */
	ws->sk.sk[0] = (ws->sk.sk[0] - 0x01) & 0xff;

	if (lc_dilithium_sign(&ws->sig, msg, sizeof(msg), &ws->sk, rng))
		goto out;

	/* modify the signature */
	ws->sig.sig[0] = (ws->sig.sig[0] + 0x01) & 0xff;
	if (lc_dilithium_verify(&ws->sig, msg, sizeof(msg), &ws->pk) !=
				-EBADMSG)
		goto out;

	ret = 0;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return dilithium_invalid();
}
