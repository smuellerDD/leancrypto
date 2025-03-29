/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include "conv_be_le.h"
#include "cpufeatures.h"
#include "lc_kyber.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

#ifdef LC_KYBER_TYPE_512
#define LC_KYBER_TYPE LC_KYBER_512
#elif defined(LC_KYBER_TYPE_768)
#define LC_KYBER_TYPE LC_KYBER_768
#else
#define LC_KYBER_TYPE LC_KYBER_1024
#endif

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	struct workspace {
		struct lc_kyber_sk sk;
		struct lc_kyber_pk pk;
		struct lc_kyber_ct ct;
		struct lc_kyber_ss ss;
	};
	int ret;
	uint8_t *ptr;
	size_t len;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	(void)argv;

	CKINT(lc_kyber_keypair(&ws->pk, &ws->sk, lc_seeded_rng, LC_KYBER_TYPE));

	CKINT(lc_kyber_pk_ptr(&ptr, &len, &ws->pk));

	/*
	 * Trigger the modulus test to fail by setting the first 16 bytes to
	 * 3329 and thus outside of the required interval of [0, q - 1].
	 */
	ptr[0] = 0x01;
	ptr[1] &= 0xf0;
	ptr[1] |= 0x0d;

	if (argc >= 2)
		lc_cpu_feature_disable();

	ret = lc_kyber_enc(&ws->ct, &ws->ss, &ws->pk);
	if (ret == -EINVAL)
		ret = 0;
	else
		ret = -EFAULT;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}
