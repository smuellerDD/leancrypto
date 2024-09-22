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

#include "compare.h"
#include "small_stack_support.h"
#include "sphincs_type.h"
#include "ret_checkers.h"
#include "visibility.h"

#ifdef LC_SPHINCS_TYPE_256F
#include "lc_sphincs_shake_256f.h"
#include "sphincs_tester_vectors_shake_256f.h"
#else
#include "lc_sphincs_shake_256s.h"
#include "sphincs_tester_vectors_shake_256s.h"
#endif

static int lc_sphincs_test(struct lc_sphincs_test *tc)
{
	struct workspace {
		struct lc_sphincs_pk pk;
		struct lc_sphincs_sk sk;
		struct lc_sphincs_sig sig;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_sphincs_keypair_from_seed(&ws->pk, &ws->sk, tc->seed,
					   sizeof(tc->seed)));
	lc_compare((uint8_t *)&ws->pk, tc->pk, sizeof(tc->pk), "PK");
	lc_compare((uint8_t *)&ws->sk, tc->sk, sizeof(tc->sk), "SK");

	CKINT(lc_sphincs_sign(&ws->sig, tc->msg, sizeof(tc->msg), &ws->sk,
			      NULL));
	lc_compare((uint8_t *)&ws->sig, tc->sig, sizeof(tc->sig), "SIG");

	CKINT(lc_sphincs_verify((struct lc_sphincs_sig *)tc->sig, tc->msg,
				sizeof(tc->msg),
				(struct lc_sphincs_pk *)tc->pk));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret, rc = 0;
	(void)argc;
	(void)argv;

	CKINT(lc_sphincs_test(&tests[0]));
	rc += ret;

out:
	return ret ? -ret : rc;
}
