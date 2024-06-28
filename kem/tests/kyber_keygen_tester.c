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

#include "ext_headers.h"
#include "kyber_type.h"
#include "kyber_internal.h"
#include "lc_cshake256_drng.h"
#include "lc_cshake_crypt.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "selftest_rng.h"
#include "small_stack_support.h"
#include "visibility.h"

static int kyber_keygen_performance(void)
{
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;
	};
	unsigned int i;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	for (i = 0; i < 500000; i++)
		CKINT(lc_kyber_keypair(&ws->pk, &ws->sk, lc_seeded_rng));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kyber_keygen_performance();
}
