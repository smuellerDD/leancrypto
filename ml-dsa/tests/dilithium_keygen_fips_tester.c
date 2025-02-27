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

#include "ext_headers.h"
#include "lc_dilithium.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

#ifdef LC_DILITHIUM_TYPE_65
#define DILITHIUM_TYPE LC_DILITHIUM_65
#elif defined(LC_DILITHIUM_TYPE_44)
#define DILITHIUM_TYPE LC_DILITHIUM_44
#else
#define DILITHIUM_TYPE LC_DILITHIUM_87
#endif

static int dilithium_keygen_fips_tester(void)
{
	struct workspace {
		struct lc_dilithium_sk sk;
		struct lc_dilithium_pk pk;
	};
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	int ret = 0;

	CKINT(lc_dilithium_keypair(&ws->pk, &ws->sk, lc_seeded_rng,
				   DILITHIUM_TYPE));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return dilithium_keygen_fips_tester();
}
