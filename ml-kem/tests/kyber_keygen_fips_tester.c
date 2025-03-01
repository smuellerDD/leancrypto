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

#include "lc_kyber.h"
#include "lc_status.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

static int kyber_keygen(void)
{
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;
	};
	enum lc_kyber_type kyber_type;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

#ifdef LC_KYBER_1024_ENABLED
	kyber_type = LC_KYBER_1024;
#elif defined(LC_KYBER_768_ENABLED)
	kyber_type = LC_KYBER_768;
#elif defined(LC_KYBER_512_ENABLED)
	kyber_type = LC_KYBER_512;
#else
#error
#endif

	/* Rerun power up integrity test */
	lc_fips_integrity_checker();

	CKINT(lc_kyber_keypair(&ws->pk, &ws->sk, lc_seeded_rng, kyber_type));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kyber_keygen();
}
