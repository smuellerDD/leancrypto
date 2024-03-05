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
#include "kyber_internal.h"
#include "kyber_kem_tester.h"
#include "lc_kyber.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "visibility.h"

static int _kyber_kem_tester_common(unsigned int rounds)
{
	return _kyber_kem_tester(rounds, lc_kyber_keypair,
				 lc_kyber_enc_internal, lc_kyber_dec);
}

static int kyber_kem_tester_common(void)
{
	int ret = 0;

	ret += _kyber_kem_tester_common(0);

	return ret;
}

static int kyber_kem_tester_enc_common(void)
{
	return _kyber_kem_enc_tester(lc_kyber_enc_internal);
}

static int kyber_kem_tester_dec_common(void)
{
	return _kyber_kem_dec_tester(lc_kyber_dec);
}

static int kyber_kem_tester_keygen_common(void)
{
	return _kyber_kem_keygen_tester(lc_kyber_keypair);
}

/*
 * Performance tests:
 *
 * Keygen: perf stat -B build/kem/tests/kyber_kem_tester_common k
 * Encapsulation: perf stat -B build/kem/tests/kyber_kem_tester_common e
 * Decapsulation: perf stat -B build/kem/tests/kyber_kem_tester_common d
 *
 * Performance tests with large round count:
 * build/kem/tests/kyber_kem_tester_common c
 *
 * Regression test:
 * build/kem/tests/kyber_kem_tester_common
 */
LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	if (argc != 2)
		return kyber_kem_tester_common();

	else if (argv[1][0] == 'e')
		return kyber_kem_tester_enc_common();

	else if (argv[1][0] == 'd')
		return kyber_kem_tester_dec_common();

	else if (argv[1][0] == 'k')
		return kyber_kem_tester_keygen_common();

	return _kyber_kem_tester_common(50000);
}
