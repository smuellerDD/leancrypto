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

#include "cpufeatures.h"
#include "ext_headers.h"
#include "kyber_type.h"
#include "kyber_kem_tester.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "visibility.h"

#include "avx2/kyber_kem_avx2.h"

static int _kyber_kem_tester_avx2(unsigned int rounds)
{
	if (!(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2))
		return 77;
	return _kyber_kem_tester(rounds, lc_kyber_keypair_avx, lc_kyber_enc_avx,
				 lc_kyber_dec_avx);
}

static int kyber_kem_tester_avx2(void)
{
	int ret = 0;

	ret += _kyber_kem_tester_avx2(0);

	return ret;
}

static int kyber_kem_tester_enc_avx2(void)
{
	return _kyber_kem_enc_tester(lc_kyber_enc_avx);
}

static int kyber_kem_tester_dec_avx2(void)
{
	return _kyber_kem_dec_tester(lc_kyber_dec_avx);
}

static int kyber_kem_tester_keygen_avx2(void)
{
	return _kyber_kem_keygen_tester(lc_kyber_keypair_avx);
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	if (argc != 2)
		return kyber_kem_tester_avx2();

	else if (argv[1][0] == 'e')
		return kyber_kem_tester_enc_avx2();

	else if (argv[1][0] == 'd')
		return kyber_kem_tester_dec_avx2();

	else if (argv[1][0] == 'k')
		return kyber_kem_tester_keygen_avx2();

	return _kyber_kem_tester_avx2(50000);
}
