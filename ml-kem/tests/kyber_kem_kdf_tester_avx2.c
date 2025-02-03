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

#include "cpufeatures.h"
#include "ext_headers.h"
#include "kyber_internal.h"
#include "kyber_kem_tester.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "visibility.h"

#include "avx2/kyber_kem_avx2.h"

static int _kyber_kem_tester_avx2(unsigned int rounds)
{
	int ret;

	if (!(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2))
		return 77;

	/* Force AVX2 only */
	lc_cpu_feature_set(LC_CPU_FEATURE_INTEL_AVX2);
	ret = _kyber_kem_kdf_tester(rounds, lc_kyber_keypair,
				    lc_kyber_enc_kdf_internal,
				    lc_kyber_dec_kdf);
	lc_cpu_feature_enable();
	return ret;
}

static int kyber_kem_tester_avx2(void)
{
	int ret = 0;

	ret += _kyber_kem_tester_avx2(0);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	if (argc != 2)
		return kyber_kem_tester_avx2();

	return _kyber_kem_tester_avx2(50000);
}
