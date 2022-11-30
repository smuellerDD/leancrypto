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

#include "cpufeatures.h"
#include "ext_headers.h"
#include "dilithium_tester.h"
#include "lc_dilithium.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "testfunctions.h"
#include "visibility.h"

#include "avx2/dilithium_signature_avx2.h"

static int _dilithium_tester_avx2(unsigned int rounds)
{
	if (!(lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2))
		return 77;
	return _dilithium_tester(rounds, 0,
				 lc_dilithium_keypair_avx2,
				 lc_dilithium_sign_avx2,
				 lc_dilithium_verify_avx2);
}

int dilithium_tester_avx2(void)
{
	int ret = 0;

	ret += _dilithium_tester_avx2(0);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	if (argc != 2)
		return dilithium_tester_avx2();

	return _dilithium_tester_avx2(10000);
}
