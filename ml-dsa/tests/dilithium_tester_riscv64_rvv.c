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
#include "cpufeatures.h"
#include "dilithium_tester.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "visibility.h"

#include "riscv64/dilithium_signature_riscv64_rvv.h"

static int _dilithium_tester_riscv64_rvv(unsigned int rounds,
					 unsigned int internal,
					 unsigned int prehashed)
{
	return _dilithium_tester(rounds, 1, internal, prehashed,
				 lc_dilithium_keypair_riscv64_rvv,
				 lc_dilithium_keypair_from_seed_riscv64_rvv,
				 lc_dilithium_sign_ctx_riscv64_rvv,
				 lc_dilithium_verify_ctx_riscv64_rvv);
}

static int dilithium_tester_riscv64_rvv(void)
{
	int ret = 0;

	ret += _dilithium_tester_riscv64_rvv(0, 0, 0);
	ret += _dilithium_tester_riscv64_rvv(0, 1, 0);
	ret += _dilithium_tester_riscv64_rvv(0, 0, 1);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	if (!(lc_cpu_feature_available() & LC_CPU_FEATURE_RISCV_ASM_RVV))
		return 77;

	if (argc != 2)
		return dilithium_tester_riscv64_rvv();

	return _dilithium_tester_riscv64_rvv(10000, 0, 0);
}
