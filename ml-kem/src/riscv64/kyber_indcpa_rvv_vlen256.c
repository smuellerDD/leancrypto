/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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
/*
 * This file is derived from https://github.com/Ji-Peng/PQRV which uses the
 * following license.
 *
 * The MIT license, the text of which is below, applies to PQRV in general.
 *
 * Copyright (c) 2024 - 2025 Jipeng Zhang (jp-zhang@outlook.com)
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Define the compilation for RISCV RVV Vector length 256 bit */
#define LC_KYBER_RVV_TYPE(func) func##_vlen256

#include "ntt_rvv_vlen256.h"
#include "kyber_indcpa_rvv_vlen256.h"
#include "kyber_poly_rvv.h"
#include "kyber_polyvec_rvv.h"
#include "kyber_kem_input_validation.h"
#include "ntt_rvv_vlen256.h"

#include "kyber_indcpa_rvv.h"

int indcpa_keypair_rvv_vlen256(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			       uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
			       struct lc_rng_ctx *rng_ctx)
{
	return indcpa_keypair_rvv_common(pk, sk, rng_ctx);
}

int indcpa_enc_rvv_vlen256(uint8_t c[LC_KYBER_INDCPA_BYTES],
			   const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			   const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			   const uint8_t coins[LC_KYBER_SYMBYTES])
{
	return indcpa_enc_rvv_common(c, m, pk, coins);
}

int indcpa_dec_rvv_vlen256(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			   const uint8_t c[LC_KYBER_INDCPA_BYTES],
			   const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES])
{
	return indcpa_dec_rvv_common(m, c, sk);
}
