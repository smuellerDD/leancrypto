/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include "conv_be_le.h"
#include "gfmul_x86_64.h"
#include "ext_headers_internal.h"
#include "ext_headers_x86.h"

void SYSV_ABI gfmu_x8664_impl(__m128i a, __m128i b, __m128i *res);
void gfmu_x8664(uint64_t a[2], const uint64_t Htable[32])
{
	__m128i aa, bb;

	LC_FPU_ENABLE

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
	/* The inputs are in big-endian order, so byte-reverse them */
	aa[0] = be_bswap64(a[1]);
	aa[1] = be_bswap64(a[0]);
	bb[0] = Htable[0];
	bb[1] = Htable[1];

	gfmu_x8664_impl(aa, bb, &aa);

	/* Now byte-reverse the outputs */
	a[0] = be_bswap64(aa[1]);
	a[1] = be_bswap64(aa[0]);
#pragma GCC diagnostic pop

	LC_FPU_DISABLE
}

void gfmu_x8664_init(uint64_t Htable[32], const uint64_t H[2])
{
	/*
	 * Simply save the key for gfmul in big-endian notatation:
	 * the individual H integers are already in big-endian, now just
	 * reverse the order of the H variables.
	 */
	Htable[0] = H[1];
	Htable[1] = H[0];
}
