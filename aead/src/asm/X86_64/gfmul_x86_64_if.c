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

#include "bitshift_be.h"
#include "conv_be_le.h"
#include "gfmul_x86_64.h"
#include "ext_headers_x86.h"

void gfmu_x8664(__m128i a, __m128i b, __m128i *res);
void gfmu_x8664_helper(unsigned char a[16],
		       const struct lc_aes_gcm_cryptor *ctx)
{
	__m128i aa, bb, cc;

	/* The inputs are in big-endian order, so byte-reverse them */
	aa[0] = ptr_to_be64(a + 8);
	aa[1] = ptr_to_be64(a + 0);
	bb[0] = ctx->gcm_ctx.HH[8];
	bb[1] = ctx->gcm_ctx.HL[8];

	gfmu_x8664(aa, bb, &cc);

	/* Now byte-reverse the outputs */
	be64_to_ptr(a, cc[1]);
	be64_to_ptr(a + 8, cc[0]);
}
