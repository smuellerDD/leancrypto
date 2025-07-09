/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#include "chacha20_internal.h"
#include "chacha20_avx512.h"
#include "ext_headers_x86.h"
#include "lc_chacha20.h"
#include "lc_chacha20_private.h"
#include "lc_memset_secure.h"
#include "lc_sym.h"
#include "visibility.h"

#include "asm/AVX512/chacha20_asm_avx512.h"

static void cc20_crypt_avx512(struct lc_sym_state *ctx, const uint8_t *in,
			      uint8_t *out, size_t len)
{
	size_t fullblock_bytes;
	int ret;

	/*
	 * cc20_crypt_bytes_avx512 can handle the partial blocks, but we
	 * deliberately handle partial blocks here as we want to keep the
	 * unused keystream.
	 */

	cc20_crypt_remaining(ctx, &in, &out, &len);

	fullblock_bytes = len &~ (LC_CC20_BLOCK_SIZE - 1);

	if (fullblock_bytes) {
		LC_FPU_ENABLE;
		ret = cc20_crypt_bytes_avx512(ctx->key.u, in, out,
					      fullblock_bytes);
		LC_FPU_DISABLE;

		if (ret)
			lc_memset_secure(out, 0, len);

		in += fullblock_bytes;
		out += fullblock_bytes;
		len -= fullblock_bytes;
	}

	if (len) {
		LC_FPU_ENABLE;
		ret = cc20_crypt_bytes_avx512(ctx->key.u, NULL,
                                              ctx->keystream.b,
					      LC_CC20_BLOCK_SIZE);
		LC_FPU_DISABLE;

		if (ret)
			lc_memset_secure(out, 0, len);

		if (in != out)
			memcpy(out, in, len);

		xor_64(out, ctx->keystream.b, len);

		/* When we are in this loop, the keystream_ptr was zero */
		ctx->keystream_ptr = (uint8_t)len;
	}
}

static struct lc_sym _lc_chacha20_avx512 = {
	.init = cc20_init,
	.setkey = cc20_setkey,
	.setiv = cc20_setiv,
	.encrypt = cc20_crypt_avx512,
	.decrypt = cc20_crypt_avx512,
	.statesize = LC_CC20_STATE_SIZE,
	.blocksize = 1,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *,
		    lc_chacha20_avx512) = &_lc_chacha20_avx512;
