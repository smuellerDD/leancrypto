/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include <crypto/aes.h>
#include <crypto/internal/skcipher.h>
#include <linux/math.h>

#include "leancrypto_kernel_aead_helper.h"

int lc_kernel_aead_update(struct aead_request *areq,
			  struct lc_aead_ctx *vola_ctx, int enc,
			  unsigned int blocksize,
			  int (*process)(struct lc_aead_ctx *ctx,
					 const uint8_t *in, uint8_t *out,
					 size_t datalen))
{
	struct skcipher_walk walk;
	unsigned int nbytes;
	int ret = 0;

	if (enc)
		ret = skcipher_walk_aead_encrypt(&walk, areq, false);
	else
		ret = skcipher_walk_aead_decrypt(&walk, areq, false);
	if (ret)
		return ret;

	while (unlikely((nbytes = walk.nbytes) < walk.total)) {
		/*
		 * Non-last segment, multiple of blocksize
		 */
		nbytes &= ~(blocksize - 1);

		/* Perform the work */
		ret = process(vola_ctx, walk.src.virt.addr, walk.dst.virt.addr,
			      nbytes);

		if (ret)
			return ret;
		ret = skcipher_walk_done(&walk, walk.nbytes - nbytes);
		if (ret)
			return ret;
	}

	/* Last segment: process all remaining data. */
	ret = process(vola_ctx, walk.src.virt.addr, walk.dst.virt.addr, nbytes);
	if (ret)
		return ret;

	if (nbytes)
		ret = skcipher_walk_done(&walk, 0);

	return ret;
}
