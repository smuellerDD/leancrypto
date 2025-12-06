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

#include "leancrypto_kernel_aead_helper.h"

int lc_kernel_aead_update(struct aead_request *areq, unsigned int nbytes,
			  int (*process)(struct lc_aead_ctx *ctx,
					 const uint8_t *in, uint8_t *out,
					 size_t datalen))
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct scatterlist sg_src[2], sg_dst[2];
	struct scatterlist *src, *dst;
	struct scatter_walk src_walk, dst_walk;
	int ret = 0;

	if (!nbytes)
		return 0;

	src = scatterwalk_ffwd(sg_src, areq->src, areq->assoclen);
	if (areq->src == areq->dst)
		dst = src;
	else
		dst = scatterwalk_ffwd(sg_dst, areq->dst, areq->assoclen);

	scatterwalk_start(&src_walk, src);
	scatterwalk_start(&dst_walk, dst);

	while (nbytes) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)

		unsigned int stodo = scatterwalk_next(&src_walk, nbytes);
		unsigned int dtodo = scatterwalk_next(&dst_walk, nbytes);
		unsigned int todo = min(stodo, dtodo);

		u8 *src_vaddr = src_walk.addr;
		u8 *dst_vaddr = dst_walk.addr;

		if (!todo)
			return -EINVAL;

		/* Perform the work */
		ret = process(ctx, src_vaddr, dst_vaddr, todo);

		scatterwalk_done_dst(&dst_walk, todo);
		scatterwalk_done_src(&src_walk, todo);
		if (ret)
			return ret;

		nbytes -= todo;

#else
		unsigned int todo =
			min_t(unsigned int, scatterwalk_pagelen(&src_walk),
			      scatterwalk_pagelen(&dst_walk));
		u8 *src_vaddr, *dst_vaddr;
		todo = min_t(unsigned int, nbytes, todo);

		if (!todo)
			return -EINVAL;

		src_vaddr = scatterwalk_map(&src_walk);
		dst_vaddr = scatterwalk_map(&dst_walk);

		/* Perform the work */
		ret = process(ctx, src_vaddr, dst_vaddr, todo);

		scatterwalk_unmap(src_vaddr);
		scatterwalk_unmap(dst_vaddr);

		if (ret)
			return ret;

		scatterwalk_advance(&src_walk, todo);
		scatterwalk_advance(&dst_walk, todo);
		nbytes -= todo;

		scatterwalk_pagedone(&src_walk, 0, nbytes);
		scatterwalk_pagedone(&dst_walk, 1, nbytes);

#endif
	}

	return ret;
}
