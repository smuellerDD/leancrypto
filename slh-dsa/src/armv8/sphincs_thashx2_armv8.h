/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/sphincs/sphincsplus
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef SPHINCS_THASHX2_ARMV8_H
#define SPHINCS_THASHX2_ARMV8_H

#include "sphincs_type.h"
#include "sphincs_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LC_THASHX4_BUFLEN                                                      \
	(LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N)
#define LC_THASHX4_BITMASKLEN (LC_SPX_WOTS_LEN * LC_SPX_N)

void thashx2_12(unsigned char *out0, unsigned char *out1,
		const unsigned char *in0, const unsigned char *in1,
		unsigned int inblocks, const spx_ctx *ctx,
		uint32_t addrx2[2 * 8]);
void thashx2(unsigned char *out0, unsigned char *out1, const unsigned char *in0,
	     const unsigned char *in1, unsigned int inblocks,
	     const spx_ctx *ctx, uint32_t addrx2[2 * 8], uint8_t *thash_buf);

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_THASHX2_ARMV8_H */
