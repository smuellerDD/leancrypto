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

#ifndef SPHINCS_WOTSX2_ARMV8_H
#define SPHINCS_WOTSX2_ARMV8_H

#include "sphincs_type.h"
#include "sphincs_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is here to provide an interface to the internal wots_gen_leafx2
 * routine.  While this routine is not referenced in the package outside of
 * wots.c, it is called from the stand-alone benchmark code to characterize
 * the performance
 */
struct leaf_info_x2 {
	unsigned char *wots_sig;
	uint32_t wots_sign_leaf; /* The index of the WOTS we're using to sign */
	uint32_t *wots_steps;
	uint32_t leaf_addr[2 * 8];
	uint32_t pk_addr[2 * 8];
};

/* Macro to set the leaf_info to something 'benign', that is, it would */
/* run with the same time as it does during the real signing process */
/* Used only by the benchmark code */
#define INITIALIZE_LEAF_INFO_X2(info, addr, step_buffer)                       \
	{                                                                      \
		info.wots_sig = 0;                                             \
		info.wots_sign_leaf = ~0;                                      \
		info.wots_steps = step_buffer;                                 \
		int i;                                                         \
		for (i = 0; i < 2; i++) {                                      \
			memcpy(&info.leaf_addr[8 * i], addr, 32);              \
			memcpy(&info.pk_addr[8 * i], addr, 32);                \
		}                                                              \
	}

void wots_gen_leafx2(unsigned char *dest, const spx_ctx *ctx, uint32_t leaf_idx,
		     void *v_info, uint8_t *pk_buffer, uint8_t *thash_buf);

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_WOTSX2_ARMV8_H */
