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

#ifndef LC_CHACHA20_H
#define LC_CHACHA20_H

#include "lc_sym.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct lc_sym *lc_chacha20;

#define LC_CC20_STATE_SIZE (132)

/**
 * @ingroup Symmetric
 * @brief ChaCha20 block function
 *
 * Block operation from the ChaCah20 state
 *
 * @param [in] state ChaCha20 state from which to derive the block output
 * @param [out] stream ChaCha20 key stream output
 */
void cc20_block(struct lc_sym_state *state, uint32_t *stream);

/**
 * @ingroup Symmetric
 * @brief Allocate stack memory for the ChaCha20 context
 *
 * @param [in] name Name of the stack variable
 */
#define LC_CC20_CTX_ON_STACK(name)                                             \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf,                              \
				  LC_SYM_STATE_SIZE_LEN(LC_CC20_STATE_SIZE),   \
				  LC_SYM_COMMON_ALIGNMENT);                    \
	struct lc_sym_ctx *name = (struct lc_sym_ctx *)name##_ctx_buf;         \
	LC_SYM_SET_CTX(name, lc_chacha20);                                     \
	lc_sym_zero(name);                                                     \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_CHACHA20_H */
