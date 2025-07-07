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

#ifndef CHACHA20_ASM_RISCV64_V_ZBB_H
#define CHACHA20_ASM_RISCV64_V_ZBB_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ChaCha20_riscv64_v_zbb - ChaCha20 encryption
 *
 * @param [out] out Output buffer of at least len size
 * @param [in] in Input buffer of at least len size
 * @param [in] len Length of the buffers to be encrypted
 * @param [in] key key material collected into 8 32-bit elements array in
 *		   host byte order
 * @param [in] counter counter / nonce material collected into 4 32-bit elements
 *		       array in host byte order
 */
void SYSV_ABI ChaCha20_riscv64_v_zbb(uint8_t *out, const uint8_t *in, size_t len,
		   const uint32_t key[8], const uint32_t counter[4]);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20_ASM_RISCV64_V_ZBB_H */
