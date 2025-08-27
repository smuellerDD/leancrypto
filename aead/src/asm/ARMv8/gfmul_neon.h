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

#ifndef GCM_ARMV8_H
#define GCM_ARMV8_H

#include "ext_headers_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_HOST_AARCH64
void gfmul_init_armv8(uint64_t Htable[32], const uint64_t Xi[2]);
void gfmul_armv8(uint64_t Xi[2], const uint64_t Htable[32]);
//void gcm_ghash_v8(uint64_t Xi[2], const u128 Htable[16], const uint8_t *inp,
//		  size_t len);
#else
static inline void gfmul_init_armv8(uint64_t Htable[32], const uint64_t Xi[2])
{
	(void)Htable;
	(void)Xi;
}

static inline void gfmul_armv8(uint64_t Xi[2], const uint64_t Htable[32])
{
	(void)Xi;
	(void)Htable;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* GCM_ARMV8_H */
