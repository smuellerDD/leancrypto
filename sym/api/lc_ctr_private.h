/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_CTR_PRIVATE_H
#define LC_CTR_PRIVATE_H

#include <stdint.h>

#include "bitshift.h"
#include "build_bug_on.h"
#include "lc_aes_private.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define AES_CTR128_64BIT_WORDS	(AES_BLOCKLEN / sizeof(uint64_t))

static inline void ctr128_inc(uint64_t ctr[AES_CTR128_64BIT_WORDS])
{
	BUILD_BUG_ON(AES_CTR128_64BIT_WORDS != 2);

	if (ctr[1] < 0xffffffffffffffff) {
		ctr[1]++;
		return;
	}
	ctr[1] = 0;

	if (ctr[0] < 0xffffffffffffffff)
		ctr[0]++;
	else
		ctr[0] = 0;
}

static inline void ptr_to_ctr128(uint64_t ctr[AES_CTR128_64BIT_WORDS],
				 const uint8_t *p)
{
	BUILD_BUG_ON(AES_CTR128_64BIT_WORDS != 2);
	ctr[0] = ptr_to_be64(p);
	ctr[1] = ptr_to_be64(p + sizeof(uint64_t));
}

static inline void ctr128_to_ptr(uint8_t *p,
				 const uint64_t ctr[AES_CTR128_64BIT_WORDS])
{
	BUILD_BUG_ON(AES_CTR128_64BIT_WORDS != 2);
	be64_to_ptr(p, ctr[0]);
	be64_to_ptr(p + sizeof(uint64_t), ctr[1]);
}

#ifdef __cplusplus
}
#endif

#endif /* LC_CTR_PRIVATE_H */