/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef ALIGNMENT_H
#define ALIGNMENT_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__)
#define __align(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
//#define __align(x) __declspec(align(x))
#define __align(x) __attribute__((aligned(x)))
#elif defined(__ARMCC_VERSION)
/* Nothing, the used macro is known to the compiler */
#else
#define __align(x)
#endif

#define ALIGNED_UINT8_COEFFS(N) N
#define ALIGNED_UINT8_UINT64(N) ((N + 7) / 8)

#define BUF_ALIGNED_UINT8_UINT64(N)                                            \
	union {                                                                \
		uint8_t coeffs[ALIGNED_UINT8_COEFFS(N)];                       \
		uint64_t vec[ALIGNED_UINT8_UINT64(N)];                         \
	}

static inline int aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* ALIGNMENT_H */
