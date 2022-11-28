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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef ALIGNMENT_X86_H
#define ALIGNMENT_X86_H

#include "alignment.h"
#include "ext_headers_x86.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define ALIGNED_UINT8_M256I(N) ((N + 31) / 32)

#define BUF_ALIGNED_UINT8_M256I(N) 					       \
	union {								       \
		uint8_t coeffs[ALIGNED_UINT8_COEFFS(N)];		       \
		__m256i vec[ALIGNED_UINT8_M256I(N)];			       \
	}

#define BUF_ALIGNED_INT16_M256I(N)					       \
	union {								       \
		int16_t coeffs[N];					       \
		__m256i vec[(N + 15) / 16];				       \
	}

#define BUF_ALIGNED_INT32_M256I(N)					       \
	union {								       \
		int32_t coeffs[N];					       \
		__m256i vec[(N + 7) / 8];				       \
	}

#ifdef __cplusplus
}
#endif

#endif /* ALIGNMENT_X86_H */
