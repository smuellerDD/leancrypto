/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * The SNTRUP code is derived in parts from the code base
 * https://libntruprime.cr.yp.to/ which uses the following license:
 *
 * Copyright (C) 2024 Free Software Foundation, Inc.; This is free software;
 * see the source for copying conditions. There is NO; warranty; not even for
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * SPDX-License-Identifier: LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT
 */

#ifndef params_H
#define params_H

#include "ext_headers_internal.h"
#ifdef LC_HOST_X86_64
#include "ext_headers_x86.h"
#endif

#define p 857
#define q 5167
#define w 322

#define ppadsort 857
#define numvec 4
#define mult3_numvec 64

#define sntrup_encode_857x5167_STRBYTES 1322
#define Rq_bytes sntrup_encode_857x5167_STRBYTES
#define Rq_encode sntrup_encode_857x5167
#define Rq_encode_avx2 sntrup_encode_857x5167_avx2

#ifdef LC_HOST_X86_64
struct ws_encode_avx2 {
	__m256i x, x2, y, y2;
	uint16_t R[429];
	uint16_t r0, r1;
	uint32_t r2;
};
#endif
struct ws_encode_ref {
	uint8_t x;
};
struct ws_encode {
	union {
#ifdef LC_HOST_X86_64
		struct ws_encode_avx2 avx2;
#endif
		struct ws_encode_ref ref;
	} u;
};
extern void sntrup_encode_857x5167(uint8_t *, const void *,
				   struct ws_encode *ws);
extern void sntrup_encode_857x5167_avx2(uint8_t *, const void *,
					struct ws_encode *ws);
#define sntrup_decode_857x5167_STRBYTES 1322
#define Rq_decode sntrup_decode_857x5167
#define Rq_decode_avx2 sntrup_decode_857x5167_avx2

#ifdef LC_HOST_X86_64
struct ws_decode_avx2 {
	__m256i A0, A1, A2, S0, S1, B0, B1, C0, C1;
	int16_t R1[429], R2[215], R3[108], R4[54], R5[27], R6[14], R7[7], R8[4],
		R9[2], R10[1];
};
#endif
struct ws_decode_ref {
	uint8_t x;
};
struct ws_decode {
	union {
#ifdef LC_HOST_X86_64
		struct ws_decode_avx2 avx2;
#endif
		struct ws_decode_ref ref;
	} u;
};
extern void sntrup_decode_857x5167(void *, const uint8_t *,
				   struct ws_decode *ws);
extern void sntrup_decode_857x5167_avx2(void *, const uint8_t *,
					struct ws_decode *ws);

#define sntrup_decode_857x1723_STRBYTES 1152
#define Rounded_bytes sntrup_decode_857x1723_STRBYTES
#define Rounded_decode sntrup_decode_857x1723
#define Rounded_decode_avx2 sntrup_decode_857x1723_avx2
extern void sntrup_decode_857x1723(void *, const uint8_t *,
				   struct ws_decode *ws);
extern void sntrup_decode_857x1723_avx2(void *, const uint8_t *,
					struct ws_decode *ws);

#define Round_and_encode sntrup_encode_857x1723round
#define Round_and_encode_avx2 sntrup_encode_857x1723round_avx2
extern void sntrup_encode_857x1723(uint8_t *, const void *);

#ifdef LC_HOST_X86_64
struct ws_round_encode_avx2 {
	__m256i x, x2, y, y2;
	uint16_t R[429];
	uint16_t r0, r1;
	uint32_t r2;
};
#endif
struct ws_round_encode_ref {
	int16_t x[p];
};
struct ws_round_encode {
	union {
#ifdef LC_HOST_X86_64
		struct ws_round_encode_avx2 avx2;
#endif
		struct ws_round_encode_ref ref;
	} u;
};
extern void sntrup_encode_857x1723round(uint8_t *, const void *,
					struct ws_round_encode *ws);
extern void sntrup_encode_857x1723round_avx2(uint8_t *, const void *,
					     struct ws_round_encode *ws);

#define sntrup_verify_clen sntrup_verify_1184
#define sntrup_verify_clen_avx2 sntrup_verify_1184_avx2
#define sntrup_encode_857x3_STRBYTES 215
#define Small_bytes sntrup_encode_857x3_STRBYTES
#define Small_encode sntrup_encode_857x3
#define Small_encode_avx2 sntrup_encode_857x3_avx2
#define Small_decode sntrup_decode_857x3
#define Small_decode_avx2 sntrup_decode_857x3_avx2
#define loops 7
#define overshoot 10

#define sntrup_encode_pxfreeze3 sntrup_encode_857xfreeze3
#define sntrup_encode_pxfreeze3_avx2 sntrup_encode_857xfreeze3_avx2
#define sntrup_decode_pxint32 sntrup_decode_857xint32
#define sntrup_decode_pxint16 sntrup_decode_857xint16
#define sntrup_encode_pxint16 sntrup_encode_857xint16
#define sntrup_core_wforce sntrup_core_wforcesntrup857
#define sntrup_core_wforce_avx2 sntrup_core_wforcesntrup857_avx2
#define sntrup_core_scale3 sntrup_core_scale3sntrup857
#define sntrup_core_scale3_avx2 sntrup_core_scale3sntrup857_avx2
#define sntrup_core_inv sntrup_core_invsntrup857
#define sntrup_core_inv_avx2 sntrup_core_invsntrup857_avx2
#define ppad 865
#define ppadavx2 1024
#define qinv -19761 /* reciprocal of q mod 2^16 */
#define q14 3 /* closest integer to 2^14/q */
#define q18 51 /* closest integer to 2^18/q */
#define q27 25976 /* closest integer to 2^27/q */
#define q31 415615 /* floor(2^31/q) */

#define sntrup_core_inv3 sntrup_core_inv3sntrup857
#define sntrup_core_inv3_avx2 sntrup_core_inv3sntrup857_avx2
#define ppad64 897
#define bitvec_len (ppad64 >> 6)
typedef uint64_t bitvec[bitvec_len];

#define sntrup_core_mult3 sntrup_core_mult3sntrup857
#define sntrup_core_mult3_avx2 sntrup_core_mult3sntrup857_avx2
#define sntrup_core_mult sntrup_core_multsntrup857
#define sntrup_core_mult_avx2 sntrup_core_multsntrup857_avx2
#define q18 51 /* closest integer to 2^18/q */
#define q27 25976 /* closest integer to 2^27/q */

#define sntrup_core_weight sntrup_core_weightsntrup857
#define sntrup_core_weight_avx2 sntrup_core_weightsntrup857_avx2
#define sntrup_verify_BYTES 1184

#ifdef LC_HOST_X86_64
#define endingmask                                                             \
	_mm256_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  \
			1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0)
#endif

#include "common.h"

#endif
