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

#define p 1277
#define q 7879
#define w 492

#define ppadsort 1280
#define numvec 5
#define mult3_numvec 80

#define sntrup_encode_1277x7879_STRBYTES 2067
#define Rq_bytes sntrup_encode_1277x7879_STRBYTES
#define Rq_encode sntrup_encode_1277x7879
#define Rq_encode_avx2 sntrup_encode_1277x7879_avx2

#ifdef LC_HOST_X86_64
struct ws_encode_avx2 {
	__m256i x, x2, y, y2;
	uint16_t R[639];
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
extern void sntrup_encode_1277x7879(uint8_t *, const void *,
				    struct ws_encode *ws);
extern void sntrup_encode_1277x7879_avx2(uint8_t *, const void *,
					 struct ws_encode *ws);
#define sntrup_decode_1277x7879_STRBYTES 2067
#define Rq_decode sntrup_decode_1277x7879
#define Rq_decode_avx2 sntrup_decode_1277x7879_avx2

#ifdef LC_HOST_X86_64
struct ws_decode_avx2 {
	__m256i A0, A1, A2, S0, S1, B0, B1, C0, C1;
	int16_t R1[639], R2[320], R3[160], R4[80], R5[40], R6[20], R7[10],
		R8[5], R9[3], R10[2], R11[1];
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
extern void sntrup_decode_1277x7879(void *, const uint8_t *,
				    struct ws_decode *ws);
extern void sntrup_decode_1277x7879_avx2(void *, const uint8_t *,
					 struct ws_decode *ws);

#define sntrup_decode_1277x2627_STRBYTES 1815
#define Rounded_bytes sntrup_decode_1277x2627_STRBYTES
#define Rounded_decode sntrup_decode_1277x2627
#define Rounded_decode_avx2 sntrup_decode_1277x2627_avx2
extern void sntrup_decode_1277x2627(void *, const uint8_t *,
				    struct ws_decode *ws);
extern void sntrup_decode_1277x2627_avx2(void *, const uint8_t *,
					 struct ws_decode *ws);

#define Round_and_encode sntrup_encode_1277x2627round
#define Round_and_encode_avx2 sntrup_encode_1277x2627round_avx2
extern void sntrup_encode_1277x2627(uint8_t *, const void *);

#ifdef LC_HOST_X86_64
struct ws_round_encode_avx2 {
	__m256i x, x2, y, y2;
	uint16_t R[639];
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
extern void sntrup_encode_1277x2627round(uint8_t *, const void *,
					 struct ws_round_encode *ws);
extern void sntrup_encode_1277x2627round_avx2(uint8_t *, const void *,
					      struct ws_round_encode *ws);

#define sntrup_verify_clen sntrup_verify_1847
#define sntrup_verify_clen_avx2 sntrup_verify_1847_avx2
#define sntrup_encode_1277x3_STRBYTES 320
#define Small_bytes sntrup_encode_1277x3_STRBYTES
#define Small_encode sntrup_encode_1277x3
#define Small_encode_avx2 sntrup_encode_1277x3_avx2
#define Small_decode sntrup_decode_1277x3
#define Small_decode_avx2 sntrup_decode_1277x3_avx2
#define loops 10
#define overshoot 1

#define sntrup_encode_pxfreeze3 sntrup_encode_1277xfreeze3
#define sntrup_encode_pxfreeze3_avx2 sntrup_encode_1277xfreeze3_avx2
#define sntrup_decode_pxint32 sntrup_decode_1277xint32
#define sntrup_decode_pxint16 sntrup_decode_1277xint16
#define sntrup_encode_pxint16 sntrup_encode_1277xint16
#define sntrup_core_wforce sntrup_core_wforcesntrup1277
#define sntrup_core_wforce_avx2 sntrup_core_wforcesntrup1277_avx2
#define sntrup_core_scale3 sntrup_core_scale3sntrup1277
#define sntrup_core_scale3_avx2 sntrup_core_scale3sntrup1277_avx2
#define sntrup_core_inv sntrup_core_invsntrup1277
#define sntrup_core_inv_avx2 sntrup_core_invsntrup1277_avx2
#define ppad 1281
#define ppadavx2 1280
#define qinv 17143 /* reciprocal of q mod 2^16 */
#define q14 2 /* closest integer to 2^14/q */
#define q18 33 /* closest integer to 2^18/q */
#define q27 17035 /* closest integer to 2^27/q */
#define q31 272557 /* floor(2^31/q) */

#define sntrup_core_inv3 sntrup_core_inv3sntrup1277
#define sntrup_core_inv3_avx2 sntrup_core_inv3sntrup1277_avx2
#define ppad64 1281
#define bitvec_len (ppad64 >> 6)
typedef uint64_t bitvec[bitvec_len];

#define sntrup_core_mult3 sntrup_core_mult3sntrup1277
#define sntrup_core_mult3_avx2 sntrup_core_mult3sntrup1277_avx2
#define sntrup_core_mult sntrup_core_multsntrup1277
#define sntrup_core_mult_avx2 sntrup_core_multsntrup1277_avx2
#define q18 33 /* closest integer to 2^18/q */
#define q27 17035 /* closest integer to 2^27/q */

#define sntrup_core_weight sntrup_core_weightsntrup1277
#define sntrup_core_weight_avx2 sntrup_core_weightsntrup1277_avx2
#define sntrup_verify_BYTES 1847

#ifdef LC_HOST_X86_64
#define endingmask                                                             \
	_mm256_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  \
			1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0)
#endif

#include "common.h"

#endif
