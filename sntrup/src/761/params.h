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

#define p 761
#define q 4591
#define w 286

#define ppadsort 768
#define numvec 3

#define sntrup_encode_761x4591_STRBYTES 1158
#define Rq_bytes sntrup_encode_761x4591_STRBYTES
#define Rq_encode sntrup_encode_761x4591
extern void sntrup_encode_761x4591(uint8_t *, const void *);
#define sntrup_decode_761x4591_STRBYTES 1158
#define Rq_decode sntrup_decode_761x4591
extern void sntrup_decode_761x4591(void *, const uint8_t *);

#define sntrup_decode_761x1531_STRBYTES 1007
#define Rounded_bytes sntrup_decode_761x1531_STRBYTES
#define Rounded_decode sntrup_decode_761x1531
extern void sntrup_decode_761x1531(void *, const uint8_t *);

#define Round_and_encode sntrup_encode_761x1531round
extern void sntrup_encode_761x1531(uint8_t *, const void *);

struct ws_round_encode {
	int16_t x[p];
};
extern void sntrup_encode_761x1531round(uint8_t *, const void *,
					struct ws_round_encode *ws);

#define sntrup_verify_clen sntrup_verify_1039
#define sntrup_verify_clen_avx2 sntrup_verify_1039_avx2
#define sntrup_encode_761x3_STRBYTES 191
#define Small_bytes sntrup_encode_761x3_STRBYTES
#define Small_encode sntrup_encode_761x3
#define Small_decode sntrup_decode_761x3
#define sntrup_encode_pxfreeze3 sntrup_encode_761xfreeze3
#define sntrup_decode_pxint32 sntrup_decode_761xint32
#define sntrup_decode_pxint16 sntrup_decode_761xint16
#define sntrup_encode_pxint16 sntrup_encode_761xint16
#define sntrup_core_wforce sntrup_core_wforcesntrup761
#define sntrup_core_scale3 sntrup_core_scale3sntrup761
#define sntrup_core_inv sntrup_core_invsntrup761
#define ppad 769
#define ppadavx2 768
#define qinv 15631 /* reciprocal of q mod 2^16 */
#define q14 4 /* closest integer to 2^14/q */
#define q18 57 /* closest integer to 2^18/q */
#define q27 29235 /* closest integer to 2^27/q */
#define q31 467759 /* floor(2^31/q) */

#define sntrup_core_inv3 sntrup_core_inv3sntrup761
#define sntrup_core_inv3_avx2 sntrup_core_inv3sntrup761_avx2
#define ppad64 769
#define bitvec_len (ppad64 >> 6)
typedef uint64_t bitvec[bitvec_len];

#define sntrup_core_mult3 sntrup_core_mult3sntrup761
#define sntrup_core_mult sntrup_core_multsntrup761
#define q18 57 /* closest integer to 2^18/q */
#define q27 29235 /* closest integer to 2^27/q */

#define sntrup_core_weight sntrup_core_weightsntrup761
#define sntrup_verify_BYTES 1039

#include "common.h"

#endif
