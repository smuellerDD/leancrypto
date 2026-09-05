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

#define p 953
#define q 6343
#define w 396

#define ppadsort 960
#define numvec 4

#define sntrup_encode_953x6343_STRBYTES 1505
#define Rq_bytes sntrup_encode_953x6343_STRBYTES
#define Rq_encode sntrup_encode_953x6343
extern void sntrup_encode_953x6343(uint8_t *, const void *);
#define sntrup_decode_953x6343_STRBYTES 1505
#define Rq_decode sntrup_decode_953x6343
extern void sntrup_decode_953x6343(void *, const uint8_t *);

#define sntrup_decode_953x2115_STRBYTES 1317
#define Rounded_bytes sntrup_decode_953x2115_STRBYTES
#define Rounded_decode sntrup_decode_953x2115
extern void sntrup_decode_953x2115(void *, const uint8_t *);

#define Round_and_encode sntrup_encode_953x2115round
extern void sntrup_encode_953x2115(uint8_t *, const void *);

struct ws_round_encode {
	int16_t x[p];
};
extern void sntrup_encode_953x2115round(uint8_t *, const void *,
					struct ws_round_encode *ws);

#define sntrup_verify_clen sntrup_verify_1349
#define sntrup_verify_clen_avx2 sntrup_verify_1349_avx2
#define sntrup_encode_953x3_STRBYTES 239
#define Small_bytes sntrup_encode_953x3_STRBYTES
#define Small_encode sntrup_encode_953x3
#define Small_decode sntrup_decode_953x3
#define sntrup_encode_pxfreeze3 sntrup_encode_953xfreeze3
#define sntrup_decode_pxint32 sntrup_decode_953xint32
#define sntrup_decode_pxint16 sntrup_decode_953xint16
#define sntrup_encode_pxint16 sntrup_encode_953xint16
#define sntrup_core_wforce sntrup_core_wforcesntrup953
#define sntrup_core_scale3 sntrup_core_scale3sntrup953
#define sntrup_core_inv sntrup_core_invsntrup953
#define ppad 961
#define ppadavx2 1024
#define qinv 10487 /* reciprocal of q mod 2^16 */
#define q14 3 /* closest integer to 2^14/q */
#define q18 41 /* closest integer to 2^18/q */
#define q27 21160 /* closest integer to 2^27/q */
#define q31 338559 /* floor(2^31/q) */

#define sntrup_core_inv3 sntrup_core_inv3sntrup953
#define sntrup_core_inv3_avx2 sntrup_core_inv3sntrup953_avx2
#define ppad64 961
#define bitvec_len (ppad64 >> 6)
typedef uint64_t bitvec[bitvec_len];

#define sntrup_core_mult3 sntrup_core_mult3sntrup953
#define sntrup_core_mult sntrup_core_multsntrup953
#define q18 41 /* closest integer to 2^18/q */
#define q27 21160 /* closest integer to 2^27/q */

#define sntrup_core_weight sntrup_core_weightsntrup953
#define sntrup_verify_BYTES 1349

#include "common.h"

#endif
