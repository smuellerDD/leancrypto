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

#ifndef common_H
#define common_H

#include "ext_headers_internal.h"

/* ----- arithmetic mod 3 */
typedef int8_t small;

/* F3 is always represented as -1,0,1 */
typedef int16_t Fq;

extern int sntrup_verify_clen(const uint8_t *, const uint8_t *);
void Small_encode(uint8_t *s, const void *v);
void Small_decode(void *v, const uint8_t *s);
void sntrup_encode_pxfreeze3(uint8_t *s, const void *v);
void sntrup_decode_pxint32(void *v, const uint8_t *s);
void sntrup_decode_pxint16(void *v, const uint8_t *s);
void sntrup_encode_pxint16(uint8_t *s, const void *v);
void sntrup_core_wforce(uint8_t *out, const uint8_t *in, const uint8_t *kbytes,
			const uint8_t *cbytes);

struct ws_core_scale3 {
	Fq f[p];
};
void sntrup_core_scale3(uint8_t *outbytes, const uint8_t *inbytes,
			const uint8_t *kbytes, const uint8_t *cbytes,
			struct ws_core_scale3 *ws);

struct ws_core_inv {
	Fq out[p], f[ppad], g[ppad], v[ppad], r[ppad];
	Fq f0, g0;
	Fq scale;
};
extern void sntrup_core_inv(uint8_t *, const uint8_t *, const uint8_t *,
			    const uint8_t *, struct ws_core_inv *ws);

struct ws_core_inv3 {
	bitvec f0, f1, g0, g1, v0, v1, r0, r1;
};
extern void sntrup_core_inv3(uint8_t *, const uint8_t *, const uint8_t *,
			     const uint8_t *, struct ws_core_inv3 *ws);

struct ws_core_mutl3 {
	small f[p];
	small g[p];
	int16_t fg[p + p - 1];
};
void sntrup_core_mult3(uint8_t *outbytes, const uint8_t *inbytes,
		       const uint8_t *kbytes, const uint8_t *cbytes,
		       struct ws_core_mutl3 *ws);

struct ws_core_mult {
	Fq f[p];
	int32_t f32[p];
	int32_t fg[p + p - 1];
	Fq h[p];
};
void sntrup_core_mult(uint8_t *outbytes, const uint8_t *inbytes,
		      const uint8_t *kbytes, const uint8_t *cbytes,
		      struct ws_core_mult *ws);
extern void sntrup_core_weight(uint8_t *, const uint8_t *, const uint8_t *,
			       const uint8_t *);
extern int sntrup_verify_clen(const uint8_t *, const uint8_t *);

#endif
