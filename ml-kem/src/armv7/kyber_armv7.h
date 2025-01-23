/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef KYBER_ARMV7_H
#define KYBER_ARMV7_H

#include "ext_headers.h"
#include "kyber_type.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const int16_t zetas_armv7[64];

extern void kyber_ntt_armv7(int16_t *r, const int16_t *zetas);
extern void kyber_invntt_armv7(int16_t *r, const int16_t *zetas);
extern void kyber_poly_sub_armv7(int16_t *, const int16_t *, const int16_t *);
extern void kyber_poly_add_armv7(int16_t *, const int16_t *, const int16_t *);
extern void kyber_barrett_reduce_armv7(int16_t *r);
extern void kyber_basemul_armv7(int16_t *, const int16_t *, const int16_t *,
				const int16_t *);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_ARMV7_H */
