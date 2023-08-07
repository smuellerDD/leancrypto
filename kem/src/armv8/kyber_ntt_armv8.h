/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/psanal2018/kyber-arm64
 *
 * That code is released under MIT license.
 */

#ifndef KYBER_NTT_ARMV8_H
#define KYBER_NTT_ARMV8_H

#include "lc_kyber.h"

#ifdef __cplusplus
extern "C" {
#endif

//extern const int16_t zetas_armv8[128];
//extern const int16_t zetas_inv[128];

// zetas for ntt_arm
extern const int16_t kyber_zetas_armv8[287];
extern const int16_t kyber_zetas_inv_armv8[287];

void kyber_ntt_armv8(int16_t *poly, const int16_t *zetas);

void kyber_inv_ntt_armv8(int16_t *poly, const int16_t *zetas_inv);

void kyber_basemul_armv8(int16_t *poly, const int16_t *a, const int16_t *b,
			 const int16_t *zetas);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_NTT_ARMV8_H */
