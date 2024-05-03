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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_REJSAMPLE_AVX2_H
#define KYBER_REJSAMPLE_AVX2_H

#include "kyber_type.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define REJ_UNIFORM_AVX_NBLOCKS                                                \
	((12 * LC_KYBER_N / 8 * (1 << 12) / LC_KYBER_Q +                       \
	  LC_SHAKE_128_SIZE_BLOCK) /                                           \
	 LC_SHAKE_128_SIZE_BLOCK)
#define REJ_UNIFORM_AVX_BUFLEN                                                 \
	(REJ_UNIFORM_AVX_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK)

unsigned int kyber_rej_uniform_avx(int16_t *r, const uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_REJSAMPLE_AVX2_H */
