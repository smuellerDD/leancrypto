/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef DILITHIUM_NTT_AVX2_H
#define DILITHIUM_NTT_AVX2_H

#include "ext_headers_x86.h"
#include "dilithium_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void SYSV_ABI dilithium_ntt_avx(__m256i *a, const __m256i *qdata);
void SYSV_ABI dilithium_invntt_avx(__m256i *a, const __m256i *qdata);

void SYSV_ABI dilithium_nttunpack_avx(__m256i *a);

void SYSV_ABI dilithium_pointwise_avx(__m256i *c, const __m256i *a,
				      const __m256i *b, const __m256i *qdata);
void SYSV_ABI dilithium_pointwise_acc_avx(__m256i *c, const __m256i *a,
					  const __m256i *b,
					  const __m256i *qdata);

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_NTT_AVX2_H */
