/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef HQC_TYPE_H
#define HQC_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Prevent HQC macros from getting undefined */
#define LC_HQC_INTERNAL

/*
 * This define replaces all symbol names accordingly to allow double compilation
 * of the same code base.
 *
 * Due to the replacement operation, this header file must be included as the
 * first header file in the entire stack.
 *
 * This file can easily be replaced with lc_hqc.h to achieve the common
 * functionality without symbol duplication. But in this case, only the
 * HQC security strength is compiled defined in lc_hqc.h. Duplicate
 * compilation different sizes would not be possible.
 */
#ifdef LC_HQC_TYPE_192
#define HQC_F(name) lc_hqc_192_##name
#define lc_hqc_pk lc_hqc_192_pk
#define lc_hqc_sk lc_hqc_192_sk
#define lc_hqc_ct lc_hqc_192_ct
#define lc_hqc_ss lc_hqc_192_ss

#include "lc_hqc_192.h"

#elif defined LC_HQC_TYPE_128
#define HQC_F(name) lc_hqc_128_##name
#define lc_hqc_pk lc_hqc_128_pk
#define lc_hqc_sk lc_hqc_128_sk
#define lc_hqc_ct lc_hqc_128_ct
#define lc_hqc_ss lc_hqc_128_ss

#include "lc_hqc_128.h"

#else
#define HQC_F(name) lc_hqc_256_##name
#define lc_hqc_pk lc_hqc_256_pk
#define lc_hqc_sk lc_hqc_256_sk
#define lc_hqc_ct lc_hqc_256_ct
#define lc_hqc_ss lc_hqc_256_ss

#include "lc_hqc_256.h"

#endif

/*
 * The following defines simply allow duplicate compilation of the
 * respective functions.
 */
#define lc_hqc_keypair HQC_F(keypair)
#define lc_hqc_keypair_from_seed HQC_F(keypair_from_seed)
#define lc_hqc_enc HQC_F(enc)
#define lc_hqc_enc_kdf HQC_F(enc_kdf)
#define lc_hqc_enc_internal HQC_F(enc_internal)
#define lc_hqc_dec HQC_F(dec)
#define lc_hqc_dec_kdf HQC_F(dec_kdf)
#define hqc_kem_keygen_selftest HQC_F(hqc_kem_keygen_selftest)
#define hqc_kem_enc_selftest HQC_F(hqc_kem_enc_selftest)
#define hqc_kem_dec_selftest HQC_F(hqc_kem_dec_selftest)

#define fft HQC_F(fft)
#define fft_retrieve_error_poly HQC_F(fft_retrieve_error_poly)
#define gf_mul HQC_F(gf_mul)
#define gf_square HQC_F(gf_square)
#define gf_inverse HQC_F(gf_inverse)
#define vect_mul HQC_F(vect_mul)
#define hqc_pke_keygen HQC_F(hqc_pke_keygen)
#define hqc_pke_encrypt HQC_F(hqc_pke_encrypt)
#define hqc_pke_decrypt HQC_F(hqc_pke_decrypt)
#define load8_arr HQC_F(load8_arr)
#define store8_arr HQC_F(store8_arr)
#define hqc_secret_key_to_string HQC_F(hqc_secret_key_to_string)
#define hqc_secret_key_from_string HQC_F(hqc_secret_key_from_string)
#define hqc_public_key_to_string HQC_F(hqc_public_key_to_string)
#define hqc_public_key_from_string HQC_F(hqc_public_key_from_string)
#define hqc_ciphertext_to_string HQC_F(hqc_ciphertext_to_string)
#define hqc_ciphertext_from_string HQC_F(hqc_ciphertext_from_string)
#define reed_muller_encode HQC_F(reed_muller_encode)
#define reed_muller_decode HQC_F(reed_muller_decode)
#define reed_solomon_encode HQC_F(reed_solomon_encode)
#define reed_solomon_decode HQC_F(reed_solomon_decode)
#define vect_set_random_fixed_weight HQC_F(vect_set_random_fixed_weight)
#define vect_set_random HQC_F(vect_set_random)
#define vect_add HQC_F(vect_add)
#define vect_compare HQC_F(vect_compare)
#define vect_resize HQC_F(vect_resize)
#define code_encode HQC_F(code_encode)
#define code_decode HQC_F(code_decode)

#ifdef __cplusplus
}
#endif

#endif /* HQC_TYPE_H */
