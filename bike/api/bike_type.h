/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef BIKE_TYPE_H
#define BIKE_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Prevent Kyber macros from getting undefined */
#define LC_BIKE_INTERNAL

/*
 * This define replaces all symbol names accordingly to allow double compilation
 * of the same code base.
 *
 * Due to the replacement operation, this header file must be included as the
 * first header file in the entire stack.
 *
 * This file can easily be replaced with lc_bike.h to achieve the common
 * functionality without symbol duplication. But in this case, only the
 * Kyber security strength is compiled defined in lc_bike.h. Duplicate
 * compilation different sizes would not be possible.
 */
#ifdef LC_BIKE_TYPE_3
#define BIKE_F(name) lc_bike_3_##name
#define lc_bike_pk lc_bike_3_pk
#define lc_bike_sk lc_bike_3_sk
#define lc_bike_ct lc_bike_3_ct
#define lc_bike_ss lc_bike_3_ss

#include "lc_bike_3.h"

#elif defined LC_BIKE_TYPE_1
#define BIKE_F(name) lc_bike_1_##name
#define lc_bike_pk lc_bike_1_pk
#define lc_bike_sk lc_bike_1_sk
#define lc_bike_ct lc_bike_1_ct
#define lc_bike_ss lc_bike_1_ss

#include "lc_bike_1.h"

#else
#define BIKE_F(name) lc_bike_5_##name
#define lc_bike_pk lc_bike_5_pk
#define lc_bike_sk lc_bike_5_sk
#define lc_bike_ct lc_bike_5_ct
#define lc_bike_ss lc_bike_5_ss

#include "lc_bike_5.h"

#endif

/*
 * The following defines simply allow duplicate compilation of the
 * respective functions.
 */
#define lc_bike_keypair BIKE_F(keypair)
#define lc_bike_enc BIKE_F(enc)
#define lc_bike_enc_internal BIKE_F(enc_internal)
#define lc_bike_dec BIKE_F(dec)

#define bike_decode BIKE_F(bike_decode)
#define rotate_right_port BIKE_F(rotate_right_port)
#define dup_port BIKE_F(dup_port)
#define bit_sliced_adder_port BIKE_F(bit_sliced_adder_port)
#define bit_slice_full_subtract_port BIKE_F(bit_slice_full_subtract_port)
#define gf2x_mod_mul BIKE_F(gf2x_mod_mul)
#define gf2x_mod_inv BIKE_F(gf2x_mod_inv)
#define gf2x_mul_base_port BIKE_F(gf2x_mul_base_port)
#define karatzuba_add1_port BIKE_F(karatzuba_add1_port)
#define karatzuba_add2_port BIKE_F(karatzuba_add2_port)
#define karatzuba_add3_port BIKE_F(karatzuba_add3_port)
#define gf2x_sqr_port BIKE_F(gf2x_sqr_port)
#define k_sqr_port BIKE_F(k_sqr_port)
#define gf2x_red_port BIKE_F(gf2x_red_port)
#define gf2x_mod_mul_with_ctx BIKE_F(gf2x_mod_mul_with_ctx)
#define generate_secret_key BIKE_F(generate_secret_key)
#define generate_error_vector BIKE_F(generate_error_vector)
#define secure_set_bits_port BIKE_F(secure_set_bits_port)

#define secure_set_bits_avx2 BIKE_F(secure_set_bits_avx2)
#define secure_set_bits_avx512 BIKE_F(secure_set_bits_avx512)
#define rotate_right_avx2 BIKE_F(rotate_right_avx2)
#define dup_avx2 BIKE_F(dup_avx2)
#define bit_sliced_adder_avx2 BIKE_F(bit_sliced_adder_avx2)
#define bit_slice_full_subtract_avx2 BIKE_F(bit_slice_full_subtract_avx2)
#define rotate_right_avx512 BIKE_F(rotate_right_avx512)
#define dup_avx512 BIKE_F(dup_avx512)
#define bit_sliced_adder_avx512 BIKE_F(bit_sliced_adder_avx512)
#define bit_slice_full_subtract_avx512 BIKE_F(bit_slice_full_subtract_avx512)
#define k_sqr_avx2 BIKE_F(k_sqr_avx2)
#define k_sqr_avx512 BIKE_F(k_sqr_avx512)
#define karatzuba_add1_avx2 BIKE_F(karatzuba_add1_avx2)
#define karatzuba_add2_avx2 BIKE_F(karatzuba_add2_avx2)
#define karatzuba_add3_avx2 BIKE_F(karatzuba_add3_avx2)
#define gf2x_red_avx2 BIKE_F(gf2x_red_avx2)
#define karatzuba_add1_avx512 BIKE_F(karatzuba_add1_avx512)
#define karatzuba_add2_avx512 BIKE_F(karatzuba_add2_avx512)
#define karatzuba_add3_avx512 BIKE_F(karatzuba_add3_avx512)
#define gf2x_red_avx512 BIKE_F(gf2x_red_avx512)
#define gf2x_mul_base_pclmul BIKE_F(gf2x_mul_base_pclmul)
#define gf2x_sqr_pclmul BIKE_F(gf2x_sqr_pclmul)
#define gf2x_mul_base_vpclmul BIKE_F(gf2x_mul_base_vpclmul)
#define gf2x_sqr_vpclmul BIKE_F(gf2x_sqr_vpclmul)

#ifdef __cplusplus
}
#endif

#endif /* BIKE_TYPE_H */
