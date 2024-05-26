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

#ifndef DILITHIUM_TYPE_H
#define DILITHIUM_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Prevent Kyber macros from getting undefined */
#define LC_DILITHIUM_INTERNAL

/*
 * This define replaces all symbol names accordingly to allow double compilation
 * of the same code base.
 *
 * Due to the replacement operation, this header file must be included as the
 * first header file in the entire stack.
 *
 * This file can easily be replaced with lc_dilithium.h to achieve the common
 * functionality without symbol duplication. But in this case, only the
 * Dilithium security strength is compiled defined in lc_dilithium.h. Duplicate
 * compilation different sizes would not be possible.
 */
#ifdef LC_DILITHIUM_TYPE_65
#define DILITHIUM_F(name) lc_dilithium_65_##name
#define lc_dilithium_pk lc_dilithium_65_pk
#define lc_dilithium_sk lc_dilithium_65_sk
#define lc_dilithium_sig lc_dilithium_65_sig
#define lc_dilithium_ed25519_pk lc_dilithium_65_ed25519_pk
#define lc_dilithium_ed25519_sk lc_dilithium_65_ed25519_sk
#define lc_dilithium_ed25519_sig lc_dilithium_65_ed25519_sig

#include "lc_dilithium_65.h"

#elif defined LC_DILITHIUM_TYPE_44
#define DILITHIUM_F(name) lc_dilithium_44_##name
#define lc_dilithium_pk lc_dilithium_44_pk
#define lc_dilithium_sk lc_dilithium_44_sk
#define lc_dilithium_sig lc_dilithium_44_sig
#define lc_dilithium_ed25519_pk lc_dilithium_44_ed25519_pk
#define lc_dilithium_ed25519_sk lc_dilithium_44_ed25519_sk
#define lc_dilithium_ed25519_sig lc_dilithium_44_ed25519_sig

#include "lc_dilithium_44.h"

#else
#define DILITHIUM_F(name) lc_dilithium_##name

#include "lc_dilithium_87.h"

#endif

/*
 * The following defines simply allow duplicate compilation of the
 * respective functions.
 */
#define lc_dilithium_keypair DILITHIUM_F(keypair)
#define lc_dilithium_sign DILITHIUM_F(sign)
#define lc_dilithium_sign_init DILITHIUM_F(sign_init)
#define lc_dilithium_sign_update DILITHIUM_F(sign_update)
#define lc_dilithium_sign_final DILITHIUM_F(sign_final)
#define lc_dilithium_verify DILITHIUM_F(verify)
#define lc_dilithium_verify_init DILITHIUM_F(verify_init)
#define lc_dilithium_verify_update DILITHIUM_F(verify_update)
#define lc_dilithium_verify_final DILITHIUM_F(verify_final)

#define lc_dilithium_keypair_c DILITHIUM_F(keypair_c)
#define lc_dilithium_sign_c DILITHIUM_F(sign_c)
#define lc_dilithium_sign_init_c DILITHIUM_F(sign_init_c)
#define lc_dilithium_sign_update_c DILITHIUM_F(sign_update_c)
#define lc_dilithium_sign_final_c DILITHIUM_F(sign_final_c)
#define lc_dilithium_verify_c DILITHIUM_F(verify_c)
#define lc_dilithium_verify_init_c DILITHIUM_F(verify_init_c)
#define lc_dilithium_verify_update_c DILITHIUM_F(verify_update_c)
#define lc_dilithium_verify_final_c DILITHIUM_F(verify_final_c)

#define lc_dilithium_ed25519_keypair DILITHIUM_F(ed25519_keypair)
#define lc_dilithium_ed25519_sign DILITHIUM_F(ed25519_sign)
#define lc_dilithium_ed25519_verify DILITHIUM_F(ed25519_verify)

#define dilithium_keypair_tester DILITHIUM_F(keypair_tester)
#define dilithium_siggen_tester DILITHIUM_F(siggen_tester)
#define dilithium_sigver_tester DILITHIUM_F(sigver_tester)

#define ntt DILITHIUM_F(ntt)
#define invntt_tomont DILITHIUM_F(invntt_tomont)
#define poly_chknorm DILITHIUM_F(poly_chknorm)
#define poly_uniform DILITHIUM_F(poly_uniform)
#define poly_uniform_eta DILITHIUM_F(poly_uniform_eta)
#define poly_uniform_gamma1 DILITHIUM_F(poly_uniform_gamma1)
#define polyz_unpack DILITHIUM_F(polyz_unpack)
#define poly_challenge DILITHIUM_F(poly_challenge)
#define polyeta_pack DILITHIUM_F(polyeta_pack)
#define polyeta_unpack DILITHIUM_F(polyeta_unpack)
#define polyt1_pack DILITHIUM_F(polyt1_pack)
#define polyt0_pack DILITHIUM_F(polyt0_pack)
#define polyt0_unpack DILITHIUM_F(polyt0_unpack)
#define polyz_pack DILITHIUM_F(polyz_pack)
#define polyw1_pack DILITHIUM_F(polyw1_pack)
#define power2round DILITHIUM_F(power2round)
#define decompose DILITHIUM_F(decompose)
#define make_hint DILITHIUM_F(make_hint)
#define use_hint DILITHIUM_F(use_hint)

#define dilithium_print_buffer DILITHIUM_F(print_buffer)
#define dilithium_print_polyvecl_k DILITHIUM_F(print_polyvecl_k)
#define dilithium_print_polyvecl DILITHIUM_F(print_polyvecl)
#define dilithium_print_polyveck DILITHIUM_F(print_polyveck)
#define dilithium_print_poly DILITHIUM_F(print_poly)

/* AVX2 Implementation */
#define dilithium_invntt_avx DILITHIUM_F(invntt_avx)
#define dilithium_ntt_avx DILITHIUM_F(ntt_avx)
#define dilithium_nttunpack_avx DILITHIUM_F(nttunpack_avx)
#define dilithium_pointwise_avx DILITHIUM_F(pointwise_avx)
#define dilithium_pointwise_acc_avx DILITHIUM_F(pointwise_acc_avx)
#define poly_reduce_avx DILITHIUM_F(poly_reduce_avx)
#define poly_caddq_avx DILITHIUM_F(poly_caddq_avx)
#define poly_add_avx DILITHIUM_F(poly_add_avx)
#define poly_sub_avx DILITHIUM_F(poly_sub_avx)
#define poly_shiftl_avx DILITHIUM_F(poly_shiftl_avx)
#define poly_chknorm_avx DILITHIUM_F(poly_chknorm_avx)
#define poly_uniform_4x_avx DILITHIUM_F(poly_uniform_4x_avx)
#define poly_uniform_eta_4x_avx DILITHIUM_F(poly_uniform_eta_4x_avx)
#define poly_uniform_gamma1_4x_avx DILITHIUM_F(poly_uniform_gamma1_4x_avx)
#define polyz_unpack_avx DILITHIUM_F(polyz_unpack_avx)
#define poly_challenge_avx DILITHIUM_F(poly_challenge_avx)
#define polyeta_pack_avx DILITHIUM_F(polyeta_pack_avx)
#define polyeta_unpack_avx DILITHIUM_F(polyeta_unpack_avx)
#define polyt1_pack_avx DILITHIUM_F(polyt1_pack_avx)
#define polyt1_unpack_avx DILITHIUM_F(polyt1_unpack_avx)
#define polyt0_pack_avx DILITHIUM_F(polyt0_pack_avx)
#define polyt0_unpack_avx DILITHIUM_F(polyt0_unpack_avx)
#define polyz_pack_avx DILITHIUM_F(polyz_pack_avx)
#define polyw1_pack_avx DILITHIUM_F(polyw1_pack_avx)
#define polyvec_matrix_expand DILITHIUM_F(polyvec_matrix_expand)
#define polyvec_matrix_expand_row0 DILITHIUM_F(polyvec_matrix_expand_row0)
#define polyvec_matrix_expand_row1 DILITHIUM_F(polyvec_matrix_expand_row1)
#define polyvec_matrix_expand_row2 DILITHIUM_F(polyvec_matrix_expand_row2)
#define polyvec_matrix_expand_row3 DILITHIUM_F(polyvec_matrix_expand_row3)
#define polyvec_matrix_expand_row4 DILITHIUM_F(polyvec_matrix_expand_row4)
#define polyvec_matrix_expand_row5 DILITHIUM_F(polyvec_matrix_expand_row5)
#define polyvec_matrix_expand_row6 DILITHIUM_F(polyvec_matrix_expand_row6)
#define polyvec_matrix_expand_row7 DILITHIUM_F(polyvec_matrix_expand_row7)
#define rej_uniform_avx DILITHIUM_F(rej_uniform_avx)
#define rej_eta_avx DILITHIUM_F(rej_eta_avx)
#define idxlut DILITHIUM_F(idxlut)
#define power2round_avx DILITHIUM_F(power2round_avx)
#define decompose_avx DILITHIUM_F(decompose_avx)
#define make_hint_avx DILITHIUM_F(make_hint_avx)
#define use_hint_avx DILITHIUM_F(use_hint_avx)
#define lc_dilithium_keypair_avx2 DILITHIUM_F(keypair_avx2)
#define lc_dilithium_sign_avx2 DILITHIUM_F(sign_avx2)
#define lc_dilithium_sign_init_avx2 DILITHIUM_F(sign_init_avx2)
#define lc_dilithium_sign_update_avx2 DILITHIUM_F(sign_update_avx2)
#define lc_dilithium_sign_final_avx2 DILITHIUM_F(sign_final_avx2)
#define lc_dilithium_verify_avx2 DILITHIUM_F(verify_avx2)
#define lc_dilithium_verify_init_avx2 DILITHIUM_F(verify_init_avx2)
#define lc_dilithium_verify_update_avx2 DILITHIUM_F(verify_update_avx2)
#define lc_dilithium_verify_final_avx2 DILITHIUM_F(verify_final_avx2)

/* ARMv8 Implementation */
#define intt_SIMD_top_armv8 DILITHIUM_F(intt_SIMD_top_armv8)
#define intt_SIMD_bot_armv8 DILITHIUM_F(intt_SIMD_bot_armv8)
#define ntt_SIMD_top_armv8 DILITHIUM_F(ntt_SIMD_top_armv8)
#define ntt_SIMD_bot_armv8 DILITHIUM_F(ntt_SIMD_bot_armv8)
#define poly_uniformx2 DILITHIUM_F(poly_uniformx2)
#define poly_uniform_etax2 DILITHIUM_F(poly_uniform_etax2)
#define poly_uniform_gamma1x2 DILITHIUM_F(poly_uniform_gamma1x2)
#define armv8_10_to_32 DILITHIUM_F(armv8_10_to_32)
#define poly_reduce_armv8 DILITHIUM_F(poly_reduce_armv8)
#define poly_caddq_armv8 DILITHIUM_F(poly_caddq_armv8)
#define poly_power2round_armv8 DILITHIUM_F(poly_power2round_armv8)
#define poly_pointwise_montgomery_armv8                                        \
	DILITHIUM_F(poly_pointwise_montgomery_armv8)
#define polyvecl_pointwise_acc_montgomery_armv8                                \
	DILITHIUM_F(polyvecl_pointwise_acc_montgomery_armv8)
#define lc_dilithium_keypair_armv8 DILITHIUM_F(keypair_armv8)
#define lc_dilithium_sign_armv8 DILITHIUM_F(sign_armv8)
#define lc_dilithium_sign_init_armv8 DILITHIUM_F(sign_init_armv8)
#define lc_dilithium_sign_update_armv8 DILITHIUM_F(sign_update_armv8)
#define lc_dilithium_sign_final_armv8 DILITHIUM_F(sign_final_armv8)
#define lc_dilithium_verify_armv8 DILITHIUM_F(verify_armv8)
#define lc_dilithium_verify_init_armv8 DILITHIUM_F(verify_init_armv8)
#define lc_dilithium_verify_update_armv8 DILITHIUM_F(verify_update_armv8)
#define lc_dilithium_verify_final_armv8 DILITHIUM_F(verify_final_armv8)

/* ARMv7 Implementation */
#define armv7_ntt_asm_smull DILITHIUM_F(armv7_ntt_asm_smull)
#define armv7_inv_ntt_asm_smull DILITHIUM_F(armv7_inv_ntt_asm_smull)
#define armv7_poly_pointwise_invmontgomery_asm_smull                           \
	DILITHIUM_F(armv7_poly_pointwise_invmontgomery_asm_smull)
#define armv7_poly_pointwise_acc_invmontgomery_asm_smull                       \
	DILITHIUM_F(armv7_poly_pointwise_acc_invmontgomery_asm_smull)
#define poly_uniform_armv7 DILITHIUM_F(poly_uniform_armv7)
#define armv7_poly_reduce_asm DILITHIUM_F(armv7_poly_reduce_asm)
#define armv7_rej_uniform_asm DILITHIUM_F(armv7_rej_uniform_asm)
#define lc_dilithium_keypair_armv7 DILITHIUM_F(keypair_armv7)
#define lc_dilithium_sign_armv7 DILITHIUM_F(sign_armv7)
#define lc_dilithium_sign_init_armv7 DILITHIUM_F(sign_init_armv7)
#define lc_dilithium_sign_update_armv7 DILITHIUM_F(sign_update_armv7)
#define lc_dilithium_sign_final_armv7 DILITHIUM_F(sign_final_armv7)
#define lc_dilithium_verify_armv7 DILITHIUM_F(verify_armv7)
#define lc_dilithium_verify_init_armv7 DILITHIUM_F(verify_init_armv7)
#define lc_dilithium_verify_update_armv7 DILITHIUM_F(verify_update_armv7)
#define lc_dilithium_verify_final_armv7 DILITHIUM_F(verify_final_armv7)

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_TYPE_H */
