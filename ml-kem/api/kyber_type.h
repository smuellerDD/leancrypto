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

#ifndef KYBER_TYPE_H
#define KYBER_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Prevent Kyber macros from getting undefined */
#define LC_KYBER_INTERNAL

/*
 * This define replaces all symbol names accordingly to allow double compilation
 * of the same code base.
 *
 * Due to the replacement operation, this header file must be included as the
 * first header file in the entire stack.
 *
 * This file can easily be replaced with lc_kyber.h to achieve the common
 * functionality without symbol duplication. But in this case, only the
 * Kyber security strength is compiled defined in lc_kyber.h. Duplicate
 * compilation different sizes would not be possible.
 */
#ifdef LC_KYBER_TYPE_768
#define KYBER_F(name) lc_kyber_768_##name
#define KEX_F(name) lc_kex_768_##name
#define lc_kyber_pk lc_kyber_768_pk
#define lc_kyber_sk lc_kyber_768_sk
#define lc_kyber_ct lc_kyber_768_ct
#define lc_kyber_ss lc_kyber_768_ss
#define lc_kyber_x25519_pk lc_kyber_768_x25519_pk
#define lc_kyber_x25519_sk lc_kyber_768_x25519_sk
#define lc_kyber_x25519_ct lc_kyber_768_x25519_ct
#define lc_kyber_x25519_ss lc_kyber_768_x25519_ss

#include "lc_kyber_768.h"

#elif defined LC_KYBER_TYPE_512
#define KYBER_F(name) lc_kyber_512_##name
#define KEX_F(name) lc_kex_512_##name
#define lc_kyber_pk lc_kyber_512_pk
#define lc_kyber_sk lc_kyber_512_sk
#define lc_kyber_ct lc_kyber_512_ct
#define lc_kyber_ss lc_kyber_512_ss
#define lc_kyber_x25519_pk lc_kyber_512_x25519_pk
#define lc_kyber_x25519_sk lc_kyber_512_x25519_sk
#define lc_kyber_x25519_ct lc_kyber_512_x25519_ct
#define lc_kyber_x25519_ss lc_kyber_512_x25519_ss

#include "lc_kyber_512.h"

#else
#define KYBER_F(name) lc_kyber_1024_##name
#define KEX_F(name) lc_kex_1024_##name
#define lc_kyber_pk lc_kyber_1024_pk
#define lc_kyber_sk lc_kyber_1024_sk
#define lc_kyber_ct lc_kyber_1024_ct
#define lc_kyber_ss lc_kyber_1024_ss
#define lc_kyber_x25519_pk lc_kyber_1024_x25519_pk
#define lc_kyber_x25519_sk lc_kyber_1024_x25519_sk
#define lc_kyber_x25519_ct lc_kyber_1024_x25519_ct
#define lc_kyber_x25519_ss lc_kyber_1024_x25519_ss

#include "lc_kyber_1024.h"

#endif

/*
 * The following defines simply allow duplicate compilation of the
 * respective functions.
 */
#define lc_kex_x25519_uake_initiator_init KEX_F(x25519_uake_initiator_init)
#define lc_kex_x25519_uake_responder_ss KEX_F(x25519_uake_responder_ss)
#define lc_kex_x25519_uake_initiator_ss KEX_F(x25519_uake_initiator_ss)
#define lc_kex_x25519_ake_initiator_init KEX_F(x25519_ake_initiator_init)
#define lc_kex_x25519_ake_responder_ss KEX_F(x25519_ake_responder_ss)
#define lc_kex_x25519_ake_initiator_ss KEX_F(x25519_ake_initiator_ss)

#define lc_kex_uake_initiator_init KEX_F(uake_initiator_init)
#define lc_kex_uake_responder_ss KEX_F(uake_responder_ss)
#define lc_kex_uake_initiator_ss KEX_F(uake_initiator_ss)
#define lc_kex_ake_initiator_init KEX_F(ake_initiator_init)
#define lc_kex_ake_responder_ss KEX_F(ake_responder_ss)
#define lc_kex_ake_initiator_ss KEX_F(ake_initiator_ss)

#define lc_kyber_x25519_keypair KYBER_F(x25519_keypair)
#define lc_kyber_x25519_enc_kdf KYBER_F(x25519_enc_kdf)
#define lc_kyber_x25519_dec_kdf KYBER_F(x25519_dec_kdf)

#define lc_kyber_keypair KYBER_F(keypair)
#define lc_kyber_keypair_from_seed KYBER_F(keypair_from_seed)
#define lc_kyber_enc KYBER_F(enc)
#define lc_kyber_dec KYBER_F(dec)
#define lc_kyber_enc_kdf KYBER_F(enc_kdf)
#define lc_kyber_dec_kdf KYBER_F(dec_kdf)

#define _lc_kyber_keypair KYBER_F(_keypair)
#define _lc_kyber_keypair_from_seed KYBER_F(_keypair_from_seed)
#define _lc_kyber_enc KYBER_F(_enc)
#define _lc_kyber_dec KYBER_F(_dec)
#define _lc_kyber_enc_kdf KYBER_F(_enc_kdf)
#define _lc_kyber_dec_kdf KYBER_F(_dec_kdf)

#define lc_kyber_keypair_c KYBER_F(keypair_c)
#define lc_kyber_keypair_from_seed_c KYBER_F(keypair_from_seed_c)
#define lc_kyber_enc_c KYBER_F(enc_c)
#define lc_kyber_dec_c KYBER_F(dec_c)
#define lc_kyber_enc_kdf_c KYBER_F(enc_kdf_c)
#define lc_kyber_dec_kdf_c KYBER_F(dec_kdf_c)

#define lc_kyber_x25519_ies_enc KYBER_F(x25519_ies_enc)
#define lc_kyber_x25519_ies_dec KYBER_F(x25519_ies_dec)
#define lc_kyber_x25519_ies_enc_init KYBER_F(x25519_ies_enc_init)
#define lc_kyber_x25519_ies_enc_update KYBER_F(x25519_ies_enc_update)
#define lc_kyber_x25519_ies_enc_final KYBER_F(x25519_ies_enc_final)
#define lc_kyber_x25519_ies_dec_init KYBER_F(x25519_ies_dec_init)
#define lc_kyber_x25519_ies_dec_update KYBER_F(x25519_ies_dec_update)
#define lc_kyber_x25519_ies_dec_final KYBER_F(x25519_ies_dec_final)

#define lc_kyber_ies_enc KYBER_F(ies_enc)
#define lc_kyber_ies_dec KYBER_F(ies_dec)
#define lc_kyber_ies_enc_init KYBER_F(ies_enc_init)
#define lc_kyber_ies_enc_update KYBER_F(ies_enc_update)
#define lc_kyber_ies_enc_final KYBER_F(ies_enc_final)
#define lc_kyber_ies_dec_init KYBER_F(ies_dec_init)
#define lc_kyber_ies_dec_update KYBER_F(ies_dec_update)
#define lc_kyber_ies_dec_final KYBER_F(ies_dec_final)

#define lc_kyber_enc_internal KYBER_F(enc_internal)
#define lc_kyber_x25519_enc_internal KYBER_F(x25519_enc_internal)
#define lc_kyber_x25519_dec_internal KYBER_F(x25519_dec_internal)
#define lc_kyber_enc_kdf_internal KYBER_F(enc_kdf_internal)
#define lc_kyber_x25519_enc_kdf_internal KYBER_F(x25519_enc_kdf_internal)
#define lc_kex_uake_initiator_init_internal KEX_F(uake_initiator_init_internal)
#define lc_kex_x25519_uake_initiator_init_internal                             \
	KEX_F(x25519_uake_initiator_init_internal)
#define lc_kex_uake_responder_ss_internal KEX_F(uake_responder_ss_internal)
#define lc_kex_x25519_uake_responder_ss_internal                               \
	KEX_F(x25519_uake_responder_ss_internal)
#define lc_kex_ake_initiator_init_internal KEX_F(ake_initiator_init_internal)
#define lc_kex_x25519_ake_initiator_init_internal                              \
	KEX_F(x25519_ake_initiator_init_internal)
#define lc_kex_ake_responder_ss_internal KEX_F(ake_responder_ss_internal)
#define lc_kex_x25519_ake_responder_ss_internal                                \
	KEX_F(x25519_ake_responder_ss_internal)
#define lc_kyber_ies_enc_internal KYBER_F(ies_enc_internal)
#define lc_kyber_x25519_ies_enc_internal KYBER_F(x25519_ies_enc_internal)
#define lc_kyber_ies_enc_init_internal KYBER_F(ies_enc_init_internal)
#define lc_kyber_x25519_ies_enc_init_internal                                  \
	KYBER_F(x25519_ies_enc_init_internal)

#define poly_cbd_eta1 KYBER_F(poly_cbd_eta1)
#define poly_cbd_eta2 KYBER_F(poly_cbd_eta2)
#define kyber_kem_dec_kdf_selftest KYBER_F(kem_dec_kdf_selftest)
#define kyber_kem_enc_kdf_selftest KYBER_F(kem_enc_kdf_selftest)
#define kyber_kem_dec_selftest KYBER_F(kem_dec_selftest)
#define kyber_kem_enc_selftest KYBER_F(kem_enc_selftest)
#define kyber_kem_keygen_selftest KYBER_F(kem_keygen_selftest)
#define polyvec_decompress KYBER_F(polyvec_decompress)
#define polyvec_compress KYBER_F(polyvec_compress)
#define poly_compress KYBER_F(poly_compress)
#define basemul KYBER_F(basemul)
#define poly_getnoise_eta2 KYBER_F(poly_getnoise_eta2)
#define poly_getnoise_eta1 KYBER_F(poly_getnoise_eta1)
#define indcpa_dec KYBER_F(indcpa_dec)
#define indcpa_enc KYBER_F(indcpa_enc)
#define indcpa_keypair KYBER_F(indcpa_keypair)

#define kyber_print_buffer KYBER_F(print_buffer)
#define kyber_print_polyvec KYBER_F(print_polyvec)
#define kyber_print_polyveck KYBER_F(print_polyveck)
#define kyber_print_poly KYBER_F(print_poly)

/* AVX2 Implementation */
#define kyber_rej_uniform_avx KYBER_F(rej_uniform_avx)
#define kyber_poly_sub_avx KYBER_F(poly_sub_avx)
#define kyber_poly_add_avx KYBER_F(poly_add_avx)
#define poly_getnoise_eta1_4x KYBER_F(poly_getnoise_eta1_4x)
#define poly_tomsg_avx KYBER_F(tomsg_avx)
#define poly_frommsg_avx KYBER_F(frommsg_avx)
#define poly_compress_avx KYBER_F(compress_avx)
#define poly_decompress_avx KYBER_F(decompress_avx)
#define lc_kyber_keypair_avx KYBER_F(keypair_avx)
#define lc_kyber_keypair_from_seed_avx KYBER_F(keypair_from_seed_avx)
#define lc_kyber_enc_avx KYBER_F(enc_avx)
#define lc_kyber_dec_avx KYBER_F(dec_avx)
#define lc_kyber_enc_kdf_avx KYBER_F(enc_kdf_avx)
#define lc_kyber_dec_kdf_avx KYBER_F(dec_kdf_avx)
#define indcpa_dec_avx KYBER_F(indcpa_dec_avx)
#define indcpa_enc_avx KYBER_F(indcpa_enc_avx)
#define indcpa_keypair_avx KYBER_F(indcpa_keypair_avx)
#define kyber_nttfrombytes_avx KYBER_F(nttfrombytes_avx)
#define kyber_ntttobytes_avx KYBER_F(ntttobytes_avx)
#define kyber_nttunpack_avx KYBER_F(nttunpack_avx)
#define kyber_ntt_avx KYBER_F(ntt_avx)
#define kyber_invntt_avx KYBER_F(invntt_avx)
#define tomont_avx KYBER_F(tomont_avx)
#define reduce_avx KYBER_F(reduce_avx)
#define kyber_basemul_avx KYBER_F(basemul_avx)

/* ARMv8 Implementation */
#define kyber_add_armv8 KYBER_F(add_armv8)
#define kyber_basemul_armv8 KYBER_F(basemul_armv8)
#define kyber_cbd2_armv2 KYBER_F(cbd2_armv2)
#define kyber_cbd3_armv8 KYBER_F(cbd3_armv8)
#define indcpa_dec_armv8 KYBER_F(indcpa_dec_armv8)
#define indcpa_enc_armv8 KYBER_F(indcpa_enc_armv8)
#define indcpa_keypair_armv8 KYBER_F(indcpa_keypair_armv8)
#define kyber_inv_ntt_armv8 KYBER_F(inv_ntt_armv8)
#define lc_kyber_keypair_armv8 KYBER_F(keypair_armv8)
#define lc_kyber_keypair_from_seed_armv8 KYBER_F(keypair_from_seed_armv8)
#define lc_kyber_enc_armv8 KYBER_F(enc_armv8)
#define lc_kyber_dec_armv8 KYBER_F(dec_armv8)
#define lc_kyber_enc_kdf_armv8 KYBER_F(enc_kdf_armv8)
#define lc_kyber_dec_kdf_armv8 KYBER_F(dec_kdf_armv8)
#define kyber_ntt_armv8 KYBER_F(ntt_armv8)
#define poly_compress_armv8 KYBER_F(poly_compress_armv8)
#define poly_decompress_armv8 KYBER_F(poly_decompress_armv8)
#define kyber_poly_tobytes_armv8 KYBER_F(poly_tobytes_armv8)
#define kyber_poly_frombytes_armv8 KYBER_F(poly_frombytes_armv8)
#define kyber_barret_red_armv8 KYBER_F(barret_red_armv8)
#define kyber_tomont_armv8 KYBER_F(tomont_armv8)
#define kyber_sub_reduce_armv8 KYBER_F(sub_reduce_armv8)
#define kyber_add_reduce_armv8 KYBER_F(add_reduce_armv8)
#define kyber_add_add_reduce_armv8 KYBER_F(add_add_reduce_armv8)
#define kyber_cbd2_armv8 KYBER_F(cbd2_armv8)

/* ARMv7 Implementation */
#define kyber_poly_sub_armv7 KYBER_F(poly_sub_armv7)
#define kyber_poly_add_armv7 KYBER_F(poly_add_armv7)
#define kyber_barrett_reduce_armv7 KYBER_F(barrett_reduce_armv7)
#define kyber_basemul_armv7 KYBER_F(basemul_armv7)

#ifdef __cplusplus
}
#endif

#endif /* KYBER_TYPE_H */
