/*
 * Linker version script for libleancrypto.
 *
 * The library is already compiled with -fvisibility=hidden, but a fair number
 * of symbols have to be marked DSO_PUBLIC so that they can be used as APIs.
 *
 * This script draws the line explicitly: LIBLEANCRYPTO_1.8 is the supported API
 * as declared by the installed headers pulled in by leancrypto.h.
 *
 * The declarations in LIBLEANCRYPTO_PRIVATE_0 are intended for in-tree users
 * like tests. This definition should be updated directly without changing its
 * version.
 *
 * Both nodes together define the ABI - do not remove a symbol from
 * LIBLEANCRYPTO_1.8 or rename the node without bumping the library soversion.
 * New API is added in a new node
 * (LIBLEANCRYPTO_1.9 { ... } LIBLEANCRYPTO_1.8;) so that
 * existing binaries keep binding to the version they were linked against.
 */

LIBLEANCRYPTO_1.9 {
	global:
		/* lc_aead.h */
		lc_aead_zero;
		lc_aead_zero_free;
		lc_aead_setkey;
		lc_aead_setkey_from_ctx;
		lc_aead_encrypt;
		lc_aead_enc_init;
		lc_aead_enc_update;
		lc_aead_enc_final;
		lc_aead_decrypt;
		lc_aead_dec_init;
		lc_aead_dec_update;
		lc_aead_dec_final;
		lc_aead_alg_status;
		lc_aead_ctx_alg_status;

		/* lc_aes_gcm.h */
		lc_aes_gcm_alloc;
		lc_aes_gcm_generate_iv;

		/* lc_aes.h */
		lc_aes_kw_encrypt;
		lc_aes_kw_decrypt;

		/* lc_ascon_aead.h */

		/* lc_ascon_keccak.h */
		lc_ak_alloc;
		lc_ak_alloc_taglen;

		/* lc_ascon_lightweight.h */
		lc_al_alloc;

		/* lc_asn1.h */

		/* lc_bike_1.h */
		lc_bike_1_keypair;
		lc_bike_1_keypair_from_seed;
		lc_bike_1_enc;
		lc_bike_1_enc_kdf;
		lc_bike_1_dec;
		lc_bike_1_dec_kdf;

		/* lc_bike_3.h */
		lc_bike_3_keypair;
		lc_bike_3_keypair_from_seed;
		lc_bike_3_enc;
		lc_bike_3_enc_kdf;
		lc_bike_3_dec;
		lc_bike_3_dec_kdf;

		/* lc_bike_5.h */
		lc_bike_5_keypair;
		lc_bike_5_keypair_from_seed;
		lc_bike_5_enc;
		lc_bike_5_enc_kdf;
		lc_bike_5_dec;
		lc_bike_5_dec_kdf;

		/* lc_bike.h */
		lc_bike_sk_type;
		lc_bike_pk_type;
		lc_bike_ct_type;
		lc_bike_ss_type;
		lc_bike_sk_size;
		lc_bike_pk_size;
		lc_bike_ct_size;
		lc_bike_ss_size;
		lc_bike_sk_load;
		lc_bike_pk_load;
		lc_bike_ct_load;
		lc_bike_ss_load;
		lc_bike_sk_ptr;
		lc_bike_pk_ptr;
		lc_bike_ct_ptr;
		lc_bike_ss_ptr;
		lc_bike_keypair;
		lc_bike_keypair_from_seed;
		lc_bike_enc;
		lc_bike_enc_kdf;
		lc_bike_dec;
		lc_bike_dec_kdf;
		lc_bike_alg_status;

		/* lc_chacha20_drng.h */
		lc_cc20_drng_alloc;

		/* lc_chacha20.h */
		cc20_block;

		/* lc_chacha20_poly1305.h */
		lc_chacha20_poly1305_alloc;

		/* lc_cshake256_drng.h */
		lc_cshake256_drng_alloc;

		/* lc_cshake_crypt.h */
		lc_cc_alloc;
		lc_cshake_init;
		lc_cshake_ctx_init;
		lc_cshake_ctx_reinit;
		lc_cshake_ctx_update;
		lc_cshake_ctx_final;
		lc_cshake_ctx_alloc;
		lc_cshake_ctx_zero_free;

		/* lc_ctr_drbg.h */
		lc_drbg_ctr_use_df_alloc;
		lc_drbg_ctr_no_df_alloc;

		/* lc_dilithium_44.h */
		lc_dilithium_44_ctx_alloc;
		lc_dilithium_44_ctx_alloc_ahat;
		lc_dilithium_44_ctx_zero_free;
		lc_dilithium_44_keypair;
		lc_dilithium_44_pk_from_sk;
		lc_dilithium_44_keypair_from_seed;
		lc_dilithium_44_sign;
		lc_dilithium_44_sign_ctx;
		lc_dilithium_44_sign_init;
		lc_dilithium_44_sign_update;
		lc_dilithium_44_sign_final;
		lc_dilithium_44_verify;
		lc_dilithium_44_verify_ctx;
		lc_dilithium_44_verify_init;
		lc_dilithium_44_verify_update;
		lc_dilithium_44_verify_final;
		lc_dilithium_44_ed25519_ctx_alloc;
		lc_dilithium_44_ed25519_ctx_zero_free;
		lc_dilithium_44_ed25519_keypair;
		lc_dilithium_44_ed25519_pk_from_sk;
		lc_dilithium_44_ed25519_sign;
		lc_dilithium_44_ed25519_sign_ctx;
		lc_dilithium_44_ed25519_sign_init;
		lc_dilithium_44_ed25519_sign_update;
		lc_dilithium_44_ed25519_sign_final;
		lc_dilithium_44_ed25519_verify;
		lc_dilithium_44_ed25519_verify_ctx;
		lc_dilithium_44_ed25519_verify_init;
		lc_dilithium_44_ed25519_verify_update;
		lc_dilithium_44_ed25519_verify_final;
		lc_dilithium_44_ed448_ctx_alloc;
		lc_dilithium_44_ed448_ctx_zero_free;
		lc_dilithium_44_ed448_keypair;
		lc_dilithium_44_ed448_pk_from_sk;
		lc_dilithium_44_ed448_sign;
		lc_dilithium_44_ed448_sign_ctx;
		lc_dilithium_44_ed448_sign_init;
		lc_dilithium_44_ed448_sign_update;
		lc_dilithium_44_ed448_sign_final;
		lc_dilithium_44_ed448_verify;
		lc_dilithium_44_ed448_verify_ctx;
		lc_dilithium_44_ed448_verify_init;
		lc_dilithium_44_ed448_verify_update;
		lc_dilithium_44_ed448_verify_final;

		/* lc_dilithium_65.h */
		lc_dilithium_65_ctx_alloc;
		lc_dilithium_65_ctx_alloc_ahat;
		lc_dilithium_65_ctx_zero_free;
		lc_dilithium_65_keypair;
		lc_dilithium_65_pk_from_sk;
		lc_dilithium_65_keypair_from_seed;
		lc_dilithium_65_sign;
		lc_dilithium_65_sign_ctx;
		lc_dilithium_65_sign_init;
		lc_dilithium_65_sign_update;
		lc_dilithium_65_sign_final;
		lc_dilithium_65_verify;
		lc_dilithium_65_verify_ctx;
		lc_dilithium_65_verify_init;
		lc_dilithium_65_verify_update;
		lc_dilithium_65_verify_final;
		lc_dilithium_65_ed25519_ctx_alloc;
		lc_dilithium_65_ed25519_ctx_zero_free;
		lc_dilithium_65_ed25519_keypair;
		lc_dilithium_65_ed25519_pk_from_sk;
		lc_dilithium_65_ed25519_sign;
		lc_dilithium_65_ed25519_sign_ctx;
		lc_dilithium_65_ed25519_sign_init;
		lc_dilithium_65_ed25519_sign_update;
		lc_dilithium_65_ed25519_sign_final;
		lc_dilithium_65_ed25519_verify;
		lc_dilithium_65_ed25519_verify_ctx;
		lc_dilithium_65_ed25519_verify_init;
		lc_dilithium_65_ed25519_verify_update;
		lc_dilithium_65_ed25519_verify_final;
		lc_dilithium_65_ed448_ctx_alloc;
		lc_dilithium_65_ed448_ctx_zero_free;
		lc_dilithium_65_ed448_keypair;
		lc_dilithium_65_ed448_pk_from_sk;
		lc_dilithium_65_ed448_sign;
		lc_dilithium_65_ed448_sign_ctx;
		lc_dilithium_65_ed448_sign_init;
		lc_dilithium_65_ed448_sign_update;
		lc_dilithium_65_ed448_sign_final;
		lc_dilithium_65_ed448_verify;
		lc_dilithium_65_ed448_verify_ctx;
		lc_dilithium_65_ed448_verify_init;
		lc_dilithium_65_ed448_verify_update;
		lc_dilithium_65_ed448_verify_final;
		lc_dilithium_87_ctx_alloc;
		lc_dilithium_87_ctx_alloc_ahat;
		lc_dilithium_87_ctx_zero_free;
		lc_dilithium_87_keypair;
		lc_dilithium_87_pk_from_sk;
		lc_dilithium_87_keypair_from_seed;
		lc_dilithium_87_sign;
		lc_dilithium_87_sign_ctx;
		lc_dilithium_87_sign_init;
		lc_dilithium_87_sign_update;
		lc_dilithium_87_sign_final;
		lc_dilithium_87_verify;
		lc_dilithium_87_verify_ctx;
		lc_dilithium_87_verify_init;
		lc_dilithium_87_verify_update;
		lc_dilithium_87_verify_final;
		lc_dilithium_87_ed25519_ctx_alloc;
		lc_dilithium_87_ed25519_ctx_zero_free;
		lc_dilithium_87_ed25519_keypair;
		lc_dilithium_87_ed25519_pk_from_sk;
		lc_dilithium_87_ed25519_sign;
		lc_dilithium_87_ed25519_sign_ctx;
		lc_dilithium_87_ed25519_sign_init;
		lc_dilithium_87_ed25519_sign_update;
		lc_dilithium_87_ed25519_sign_final;
		lc_dilithium_87_ed25519_verify;
		lc_dilithium_87_ed25519_verify_ctx;
		lc_dilithium_87_ed25519_verify_init;
		lc_dilithium_87_ed25519_verify_update;
		lc_dilithium_87_ed25519_verify_final;
		lc_dilithium_87_ed448_ctx_alloc;
		lc_dilithium_87_ed448_ctx_zero_free;
		lc_dilithium_87_ed448_keypair;
		lc_dilithium_87_ed448_pk_from_sk;
		lc_dilithium_87_ed448_sign;
		lc_dilithium_87_ed448_sign_ctx;
		lc_dilithium_87_ed448_sign_init;
		lc_dilithium_87_ed448_sign_update;
		lc_dilithium_87_ed448_sign_final;
		lc_dilithium_87_ed448_verify;
		lc_dilithium_87_ed448_verify_ctx;
		lc_dilithium_87_ed448_verify_init;
		lc_dilithium_87_ed448_verify_update;
		lc_dilithium_87_ed448_verify_final;

		/* lc_dilithium.h */
		lc_dilithium_ctx_alloc;
		lc_dilithium_ctx_alloc_ahat;
		lc_dilithium_ctx_zero_free;
		lc_dilithium_ctx_zero;
		lc_dilithium_ctx_internal;
		lc_dilithium_ctx_hash;
		lc_dilithium_ctx_userctx;
		lc_dilithium_ctx_external_mu;
		lc_dilithium_ctx_drop_ahat;
		lc_dilithium_sk_type;
		lc_dilithium_pk_type;
		lc_dilithium_sig_type;
		lc_dilithium_sk_size;
		lc_dilithium_pk_size;
		lc_dilithium_sig_size;
		lc_dilithium_sk_load;
		lc_dilithium_pk_load;
		lc_dilithium_sig_load;
		lc_dilithium_sk_ptr;
		lc_dilithium_pk_ptr;
		lc_dilithium_sig_ptr;
		lc_dilithium_keypair;
		lc_dilithium_pk_from_sk;
		lc_dilithium_keypair_from_seed;
		lc_dilithium_pct;
		lc_dilithium_sign;
		lc_dilithium_sign_ctx;
		lc_dilithium_sign_init;
		lc_dilithium_sign_update;
		lc_dilithium_sign_final;
		lc_dilithium_verify;
		lc_dilithium_verify_ctx;
		lc_dilithium_verify_init;
		lc_dilithium_verify_update;
		lc_dilithium_verify_final;
		lc_dilithium_alg_status;
		lc_dilithium_ed25519_ctx_alloc;
		lc_dilithium_ed25519_ctx_zero_free;
		lc_dilithium_ed25519_ctx_zero;
		lc_dilithium_ed25519_ctx_hash;
		lc_dilithium_ed25519_ctx_internal;
		lc_dilithium_ed25519_ctx_userctx;
		lc_dilithium_ed25519_sk_type;
		lc_dilithium_ed25519_pk_type;
		lc_dilithium_ed25519_sig_type;
		lc_dilithium_ed25519_sk_size;
		lc_dilithium_ed25519_pk_size;
		lc_dilithium_ed25519_sig_size;
		lc_dilithium_ed25519_sk_load;
		lc_dilithium_ed25519_pk_load;
		lc_dilithium_ed25519_sig_load;
		lc_dilithium_ed25519_sk_ptr;
		lc_dilithium_ed25519_pk_ptr;
		lc_dilithium_ed25519_sig_ptr;
		lc_dilithium_ed25519_keypair;
		lc_dilithium_ed25519_pk_from_sk;
		lc_dilithium_ed25519_sign;
		lc_dilithium_ed25519_sign_ctx;
		lc_dilithium_ed25519_sign_init;
		lc_dilithium_ed25519_sign_update;
		lc_dilithium_ed25519_sign_final;
		lc_dilithium_ed25519_verify;
		lc_dilithium_ed25519_verify_ctx;
		lc_dilithium_ed25519_verify_init;
		lc_dilithium_ed25519_verify_update;
		lc_dilithium_ed25519_verify_final;
		lc_dilithium_ed448_ctx_alloc;
		lc_dilithium_ed448_ctx_zero_free;
		lc_dilithium_ed448_ctx_zero;
		lc_dilithium_ed448_ctx_hash;
		lc_dilithium_ed448_ctx_internal;
		lc_dilithium_ed448_ctx_userctx;
		lc_dilithium_ed448_sk_type;
		lc_dilithium_ed448_pk_type;
		lc_dilithium_ed448_sig_type;
		lc_dilithium_ed448_sk_size;
		lc_dilithium_ed448_pk_size;
		lc_dilithium_ed448_sig_size;
		lc_dilithium_ed448_sk_load;
		lc_dilithium_ed448_pk_load;
		lc_dilithium_ed448_sig_load;
		lc_dilithium_ed448_sk_ptr;
		lc_dilithium_ed448_pk_ptr;
		lc_dilithium_ed448_sig_ptr;
		lc_dilithium_ed448_keypair;
		lc_dilithium_ed448_pk_from_sk;
		lc_dilithium_ed448_sign;
		lc_dilithium_ed448_sign_ctx;
		lc_dilithium_ed448_sign_init;
		lc_dilithium_ed448_sign_update;
		lc_dilithium_ed448_sign_final;
		lc_dilithium_ed448_verify;
		lc_dilithium_ed448_verify_ctx;
		lc_dilithium_ed448_verify_init;
		lc_dilithium_ed448_verify_update;
		lc_dilithium_ed448_verify_final;

		/* lc_drbg.h */

		/* lc_ed25519.h */
		lc_ed25519_keypair;
		lc_ed25519_pk_from_sk;
		lc_ed25519_derive_pk;
		lc_ed25519_sign;
		lc_ed25519_verify;
		lc_ed25519_sk_ptr;
		lc_ed25519_pk_ptr;
		lc_ed25519_sig_ptr;
		lc_ed25519_sk_load;
		lc_ed25519_pk_load;
		lc_ed25519_sig_load;
		lc_ed25519_sig_size;
		lc_ed25519_pk_size;
		lc_ed25519_sk_size;
		lc_ed25519ph_sign;
		lc_ed25519ph_verify;
		lc_ed25519_alg_status;

		/* lc_ed448.h */
		lc_ed448_keypair;
		lc_ed448_pk_from_sk;
		lc_ed448_sign;
		lc_ed448_verify;
		lc_ed448_sk_ptr;
		lc_ed448_pk_ptr;
		lc_ed448_sig_ptr;
		lc_ed448_sk_load;
		lc_ed448_pk_load;
		lc_ed448_sig_load;
		lc_ed448_sig_size;
		lc_ed448_pk_size;
		lc_ed448_sk_size;
		lc_ed448ph_sign;
		lc_ed448ph_verify;
		lc_ed448_alg_status;

		/* lc_export.h */

		/* lc_hash_crypt.h */
		lc_hc_alloc;

		/* lc_hash_drbg.h */
		lc_drbg_hash_alloc;
		lc_drbg_hash_healthcheck_sanity;

		/* lc_hash.h */
		lc_hash_init;
		lc_hash_set_ctx;
		lc_hash_update;
		lc_hash_final;
		lc_hash_set_digestsize;
		lc_hash_digestsize;
		lc_hash_blocksize;
		lc_hash_ctxsize;
		lc_hash_zero;
		lc_hash_alloc;
		lc_hash_zero_free;
		lc_hash;
		lc_xof;
		lc_sponge;
		lc_sponge_add_bytes;
		lc_sponge_extract_bytes;
		lc_sponge_newstate;
		lc_hash_alg_status;
		lc_hash_ctx_alg_status;

		/* lc_hkdf.h */
		lc_hkdf_extract;
		lc_hkdf_extract_prk;
		lc_hkdf_expand;
		lc_hkdf_expand_prk;
		lc_hkdf_zero;
		lc_hkdf_alloc;
		lc_hkdf_zero_free;
		lc_hkdf;
		lc_hkdf_alg_status;
		lc_hkdf_rng_alloc;

		/* lc_hmac_drbg.h */
		lc_drbg_hmac_alloc;
		lc_drbg_hmac_healthcheck_sanity;

		/* lc_hmac_drbg_sha512.h */

		/* lc_hmac.h */
		lc_hmac_init;
		lc_hmac_reinit;
		lc_hmac_setkey;
		lc_hmac_init_with_hmac_key;
		lc_hmac_update;
		lc_hmac_final;
		lc_hmac_alloc;
		lc_hmac_zero_free;
		lc_hmac_zero;
		lc_hmac_alg_status;
		lc_hmac_ctx_alg_status;
		lc_hmac_macsize;
		lc_hmac;

		/* lc_hotp.h */
		lc_hotp;

		/* lc_hqc_128.h */
		lc_hqc_128_keypair;
		lc_hqc_128_keypair_from_seed;
		lc_hqc_128_enc;
		lc_hqc_128_enc_kdf;
		lc_hqc_128_dec;
		lc_hqc_128_dec_kdf;

		/* lc_hqc_192.h */
		lc_hqc_192_keypair;
		lc_hqc_192_keypair_from_seed;
		lc_hqc_192_enc;
		lc_hqc_192_enc_kdf;
		lc_hqc_192_dec;
		lc_hqc_192_dec_kdf;

		/* lc_hqc_256.h */
		lc_hqc_256_keypair;
		lc_hqc_256_keypair_from_seed;
		lc_hqc_256_enc;
		lc_hqc_256_enc_kdf;
		lc_hqc_256_dec;
		lc_hqc_256_dec_kdf;

		/* lc_hqc.h */
		lc_hqc_sk_type;
		lc_hqc_pk_type;
		lc_hqc_ct_type;
		lc_hqc_ss_type;
		lc_hqc_sk_size;
		lc_hqc_pk_size;
		lc_hqc_ct_size;
		lc_hqc_ss_size;
		lc_hqc_sk_load;
		lc_hqc_pk_load;
		lc_hqc_ct_load;
		lc_hqc_ss_load;
		lc_hqc_sk_ptr;
		lc_hqc_pk_ptr;
		lc_hqc_ct_ptr;
		lc_hqc_ss_ptr;
		lc_hqc_keypair;
		lc_hqc_keypair_from_seed;
		lc_hqc_enc;
		lc_hqc_enc_kdf;
		lc_hqc_dec;
		lc_hqc_dec_kdf;
		lc_hqc_alg_status;

		/* lc_init.h */
		lc_exit;
		lc_init;

		/* lc_kdf_ctr.h */
		lc_kdf_ctr_init;
		lc_kdf_ctr_generate;
		lc_kdf_ctr;
		lc_kdf_ctr_alg_status;
		lc_kdf_ctr_rng_alloc;

		/* lc_kdf_dpi.h */
		lc_kdf_dpi_init;
		lc_kdf_dpi_generate;
		lc_kdf_dpi;
		lc_kdf_dpi_alg_status;

		/* lc_kdf_fb.h */
		lc_kdf_fb_init;
		lc_kdf_fb_generate;
		lc_kdf_fb;
		lc_kdf_fb_alg_status;

		/* lc_kmac256_drng.h */
		lc_kmac256_drng_alloc;

		/* lc_kmac_crypt.h */
		lc_kc_alloc;

		/* lc_kmac.h */
		lc_kmac_init;
		lc_kmac_reinit;
		lc_kmac_update;
		lc_kmac_final;
		lc_kmac_final_xof;
		lc_kmac_alloc;
		lc_kmac_zero_free;
		lc_kmac_zero;
		lc_kmac_alg_status;
		lc_kmac_ctx_alg_status;
		lc_kmac_macsize;
		lc_kmac;
		lc_kmac_xof;
		lc_kmac_rng_alloc;

		/* lc_kyber_1024.h */
		lc_kyber_1024_keypair;
		lc_kyber_1024_keypair_from_seed;
		lc_kyber_1024_pk_from_sk;
		lc_kyber_1024_enc;
		lc_kyber_1024_enc_kdf;
		lc_kyber_1024_dec;
		lc_kyber_1024_dec_kdf;
		lc_kyber_1024_iv_sk;
		lc_kex_1024_uake_initiator_init;
		lc_kex_1024_uake_responder_ss;
		lc_kex_1024_uake_initiator_ss;
		lc_kex_1024_ake_initiator_init;
		lc_kex_1024_ake_responder_ss;
		lc_kex_1024_ake_initiator_ss;
		lc_kyber_1024_ies_enc;
		lc_kyber_1024_ies_enc_init;
		lc_kyber_1024_ies_dec;
		lc_kyber_1024_ies_dec_init;
		lc_kyber_1024_x25519_keypair;
		lc_kyber_1024_x25519_pk_from_sk;
		lc_kyber_1024_x25519_enc_kdf;
		lc_kyber_1024_x25519_enc;
		lc_kyber_1024_x25519_dec_kdf;
		lc_kyber_1024_x25519_dec;
		lc_kex_1024_x25519_uake_initiator_init;
		lc_kex_1024_x25519_uake_responder_ss;
		lc_kex_1024_x25519_uake_initiator_ss;
		lc_kex_1024_x25519_ake_initiator_init;
		lc_kex_1024_x25519_ake_responder_ss;
		lc_kex_1024_x25519_ake_initiator_ss;
		lc_kyber_1024_x25519_ies_enc;
		lc_kyber_1024_x25519_ies_enc_init;
		lc_kyber_1024_x25519_ies_dec;
		lc_kyber_1024_x25519_ies_dec_init;
		lc_kyber_1024_x448_keypair;
		lc_kyber_1024_x448_pk_from_sk;
		lc_kyber_1024_x448_enc_kdf;
		lc_kyber_1024_x448_enc;
		lc_kyber_1024_x448_dec_kdf;
		lc_kyber_1024_x448_dec;
		lc_kex_1024_x448_uake_initiator_init;
		lc_kex_1024_x448_uake_responder_ss;
		lc_kex_1024_x448_uake_initiator_ss;
		lc_kex_1024_x448_ake_initiator_init;
		lc_kex_1024_x448_ake_responder_ss;
		lc_kex_1024_x448_ake_initiator_ss;
		lc_kyber_1024_x448_ies_enc;
		lc_kyber_1024_x448_ies_enc_init;
		lc_kyber_1024_x448_ies_dec;
		lc_kyber_1024_x448_ies_dec_init;

		/* lc_kyber_512.h */
		lc_kyber_512_keypair;
		lc_kyber_512_keypair_from_seed;
		lc_kyber_512_pk_from_sk;
		lc_kyber_512_enc;
		lc_kyber_512_enc_kdf;
		lc_kyber_512_dec;
		lc_kyber_512_dec_kdf;
		lc_kyber_512_iv_sk;
		lc_kex_512_uake_initiator_init;
		lc_kex_512_uake_responder_ss;
		lc_kex_512_uake_initiator_ss;
		lc_kex_512_ake_initiator_init;
		lc_kex_512_ake_responder_ss;
		lc_kex_512_ake_initiator_ss;
		lc_kyber_512_ies_enc;
		lc_kyber_512_ies_enc_init;
		lc_kyber_512_ies_dec;
		lc_kyber_512_ies_dec_init;
		lc_kyber_512_x25519_keypair;
		lc_kyber_512_x25519_pk_from_sk;
		lc_kyber_512_x25519_enc_kdf;
		lc_kyber_512_x25519_enc;
		lc_kyber_512_x25519_dec_kdf;
		lc_kyber_512_x25519_dec;
		lc_kex_512_x25519_uake_initiator_init;
		lc_kex_512_x25519_uake_responder_ss;
		lc_kex_512_x25519_uake_initiator_ss;
		lc_kex_512_x25519_ake_initiator_init;
		lc_kex_512_x25519_ake_responder_ss;
		lc_kex_512_x25519_ake_initiator_ss;
		lc_kyber_512_x25519_ies_enc;
		lc_kyber_512_x25519_ies_enc_init;
		lc_kyber_512_x25519_ies_dec;
		lc_kyber_512_x25519_ies_dec_init;
		lc_kyber_512_x448_keypair;
		lc_kyber_512_x448_pk_from_sk;
		lc_kyber_512_x448_enc_kdf;
		lc_kyber_512_x448_enc;
		lc_kyber_512_x448_dec_kdf;
		lc_kyber_512_x448_dec;
		lc_kex_512_x448_uake_initiator_init;
		lc_kex_512_x448_uake_responder_ss;
		lc_kex_512_x448_uake_initiator_ss;
		lc_kex_512_x448_ake_initiator_init;
		lc_kex_512_x448_ake_responder_ss;
		lc_kex_512_x448_ake_initiator_ss;
		lc_kyber_512_x448_ies_enc;
		lc_kyber_512_x448_ies_enc_init;
		lc_kyber_512_x448_ies_dec;
		lc_kyber_512_x448_ies_dec_init;

		/* lc_kyber_768.h */
		lc_kyber_768_keypair;
		lc_kyber_768_keypair_from_seed;
		lc_kyber_768_pk_from_sk;
		lc_kyber_768_enc;
		lc_kyber_768_enc_kdf;
		lc_kyber_768_dec;
		lc_kyber_768_dec_kdf;
		lc_kyber_768_iv_sk;
		lc_kex_768_uake_initiator_init;
		lc_kex_768_uake_responder_ss;
		lc_kex_768_uake_initiator_ss;
		lc_kex_768_ake_initiator_init;
		lc_kex_768_ake_responder_ss;
		lc_kex_768_ake_initiator_ss;
		lc_kyber_768_ies_enc;
		lc_kyber_768_ies_enc_init;
		lc_kyber_768_ies_dec;
		lc_kyber_768_ies_dec_init;
		lc_kyber_768_x25519_keypair;
		lc_kyber_768_x25519_pk_from_sk;
		lc_kyber_768_x25519_enc_kdf;
		lc_kyber_768_x25519_enc;
		lc_kyber_768_x25519_dec_kdf;
		lc_kyber_768_x25519_dec;
		lc_kex_768_x25519_uake_initiator_init;
		lc_kex_768_x25519_uake_responder_ss;
		lc_kex_768_x25519_uake_initiator_ss;
		lc_kex_768_x25519_ake_initiator_init;
		lc_kex_768_x25519_ake_responder_ss;
		lc_kex_768_x25519_ake_initiator_ss;
		lc_kyber_768_x25519_ies_enc;
		lc_kyber_768_x25519_ies_enc_init;
		lc_kyber_768_x25519_ies_dec;
		lc_kyber_768_x25519_ies_dec_init;
		lc_kyber_768_x448_keypair;
		lc_kyber_768_x448_pk_from_sk;
		lc_kyber_768_x448_enc_kdf;
		lc_kyber_768_x448_enc;
		lc_kyber_768_x448_dec_kdf;
		lc_kyber_768_x448_dec;
		lc_kex_768_x448_uake_initiator_init;
		lc_kex_768_x448_uake_responder_ss;
		lc_kex_768_x448_uake_initiator_ss;
		lc_kex_768_x448_ake_initiator_init;
		lc_kex_768_x448_ake_responder_ss;
		lc_kex_768_x448_ake_initiator_ss;
		lc_kyber_768_x448_ies_enc;
		lc_kyber_768_x448_ies_enc_init;
		lc_kyber_768_x448_ies_dec;
		lc_kyber_768_x448_ies_dec_init;

		/* lc_kyber.h */
		lc_kyber_sk_type;
		lc_kyber_pk_type;
		lc_kyber_ct_type;
		lc_kyber_ss_type;
		lc_kyber_sk_size;
		lc_kyber_pk_size;
		lc_kyber_ct_size;
		lc_kyber_ss_size;
		lc_kyber_sk_load;
		lc_kyber_pk_load;
		lc_kyber_ct_load;
		lc_kyber_ss_load;
		lc_kyber_pct;
		lc_kyber_sk_ptr;
		lc_kyber_pk_ptr;
		lc_kyber_ct_ptr;
		lc_kyber_ss_ptr;
		lc_kyber_keypair;
		lc_kyber_keypair_from_seed;
		lc_kyber_pk_from_sk;
		lc_kyber_enc;
		lc_kyber_enc_kdf;
		lc_kyber_dec;
		lc_kyber_dec_kdf;
		lc_kyber_alg_status;
		lc_kex_uake_initiator_init;
		lc_kex_uake_responder_ss;
		lc_kex_uake_initiator_ss;
		lc_kex_ake_initiator_init;
		lc_kex_ake_responder_ss;
		lc_kex_ake_initiator_ss;
		lc_kyber_ies_enc;
		lc_kyber_ies_enc_init;
		lc_kyber_ies_enc_update;
		lc_kyber_ies_enc_final;
		lc_kyber_ies_dec;
		lc_kyber_ies_dec_init;
		lc_kyber_ies_dec_update;
		lc_kyber_ies_dec_final;
		lc_kyber_x25519_sk_type;
		lc_kyber_x25519_pk_type;
		lc_kyber_x25519_ct_type;
		lc_kyber_x25519_ss_type;
		lc_kyber_x25519_sk_size;
		lc_kyber_x25519_pk_size;
		lc_kyber_x25519_ct_size;
		lc_kyber_x25519_ss_size;
		lc_kyber_x25519_sk_load;
		lc_kyber_x25519_pk_load;
		lc_kyber_x25519_ct_load;
		lc_kyber_x25519_ss_load;
		lc_kyber_x25519_sk_ptr;
		lc_kyber_x25519_pk_ptr;
		lc_kyber_x25519_ct_ptr;
		lc_kyber_x25519_ss_ptr;
		lc_kyber_x25519_keypair;
		lc_kyber_x25519_pk_from_sk;
		lc_kyber_x25519_enc_kdf;
		lc_kyber_x25519_enc;
		lc_kyber_x25519_dec_kdf;
		lc_kyber_x25519_dec;
		lc_kex_x25519_uake_initiator_init;
		lc_kex_x25519_uake_responder_ss;
		lc_kex_x25519_uake_initiator_ss;
		lc_kex_x25519_ake_initiator_init;
		lc_kex_x25519_ake_responder_ss;
		lc_kex_x25519_ake_initiator_ss;
		lc_kyber_x25519_ies_enc;
		lc_kyber_x25519_ies_enc_init;
		lc_kyber_x25519_ies_enc_update;
		lc_kyber_x25519_ies_enc_final;
		lc_kyber_x25519_ies_dec;
		lc_kyber_x25519_ies_dec_init;
		lc_kyber_x25519_ies_dec_update;
		lc_kyber_x25519_ies_dec_final;
		lc_kyber_x448_sk_type;
		lc_kyber_x448_pk_type;
		lc_kyber_x448_ct_type;
		lc_kyber_x448_ss_type;
		lc_kyber_x448_sk_size;
		lc_kyber_x448_pk_size;
		lc_kyber_x448_ct_size;
		lc_kyber_x448_ss_size;
		lc_kyber_x448_sk_load;
		lc_kyber_x448_pk_load;
		lc_kyber_x448_ct_load;
		lc_kyber_x448_ss_load;
		lc_kyber_x448_sk_ptr;
		lc_kyber_x448_pk_ptr;
		lc_kyber_x448_ct_ptr;
		lc_kyber_x448_ss_ptr;
		lc_kyber_x448_keypair;
		lc_kyber_x448_pk_from_sk;
		lc_kyber_x448_enc_kdf;
		lc_kyber_x448_enc;
		lc_kyber_x448_dec_kdf;
		lc_kyber_x448_dec;
		lc_kex_x448_uake_initiator_init;
		lc_kex_x448_uake_responder_ss;
		lc_kex_x448_uake_initiator_ss;
		lc_kex_x448_ake_initiator_init;
		lc_kex_x448_ake_responder_ss;
		lc_kex_x448_ake_initiator_ss;
		lc_kyber_x448_ies_enc;
		lc_kyber_x448_ies_enc_init;
		lc_kyber_x448_ies_enc_update;
		lc_kyber_x448_ies_enc_final;
		lc_kyber_x448_ies_dec;
		lc_kyber_x448_ies_dec_init;
		lc_kyber_x448_ies_dec_update;
		lc_kyber_x448_ies_dec_final;

		/* lc_memcmp_secure.h */
		lc_memcmp_secure;

		/* lc_memcpy_secure.h */
		*lc_memcpy_secure;

		/* lc_memory_support.h */
		lc_alloc_aligned;
		lc_alloc_aligned_secure;
		lc_alloc_high_aligned;
		lc_free;
		lc_free_high_aligned;

		/* lc_memset_secure.h */

		/* lc_pbkdf2.h */
		lc_pbkdf2;
		lc_pbkdf2_alg_status;

		/* lc_pem.h */
		lc_pem_encode_len;
		lc_pem_decode_len;
		lc_pem_encode;
		lc_pem_decode;
		lc_pem_is_encoded;
		lc_pem_type;

		/* lc_pkcs7_common.h */

		/* lc_pkcs7_generator.h */
		lc_pkcs7_encode;
		lc_pkcs7_encode_ctx_init;
		lc_pkcs7_encode_ctx_clear;
		lc_pkcs7_encode_ctx_set_pkcs7;
		lc_pkcs7_encode_ctx_set_signer_data_type;
		lc_pkcs7_encode_ctx;
		lc_pkcs7_set_certificate;
		lc_pkcs7_set_signer;
		lc_pkcs7_set_data;
		lc_pkcs7_set_data_with_type;

		/* lc_pkcs7_parser.h */
		lc_pkcs7_decode;
		lc_pkcs7_decode_ctx_init;
		lc_pkcs7_decode_ctx_clear;
		lc_pkcs7_decode_ctx_set_pkcs7;
		lc_pkcs7_decode_ctx_set_aa_content_type;
		lc_pkcs7_decode_ctx;
		lc_pkcs7_message_clear;
		lc_pkcs7_get_content_data;
		lc_pkcs7_verify;
		lc_pkcs7_supply_detached_data;
		lc_pkcs7_get_digest;
		lc_pkcs7_trust_store_add;
		lc_pkcs7_trust_store_clear;

		/* lc_pkcs8_common.h */
		lc_pkcs8_encode;

		/* lc_pkcs8_parser.h */
		lc_pkcs8_decode;
		lc_pkcs8_set_privkey;
		lc_pkcs8_message_clear;
		lc_pkcs8_get_signature_size_from_sk;
		lc_pkcs8_signature_gen;
		lc_pkcs8_key_type;

		/* lc_poly1305.h */
		lc_poly1305_init;
		lc_poly1305_update;
		lc_poly1305_final;

		/* lc_rng.h */
		lc_rng_check;
		lc_rng_zero;
		lc_rng_zero_free;
		lc_rng_generate;
		lc_rng_seed;
		lc_rng_set_seeded;
		lc_rng_alg_status;
		lc_rng_ctx_alg_status;

		/* lc_sha256.h */

		/* lc_sha3.h */

		/* lc_sha512.h */

		/* lc_sntrup.h */
		lc_sntrup_sk_type;
		lc_sntrup_pk_type;
		lc_sntrup_ct_type;
		lc_sntrup_ss_type;
		lc_sntrup_sk_size;
		lc_sntrup_pk_size;
		lc_sntrup_ct_size;
		lc_sntrup_ss_size;
		lc_sntrup_sk_load;
		lc_sntrup_pk_load;
		lc_sntrup_ct_load;
		lc_sntrup_ss_load;
		lc_sntrup_sk_ptr;
		lc_sntrup_pk_ptr;
		lc_sntrup_ct_ptr;
		lc_sntrup_ss_ptr;
		lc_sntrup_dec;
		lc_sntrup_enc;
		lc_sntrup_keypair;

		/* lc_sntrup_1277.h */
		lc_sntrup_1277_dec;
		lc_sntrup_1277_enc;
		lc_sntrup_1277_keypair;

		/* lc_sntrup_1013.h */
		lc_sntrup_1013_dec;
		lc_sntrup_1013_enc;
		lc_sntrup_1013_keypair;

		/* lc_sntrup_953.h */
		lc_sntrup_953_dec;
		lc_sntrup_953_enc;
		lc_sntrup_953_keypair;

                /* lc_sntrup_857.h */
		lc_sntrup_857_dec;
		lc_sntrup_857_enc;
		lc_sntrup_857_keypair;

		/* lc_sntrup_761.h */
		lc_sntrup_761_dec;
		lc_sntrup_761_enc;
		lc_sntrup_761_keypair;

		/* lc_sphincs_ascon_128f.h */
		lc_sphincs_ascon_128f_keypair;
		lc_sphincs_ascon_128f_keypair_from_seed;
		lc_sphincs_ascon_128f_pk_from_sk;
		lc_sphincs_ascon_128f_sign;
		lc_sphincs_ascon_128f_sign_ctx;
		lc_sphincs_ascon_128f_sign_init;
		lc_sphincs_ascon_128f_sign_update;
		lc_sphincs_ascon_128f_sign_final;
		lc_sphincs_ascon_128f_verify;
		lc_sphincs_ascon_128f_verify_ctx;
		lc_sphincs_ascon_128f_verify_init;
		lc_sphincs_ascon_128f_verify_update;
		lc_sphincs_ascon_128f_verify_final;

		/* lc_sphincs_ascon_128s.h */
		lc_sphincs_ascon_128s_keypair;
		lc_sphincs_ascon_128s_keypair_from_seed;
		lc_sphincs_ascon_128s_pk_from_sk;
		lc_sphincs_ascon_128s_sign;
		lc_sphincs_ascon_128s_sign_ctx;
		lc_sphincs_ascon_128s_sign_init;
		lc_sphincs_ascon_128s_sign_update;
		lc_sphincs_ascon_128s_sign_final;
		lc_sphincs_ascon_128s_verify;
		lc_sphincs_ascon_128s_verify_ctx;
		lc_sphincs_ascon_128s_verify_init;
		lc_sphincs_ascon_128s_verify_update;
		lc_sphincs_ascon_128s_verify_final;

		/* lc_sphincs.h */
		lc_sphincs_ctx_alloc;
		lc_sphincs_ctx_zero_free;
		lc_sphincs_ctx_zero;
		lc_sphincs_ctx_internal;
		lc_sphincs_ctx_hash;
		lc_sphincs_ctx_userctx;
		lc_sphincs_sk_type;
		lc_sphincs_pk_type;
		lc_sphincs_sig_type;
		lc_sphincs_sk_size;
		lc_sphincs_pk_size;
		lc_sphincs_sig_size;
		lc_sphincs_sk_load;
		lc_sphincs_sk_set_keytype_fast;
		lc_sphincs_sk_set_keytype_small;
		lc_sphincs_pk_load;
		lc_sphincs_pk_set_keytype_fast;
		lc_sphincs_pk_set_keytype_small;
		lc_sphincs_sig_load;
		lc_sphincs_sk_ptr;
		lc_sphincs_pk_ptr;
		lc_sphincs_sig_ptr;
		lc_sphincs_keypair;
		lc_sphincs_keypair_from_seed;
		lc_sphincs_pk_from_sk;
		lc_sphincs_pct;
		lc_sphincs_sign;
		lc_sphincs_sign_ctx;
		lc_sphincs_sign_init;
		lc_sphincs_sign_update;
		lc_sphincs_sign_final;
		lc_sphincs_verify;
		lc_sphincs_verify_ctx;
		lc_sphincs_verify_init;
		lc_sphincs_verify_update;
		lc_sphincs_verify_final;
		lc_sphincs_alg_status;

		/* lc_sphincs_shake_128f.h */
		lc_sphincs_shake_128f_ctx_alloc;
		lc_sphincs_shake_128f_ctx_zero_free;
		lc_sphincs_shake_128f_keypair;
		lc_sphincs_shake_128f_keypair_from_seed;
		lc_sphincs_shake_128f_pk_from_sk;
		lc_sphincs_shake_128f_sign;
		lc_sphincs_shake_128f_sign_ctx;
		lc_sphincs_shake_128f_sign_init;
		lc_sphincs_shake_128f_sign_update;
		lc_sphincs_shake_128f_sign_final;
		lc_sphincs_shake_128f_verify;
		lc_sphincs_shake_128f_verify_ctx;
		lc_sphincs_shake_128f_verify_init;
		lc_sphincs_shake_128f_verify_update;
		lc_sphincs_shake_128f_verify_final;

		/* lc_sphincs_shake_128s.h */
		lc_sphincs_shake_128s_ctx_alloc;
		lc_sphincs_shake_128s_ctx_zero_free;
		lc_sphincs_shake_128s_keypair;
		lc_sphincs_shake_128s_keypair_from_seed;
		lc_sphincs_shake_128s_pk_from_sk;
		lc_sphincs_shake_128s_sign;
		lc_sphincs_shake_128s_sign_ctx;
		lc_sphincs_shake_128s_sign_init;
		lc_sphincs_shake_128s_sign_update;
		lc_sphincs_shake_128s_sign_final;
		lc_sphincs_shake_128s_verify;
		lc_sphincs_shake_128s_verify_ctx;
		lc_sphincs_shake_128s_verify_init;
		lc_sphincs_shake_128s_verify_update;
		lc_sphincs_shake_128s_verify_final;

		/* lc_sphincs_shake_192f.h */
		lc_sphincs_shake_192f_ctx_alloc;
		lc_sphincs_shake_192f_ctx_zero_free;
		lc_sphincs_shake_192f_keypair;
		lc_sphincs_shake_192f_keypair_from_seed;
		lc_sphincs_shake_192f_pk_from_sk;
		lc_sphincs_shake_192f_sign;
		lc_sphincs_shake_192f_sign_ctx;
		lc_sphincs_shake_192f_sign_init;
		lc_sphincs_shake_192f_sign_update;
		lc_sphincs_shake_192f_sign_final;
		lc_sphincs_shake_192f_verify;
		lc_sphincs_shake_192f_verify_ctx;
		lc_sphincs_shake_192f_verify_init;
		lc_sphincs_shake_192f_verify_update;
		lc_sphincs_shake_192f_verify_final;

		/* lc_sphincs_shake_192s.h */
		lc_sphincs_shake_192s_ctx_alloc;
		lc_sphincs_shake_192s_ctx_zero_free;
		lc_sphincs_shake_192s_keypair;
		lc_sphincs_shake_192s_keypair_from_seed;
		lc_sphincs_shake_192s_pk_from_sk;
		lc_sphincs_shake_192s_sign;
		lc_sphincs_shake_192s_sign_ctx;
		lc_sphincs_shake_192s_sign_init;
		lc_sphincs_shake_192s_sign_update;
		lc_sphincs_shake_192s_sign_final;
		lc_sphincs_shake_192s_verify;
		lc_sphincs_shake_192s_verify_ctx;
		lc_sphincs_shake_192s_verify_init;
		lc_sphincs_shake_192s_verify_update;
		lc_sphincs_shake_192s_verify_final;

		/* lc_sphincs_shake_256f.h */
		lc_sphincs_shake_256f_ctx_alloc;
		lc_sphincs_shake_256f_ctx_zero_free;
		lc_sphincs_shake_256f_keypair;
		lc_sphincs_shake_256f_keypair_from_seed;
		lc_sphincs_shake_256f_pk_from_sk;
		lc_sphincs_shake_256f_sign;
		lc_sphincs_shake_256f_sign_ctx;
		lc_sphincs_shake_256f_sign_init;
		lc_sphincs_shake_256f_sign_update;
		lc_sphincs_shake_256f_sign_final;
		lc_sphincs_shake_256f_verify;
		lc_sphincs_shake_256f_verify_ctx;
		lc_sphincs_shake_256f_verify_init;
		lc_sphincs_shake_256f_verify_update;
		lc_sphincs_shake_256f_verify_final;

		/* lc_sphincs_shake_256s.h */
		lc_sphincs_shake_256s_ctx_alloc;
		lc_sphincs_shake_256s_ctx_zero_free;
		lc_sphincs_shake_256s_keypair;
		lc_sphincs_shake_256s_keypair_from_seed;
		lc_sphincs_shake_256s_pk_from_sk;
		lc_sphincs_shake_256s_sign;
		lc_sphincs_shake_256s_sign_ctx;
		lc_sphincs_shake_256s_sign_init;
		lc_sphincs_shake_256s_sign_update;
		lc_sphincs_shake_256s_sign_final;
		lc_sphincs_shake_256s_verify;
		lc_sphincs_shake_256s_verify_ctx;
		lc_sphincs_shake_256s_verify_init;
		lc_sphincs_shake_256s_verify_update;
		lc_sphincs_shake_256s_verify_final;

		/* lc_status.h */
		lc_rerun_selftests;
		lc_rerun_one_selftest;
		lc_lib_alg_status;
		lc_fips_integrity_checker;
		lc_status;
		lc_status_get_result;
		lc_alg_disable_selftests;

		/* lc_sym.h */
		lc_sym_init;
		lc_sym_setkey;
		lc_sym_setiv;
		lc_sym_getiv;
		lc_sym_encrypt;
		lc_sym_decrypt;
		lc_sym_encrypt_iv;
		lc_sym_decrypt_iv;
		lc_sym_init_iv;
		lc_sym_zero;
		lc_sym_alloc;
		lc_sym_zero_free;
		lc_sym_alg_status;
		lc_sym_ctx_alg_status;

		/* lc_symhmac.h */
		lc_sh_alloc;

		/* lc_symkmac.h */
		lc_kh_alloc;

		/* lc_totp.h */
		lc_totp;

		/* lc_uuid.h */
		lc_uuid_bin2hex;
		lc_uuid_hex2bin;
		lc_uuid_random;
		lc_uuid_time;

		/* lc_x25519.h */
		lc_x25519_keypair;
		lc_x25519_pk_from_sk;
		lc_x25519_ss;
		lc_x25519_sk_ptr;
		lc_x25519_pk_ptr;
		lc_x25519_ss_ptr;
		lc_x25519_sk_load;
		lc_x25519_pk_load;
		lc_x25519_ss_load;
		lc_x25519_alg_status;

		/* lc_x448.h */
		lc_x448_keypair;
		lc_x448_pk_from_sk;
		lc_x448_ss;
		lc_x448_sk_ptr;
		lc_x448_pk_ptr;
		lc_x448_ss_ptr;
		lc_x448_sk_load;
		lc_x448_pk_load;
		lc_x448_ss_load;
		lc_x448_alg_status;

		/* lc_x509_common.h */
		lc_x509_sig_type_to_name;
		lc_x509_sig_type_to_hash;
		lc_x509_oid_to_hash;
		lc_look_up_OID;
		lc_gmtime;
		lc_OID_to_data;
		lc_asn1_ber_encoder;
		lc_asn1_ber_encoder_small;
		lc_asn1_ber_decoder;

		/* lc_x509_csr_generator.h */
		lc_x509_csr_encode;

		/* lc_x509_csr_parser.h */
		lc_x509_csr_decode;

		/* lc_x509_generator.h */
		lc_x509_sufficient_size;
		lc_x509_cert_encode;
		lc_x509_sk_encode;
		lc_x509_signature_gen;
		lc_x509_keypair_gen;
		lc_x509_keypair_data_alloc;
		lc_x509_keypair_data_zero_free;
		lc_x509_keypair_load;
		lc_x509_keypair_pk;
		lc_x509_cert_set_signer;
		lc_x509_cert_set_eku;
		lc_x509_cert_set_eku_val;
		lc_x509_cert_set_keyusage;
		lc_x509_cert_set_keyusage_val;
		lc_x509_cert_set_ca;
		lc_x509_cert_set_ca_pathlen;
		lc_x509_cert_check_issuer_ca;
		lc_x509_cert_set_san_email;
		lc_x509_cert_set_san_dns;
		lc_x509_cert_set_san_ip;
		lc_x509_cert_set_skid;
		lc_x509_cert_set_akid;
		lc_x509_cert_set_valid_from;
		lc_x509_cert_set_valid_to;
		lc_x509_cert_set_subject_cn;
		lc_x509_cert_set_subject_email;
		lc_x509_cert_set_subject_ou;
		lc_x509_cert_set_subject_o;
		lc_x509_cert_set_subject_st;
		lc_x509_cert_set_subject_c;
		lc_x509_cert_set_issuer_cn;
		lc_x509_cert_set_issuer_email;
		lc_x509_cert_set_issuer_ou;
		lc_x509_cert_set_issuer_o;
		lc_x509_cert_set_issuer_st;
		lc_x509_cert_set_issuer_c;
		lc_x509_cert_set_serial;
		lc_x509_pkey_name_to_algorithm;
		lc_x509_name_to_hash;
		lc_x509_hash_to_name;
		lc_x509_name_to_keyusage;
		lc_x509_name_to_eku;
		lc_x509_hash_to_oid;

		/* lc_x509_parser.h */
		lc_x509_cert_clear;
		lc_x509_cert_decode;
		lc_x509_keys_dilithium_ed25519_alloc;
		lc_x509_keys_dilithium_ed448_alloc;
		lc_x509_keys_dilithium_alloc;
		lc_x509_keys_sphincs_alloc;
		lc_x509_keys_alloc;
		lc_x509_privkeys_dilithium_ed25519_alloc;
		lc_x509_privkeys_dilithium_ed448_alloc;
		lc_x509_privkeys_dilithium_alloc;
		lc_x509_privkeys_sphincs_alloc;
		lc_x509_privkeys_alloc;
		lc_x509_keys_zero_free;
		lc_x509_sk_decode;
		lc_x509_pk_decode;
		lc_x509_signature_verify;
		lc_x509_get_signature_size_from_sk;
		lc_x509_get_signature_size_from_cert;
		lc_x509_cert_verify;
		lc_x509_cert_load_pk_dilithium_ed25519;
		lc_x509_cert_load_pk_dilithium_ed448;
		lc_x509_cert_get_pubkey;
		lc_x509_cert_get_eku;
		lc_x509_cert_get_eku_val;
		lc_x509_cert_get_keyusage;
		lc_x509_cert_get_keyusage_val;
		lc_x509_cert_get_san_dns;
		lc_x509_enc_san_ip;
		lc_x509_cert_get_san_ip;
		lc_x509_dec_san_ip;
		lc_x509_cert_get_skid;
		lc_x509_cert_get_akid;
		lc_x509_cert_get_valid_from;
		lc_x509_cert_get_valid_to;
		lc_x509_cert_get_subject_cn;
		lc_x509_cert_get_subject_email;
		lc_x509_cert_get_subject_ou;
		lc_x509_cert_get_subject_o;
		lc_x509_cert_get_subject_st;
		lc_x509_cert_get_subject_c;
		lc_x509_cert_get_issuer_cn;
		lc_x509_cert_get_issuer_email;
		lc_x509_cert_get_issuer_ou;
		lc_x509_cert_get_issuer_o;
		lc_x509_cert_get_issuer_st;
		lc_x509_cert_get_issuer_c;
		lc_x509_cert_get_serial;
		lc_x509_policy_is_ca;
		lc_x509_policy_can_validate_crls;
		lc_x509_policy_is_selfsigned;
		lc_x509_policy_is_root_ca;
		lc_x509_policy_match_akid;
		lc_x509_policy_match_skid;
		lc_x509_policy_match_key_usage;
		lc_x509_policy_match_extended_key_usage;
		lc_x509_policy_time_valid;
		lc_x509_policy_time_valid_now;
		lc_x509_policy_cert_valid;
		lc_x509_policy_verify_cert;
		lc_x509_policy_cert_subject_match;

		/* lc_xdrbg.h */
		lc_xdrbg256_drng_alloc;
		lc_xdrbg512_drng_alloc;
		lc_xdrbg128_drng_alloc;

		/* Exported data symbols */
		lc_aes;
		lc_aes_aesni;
		lc_aes_armce;
		lc_aes_c;
		lc_aes_cbc;
		lc_aes_cbc_aesni;
		lc_aes_cbc_armce;
		lc_aes_cbc_c;
		lc_aes_cbc_riscv64;
		lc_aes_ct;
		lc_aes_ctr;
		lc_aes_ctr_aesni;
		lc_aes_ctr_armce;
		lc_aes_ctr_c;
		lc_aes_ctr_riscv64;
		/*lc_aes_ecb*/
		lc_aes_gcm_aead;
		lc_aes_kw;
		lc_aes_kw_aesni;
		lc_aes_kw_armce;
		lc_aes_kw_c;
		lc_aes_kw_riscv64;
		lc_aes_riscv64;
		lc_aes_sbox;
		lc_aes_xts;
		lc_aes_xts_aesni;
		lc_aes_xts_armce;
		lc_aes_xts_c;
		lc_aes_xts_riscv64;
		lc_ascon_128a;
		lc_ascon_128a_arm_neon;
		lc_ascon_128a_avx512;
		lc_ascon_128a_c;
		lc_ascon_256;
		lc_ascon_256_arm_neon;
		lc_ascon_256_avx512;
		lc_ascon_256_c;
		lc_ascon_aead;
		lc_ascon_keccak_aead;
		lc_ascon_xof;
		lc_ascon_xof_arm_neon;
		lc_ascon_xof_avx512;
		lc_ascon_xof_c;
		lc_cc20_drng;
		lc_chacha20;
		lc_chacha20_avx2;
		lc_chacha20_avx512;
		lc_chacha20_c;
		lc_chacha20_neon;
		lc_chacha20_poly1305_aead;
		lc_chacha20_riscv64_v_zbb;
		lc_chacha20_64;
		lc_chacha20_64_avx2;
		lc_chacha20_64_avx512;
		lc_chacha20_64_c;
		lc_chacha20_64_neon;
		lc_chacha20_64_riscv64_v_zbb;
		lc_cshake128;
		lc_cshake128_arm_asm;
		lc_cshake128_arm_ce;
		lc_cshake128_arm_neon;
		lc_cshake128_avx2;
		lc_cshake128_avx512;
		lc_cshake128_c;
		lc_cshake128_riscv_asm;
		lc_cshake128_riscv_asm_zbb;
		lc_cshake256;
		lc_cshake256_arm_asm;
		lc_cshake256_arm_ce;
		lc_cshake256_arm_neon;
		lc_cshake256_avx2;
		lc_cshake256_avx512;
		lc_cshake256_c;
		lc_cshake256_drng;
		lc_cshake256_riscv_asm;
		lc_cshake256_riscv_asm_zbb;
		lc_cshake_aead;
		lc_ctr_drbg;
		lc_hash_aead;
		lc_hash_drbg;
		lc_hkdf_rng;
		lc_hmac_drbg;
		lc_kdf_ctr_rng;
		lc_kmac256_drng;
		lc_kmac_rng;
		lc_kmac_aead;
		lc_mode_cbc_c;
		lc_mode_ctr_c;
		lc_mode_xts_c;
		lc_seeded_rng;
		lc_sha256;
		lc_sha256_arm_ce;
		lc_sha256_arm_neon;
		lc_sha256_avx2;
		lc_sha256_c;
		lc_sha256_riscv;
		lc_sha256_riscv_zbb;
		lc_sha256_shani;
		lc_sha3_224;
		lc_sha3_224_arm_asm;
		lc_sha3_224_arm_ce;
		lc_sha3_224_arm_neon;
		lc_sha3_224_avx2;
		lc_sha3_224_avx512;
		lc_sha3_224_c;
		lc_sha3_224_riscv_asm;
		lc_sha3_224_riscv_asm_zbb;
		lc_sha3_256;
		lc_sha3_256_arm_asm;
		lc_sha3_256_arm_ce;
		lc_sha3_256_arm_neon;
		lc_sha3_256_avx2;
		lc_sha3_256_avx512;
		lc_sha3_256_c;
		lc_sha3_256_riscv_asm;
		lc_sha3_256_riscv_asm_zbb;
		lc_sha3_384;
		lc_sha3_384_arm_asm;
		lc_sha3_384_arm_ce;
		lc_sha3_384_arm_neon;
		lc_sha3_384_avx2;
		lc_sha3_384_avx512;
		lc_sha3_384_c;
		lc_sha3_384_riscv_asm;
		lc_sha3_384_riscv_asm_zbb;
		lc_sha3_512;
		lc_sha3_512_arm_asm;
		lc_sha3_512_arm_ce;
		lc_sha3_512_arm_neon;
		lc_sha3_512_avx2;
		lc_sha3_512_avx512;
		lc_sha3_512_c;
		lc_sha3_512_riscv_asm;
		lc_sha3_512_riscv_asm_zbb;
		lc_sha384;
		lc_sha384_arm_ce;
		lc_sha384_arm_neon;
		lc_sha384_avx2;
		lc_sha384_c;
		lc_sha384_riscv;
		lc_sha384_riscv_zbb;
		lc_sha384_shani;
		lc_sha512;
		lc_sha512_arm_ce;
		lc_sha512_arm_neon;
		lc_sha512_avx2;
		lc_sha512_c;
		lc_sha512_riscv;
		lc_sha512_riscv_zbb;
		lc_sha512_shani;
		lc_shake128;
		lc_shake128_arm_asm;
		lc_shake128_arm_ce;
		lc_shake128_arm_neon;
		lc_shake128_avx2;
		lc_shake128_avx512;
		lc_shake128_c;
		lc_shake128_riscv_asm;
		lc_shake128_riscv_asm_zbb;
		lc_shake256;
		lc_shake256_arm_asm;
		lc_shake256_arm_ce;
		lc_shake256_arm_neon;
		lc_shake256_avx2;
		lc_shake256_avx512;
		lc_shake256_c;
		lc_shake256_riscv_asm;
		lc_shake256_riscv_asm_zbb;
		lc_shake512;
		lc_shake512_arm_asm;
		lc_shake512_arm_ce;
		lc_shake512_arm_neon;
		lc_shake512_avx2;
		lc_shake512_avx512;
		lc_shake512_c;
		lc_shake512_riscv_asm;
		lc_shake512_riscv_asm_zbb;
		lc_symhmac_aead;
		lc_symkmac_aead;
		lc_xdrbg128_drng;
		lc_xdrbg256_drng;
		lc_xdrbg512_drng;

	local:
		*;
};

/*
 * Not API: these are consumed by the the test suite, which ships from this
 * very tree and are therefore always in lockstep with the library. They may
 * change or disappear in any release - do not use them from outside this
 * project.
 *
 * PS: This list is used by ACVP-Parser, but it is expected to freshly compile
 * against any new version.
 */
LIBLEANCRYPTO_PRIVATE_0 {
	global:
		lc_compare;
		lc_cpu_feature_available;
		lc_cpu_feature_disable;
		lc_cpu_feature_enable;

		lc_dilithium_87_keypair_avx2;
		lc_dilithium_65_keypair_avx2;
		lc_dilithium_87_keypair_armv7;
		lc_dilithium_65_keypair_armv7;
		lc_dilithium_44_keypair_armv7;
		lc_dilithium_87_keypair_armv8;
		lc_dilithium_65_keypair_armv8;
		lc_dilithium_44_keypair_armv8;
		lc_dilithium_87_keypair_c;
		lc_dilithium_65_keypair_c;
		lc_dilithium_44_keypair_c;
		lc_dilithium_87_keypair_riscv64;
		lc_dilithium_65_keypair_riscv64;
		lc_dilithium_44_keypair_riscv64;
		lc_dilithium_87_keypair_riscv64_rvv;
		lc_dilithium_65_keypair_riscv64_rvv;
		lc_dilithium_44_keypair_riscv64_rvv;
		lc_dilithium_87_keypair_from_seed_avx2;
		lc_dilithium_65_keypair_from_seed_avx2;
		lc_dilithium_87_keypair_from_seed_c;
		lc_dilithium_65_keypair_from_seed_c;
		lc_dilithium_44_keypair_from_seed_c;
		lc_dilithium_87_keypair_from_seed_armv7;
		lc_dilithium_65_keypair_from_seed_armv7;
		lc_dilithium_44_keypair_from_seed_armv7;
		lc_dilithium_87_keypair_from_seed_armv8;
		lc_dilithium_65_keypair_from_seed_armv8;
		lc_dilithium_44_keypair_from_seed_armv8;
		lc_dilithium_87_keypair_from_seed_riscv64;
		lc_dilithium_65_keypair_from_seed_riscv64;
		lc_dilithium_44_keypair_from_seed_riscv64;
		lc_dilithium_87_keypair_from_seed_riscv64_rvv;
		lc_dilithium_65_keypair_from_seed_riscv64_rvv;
		lc_dilithium_44_keypair_from_seed_riscv64_rvv;
		lc_dilithium_87_pk_from_sk_avx2;
		lc_dilithium_65_pk_from_sk_avx2;
		lc_dilithium_87_pk_from_sk_c;
		lc_dilithium_65_pk_from_sk_c;
		lc_dilithium_44_pk_from_sk_c;
		lc_dilithium_87_pk_from_sk_armv7;
		lc_dilithium_65_pk_from_sk_armv7;
		lc_dilithium_44_pk_from_sk_armv7;
		lc_dilithium_87_pk_from_sk_armv8;
		lc_dilithium_65_pk_from_sk_armv8;
		lc_dilithium_44_pk_from_sk_armv8;
		lc_dilithium_87_pk_from_sk_riscv64;
		lc_dilithium_65_pk_from_sk_riscv64;
		lc_dilithium_44_pk_from_sk_riscv64;
		lc_dilithium_87_pk_from_sk_riscv64_rvv;
		lc_dilithium_65_pk_from_sk_riscv64_rvv;
		lc_dilithium_44_pk_from_sk_riscv64_rvv;
		lc_dilithium_87_sign_avx2;
		lc_dilithium_65_sign_avx2;
		lc_dilithium_87_sign_c;
		lc_dilithium_65_sign_c;
		lc_dilithium_44_sign_c;
		lc_dilithium_87_sign_armv7;
		lc_dilithium_65_sign_armv7;
		lc_dilithium_44_sign_armv7;
		lc_dilithium_87_sign_armv8;
		lc_dilithium_65_sign_armv8;
		lc_dilithium_44_sign_armv8;
		lc_dilithium_87_sign_riscv64;
		lc_dilithium_65_sign_riscv64;
		lc_dilithium_44_sign_riscv64;
		lc_dilithium_87_sign_riscv64_rvv;
		lc_dilithium_65_sign_riscv64_rvv;
		lc_dilithium_44_sign_riscv64_rvv;
		lc_dilithium_87_sign_ctx_avx2;
		lc_dilithium_65_sign_ctx_avx2;
		lc_dilithium_87_sign_ctx_c;
		lc_dilithium_65_sign_ctx_c;
		lc_dilithium_44_sign_ctx_c;
		lc_dilithium_87_sign_ctx_armv7;
		lc_dilithium_65_sign_ctx_armv7;
		lc_dilithium_44_sign_ctx_armv7;
		lc_dilithium_87_sign_ctx_armv8;
		lc_dilithium_65_sign_ctx_armv8;
		lc_dilithium_44_sign_ctx_armv8;
		lc_dilithium_87_sign_ctx_riscv64;
		lc_dilithium_65_sign_ctx_riscv64;
		lc_dilithium_44_sign_ctx_riscv64;
		lc_dilithium_87_sign_ctx_riscv64_rvv;
		lc_dilithium_65_sign_ctx_riscv64_rvv;
		lc_dilithium_44_sign_ctx_riscv64_rvv;
		lc_dilithium_87_sign_final_avx2;
		lc_dilithium_65_sign_final_avx2;
		lc_dilithium_87_sign_final_c;
		lc_dilithium_65_sign_final_c;
		lc_dilithium_44_sign_final_c;
		lc_dilithium_87_sign_final_armv7;
		lc_dilithium_65_sign_final_armv7;
		lc_dilithium_44_sign_final_armv7;
		lc_dilithium_87_sign_final_armv8;
		lc_dilithium_65_sign_final_armv8;
		lc_dilithium_44_sign_final_armv8;
		lc_dilithium_87_sign_final_riscv64;
		lc_dilithium_65_sign_final_riscv64;
		lc_dilithium_44_sign_final_riscv64;
		lc_dilithium_87_sign_final_riscv64_rvv;
		lc_dilithium_65_sign_final_riscv64_rvv;
		lc_dilithium_44_sign_final_riscv64_rvv;
		lc_dilithium_87_sign_init_avx2;
		lc_dilithium_65_sign_init_avx2;
		lc_dilithium_87_sign_init_c;
		lc_dilithium_65_sign_init_c;
		lc_dilithium_44_sign_init_c;
		lc_dilithium_87_sign_init_armv7;
		lc_dilithium_65_sign_init_armv7;
		lc_dilithium_44_sign_init_armv7;
		lc_dilithium_87_sign_init_armv8;
		lc_dilithium_65_sign_init_armv8;
		lc_dilithium_44_sign_init_armv8;
		lc_dilithium_87_sign_init_riscv64;
		lc_dilithium_65_sign_init_riscv64;
		lc_dilithium_44_sign_init_riscv64;
		lc_dilithium_87_sign_init_riscv64_rvv;
		lc_dilithium_65_sign_init_riscv64_rvv;
		lc_dilithium_44_sign_init_riscv64_rvv;
		lc_dilithium_87_sign_update_avx2;
		lc_dilithium_65_sign_update_avx2;
		lc_dilithium_87_sign_update_c;
		lc_dilithium_65_sign_update_c;
		lc_dilithium_44_sign_update_c;
		lc_dilithium_87_sign_update_armv7;
		lc_dilithium_65_sign_update_armv7;
		lc_dilithium_44_sign_update_armv7;
		lc_dilithium_87_sign_update_armv8;
		lc_dilithium_65_sign_update_armv8;
		lc_dilithium_44_sign_update_armv8;
		lc_dilithium_87_sign_update_riscv64;
		lc_dilithium_65_sign_update_riscv64;
		lc_dilithium_44_sign_update_riscv64;
		lc_dilithium_87_sign_update_riscv64_rvv;
		lc_dilithium_65_sign_update_riscv64_rvv;
		lc_dilithium_44_sign_update_riscv64_rvv;
		lc_dilithium_87_verify_avx2;
		lc_dilithium_65_verify_avx2;
		lc_dilithium_87_verify_c;
		lc_dilithium_65_verify_c;
		lc_dilithium_44_verify_c;
		lc_dilithium_87_verify_armv7;
		lc_dilithium_65_verify_armv7;
		lc_dilithium_44_verify_armv7;
		lc_dilithium_87_verify_armv8;
		lc_dilithium_65_verify_armv8;
		lc_dilithium_44_verify_armv8;
		lc_dilithium_87_verify_riscv64;
		lc_dilithium_65_verify_riscv64;
		lc_dilithium_44_verify_riscv64;
		lc_dilithium_87_verify_riscv64_rvv;
		lc_dilithium_65_verify_riscv64_rvv;
		lc_dilithium_44_verify_riscv64_rvv;
		lc_dilithium_87_verify_ctx_avx2;
		lc_dilithium_65_verify_ctx_avx2;
		lc_dilithium_87_verify_ctx_c;
		lc_dilithium_65_verify_ctx_c;
		lc_dilithium_44_verify_ctx_c;
		lc_dilithium_87_verify_ctx_armv7;
		lc_dilithium_65_verify_ctx_armv7;
		lc_dilithium_44_verify_ctx_armv7;
		lc_dilithium_87_verify_ctx_armv8;
		lc_dilithium_65_verify_ctx_armv8;
		lc_dilithium_44_verify_ctx_armv8;
		lc_dilithium_87_verify_ctx_riscv64;
		lc_dilithium_65_verify_ctx_riscv64;
		lc_dilithium_44_verify_ctx_riscv64;
		lc_dilithium_87_verify_ctx_riscv64_rvv;
		lc_dilithium_65_verify_ctx_riscv64_rvv;
		lc_dilithium_44_verify_ctx_riscv64_rvv;
		lc_dilithium_87_verify_final_avx2;
		lc_dilithium_65_verify_final_avx2;
		lc_dilithium_87_verify_final_c;
		lc_dilithium_65_verify_final_c;
		lc_dilithium_44_verify_final_c;
		lc_dilithium_87_verify_final_armv7;
		lc_dilithium_65_verify_final_armv7;
		lc_dilithium_44_verify_final_armv7;
		lc_dilithium_87_verify_final_armv8;
		lc_dilithium_65_verify_final_armv8;
		lc_dilithium_44_verify_final_armv8;
		lc_dilithium_87_verify_final_riscv64;
		lc_dilithium_65_verify_final_riscv64;
		lc_dilithium_44_verify_final_riscv64;
		lc_dilithium_87_verify_final_riscv64_rvv;
		lc_dilithium_65_verify_final_riscv64_rvv;
		lc_dilithium_44_verify_final_riscv64_rvv;
		lc_dilithium_87_verify_init_avx2;
		lc_dilithium_65_verify_init_avx2;
		lc_dilithium_87_verify_init_c;
		lc_dilithium_65_verify_init_c;
		lc_dilithium_44_verify_init_c;
		lc_dilithium_87_verify_init_armv7;
		lc_dilithium_65_verify_init_armv7;
		lc_dilithium_44_verify_init_armv7;
		lc_dilithium_87_verify_init_armv8;
		lc_dilithium_65_verify_init_armv8;
		lc_dilithium_44_verify_init_armv8;
		lc_dilithium_87_verify_init_riscv64;
		lc_dilithium_65_verify_init_riscv64;
		lc_dilithium_44_verify_init_riscv64;
		lc_dilithium_87_verify_init_riscv64_rvv;
		lc_dilithium_65_verify_init_riscv64_rvv;
		lc_dilithium_44_verify_init_riscv64_rvv;
		lc_dilithium_87_verify_update_avx2;
		lc_dilithium_65_verify_update_avx2;
		lc_dilithium_87_verify_update_c;
		lc_dilithium_65_verify_update_c;
		lc_dilithium_44_verify_update_c;
		lc_dilithium_87_verify_update_armv7;
		lc_dilithium_65_verify_update_armv7;
		lc_dilithium_44_verify_update_armv7;
		lc_dilithium_87_verify_update_armv8;
		lc_dilithium_65_verify_update_armv8;
		lc_dilithium_44_verify_update_armv8;
		lc_dilithium_87_verify_update_riscv64;
		lc_dilithium_65_verify_update_riscv64;
		lc_dilithium_44_verify_update_riscv64;
		lc_dilithium_87_verify_update_riscv64_rvv;
		lc_dilithium_65_verify_update_riscv64_rvv;
		lc_dilithium_44_verify_update_riscv64_rvv;

		lc_hqc_256_dec_avx2;
		lc_hqc_192_dec_avx2;
		lc_hqc_128_dec_avx2;
		lc_hqc_256_dec_c;
		lc_hqc_192_dec_c;
		lc_hqc_128_dec_c;
		lc_hqc_256_dec_kdf_avx2;
		lc_hqc_192_dec_kdf_avx2;
		lc_hqc_128_dec_kdf_avx2;
		lc_hqc_256_dec_kdf_c;
		lc_hqc_192_dec_kdf_c;
		lc_hqc_128_dec_kdf_c;
		lc_hqc_256_enc_avx2;
		lc_hqc_192_enc_avx2;
		lc_hqc_128_enc_avx2;
		lc_hqc_256_enc_c;
		lc_hqc_192_enc_c;
		lc_hqc_128_enc_c;
		lc_hqc_256_enc_internal;
		lc_hqc_192_enc_internal;
		lc_hqc_128_enc_internal;
		lc_hqc_256_enc_internal_avx2;
		lc_hqc_192_enc_internal_avx2;
		lc_hqc_128_enc_internal_avx2;
		lc_hqc_256_enc_internal_c;
		lc_hqc_192_enc_internal_c;
		lc_hqc_128_enc_internal_c;
		lc_hqc_256_enc_kdf_avx2;
		lc_hqc_192_enc_kdf_avx2;
		lc_hqc_128_enc_kdf_avx2;
		lc_hqc_256_enc_kdf_c;
		lc_hqc_192_enc_kdf_c;
		lc_hqc_128_enc_kdf_c;
		lc_hqc_256_keypair_avx2;
		lc_hqc_192_keypair_avx2;
		lc_hqc_128_keypair_avx2;
		lc_hqc_256_keypair_c;
		lc_hqc_192_keypair_c;
		lc_hqc_128_keypair_c;
		lc_hqc_256_keypair_from_seed_avx2;
		lc_hqc_192_keypair_from_seed_avx2;
		lc_hqc_128_keypair_from_seed_avx2;
		lc_hqc_256_keypair_from_seed_c;
		lc_hqc_192_keypair_from_seed_c;
		lc_hqc_128_keypair_from_seed_c;

		lc_kyber_1024_dec_c;
		lc_kyber_768_dec_c;
		lc_kyber_512_dec_c;
		lc_kyber_1024_dec_kdf_c;
		lc_kyber_768_dec_kdf_c;
		lc_kyber_512_dec_kdf_c;
		lc_kyber_1024_enc_c;
		lc_kyber_768_enc_c;
		lc_kyber_512_enc_c;
		lc_kyber_1024_enc_kdf_c;
		lc_kyber_768_enc_kdf_c;
		lc_kyber_512_enc_kdf_c;
		lc_kyber_1024_keypair_c;
		lc_kyber_768_keypair_c;
		lc_kyber_512_keypair_c;
		lc_kyber_1024_keypair_from_seed_c;
		lc_kyber_768_keypair_from_seed_c;
		lc_kyber_512_keypair_from_seed_c;
		lc_kyber_1024_pk_from_sk_c;
		lc_kyber_768_pk_from_sk_c;
		lc_kyber_512_pk_from_sk_c;

		shake128x2_armv8;
		shake256x2_armv8;
		shake128x4;
		shake256x4;
} LIBLEANCRYPTO_1.9;

FREEBSD_0 {
	environ;
};

DRAGONFLYBSD_0 {
	__progname;
};
