/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef TESTFUNCTIONS_H
#define TESTFUNCTIONS_H

#ifdef __cplusplus
extern "C"
{
#endif

int cc_tester_cshake_validate(void);
int cc_tester_cshake(void);

int hc_tester_sha512(void);

int kc_tester_kmac_validate(void);
int kc_tester_kmac(void);

int sh_nonaligned(void);
int sh_tester(void);

int kmac_128_tester(void);
int kmac_tester(void);
int kmac_xof_more_tester(void);
int kmac_xof_tester(void);

int chacha20_enc_selftest(void);
int chacha20_block_selftest(void);
int test_kw(void);
int test_encrypt_all(void);
int test_decrypt(void);
int test_ctr(void);
int test_encrypt_cbc(void);
int test_decrypt_cbc(void);

int hkdf_tester(void);
int kdf_ctr_tester(void);
int kdf_dpi_tester(void);
int kdf_fb_tester(void);
int pbkdf2_tester(void);

int hmac_sha2_256_tester(void);
int hmac_sha2_512_tester(void);
int sha3_hmac_tester(void);

int cshake128_tester(void);
int cshake256_tester(void);
int shake128_tester(void);
int shake256_tester(void);
int sha512_tester(void);
int sha3_512_tester(void);
int sha3_256_tester(void);
int sha3_224_tester(void);
int sha256_tester(void);
int shake_sqeeze_more_tester(void);

int chacha20_tester(void);
int kmac_test(void);
int hmac_drbg_tester(void);
int hash_drbg_tester(void);
int cshake_drng_test(void);

int dilitium_tester(void);
int dilithium_invalid(void);

int kyber_kem_tester_c(void);
int kyber_kem_tester_avx(void);
int kyber_kem_tester_common(void);
int kyber_kex_tester(void);
int kyber_ies_tester(void);
int kyber_invalid(void);

int status_tester(void);

#ifdef __cplusplus
}
#endif

#endif /* TESTFUNCTIONS_H */
