/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef HQC_KEM_C_H
#define HQC_KEM_C_H

#include "hqc_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_hqc_keypair_c(struct lc_hqc_pk *pk, struct lc_hqc_sk *sk,
		     struct lc_rng_ctx *rng_ctx);
int lc_hqc_keypair_from_seed_c(struct lc_hqc_pk *pk, struct lc_hqc_sk *sk,
			       const uint8_t *seed, size_t seedlen);
int lc_hqc_enc_internal_c(struct lc_hqc_ct *ct, struct lc_hqc_ss *ss,
			  const struct lc_hqc_pk *pk,
			  struct lc_rng_ctx *rng_ctx);
int lc_hqc_enc_c(struct lc_hqc_ct *ct, struct lc_hqc_ss *ss,
		 const struct lc_hqc_pk *pk);
int lc_hqc_enc_kdf_c(struct lc_hqc_ct *ct, uint8_t *ss, size_t ss_len,
		     const struct lc_hqc_pk *pk);
int lc_hqc_dec_c(struct lc_hqc_ss *ss, const struct lc_hqc_ct *ct,
		 const struct lc_hqc_sk *sk);
int lc_hqc_dec_kdf_c(uint8_t *ss, size_t ss_len, const struct lc_hqc_ct *ct,
		     const struct lc_hqc_sk *sk);

#ifdef __cplusplus
}
#endif

#endif /* HQC_KEM_C_H */
