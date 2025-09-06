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

#ifndef HQC_SELFTEST_H
#define HQC_SELFTEST_H

#include "hqc_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void hqc_kem_keygen_selftest(
	int (*_lc_hqc_keypair)(struct lc_hqc_pk *pk, struct lc_hqc_sk *sk,
			       struct lc_rng_ctx *rng_ctx));

void hqc_kem_enc_selftest(int (*_lc_hqc_enc)(struct lc_hqc_ct *ct,
					     struct lc_hqc_ss *ss,
					     const struct lc_hqc_pk *pk,
					     struct lc_rng_ctx *rng_ctx));

void hqc_kem_dec_selftest(int (*_lc_hqc_dec)(struct lc_hqc_ss *ss,
					     const struct lc_hqc_ct *ct,
					     const struct lc_hqc_sk *sk));

#ifdef __cplusplus
}
#endif

#endif /* HQC_SELFTEST_H */
