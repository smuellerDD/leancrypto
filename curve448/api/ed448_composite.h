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

#ifndef ED448_COMPOSITE_H
#define ED448_COMPOSITE_H

#include "dilithium_type.h"
#include "lc_ed448.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_ed448_sign_ctx(struct lc_ed448_sig *sig, const uint8_t *msg, size_t mlen,
		      const struct lc_ed448_sk *sk, struct lc_rng_ctx *rng_ctx,
		      struct lc_dilithium_ed448_ctx *composite_ml_dsa_ctx);

int lc_ed448_verify_ctx(const struct lc_ed448_sig *sig, const uint8_t *msg,
			size_t mlen, const struct lc_ed448_pk *pk,
			struct lc_dilithium_ed448_ctx *composite_ml_dsa_ctx);

#ifdef __cplusplus
}
#endif

#endif /* ED448_COMPOSITE_H */
