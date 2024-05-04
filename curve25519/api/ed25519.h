/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef ED25519_H
#define ED25519_H

#include "dilithium_type.h"
#include "lc_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_ed25519_keypair(struct lc_ed25519_pk *pk, struct lc_ed25519_sk *sk,
		       struct lc_rng_ctx *rng_ctx);
int lc_ed25519_sign(struct lc_ed25519_sig *sig, const uint8_t *msg, size_t mlen,
		    const struct lc_ed25519_sk *sk, struct lc_rng_ctx *rng_ctx);
int lc_ed25519_verify(const struct lc_ed25519_sig *sig, const uint8_t *msg,
		      size_t mlen, const struct lc_ed25519_pk *pk);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_H */
