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

#ifndef SIGNATURE_DOMAIN_SEPARATION_H
#define SIGNATURE_DOMAIN_SEPARATION_H

#include "dilithium_type.h"
#include "lc_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

int signature_domain_separation(struct lc_hash_ctx *hash_ctx,
				unsigned int ml_dsa_internal,
				const struct lc_hash *signature_prehash_type,
				const uint8_t *userctx, size_t userctxlen,
				const uint8_t *m,
				size_t mlen, unsigned int nist_category);

#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_DOMAIN_SEPARATION_H */
