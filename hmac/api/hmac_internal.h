/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef HMAC_INTERNAL_H
#define HMAC_INTERNAL_H

#include "lc_hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * HMAC init for KDFs whose HMAC key is not a key in the SP800-131A sense
 * (HKDF salt and PRK, PBKDF2 password): runs the HMAC self test but not the
 * FIPS minimum key size check. The KDF enforces its own input rules.
 */
int lc_hmac_init_kdf(struct lc_hmac_ctx *hmac_ctx, const uint8_t *key,
		     size_t keylen);

#ifdef __cplusplus
}
#endif

#endif /* HMAC_INTERNAL_H */
