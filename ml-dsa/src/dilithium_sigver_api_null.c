/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#include "ext_headers_internal.h"
#include "lc_dilithium.h"
#include "status_algorithms.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify,
		      const struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	(void)sig;
	(void)m;
	(void)mlen;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_ctx,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	(void)sig;
	(void)ctx;
	(void)m;
	(void)mlen;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	(void)ctx;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_update,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	(void)ctx;
	(void)m;
	(void)mlen;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_final,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	(void)sig;
	(void)ctx;
	(void)pk;
	return -EOPNOTSUPP;
}

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED25519_SIG

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify,
		      const struct lc_dilithium_ed25519_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	(void)sig;
	(void)m;
	(void)mlen;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_ctx,
		      const struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed25519_pk *pk)
{
	(void)sig;
	(void)ctx;
	(void)m;
	(void)mlen;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_init,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	(void)ctx;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_update,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	(void)ctx;
	(void)m;
	(void)mlen;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_final,
		      const struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	(void)sig;
	(void)ctx;
	(void)pk;
	return -EOPNOTSUPP;
}

#endif /* LC_DILITHIUM_ED25519_SIG */

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED448_SIG

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify,
		      const struct lc_dilithium_ed448_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_ed448_pk *pk)
{
	(void)sig;
	(void)m;
	(void)mlen;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_ctx,
		      const struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed448_pk *pk)
{
	(void)sig;
	(void)ctx;
	(void)m;
	(void)mlen;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_init,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_pk *pk)
{
	(void)ctx;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_update,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	(void)ctx;
	(void)m;
	(void)mlen;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_final,
		      const struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_pk *pk)
{
	(void)sig;
	(void)ctx;
	(void)pk;
	return -EOPNOTSUPP;
}

#endif /* LC_DILITHIUM_ED448_SIG */
