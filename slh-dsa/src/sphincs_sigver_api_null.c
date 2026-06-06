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

#include "lc_sphincs.h"
#include "sphincs_pct.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify, const struct lc_sphincs_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_pk *pk)
{
	(void)sig;
	(void)m;
	(void)mlen;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_ctx,
		      const struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx, const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_pk *pk)
{
	(void)sig;
	(void)ctx;
	(void)m;
	(void)mlen;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_init, struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_pk *pk)
{
	(void)ctx;
	(void)pk;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_update, struct lc_sphincs_ctx *ctx,
		      const uint8_t *m, size_t mlen)
{
	(void)ctx;
	(void)m;
	(void)mlen;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_final,
		      const struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_pk *pk)
{
	(void)sig;
	(void)ctx;
	(void)pk;
	return -EOPNOTSUPP;
}
