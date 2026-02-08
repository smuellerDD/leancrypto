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

#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "lc_status.h"
#include "lc_sym.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(uint64_t, lc_sym_algorithm_type, const struct lc_sym *sym)
{
	if (!sym)
		return 0;

	/*
	 * Only the regular interfaces are considered to have a type to be
	 * resolvable as FIPS algorithm.
	 */
	if (sym == lc_aes || sym == lc_aes_cbc || sym == lc_aes_ctr ||
	    sym == lc_aes_kw || sym == lc_aes_xts)
		return sym->algorithm_type | LC_ALG_STATUS_FIPS;

	return sym->algorithm_type;
}

LC_INTERFACE_FUNCTION(uint64_t, lc_sym_ctx_algorithm_type,
		      const struct lc_sym_ctx *ctx)
{
	if (!ctx)
		return 0;

	return lc_sym_algorithm_type(ctx->sym);
}
