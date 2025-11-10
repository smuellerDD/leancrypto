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

#include "ext_headers_internal.h"
#include "lc_pkcs8_parser.h"
#include "visibility.h"

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(void, lc_pkcs8_message_clear,
		      struct lc_pkcs8_message *pkcs8)
{
	(void)pkcs8;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs8_decode, struct lc_pkcs8_message *pkcs8,
		      const uint8_t *data, size_t datalen)
{
	(void)pkcs8;
	(void)data;
	(void)datalen;
	return -EOPNOTSUPP;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs8_signature_gen, uint8_t *sig_data,
		      size_t *siglen, const struct lc_pkcs8_message *pkcs8,
		      const uint8_t *m, size_t mlen,
		      const struct lc_hash *prehash_algo)
{
	(void)sig_data;
	(void)siglen;
	(void)pkcs8;
	(void)m;
	(void)mlen;
	(void)prehash_algo return -EOPNOTSUPP;
}
