/*
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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

#include "conv_be_le.h"
#include "lc_hmac.h"
#include "lc_hotp.h"
#include "lc_sha256.h"
#include "memset_secure.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(
void, lc_hotp, const uint8_t *hmac_key, size_t hmac_key_len, uint64_t counter,
	       uint32_t digits, uint32_t *hotp_val)
{
	LC_HMAC_CTX_ON_STACK(ctx256, lc_sha256);
	uint32_t offset, truncated, modulo = 1;
	uint8_t md[LC_SHA_MAX_SIZE_DIGEST];

	if (!hotp_val)
		return;

	/* calculate the modulo value */
	while (digits > 0) {
		modulo *= 10;
		digits--;
	}

	/* convert counter into network-byte order */
	counter = be_bswap64(counter);

	/* HMAC */
	lc_hmac_init(ctx256, hmac_key, hmac_key_len);
	lc_hmac_update(ctx256, (uint8_t *)&counter, sizeof(counter));
	lc_hmac_final(ctx256, md);
	lc_hmac_zero(ctx256);

	/* DT */
	offset = md[lc_hmac_macsize(ctx256) - 1] & 0xf;
	truncated = (uint32_t)((md[offset] & 0x7f) << 24) |
		    (uint32_t)((md[offset + 1] & 0xff) << 16) |
		    (uint32_t)((md[offset + 2] & 0xff) << 8) |
		    (uint32_t)((md[offset + 3] & 0xff));

	*hotp_val = truncated % modulo;

	memset_secure(md, 0, sizeof(md));
}
