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

#include "asym_key_ed25519.h"
#include "eddsa_curve_private_key_asn1.h"
#include "ret_checkers.h"

#ifdef LC_X509_GENERATOR
int lc_x509_eddsa_private_key_enc(void *context, uint8_t *data,
				  size_t *avail_datalen, uint8_t *tag)
{
	const struct x509_generate_privkey_context *ctx = context;
	const struct lc_x509_key_data *keys = ctx->keys;
	size_t sklen;
	uint8_t *skptr;
	int ret;

	(void)tag;

	if (keys->sig_type == LC_SIG_ED25519) {
		CKINT(lc_ed25519_sk_ptr(&skptr, &sklen, keys->sk.ed25519_sk));
	} else if (keys->sig_type == LC_SIG_ED448) {
		CKINT(lc_ed448_sk_ptr(&skptr, &sklen, keys->sk.ed448_sk));
	} else {
		return -EOPNOTSUPP;
	}

	/* Only export the secret part of the ED25519 secret key */
	CKINT(lc_x509_concatenate_bit_string(&data, avail_datalen, skptr,
					     sklen));

	printf_debug("Set composite secret key of size %zu\n", sklen);

out:
	return ret;
}
#endif

int lc_x509_eddsa_private_key(void *context, size_t hdrlen, unsigned char tag,
			      const uint8_t *value, size_t vlen)
{
	struct lc_x509_key_data *keys = context;
	int ret;

	(void)hdrlen;
	(void)tag;

	if (keys->sig_type == LC_SIG_ED25519) {
		CKINT(lc_ed25519_sk_load(keys->sk.ed25519_sk, value, vlen));
	} else if (keys->sig_type == LC_SIG_ED448) {
		CKINT(lc_ed448_sk_load(keys->sk.ed448_sk, value, vlen));
	} else {
		return -EOPNOTSUPP;
	}

	printf_debug("Loaded composite public key of size %zu\n", vlen);

out:
	return ret;
}
