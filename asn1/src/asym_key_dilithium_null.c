/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "asym_key_dilithium.h"

int public_key_verify_signature_dilithium(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig)
{
	(void)pkey;
	(void)sig;
	return -ENOPKG;
}

int public_key_generate_signature_dilithium(
	const struct lc_x509_key_data *gen_data,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len)
{
	(void)gen_data;
	(void)sig;
	(void)sig_data;
	(void)available_len;
	return -ENOPKG;
}

int private_key_encode_dilithium(uint8_t *data, size_t *avail_datalen,
				 struct x509_generate_privkey_context *ctx)
{
	(void)data;
	(void)avail_datalen;
	(void)ctx;
	return -ENOPKG;
}

int private_key_decode_dilithium(struct lc_x509_key_data *keys,
				 const uint8_t *data, size_t datalen)
{
	(void)keys;
	(void)data;
	(void)datalen;
	return -ENOPKG;
}

int asym_set_dilithium_keypair(struct lc_x509_key_data *gen_data,
			       struct lc_dilithium_pk *pk,
			       struct lc_dilithium_sk *sk)
{
	(void)gen_data;
	(void)pk;
	(void)sk;
	return -ENOPKG;
}
