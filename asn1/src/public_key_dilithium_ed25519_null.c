/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "public_key_dilithium_ed25519.h"

int public_key_encode_dilithium_ed25519(uint8_t *data, size_t *avail_datalen,
					struct x509_generate_context *ctx)
{
	(void)data;
	(void)avail_datalen;
	(void)ctx;
	return -ENOPKG;
}

int public_key_verify_signature_dilithium_ed25519(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig)
{
	(void)pkey;
	(void)sig;
	return -ENOPKG;
}

int public_key_generate_signature_dilithium_ed25519(
	const struct lc_x509_generate_data *gen_data,
	struct lc_x509_certificate *x509)
{
	(void)gen_data;
	(void)x509;
	return -ENOPKG;
}

int public_key_signature_size_dilithium_ed25519(
	enum lc_dilithium_type dilithium_type, size_t *size)
{
	void)dilithium_type;
	(void)size;
	return -ENOPKG;
}
