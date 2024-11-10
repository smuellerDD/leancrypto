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

#ifndef PUBLIC_KEY_H
#define PUBLIC_KEY_H

#include "asymmetric_type.h"
#include "lc_x509_parser.h"
#include "lc_sha256.h"
#include "lc_sha512.h"
#include "lc_sha3.h"
#include "oid_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_PKCS7_DEBUG
#warning                                                                       \
	"LC_PKCS7_DEBUG enabled - code MUST ONLY BE USED FOR TESTING - NEVER IN PRODUCTION!"
#define CKINT_SIGCHECK(x)                                                      \
	{                                                                      \
		ret = x;                                                       \
		if (ret == -ENOPKG) {                                          \
			printf("WARNING: NO SIGNATURE CHECK\n");               \
			ret = 0;                                               \
		}                                                              \
		if (ret < 0)                                                   \
			goto out;                                              \
	}
#else
#define CKINT_SIGCHECK CKINT
#endif

void public_key_clear(struct lc_public_key *key);

void public_key_signature_clear(struct lc_public_key_signature *sig);

int public_key_verify_signature(const struct lc_public_key *pkey,
				const struct lc_public_key_signature *sig);

int public_key_generate_signature(const struct lc_x509_generate_data *gen_data,
				  struct lc_x509_certificate *x509);

#ifdef __cplusplus
}
#endif

#endif /* PUBLIC_KEY_H */
