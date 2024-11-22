/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef X509_ALGORITHM_MAPPER_H
#define X509_ALGORITHM_MAPPER_H

#include "lc_x509_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_x509_sig_type_to_oid(enum lc_sig_types pkey_algo, enum OID *oid);
int lc_x509_sig_check_hash(enum lc_sig_types pkey_algo,
			   const struct lc_hash *hash_algo);
int lc_x509_oid_to_sig_type(enum OID oid, enum lc_sig_types *pkey_algo);
const char *lc_x509_oid_to_name(enum OID oid);
int lc_x509_hash_to_oid(const struct lc_hash *hash_algo, enum OID *oid);
int lc_x509_oid_to_hash(enum OID oid, const struct lc_hash **hash_algo);

#ifdef __cplusplus
}
#endif

#endif /* X509_ALGORITHM_MAPPER_H */
