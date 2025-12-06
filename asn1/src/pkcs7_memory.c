/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "asym_key.h"
#include "lc_memory_support.h"
#include "pkcs7_internal.h"

void lc_pkcs7_sinfo_free(struct lc_pkcs7_message *pkcs7)
{
	struct lc_pkcs7_signed_info *sinfo;
	uint8_t idx = 0;

	while (pkcs7->list_head_sinfo) {
		sinfo = pkcs7->list_head_sinfo;
		pkcs7->list_head_sinfo = sinfo->next;
		lc_public_key_signature_clear(&sinfo->sig);
		if (idx < pkcs7->consumed_preallocated_sinfo) {
			idx++;
		} else {
			lc_free(sinfo);
		}
	}

	if (pkcs7->curr_sinfo) {
		sinfo = pkcs7->curr_sinfo;
		lc_public_key_signature_clear(&sinfo->sig);

		if (idx >= pkcs7->consumed_preallocated_sinfo)
			lc_free(sinfo);
	}
}

int lc_pkcs7_sinfo_add(struct lc_pkcs7_message *pkcs7)
{
	if (!pkcs7->list_head_sinfo) {
		pkcs7->list_head_sinfo = pkcs7->curr_sinfo;
	} else {
		*pkcs7->list_tail_sinfo = pkcs7->curr_sinfo;
	}

	pkcs7->list_tail_sinfo = &pkcs7->curr_sinfo->next;
	pkcs7->curr_sinfo = NULL;

	return 0;
}

int lc_pkcs7_sinfo_get(struct lc_pkcs7_signed_info **sinfo,
		       struct lc_pkcs7_message *pkcs7)
{
	int ret = 0;

	CKNULL(sinfo, -EINVAL);

	if (!pkcs7->curr_sinfo) {
		if (pkcs7->consumed_preallocated_sinfo <
		    pkcs7->avail_preallocated_sinfo) {
			pkcs7->curr_sinfo = pkcs7->preallocated_sinfo;
			pkcs7->consumed_preallocated_sinfo++;
			pkcs7->preallocated_sinfo++;
			memset(pkcs7->curr_sinfo, 0,
			       sizeof(struct lc_pkcs7_signed_info));
		} else {
			CKINT(lc_alloc_aligned(
				(void **)&pkcs7->curr_sinfo, 8,
				sizeof(struct lc_pkcs7_signed_info)));
		}
	}

	*sinfo = pkcs7->curr_sinfo;

out:
	return ret;
}

void lc_pkcs7_x509_free(struct lc_x509_certificate *x509)
{
	if (x509->allocated) {
		lc_x509_cert_clear(x509);
		lc_free(x509);
	} else {
		lc_x509_cert_clear(x509);
	}
}

int lc_pkcs7_x509_get(struct lc_x509_certificate **x509,
		      struct lc_pkcs7_message *pkcs7)
{
	struct lc_x509_certificate *tmp_x509;
	int ret = 0;

	CKNULL(x509, -EINVAL);

	if (pkcs7->consumed_preallocated_x509 <
	    pkcs7->avail_preallocated_x509) {
		tmp_x509 = pkcs7->preallocated_x509;
		pkcs7->consumed_preallocated_x509++;
		pkcs7->preallocated_x509++;
		memset(tmp_x509, 0, sizeof(struct lc_x509_certificate));
	} else {
		CKINT(lc_alloc_aligned((void **)&tmp_x509, 8,
				       sizeof(struct lc_x509_certificate)));
		tmp_x509->allocated = 1;
	}

	*x509 = tmp_x509;

out:
	return ret;
}
