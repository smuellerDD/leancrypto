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

#include "asym_key.h"
#include "lc_memory_support.h"
#include "pkcs7_internal.h"

void pkcs7_sinfo_free(struct lc_pkcs7_message *pkcs7)
{
	struct lc_pkcs7_signed_info *sinfo;
	uint8_t idx = 0;

	while (pkcs7->list_head_signed_infos) {
		sinfo = pkcs7->list_head_signed_infos;
		pkcs7->list_head_signed_infos = sinfo->next;
		public_key_signature_clear(&sinfo->sig);
		if (idx < pkcs7->consumed_preallocated_sinfo) {
			idx++;
		} else {
			lc_free(sinfo);
		}
	}

	if (pkcs7->curr_signed_infos) {
		sinfo = pkcs7->curr_signed_infos;
		public_key_signature_clear(&sinfo->sig);

		if (idx >= pkcs7->consumed_preallocated_sinfo)
			lc_free(sinfo);
	}
}

int pkcs7_sinfo_add(struct lc_pkcs7_message *pkcs7)
{
	if (!pkcs7->list_head_signed_infos) {
		pkcs7->list_head_signed_infos = pkcs7->curr_signed_infos;
	} else {
		*pkcs7->list_tail_signed_infos = pkcs7->curr_signed_infos;
	}

	pkcs7->list_tail_signed_infos = &pkcs7->curr_signed_infos->next;
	pkcs7->curr_signed_infos = NULL;

	return 0;
}

int pkcs7_sinfo_get(struct lc_pkcs7_signed_info **sinfo,
		    struct lc_pkcs7_message *pkcs7)
{
	int ret = 0;

	CKNULL(sinfo, -EINVAL);

	if (!pkcs7->curr_signed_infos) {
		if (pkcs7->consumed_preallocated_sinfo <
		    pkcs7->avail_preallocated_sinfo) {
			pkcs7->curr_signed_infos = pkcs7->preallocated_sinfo;
			pkcs7->consumed_preallocated_sinfo++;
			pkcs7->preallocated_sinfo++;
		} else {
			CKINT(lc_alloc_aligned(
				(void **)&pkcs7->curr_signed_infos, 8,
				sizeof(struct lc_pkcs7_signed_info)));
		}
	}

	*sinfo = pkcs7->curr_signed_infos;

out:
	return ret;
}
