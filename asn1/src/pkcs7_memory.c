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

void pkcs7_sinfo_free(struct lc_pkcs7_message *pkcs7,
		      struct lc_pkcs7_signed_info *sinfo)
{
	(void)pkcs7;
	if (!sinfo)
		return;
	public_key_signature_clear(&sinfo->sig);
	lc_free(sinfo);
}

int pkcs7_sinfo_add(struct lc_pkcs7_message *pkcs7,
		    struct lc_pkcs7_signed_info *sinfo)
{
	if (!pkcs7->signed_infos) {
		pkcs7->signed_infos = sinfo;
	} else {
		*pkcs7->list_tail_signed_infos = sinfo;
	}

	pkcs7->list_tail_signed_infos = &sinfo->next;

	return 0;
}

int pkcs7_sinfo_get(struct lc_pkcs7_signed_info **sinfo,
		    struct lc_pkcs7_message *pkcs7)
{
	struct lc_pkcs7_signed_info *sinfo_tmp = NULL;
	int ret;

	(void)pkcs7;

	CKNULL(sinfo, -EINVAL);

	CKINT(lc_alloc_aligned((void **)&sinfo_tmp, 8,
			       sizeof(struct lc_pkcs7_signed_info)));

	/* Return the signer info */
	*sinfo = sinfo_tmp;

	sinfo_tmp = NULL;

out:
	lc_free(sinfo_tmp);
	return ret;
}
