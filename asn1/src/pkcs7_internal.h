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

#ifndef PKCS7_INTERNAL_H
#define PKCS7_INTERNAL_H

#include "lc_pkcs7.h"
#include "ret_checkers.h"

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

int pkcs7_verify_sig_chain(struct x509_certificate *certificate_chain,
			   struct x509_certificate *x509,
			   struct pkcs7_signed_info *sinfo);

#ifdef __cplusplus
}
#endif

#endif /* PKCS7_INTERNAL_H */
