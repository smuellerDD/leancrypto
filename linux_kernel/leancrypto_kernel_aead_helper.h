/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LEANCRYPTO_KERNEL_AEAD_HELPER_H
#define LEANCRYPTO_KERNEL_AEAD_HELPER_H

#include <crypto/internal/aead.h>
#include <crypto/scatterwalk.h>

#include "lc_aead.h"
#include "leancrypto_kernel.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_kernel_aead_update(struct aead_request *areq, unsigned int nbytes,
			  int (*process)(struct lc_aead_ctx *ctx,
					 const uint8_t *in, uint8_t *out,
					 size_t datalen));

#ifdef __cplusplus
}
#endif

#endif /* LEANCRYPTO_KERNEL_AEAD_HELPER_H */
