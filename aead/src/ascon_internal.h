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

#ifndef ASCON_INTERNAL_H
#define ASCON_INTERNAL_H

#include "lc_ascon.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(LC_ASCON_KECCAK) || defined(CONFIG_LEANCRYPTO_SHA3)
int lc_ak_setiv(struct lc_ascon_cryptor *ascon, size_t keylen);
#else
static inline int lc_ak_setiv(struct lc_ascon_cryptor *ascon, size_t keylen)
{
	(void)ascon;
	(void)keylen;
	return 0;
}
#endif

int lc_ascon_ascon_setiv(struct lc_ascon_cryptor *ascon, size_t keylen);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_INTERNAL_H */
