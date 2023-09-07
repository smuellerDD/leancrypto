/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef DILITHIUM_PACK_H
#define DILITHIUM_PACK_H

#include "lc_dilithium.h"
#include "dilithium_polyvec.h"

#ifdef __cplusplus
extern "C" {
#endif

void pack_pk(struct lc_dilithium_pk *pk,
	     const uint8_t rho[LC_DILITHIUM_SEEDBYTES], const polyveck *t1);

void pack_sk(struct lc_dilithium_sk *sk,
	     const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
	     const uint8_t tr[LC_DILITHIUM_TRBYTES],
	     const uint8_t key[LC_DILITHIUM_SEEDBYTES], const polyveck *t0,
	     const polyvecl *s1, const polyveck *s2);

void pack_sig(struct lc_dilithium_sig *sig,const polyvecl *z,
	      const polyveck *h);

void unpack_pk(uint8_t rho[LC_DILITHIUM_SEEDBYTES], polyveck *t1,
	       const struct lc_dilithium_pk *pk);

void unpack_sk(uint8_t rho[LC_DILITHIUM_SEEDBYTES],
	       uint8_t tr[LC_DILITHIUM_TRBYTES],
	       uint8_t key[LC_DILITHIUM_SEEDBYTES], polyveck *t0, polyvecl *s1,
	       polyveck *s2, const struct lc_dilithium_sk *sk);
void unpack_sk_tr(uint8_t tr[LC_DILITHIUM_TRBYTES],
		  const struct lc_dilithium_sk *sk);
void unpack_sk_ex_tr(uint8_t rho[LC_DILITHIUM_SEEDBYTES],
		     uint8_t key[LC_DILITHIUM_SEEDBYTES], polyveck *t0,
		     polyvecl *s1, polyveck *s2,
		     const struct lc_dilithium_sk *sk);

int unpack_sig(polyvecl *z, polyveck *h, const struct lc_dilithium_sig *sig);

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_PACK_H */
