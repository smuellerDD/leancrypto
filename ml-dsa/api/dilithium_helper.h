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

#ifndef DILITHIUM_HELPER_H
#define DILITHIUM_HELPER_H

#include "lc_dilithium.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_DILITHIUM_ED25519_SIG

int lc_dilithium_ed25519_sig_load_partial(struct lc_dilithium_ed25519_sig *sig,
					  const uint8_t *dilithium_src_sig,
					  size_t dilithium_src_sig_len,
					  const uint8_t *ed25519_src_sig,
					  size_t ed25519_src_sig_len);

int lc_dilithium_ed25519_pk_load_partial(struct lc_dilithium_ed25519_pk *pk,
					 const uint8_t *dilithium_src_key,
					 size_t dilithium_src_key_len,
					 const uint8_t *ed25519_src_key,
					 size_t ed25519_src_key_len);

int lc_dilithium_ed25519_sk_load_partial(struct lc_dilithium_ed25519_sk *sk,
					 const uint8_t *dilithium_src_key,
					 size_t dilithium_src_key_len,
					 const uint8_t *ed25519_src_key,
					 size_t ed25519_src_key_len);
#endif

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_HELPER_H */
