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

#ifndef LC_ASCON_AEAD_H
#define LC_ASCON_AEAD_H

#include "lc_aead.h"
#include "lc_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
#define LC_ASCON_MAX_KEYSIZE 64

struct lc_ascon_cryptor {
	uint8_t key[LC_ASCON_MAX_KEYSIZE];
	uint8_t keylen;
	uint8_t rate_offset;
	uint8_t statesize;
	uint8_t roundb;
	uint8_t taglen;
	const struct lc_hash *hash;
	uint64_t *state;
};

#define LC_ASCON_ALIGNMENT LC_XOR_ALIGNMENT(LC_HASH_COMMON_ALIGNMENT)

/* Ascon-Keccak-based AEAD-algorithm */
extern const struct lc_aead *lc_ascon_aead;

#define _LC_ASCON_SET_CTX(name, hashname, ctx, offset)                         \
	name->state = LC_ALIGN_HASH_MASK(((uint8_t *)(ctx)) + (offset));       \
	name->hash = hashname

#define LC_ASCON_SET_CTX(name, hashname)                                       \
	LC_AEAD_HASH_ALIGN_CTX(name, lc_ascon_aead);                           \
	_LC_ASCON_SET_CTX(((struct lc_ascon_cryptor *)name->aead_state),       \
			  hashname,                                            \
			  ((struct lc_ascon_cryptor *)name->aead_state),       \
			  (sizeof(struct lc_ascon_cryptor)))

static inline int lc_ascon_load_key(struct lc_ascon_cryptor *ascon,
				    const uint8_t *key, size_t keylen)
{
	if (ascon && keylen < LC_ASCON_MAX_KEYSIZE) {
		memcpy(ascon->key, key, keylen);
		ascon->keylen = (uint8_t)keylen;
		return 0;
	}
	return -EINVAL;
}

/*
 * This function adds the padding byte with which the AAD as well as the
 * plaintext is appended with.
 */
static inline void lc_ascon_add_padbyte(struct lc_ascon_cryptor *ascon,
					size_t offset)
{
	const struct lc_hash *hash = ascon->hash;
	/* Rationale for pad byte: see ascon_squeeze_common */
	static const uint8_t pad_data = 0x01;

	/*
	 * The data was exactly a multiple of the rate -> permute before adding
	 * the padding byte.
	 */
	if (offset == hash->sponge_rate)
		offset = 0;

	lc_sponge_add_bytes(hash, ascon->state, &pad_data, offset, 1);
}
/// \endcond

#ifdef __cplusplus
}
#endif

#endif /* LC_ASCON_AEAD_H */
