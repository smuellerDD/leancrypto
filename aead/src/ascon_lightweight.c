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

#include "ascon_internal.h"
#include "build_bug_on.h"
#include "lc_ascon_lightweight.h"
#include "visibility.h"

/*
 * Ascon with standard Ascon permutation
 */
#define LC_AEAD_ASCON_128_IV 0x80400c0600000000
#define LC_AEAD_ASCON_128a_IV 0x80800c0800000000

int lc_ascon_ascon_setiv(struct lc_ascon_cryptor *ascon, size_t keylen)
{
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;
//	static int tested = 0;

	/* Check that the key store is sufficiently large */
	BUILD_BUG_ON(sizeof(ascon->key) < 64);

	switch (hash->sponge_rate) {
	case 128 / 8: /* Ascon 128a */
		if (keylen != 16)
			return -EINVAL;
		state_mem[0] = LC_AEAD_ASCON_128a_IV;
		ascon->keylen = 16;
		ascon->roundb = 8;

		break;

	case 64 / 8: /* Ascon 128 */
		if (keylen != 16)
			return -EINVAL;
		state_mem[0] = LC_AEAD_ASCON_128_IV;
		ascon->keylen = 16;
		ascon->roundb = 6;

		break;
	default:
		return 0;
	}

	return 1;
}

LC_INTERFACE_FUNCTION(int, lc_al_alloc, const struct lc_hash *hash,
		      struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	struct lc_ascon_cryptor *ascon;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_ASCON_ALIGNMENT,
			       LC_AL_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_ASCON_SET_CTX(tmp, hash);

	ascon = tmp->aead_state;
	ascon->statesize = LC_ASCON_HASH_STATE_SIZE;

	*ctx = tmp;

	return 0;
}
