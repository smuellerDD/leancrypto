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

#include "asm/ascon_arm_neon/permutations.h"

#include "ascon_arm_neon.h"
#include "ascon_hash.h"
#include "ascon_hash_common.h"
#include "ext_headers_arm.h"
#include "lc_ascon_hash.h"
#include "visibility.h"

static void ascon_arm_neon_permutation(void *state, unsigned int rounds)
{
	LC_NEON_ENABLE;
	switch (rounds) {
	case 12:
		ascon_permutation_12_arm_neon((uint64_t *)state);
		break;
	case 8:
		ascon_permutation_8_arm_neon((uint64_t *)state);
		break;
	case 6:
		ascon_permutation_6_arm_neon((uint64_t *)state);
		break;
	default:
		break;
	}
	LC_NEON_DISABLE;
}

static void ascon_absorb(void *state, const uint8_t *in, size_t inlen)
{
	ascon_absorb_common(state, in, inlen, ascon_arm_neon_permutation);
}

static void ascon_squeeze(void *state, uint8_t *digest)
{
	ascon_squeeze_common(state, digest, ascon_permutation_12_arm_neon,
			     ascon_arm_neon_permutation);
}

static const struct lc_hash _ascon_256_arm_neon = {
	.init = ascon_128_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = ascon_digestsize,
	.sponge_permutation = ascon_arm_neon_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_ascon_256_arm_neon) = &_ascon_256_arm_neon;

static const struct lc_hash _ascon_128a_arm_neon = {
	.init = ascon_128a_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = ascon_digestsize,
	.sponge_permutation = ascon_arm_neon_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 128 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_ascon_128a_arm_neon) = &_ascon_128a_arm_neon;

static const struct lc_hash _ascon_xof_arm_neon = {
	.init = ascon_xof_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = ascon_xof_set_digestsize,
	.get_digestsize = ascon_xof_get_digestsize,
	.sponge_permutation = ascon_arm_neon_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_ascon_xof_arm_neon) = &_ascon_xof_arm_neon;
