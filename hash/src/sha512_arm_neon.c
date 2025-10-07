/* Generic SHA-512 implementation
 *
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

#include "asm/ARMv8A/sha2-512-ARMv8.h"

#include "bitshift.h"
#include "ext_headers_arm.h"
#include "lc_status.h"
#include "sha512_arm_neon.h"
#include "sha2_common.h"
#include "visibility.h"

static void sha512_update_arm_neon(void *_state, const uint8_t *in,
				   size_t inlen)
{
	struct lc_sha512_state *ctx = _state;

	LC_NEON_ENABLE;
	sha512_update(ctx, in, inlen, sha512_block_neon);
	LC_NEON_DISABLE;
}

static void sha384_final_arm_neon(void *_state, uint8_t *digest)
{
	struct lc_sha512_state *ctx = _state;

	LC_NEON_ENABLE;
	sha512_final(ctx, digest, sha512_block_neon);
	LC_NEON_DISABLE;
}

static void sha512_final_arm_neon(void *_state, uint8_t *digest)
{
	struct lc_sha512_state *ctx = _state;

	LC_NEON_ENABLE;
	sha512_final(ctx, digest, sha512_block_neon);
	LC_NEON_DISABLE;
}

static const struct lc_hash _sha384_arm_neon = {
	.init = sha384_init,
	.init_nocheck = sha384_init_nocheck,
	.update = sha512_update_arm_neon,
	.final = sha384_final_arm_neon,
	.set_digestsize = NULL,
	.get_digestsize = sha384_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = sha512_extract_bytes,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha512_state),
	.algorithm_type = LC_ALG_STATUS_SHA512
};

LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha384_arm_neon) = &_sha384_arm_neon;

static const struct lc_hash _sha512_arm_neon = {
	.init = sha512_init,
	.init_nocheck = sha512_init_nocheck,
	.update = sha512_update_arm_neon,
	.final = sha512_final_arm_neon,
	.set_digestsize = NULL,
	.get_digestsize = sha512_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = sha512_extract_bytes,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha512_state),
	.algorithm_type = LC_ALG_STATUS_SHA512
};

LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha512_arm_neon) = &_sha512_arm_neon;
