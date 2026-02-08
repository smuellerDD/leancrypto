/* Generic SHA-256 implementation
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

#include "asm/AVX2/sha2-256-AVX2.h"

#include "bitshift.h"
#include "ext_headers_x86.h"
#include "status_algorithms.h"
#include "sha256_shani.h"
#include "sha2_common.h"
#include "visibility.h"

static void sha256_update_shani(void *_state, const uint8_t *in, size_t inlen)
{
	struct lc_sha256_state *ctx = _state;

	LC_FPU_ENABLE;
	lc_sha256_update(ctx, in, inlen, sha256_block_data_order_shaext);
	LC_FPU_DISABLE;
}

static void sha256_final_shani(void *_state, uint8_t *digest)
{
	struct lc_sha256_state *ctx = _state;

	LC_FPU_ENABLE;
	lc_sha256_final(ctx, digest, sha256_block_data_order_shaext);
	LC_FPU_DISABLE;
}

static const struct lc_hash _sha256_shani = {
	.init = lc_sha256_init,
	.init_nocheck = lc_sha256_init_nocheck,
	.update = sha256_update_shani,
	.final = sha256_final_shani,
	.set_digestsize = NULL,
	.get_digestsize = lc_sha256_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = NULL,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha256_state),
	.algorithm_type = LC_ALG_STATUS_SHA256
};

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha256_shani) = &_sha256_shani;
