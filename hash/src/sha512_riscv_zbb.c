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

#include "asm/riscv64/sha2-512-riscv.h"

#include "bitshift.h"
#include "status_algorithms.h"
#include "sha512_riscv_zbb.h"
#include "sha2_common.h"
#include "visibility.h"

static void sha512_update_riscv_zbb(void *_state, const uint8_t *in,
				    size_t inlen)
{
	struct lc_sha512_state *ctx = _state;

	lc_sha512_update(ctx, in, inlen, sha512_block_data_order_riscv_zbb);
}

static void sha384_final_riscv_zbb(void *_state, uint8_t *digest)
{
	struct lc_sha512_state *ctx = _state;

	lc_sha384_final(ctx, digest, sha512_block_data_order_riscv_zbb);
}

static void sha512_final_riscv_zbb(void *_state, uint8_t *digest)
{
	struct lc_sha512_state *ctx = _state;

	lc_sha512_final(ctx, digest, sha512_block_data_order_riscv_zbb);
}

static const struct lc_hash _sha384_riscv_zbb = {
	.init = lc_sha384_init,
	.init_nocheck = lc_sha384_init_nocheck,
	.update = sha512_update_riscv_zbb,
	.final = sha384_final_riscv_zbb,
	.set_digestsize = NULL,
	.get_digestsize = lc_sha384_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = lc_sha512_extract_bytes,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha512_state),
	.algorithm_type = LC_ALG_STATUS_SHA512
};

LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha384_riscv_zbb) = &_sha384_riscv_zbb;

static const struct lc_hash _sha512_riscv_zbb = {
	.init = lc_sha512_init,
	.init_nocheck = lc_sha512_init_nocheck,
	.update = sha512_update_riscv_zbb,
	.final = sha512_final_riscv_zbb,
	.set_digestsize = NULL,
	.get_digestsize = lc_sha512_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = lc_sha512_extract_bytes,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha512_state),
	.algorithm_type = LC_ALG_STATUS_SHA512
};

LC_INTERFACE_SYMBOL(const struct lc_hash *,
		    lc_sha512_riscv_zbb) = &_sha512_riscv_zbb;
