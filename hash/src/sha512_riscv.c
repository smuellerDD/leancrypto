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
#include "sha512_riscv.h"
#include "sha2_common.h"
#include "visibility.h"

static void sha512_update_riscv(void *_state, const uint8_t *in, size_t inlen)
{
	struct lc_sha512_state *ctx = _state;

	sha512_update(ctx, in, inlen, sha512_block_data_order_riscv);
}

static void sha384_final_riscv(void *_state, uint8_t *digest)
{
	struct lc_sha512_state *ctx = _state;
	unsigned int i;

	if (!ctx)
		return;

	sha512_final(_state, sha512_block_data_order_riscv);

	/* Output digest */
	for (i = 0; i < 6; i++, digest += 8)
		be64_to_ptr(digest, ctx->H[i]);
}

static void sha512_final_riscv(void *_state, uint8_t *digest)
{
	struct lc_sha512_state *ctx = _state;
	unsigned int i;

	if (!ctx)
		return;

	sha512_final(_state, sha512_block_data_order_riscv);

	/* Output digest */
	for (i = 0; i < 8; i++, digest += 8)
		be64_to_ptr(digest, ctx->H[i]);
}

static const struct lc_hash _sha384_riscv = {
	.init = sha384_init,
	.update = sha512_update_riscv,
	.final = sha384_final_riscv,
	.set_digestsize = NULL,
	.get_digestsize = sha384_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = sha512_extract_bytes,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha512_state),
};

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha384_riscv) = &_sha384_riscv;

static const struct lc_hash _sha512_riscv = {
	.init = sha512_init,
	.update = sha512_update_riscv,
	.final = sha512_final_riscv,
	.set_digestsize = NULL,
	.get_digestsize = sha512_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = sha512_extract_bytes,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha512_state),
};

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha512_riscv) = &_sha512_riscv;
