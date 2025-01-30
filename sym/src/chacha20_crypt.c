/*
 * Copyright (C) 2016 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#include "alignment.h"
#include "chacha20.h"
#include "ext_headers.h"
#include "lc_chacha20.h"
#include "lc_chacha20_private.h"
#include "math_helper.h"
#include "xor256.h"

void cc20_crypt(struct lc_sym_state *ctx, const uint8_t *in, uint8_t *out,
		size_t len)
{
	uint32_t keystream[LC_CC20_BLOCK_SIZE_WORDS] __align(
		LC_XOR_ALIGNMENT(sizeof(uint64_t)));

	if (!ctx)
		return;

	while (len) {
		size_t todo = min_size(len, sizeof(keystream));

		cc20_block(ctx, keystream);

		if (in != out)
			memcpy(out, in, todo);

		xor_256(out, (uint8_t *)keystream, todo);

		len -= todo;
		in += todo;
		out += todo;
	}

	lc_memset_secure(keystream, 0, sizeof(keystream));
}
