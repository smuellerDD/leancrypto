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
#include "bitshift.h"
#include "chacha20.h"
#include "compare.h"
#include "conv_be_le.h"
#include "cpufeatures.h"
#include "ext_headers.h"
#include "lc_chacha20.h"
#include "lc_chacha20_private.h"
#include "lc_sym.h"
#include "math_helper.h"
#include "rotate.h"
#include "timecop.h"
#include "visibility.h"

static void cc20_selftest(int *tested, const char *impl)
{
	/* Test vector according to RFC 7539 section 2.4.2 */
	static const uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				       0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				       0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				       0x1c, 0x1d, 0x1e, 0x1f };
	static const uint8_t iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				      0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
	static const char *string =
		"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
	static const uint8_t exp[] = {
		0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba,
		0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec,
		0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f,
		0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
		0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39,
		0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
		0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
		0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
		0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c,
		0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b, 0xbf,
		0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78,
		0x5e, 0x42, 0x87, 0x4d
	};
	uint8_t res[sizeof(exp)];
	char str[25];
	LC_SYM_CTX_ON_STACK(chacha20, lc_chacha20);

	LC_SELFTEST_RUN(tested);

	/* Encrypt */
	lc_sym_init(chacha20);

	/*
	 * Stop the self test when it is not supported - this error here is
	 * triggered when no AVX2 support is present. Thus, the algorithm
	 * is not available.
	 */
	if (lc_sym_setkey(chacha20, (uint8_t *)key, sizeof(key)) == -EOPNOTSUPP)
		return;

	lc_sym_setiv(chacha20, (uint8_t *)iv, sizeof(iv));
	lc_sym_encrypt(chacha20, (uint8_t *)string, res, sizeof(res));
	snprintf(str, sizeof(str), "%s enc", impl);
	lc_compare_selftest(res, exp, sizeof(exp), str);
	lc_sym_zero(chacha20);

	/* Decrypt */
	lc_sym_init(chacha20);
	lc_sym_setkey(chacha20, (uint8_t *)key, sizeof(key));
	lc_sym_setiv(chacha20, (uint8_t *)iv, sizeof(iv));
	lc_sym_decrypt(chacha20, res, res, sizeof(res));
	snprintf(str, sizeof(str), "%s dec", impl);
	lc_compare_selftest(res, (uint8_t *)string, sizeof(res), str);
	lc_sym_zero(chacha20);
}

/* ChaCha20 block function according to RFC 7539 section 2.3 */
LC_INTERFACE_FUNCTION(void, cc20_block, struct lc_sym_state *state,
		      uint32_t *stream)
{
	uint32_t *state_w = &state->constants[0];
	uint32_t i, ws[LC_CC20_BLOCK_SIZE_WORDS], *out = stream;

	for (i = 0; i < LC_CC20_BLOCK_SIZE_WORDS; i++)
		ws[i] = state_w[i];

	for (i = 0; i < 10; i++) {
		/* Quarterround 1 */
		ws[0] += ws[4];
		ws[12] = rol32(ws[12] ^ ws[0], 16);
		ws[8] += ws[12];
		ws[4] = rol32(ws[4] ^ ws[8], 12);
		ws[0] += ws[4];
		ws[12] = rol32(ws[12] ^ ws[0], 8);
		ws[8] += ws[12];
		ws[4] = rol32(ws[4] ^ ws[8], 7);

		/* Quarterround 2 */
		ws[1] += ws[5];
		ws[13] = rol32(ws[13] ^ ws[1], 16);
		ws[9] += ws[13];
		ws[5] = rol32(ws[5] ^ ws[9], 12);
		ws[1] += ws[5];
		ws[13] = rol32(ws[13] ^ ws[1], 8);
		ws[9] += ws[13];
		ws[5] = rol32(ws[5] ^ ws[9], 7);

		/* Quarterround 3 */
		ws[2] += ws[6];
		ws[14] = rol32(ws[14] ^ ws[2], 16);
		ws[10] += ws[14];
		ws[6] = rol32(ws[6] ^ ws[10], 12);
		ws[2] += ws[6];
		ws[14] = rol32(ws[14] ^ ws[2], 8);
		ws[10] += ws[14];
		ws[6] = rol32(ws[6] ^ ws[10], 7);

		/* Quarterround 4 */
		ws[3] += ws[7];
		ws[15] = rol32(ws[15] ^ ws[3], 16);
		ws[11] += ws[15];
		ws[7] = rol32(ws[7] ^ ws[11], 12);
		ws[3] += ws[7];
		ws[15] = rol32(ws[15] ^ ws[3], 8);
		ws[11] += ws[15];
		ws[7] = rol32(ws[7] ^ ws[11], 7);

		/* Quarterround 5 */
		ws[0] += ws[5];
		ws[15] = rol32(ws[15] ^ ws[0], 16);
		ws[10] += ws[15];
		ws[5] = rol32(ws[5] ^ ws[10], 12);
		ws[0] += ws[5];
		ws[15] = rol32(ws[15] ^ ws[0], 8);
		ws[10] += ws[15];
		ws[5] = rol32(ws[5] ^ ws[10], 7);

		/* Quarterround 6 */
		ws[1] += ws[6];
		ws[12] = rol32(ws[12] ^ ws[1], 16);
		ws[11] += ws[12];
		ws[6] = rol32(ws[6] ^ ws[11], 12);
		ws[1] += ws[6];
		ws[12] = rol32(ws[12] ^ ws[1], 8);
		ws[11] += ws[12];
		ws[6] = rol32(ws[6] ^ ws[11], 7);

		/* Quarterround 7 */
		ws[2] += ws[7];
		ws[13] = rol32(ws[13] ^ ws[2], 16);
		ws[8] += ws[13];
		ws[7] = rol32(ws[7] ^ ws[8], 12);
		ws[2] += ws[7];
		ws[13] = rol32(ws[13] ^ ws[2], 8);
		ws[8] += ws[13];
		ws[7] = rol32(ws[7] ^ ws[8], 7);

		/* Quarterround 8 */
		ws[3] += ws[4];
		ws[14] = rol32(ws[14] ^ ws[3], 16);
		ws[9] += ws[14];
		ws[4] = rol32(ws[4] ^ ws[9], 12);
		ws[3] += ws[4];
		ws[14] = rol32(ws[14] ^ ws[3], 8);
		ws[9] += ws[14];
		ws[4] = rol32(ws[4] ^ ws[9], 7);
	}

	for (i = 0; i < LC_CC20_BLOCK_SIZE_WORDS; i++)
		out[i] = le_bswap32(ws[i] + state_w[i]);

	state_w[12]++;

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(stream, LC_CC20_BLOCK_SIZE);
}

static void cc20_init(struct lc_sym_state *ctx)
{
	static int tested = 0;

	if (!ctx)
		return;

	cc20_selftest(&tested, "ChaCha20");

	/* String "expand 32-byte k" */
	ctx->constants[0] = 0x61707865;
	ctx->constants[1] = 0x3320646e;
	ctx->constants[2] = 0x79622d32;
	ctx->constants[3] = 0x6b206574;
	ctx->counter = 1;
}

static int cc20_setkey(struct lc_sym_state *ctx, const uint8_t *key,
		       size_t keylen)
{
	enum lc_cpu_features feat;

	if (!ctx || keylen != 32)
		return -EINVAL;

	/* The XOR operation in cc20_crypt requires acceleration */
	feat = lc_cpu_feature_available();
	if ((feat & LC_CPU_FEATURE_INTEL) &&
	    !(feat & LC_CPU_FEATURE_INTEL_AVX2))
		return -EOPNOTSUPP;
	if ((feat & LC_CPU_FEATURE_ARM) && !(feat & LC_CPU_FEATURE_ARM_NEON))
		return -EOPNOTSUPP;

	/* Timecop: key is sensitive. */
	poison(key, keylen);

	ctx->key.u[0] = ptr_to_le32(key);
	ctx->key.u[1] = ptr_to_le32(key + sizeof(uint32_t));
	ctx->key.u[2] = ptr_to_le32(key + sizeof(uint32_t) * 2);
	ctx->key.u[3] = ptr_to_le32(key + sizeof(uint32_t) * 3);
	ctx->key.u[4] = ptr_to_le32(key + sizeof(uint32_t) * 4);
	ctx->key.u[5] = ptr_to_le32(key + sizeof(uint32_t) * 5);
	ctx->key.u[6] = ptr_to_le32(key + sizeof(uint32_t) * 6);
	ctx->key.u[7] = ptr_to_le32(key + sizeof(uint32_t) * 7);

	return 0;
}

static int cc20_setiv(struct lc_sym_state *ctx, const uint8_t *iv, size_t ivlen)
{
	/* IV is counter + nonce */
	if (!ctx || ivlen != 12)
		return -EINVAL;

	ctx->nonce[0] = ptr_to_le32(iv);
	ctx->nonce[1] = ptr_to_le32(iv + sizeof(uint32_t));
	ctx->nonce[2] = ptr_to_le32(iv + sizeof(uint32_t) * 2);

	return 0;
}

static struct lc_sym _lc_chacha20 = {
	.init = cc20_init,
	.setkey = cc20_setkey,
	.setiv = cc20_setiv,
	.encrypt = cc20_crypt,
	.decrypt = cc20_crypt,
	.statesize = LC_CC20_BLOCK_SIZE,
	.blocksize = 1,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_chacha20) = &_lc_chacha20;
