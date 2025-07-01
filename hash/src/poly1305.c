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
/*
 * This file is derived from
 * https://github.com/floodyberry/poly1305-donna marked as "PUBLIC DOMAIN"
 */

#include "compare.h"
#include "lc_memcmp_secure.h"
#include "lc_memset_secure.h"
#include "lc_poly1305.h"

/* auto detect between 32bit / 64bit */
#define HAS_SIZEOF_INT128_64BIT                                                \
	(defined(__SIZEOF_INT128__) && defined(__LP64__))
#define HAS_MSVC_64BIT (defined(_MSC_VER) && defined(_M_X64))
#define HAS_GCC_4_4_64BIT

#if ((defined(__SIZEOF_INT128__) && defined(__LP64__)) ||                      \
     (defined(_MSC_VER) && defined(_M_X64)) ||                                 \
     ((defined(__GNUC__) && defined(__LP64__) &&                               \
       ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4))))))
#include "poly1305-64.h"
#else
#include "poly1305-32.h"
#endif

void lc_poly1305_update(struct lc_poly1305_context *ctx, const uint8_t *m,
			size_t bytes)
{
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	size_t i;

	/* handle leftover */
	if (st->leftover) {
		size_t want = (poly1305_block_size - st->leftover);
		if (want > bytes)
			want = bytes;
		for (i = 0; i < want; i++)
			st->buffer[st->leftover + i] = m[i];
		bytes -= want;
		m += want;
		st->leftover += want;
		if (st->leftover < poly1305_block_size)
			return;
		lc_poly1305_blocks(st, st->buffer, poly1305_block_size);
		st->leftover = 0;
	}

	/* process full blocks */
	if (bytes >= poly1305_block_size) {
		size_t want = (bytes & ~(poly1305_block_size - 1));
		lc_poly1305_blocks(st, m, want);
		m += want;
		bytes -= want;
	}

	/* store leftover */
	if (bytes) {
		for (i = 0; i < bytes; i++)
			st->buffer[st->leftover + i] = m[i];
		st->leftover += bytes;
	}
}

void lc_poly1305_auth(uint8_t mac[LC_POLY1305_TAGSIZE], const uint8_t *m,
		      size_t bytes, const uint8_t key[32])
{
	struct lc_poly1305_context ctx;

	lc_poly1305_init(&ctx, key);
	lc_poly1305_update(&ctx, m, bytes);
	lc_poly1305_final(&ctx, mac);

	lc_memset_secure(&ctx, 0, sizeof(ctx));
}

int lc_poly1305_verify(const uint8_t mac1[LC_POLY1305_TAGSIZE],
		       const uint8_t mac2[LC_POLY1305_TAGSIZE])
{
	return lc_memcmp_secure(mac1, LC_POLY1305_TAGSIZE, mac2,
				LC_POLY1305_TAGSIZE);
}

/* test a few basic operations */
void lc_poly1305_power_on_self_test(void)
{
	/* example from nacl */
	static const uint8_t nacl_key[] = {
		0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91,
		0x6d, 0x11, 0xc2, 0xcb, 0x21, 0x4d, 0x3c, 0x25,
		0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65,
		0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80,
	};

	static const uint8_t nacl_msg[] = {
		0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96,
		0x50, 0xba, 0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7,
		0x16, 0x4d, 0x96, 0xa4, 0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1,
		0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
		0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72, 0x71, 0xd2,
		0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2, 0x27, 0x0d, 0x6f, 0xb8,
		0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7,
		0xcc, 0x8a, 0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
		0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b,
		0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda, 0x99, 0x83, 0x2b, 0x61,
		0xca, 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5,
		0xf9, 0xb3, 0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
		0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74, 0xe3, 0x55,
		0xa5
	};

	static const uint8_t nacl_mac[] = { 0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94,
					    0x00, 0xe5, 0x2a, 0x7d, 0xfb, 0x4b,
					    0x3d, 0x33, 0x05, 0xd9 };

	uint8_t mac[LC_POLY1305_TAGSIZE];
	static int tested = 0;

	LC_SELFTEST_RUN(&tested);

	memset(mac, 0, sizeof(mac));

	lc_poly1305_auth(mac, nacl_msg, sizeof(nacl_msg), nacl_key);
	assert(lc_poly1305_verify(nacl_mac, mac));
}
