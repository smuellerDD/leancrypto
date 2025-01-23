/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_DRBG_H
#define LC_DRBG_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
/******************************************************************
 * Generic internal DRBG helper functions
 ******************************************************************/

/*
 * Concatenation Helper and string operation helper
 *
 * SP800-90A requires the concatenation of different data. To avoid copying
 * buffers around or allocate additional memory, the following data structure
 * is used to point to the original memory with its size. In addition, it
 * is used to build a linked list. The linked list defines the concatenation
 * of individual buffers. The order of memory block referenced in that
 * linked list determines the order of concatenation.
 */
struct lc_drbg_string {
	const uint8_t *buf;
	size_t len;
	struct lc_drbg_string *next;
};

enum lc_drbg_prefixes {
	DRBG_PREFIX0 = 0x00,
	DRBG_PREFIX1,
	DRBG_PREFIX2,
	DRBG_PREFIX3
};

static inline void lc_drbg_string_fill(struct lc_drbg_string *string,
				       const uint8_t *buf, size_t len)
{
	string->buf = buf;
	string->len = len;
	string->next = NULL;
}

/* SP800-90A requires the limit 2**19 bits, but we return bytes */
#define LC_DRBG_MAX_REQUEST_BYTES (1U << 16)
static inline size_t lc_drbg_max_request_bytes(void)
{
	return LC_DRBG_MAX_REQUEST_BYTES;
}

static inline size_t lc_drbg_max_addtl(void)
{
	return (1UL << 31);
}
/// \endcond

#ifdef __cplusplus
}
#endif

#endif /* LC_DRBG_H */
