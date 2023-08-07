/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef SHA3_COMMON_H
#define SHA3_COMMON_H

#include "ext_headers.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void sha3_state_init(uint64_t state[LC_SHA3_STATE_WORDS])
{
	unsigned int i;

	for (i = 0; i < LC_SHA3_STATE_WORDS; i++)
		state[i] = 0;
}

void sha3_224_init_common(void *_state);
size_t sha3_224_digestsize(void *_state);

void sha3_256_init_common(void *_state);
size_t sha3_256_digestsize(void *_state);

void sha3_384_init_common(void *_state);
size_t sha3_384_digestsize(void *_state);

void sha3_512_init_common(void *_state);
size_t sha3_512_digestsize(void *_state);

void shake_128_init_common(void *_state);
void shake_256_init_common(void *_state);
void cshake_256_init_common(void *_state);
void cshake_128_init_common(void *_state);

size_t shake_get_digestsize(void *_state);
void shake_set_digestsize(void *_state, size_t digestsize);

#ifdef __cplusplus
}
#endif

#endif /* SHA3_COMMON_H */
