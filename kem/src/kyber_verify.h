/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_VERIFY_H
#define KYBER_VERIFY_H

#include "ext_headers.h"
#include "kyber_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief cmov - Copy len bytes from x to r if b is 1;
 *		 don't modify x if b is 0. Requires b to be in {0,1};
 *		 assumes two's complement representation of negative integers.
 *		 Runs in constant time.
 *
 * @param [out] r pointer to output byte array
 * @param [in] x pointer to input byte array
 * @param [in] len Amount of bytes to be copied
 * @param [in] b Condition bit; has to be in {0,1}
 */
static inline void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
	size_t i;

	b = -b;
	for (i = 0; i < len; i++)
		r[i] ^= b & (r[i] ^ x[i]);
}

/**
 * @brief cmov_int16 - Copy input v to *r if b is 1, don't modify *r if b is 0.
 *		       Requires b to be in {0,1}; Runs in constant time.
 *
 * @param [out] r pointer to output int16_t
 * @param [in] v input int16_t
 * @param [in] b Condition bit; has to be in {0,1}
 */
static inline void cmov_int16(int16_t *r, int16_t v, uint16_t b)
{
	b = -b;
	*r ^= (int16_t)(b & ((*r) ^ v));
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_VERIFY_H */
