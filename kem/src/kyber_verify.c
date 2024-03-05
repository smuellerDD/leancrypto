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

#include "kyber_verify.h"

/**
 * @brief verify - Compare two arrays for equality in constant time.
 *
 * @param a [in] pointer to first byte array
 * @param b [in] pointer to second byte array
 * @param len [in] length of the byte arrays
 *
 * @return 0 if the byte arrays are equal, 1 otherwise
 */
uint8_t verify(const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i;
	uint8_t r = 0;

	for (i = 0; i < len; i++)
		r |= a[i] ^ b[i];

	return !!r;
}

/**
 * @brief cmov - Copy len bytes from x to r if b is 1;
 *		 don't modify x if b is 0. Requires b to be in {0,1};
 *		 assumes two's complement representation of negative integers.
 *		 Runs in constant time.
 *
 * @param r [out] pointer to output byte array
 * @param x [in] pointer to input byte array
 * @param len [in] Amount of bytes to be copied
 * @param b [in] Condition bit; has to be in {0,1}
 */
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
	size_t i;

	b = -b;
	for (i = 0; i < len; i++)
		r[i] ^= b & (r[i] ^ x[i]);
}
