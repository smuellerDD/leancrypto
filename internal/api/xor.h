/* Efficient XOR implementation
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef XOR_H
#define XOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

static inline int aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

static inline void xor_8(uint8_t *dst, const uint8_t *src, size_t size)
{
	for (; size; size--)
		*dst++ ^= *src++;
}

static inline void xor_32_aligned(uint8_t *dst, const uint8_t *src, size_t size)
{
	/*
	 * We can ignore the alignment warning as we checked
	 * for proper alignment.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	uint32_t *dst_word = (uint32_t *)dst;
	uint32_t *src_word = (uint32_t *)src;
#pragma GCC diagnostic pop

	for (; size >= sizeof(*src_word); size -= sizeof(*src_word))
		*dst_word++ ^= *src_word++;

	xor_8((uint8_t *)dst_word, (uint8_t *)src_word, size);
}

static inline void xor_32(uint8_t *dst, const uint8_t *src, size_t size)
{
	if (aligned(src, sizeof(uint32_t) - 1) &&
	    aligned(dst, sizeof(uint32_t) - 1))
		xor_32_aligned(dst, src, size);
	else
		xor_8(dst, src, size);
}

#ifdef __LP64__
static inline void xor_64_aligned(uint8_t *dst, const uint8_t *src, size_t size)
{
	/*
	 * We can ignore the alignment warning as we checked
	 * for proper alignment.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	uint64_t *dst_dword = (uint64_t *)dst;
	uint64_t *src_dword = (uint64_t *)src;
#pragma GCC diagnostic pop

	for (; size >= sizeof(*src_dword); size -= sizeof(*src_dword))
		*dst_dword++ ^= *src_dword++;

	xor_32_aligned((uint8_t *)dst_dword, (uint8_t *)src_dword, size);
}
#endif

/**
 * @brief Perform XOR operation efficiently
 *
 * @param dst [in/out] Data in which the source data is XORed into
 * @param src [in] Source data which is XORed into the destination
 * @param size [in] Buffer lengths of both, dst and src
 */
static inline void xor_64(uint8_t *dst, const uint8_t *src, size_t size)
{
#ifdef __LP64__
	if (aligned(src, sizeof(uint64_t) - 1) &&
	    aligned(dst, sizeof(uint64_t) - 1))
		xor_64_aligned(dst, src, size);
	else
#endif
		xor_32(dst, src, size);
}

#ifdef __cplusplus
}
#endif

#endif /* XOR_H */
