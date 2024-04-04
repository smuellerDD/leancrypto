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

#ifndef LC_MEMORY_SUPPORT_H
#define LC_MEMORY_SUPPORT_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Default memory alignment */
#define LC_MEM_COMMON_ALIGNMENT (8)

/**
 * @brief Allocate aligned stack memory
 *
 * The variable can be casted to any structure
 *
 * @param name variable name
 * @param size size of the buffer
 * @param alignment alignment of the buffer
 */
#define LC_ALIGNED_BUFFER(name, size, alignment)                               \
	uint64_t name[(size + sizeof(uint64_t) - 1) / sizeof(uint64_t)]        \
		__attribute__((aligned(alignment)))

/* Helpers to align a pointer */
#define LC_ALIGNMENT_MASK(alignment) (alignment - 1)
#define LC_ALIGN_APPLY(x, mask) (((x) + (mask)) & ~(mask))
#define LC_ALIGN(x, a) LC_ALIGN_APPLY((x), (unsigned long)(a))

/**
 * @brief Align pointer interpreted as 64 bit variable
 *
 * @param p pointer
 * @param a alignment
 */
#define LC_ALIGN_PTR_64(p, a) ((uint64_t *)LC_ALIGN((unsigned long)(p), (a)))

/**
 * @brief Align pointer interpreted as 32 bit variable
 *
 * @param p pointer
 * @param a alignment
 */
#define LC_ALIGN_PTR_32(p, a) ((uint32_t *)LC_ALIGN((unsigned long)(p), (a)))

/**
 * @brief Align pointer interpreted as 16 bit variable
 *
 * @param p pointer
 * @param a alignment
 */
#define LC_ALIGN_PTR_16(p, a) ((uint16_t *)LC_ALIGN((unsigned long)(p), (a)))

/**
 * @brief Align pointer interpreted as 8 bit variable
 *
 * @param p pointer
 * @param a alignment
 */
#define LC_ALIGN_PTR_8(p, a) ((uint8_t *)LC_ALIGN((unsigned long)(p), (a)))

/**
 * Proper memory alignment value when using XOR
 */
#define LC_XOR_MIN_ALIGNMENT(min, requested)                                   \
	((min < requested) ? (requested) : (min))

#ifdef LC_HOST_X86_64

/*
 * The load of data into __m256i does not require alignment, the store
 * requires 64 bit alignment by using _mm_storel_pd / _mm_storeh_pd.
 */
#define LC_XOR_AVX2_ALIGNMENT (sizeof(uint64_t))
#define LC_XOR_ALIGNMENT(min) LC_XOR_MIN_ALIGNMENT(min, LC_XOR_AVX2_ALIGNMENT)

#elif (defined(LC_HOST_ARM32_NEON) || defined(LC_HOST_AARCH64)) &&             \
	!defined(LINUX_KERNEL)

/*
 * The load of data into uint64x2_t requires 64 bit alignment, the store
 * requires 64 bit alignment.
 */
#define LC_XOR_NEON_ALIGNMENT (sizeof(uint64_t))
#define LC_XOR_ALIGNMENT(min) LC_XOR_MIN_ALIGNMENT(min, LC_XOR_NEON_ALIGNMENT)

#else

#define LC_XOR_ALIGNMENT(min) LC_XOR_MIN_ALIGNMENT(min, (sizeof(uint64_t)))

#endif

/**
 * @brief allocate aligned memory up to 8 bytes alignment
 *
 * @param [out] memptr pointer to the newly allocated memory
 * @param [in] alignment alignment of the memory
 * @param [in] size size of the memory buffer
 */
int lc_alloc_aligned(void **memptr, size_t alignment, size_t size);

/**
 * @brief allocate aligned memory up to 8 bytes alignment with additional
 *	  security precautions
 *
 * @param [out] memptr pointer to the newly allocated memory
 * @param [in] alignment alignment of the memory
 * @param [in] size size of the memory buffer
 */
int lc_alloc_aligned_secure(void **memptr, size_t alignment, size_t size);

/**
 * @brief allocate aligned memory with arbitrary alignment
 *
 * @param [out] memptr pointer to the newly allocated memory
 * @param [in] alignment alignment of the memory
 * @param [in] size size of the memory buffer
 */
int lc_alloc_high_aligned(void **memptr, size_t alignment, size_t size);

/**
 * @brief free the memory allocated with lc_alloc_aligned
 *
 * The memory is NOT zeroized.
 *
 * @param [in] ptr memory pointer to free
 */
void lc_free(void *ptr);

/**
 * @brief free the memory allocated with lc_alloc_high_aligned
 *
 * The memory is NOT zeroized.
 *
 * @param [in] ptr memory pointer to free
 * @param [in] size size of the memory to free
 */
void lc_free_high_aligned(void *ptr, size_t size);

/**
 * @brief Check if memory pointer is aligned to given alignment mask
 *
 * @param [in] ptr memory pointer to check
 * @param [in] alignmask alignment mask to check for
 *
 * @return 1 if pointer is aligned, 0 if not aligned
 */
static inline int mem_aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* LC_MEMORY_SUPPORT_H */
