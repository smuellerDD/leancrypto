/*
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

#ifndef LC_MEMORY_SUPPORT_H
#define LC_MEMORY_SUPPORT_H

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Allocate aligned stack memory
 *
 * The variable can be casted to any structure
 *
 * @param name variable name
 * @param size size of the buffer
 * @param alignment alignment of the buffer
 */
#define LC_ALIGNED_BUFFER(name, size, alignment)			       \
	uint64_t name[(size + sizeof(uint64_t) - 1) / sizeof(uint64_t)]	       \
					__attribute__(( aligned(alignment) ))

/* Helpers to align a pointer */
#define LC_ALIGNMENT_MASK(alignment)	(alignment - 1)
#define LC_ALIGN_APPLY(x, mask)	(((x) + (mask)) & ~(mask))
#define LC_ALIGN(x, a)		LC_ALIGN_APPLY((x), (unsigned long)(a))

/**
 * @brief Align pointer interpreted as 64 bit variable
 *
 * @param p pointer
 * @param a alignment
 */
#define LC_ALIGN_PTR_64(p, a)	((uint64_t *)LC_ALIGN((unsigned long)(p), (a)))

/**
 * @brief Align pointer interpreted as 32 bit variable
 *
 * @param p pointer
 * @param a alignment
 */
#define LC_ALIGN_PTR_32(p, a)	((uint32_t *)LC_ALIGN((unsigned long)(p), (a)))

/**
 * @brief Align pointer interpreted as 16 bit variable
 *
 * @param p pointer
 * @param a alignment
 */
#define LC_ALIGN_PTR_16(p, a)	((uint16_t *)LC_ALIGN((unsigned long)(p), (a)))

/**
 * @brief Align pointer interpreted as 8 bit variable
 *
 * @param p pointer
 * @param a alignment
 */
#define LC_ALIGN_PTR_8(p, a)	((uint8_t *)LC_ALIGN((unsigned long)(p), (a)))

#ifdef __cplusplus
}
#endif

#endif /* LC_MEMORY_SUPPORT_H */