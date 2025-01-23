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

#ifndef SMALL_STACK_SUPPORT_H
#define SMALL_STACK_SUPPORT_H

#include "lc_memory_support.h"
#include "lc_memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LC_ALIGNED_BUFFER_ALIGNMENTSIZE(name, size, alignment)                 \
	uint64_t name[(size + sizeof(uint64_t) - 1) / sizeof(uint64_t)]        \
		__attribute__((aligned(alignment)))

/* Allocate memory on stack */
#define __LC_DECLARE_MEM_STACK(name, type, alignment)                          \
	LC_ALIGNED_BUFFER_ALIGNMENTSIZE(name##_buf, sizeof(type), alignment);  \
	lc_memset_secure(name##_buf, 0, sizeof(type));                         \
	type *name = (type *)name##_buf
#define __LC_RELEASE_MEM_STACK(name) lc_memset_secure(name, 0, sizeof(*name))

/* Allocate memory on heap */
#define __LC_DECLARE_MEM_HEAP(name, type, alignment)                           \
	type *name = NULL;                                                     \
	int __ret =                                                            \
		lc_alloc_high_aligned((void *)&name, alignment, sizeof(type)); \
	if (__ret || !name)                                                    \
		return __ret;                                                  \
	lc_memset_secure(name, 0, sizeof(type))

#define __LC_RELEASE_MEM_HEAP(name)                                            \
	lc_memset_secure(name, 0, sizeof(*name));                              \
	lc_free_high_aligned(name, sizeof(*name))

/* Define macro LC_MEM_ON_HEAP if stack is less than 256KiB in size */
#ifdef LC_MEM_ON_HEAP

#define LC_DECLARE_MEM(name, type, alignment)                                  \
	_Pragma("GCC diagnostic push")                                         \
		_Pragma("GCC diagnostic ignored \"-Wcast-align\"")             \
			__LC_DECLARE_MEM_HEAP(name, type, alignment);          \
	_Pragma("GCC diagnostic pop")
#define LC_RELEASE_MEM(name) __LC_RELEASE_MEM_HEAP(name)

#else

#define LC_DECLARE_MEM(name, type, alignment)                                  \
	_Pragma("GCC diagnostic push")                                         \
		_Pragma("GCC diagnostic ignored \"-Wcast-align\"")             \
			__LC_DECLARE_MEM_STACK(name, type, alignment);         \
	_Pragma("GCC diagnostic pop")
#define LC_RELEASE_MEM(name) __LC_RELEASE_MEM_STACK(name)

#endif

#ifdef __cplusplus
}
#endif

#endif /* SMALL_STACK_SUPPORT_H */
