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

#ifndef MEMORY_SUPPORT_H
#define MEMORY_SUPPORT_H

#include "build_bug_on.h"
#include "ext_headers.h"
#include "lc_hash.h"
#include "memcmp_secure.h"

#ifdef __cplusplus
extern "C"
{
#endif

static inline int
lc_alloc_aligned_clear(void **memptr, size_t alignment, size_t size)
{
	int ret = posix_memalign(memptr, alignment, size);

	if (ret)
		return ret;
	memset_secure(*memptr, 0, size);

	return 0;
}

static inline void lc_free_clear(void *ptr, size_t size)
{
	if (!ptr)
		return;
	memset_secure(ptr, 0, size);
	free(ptr);
}

/* Allocate memory on stack */
#define __LC_DECLARE_MEM_STACK(name, type, alignment)			       \
	BUILD_BUG_ON(alignment > sizeof(uint64_t));			       \
	LC_ALIGNED_BUFFER(name ## _buf, sizeof(type), uint64_t);	       \
	type *name = (type *) name ## _buf
#define __LC_RELEASE_MEM_STACK(name)	\
	memset_secure(name, 0, sizeof(name))

/* Allocate memory on heap */
#define __LC_DECLARE_MEM_HEAP(name, type, alignment)			       \
	type *name;							       \
	int __ret = lc_alloc_aligned_clear((void *)&name, alignment,	       \
					   sizeof(type));		       \
	if (__ret)							       \
			return __ret

#define __LC_RELEASE_MEM_HEAP(name)					       \
	memset_secure(name, 0, sizeof(name));				       \
	free(name)

/* Define macro LC_MEM_ON_HEAP if stack is less than 256KiB in size */
#ifdef LC_MEM_ON_HEAP

#define LC_DECLARE_MEM(name, type, alignment)				       \
	__LC_DECLARE_MEM_HEAP(name, type, alignment)
#define LC_RELEASE_MEM(name)	__LC_RELEASE_MEM_HEAP(name)

#else

#define  LC_DECLARE_MEM(name, type, alignment)				       \
	 __LC_DECLARE_MEM_STACK(name, type, alignment)
#define LC_RELEASE_MEM(name)	__LC_RELEASE_MEM_STACK(name)

#endif

#ifdef __cplusplus
}
#endif

#endif /* MEMORY_SUPPORT_H */