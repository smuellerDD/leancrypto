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

#include "ext_headers.h"
#include "lc_memory_support.h"
#include "visibility.h"

#ifdef _WIN32
static int check_align(size_t align)
{
	for (size_t i = sizeof(void *); i != 0; i *= 2)
		if (align == i)
			return 0;
	return -EINVAL;
}

int posix_memalign(void **ptr, size_t align, size_t size);
int posix_memalign(void **ptr, size_t align, size_t size)
{
	if (check_align(align))
		return -EINVAL;

	int saved_errno = errno;
	void *p = _aligned_malloc(size, align);
	if (p == NULL) {
		errno = saved_errno;
		return -ENOMEM;
	}

	*ptr = p;

	memset(p, 0, size);

	return 0;
}

#elif defined(LC_EFI_ENVIRONMENT)

int posix_memalign(void **ptr, size_t align, size_t size);
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	(void)memptr;
	(void)alignment;
	(void)size;
	return ENOMEM;
}

void free(void *ptr);
void free(void *ptr)
{
	(void)ptr;
}


#endif

LC_INTERFACE_FUNCTION(int, lc_alloc_aligned, void **memptr, size_t alignment,
		      size_t size)
{
	int ret = posix_memalign(memptr, alignment, size);

	if (ret)
		return ret;

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_alloc_aligned_secure, void **memptr,
		      size_t alignment, size_t size)
{
	int ret = lc_alloc_aligned(memptr, alignment, size);

	if (ret)
		return ret;

	/* prevent paging out of the memory state to swap space */
	ret = mlock(memptr, size);
	if (ret && errno != EPERM && errno != EAGAIN) {
		int errsv = errno;

		lc_free(memptr);
		return -errsv;
	}

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_alloc_high_aligned, void **memptr,
		      size_t alignment, size_t size)
{
	return lc_alloc_aligned(memptr, alignment, size);
}

LC_INTERFACE_FUNCTION(void, lc_free, void *ptr)
{
	if (!ptr)
		return;
#ifdef _WIN32
	_aligned_free(ptr);
#else
	free(ptr);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_free_high_aligned, void *ptr, size_t size)
{
	(void)size;
	lc_free(ptr);
}
