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

#define _POSIX_C_SOURCE 200112L
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "build_bug_on.h"
#include "ext_headers.h"
#include "lc_hash.h"
#include "lc_memory_support.h"
#include "lc_memset_secure.h"
#include "visibility.h"

#define LC_MEM_DEF_ALIGNED_OFFSET	16
struct lc_mem_def {
	int fd;
	size_t size;
};

static int lc_alloc_have_memfd_secret = 1;

static int alloc_aligned_secure_internal(void **memptr, size_t alignment,
					 size_t size, int secure)
{
	size_t full_size = LC_MEM_DEF_ALIGNED_OFFSET + size;
	struct lc_mem_def *mem;
	void *ptr;
	int ret = posix_memalign(&ptr, alignment, full_size);

	BUILD_BUG_ON(LC_HASH_COMMON_ALIGNMENT > LC_MEM_DEF_ALIGNED_OFFSET);
	BUILD_BUG_ON(LC_MEM_DEF_ALIGNED_OFFSET < sizeof(struct lc_mem_def));

	if (ret)
		return ret;

	/* prevent paging out of the memory state to swap space */
	if (secure) {
		ret = mlock(ptr, full_size);
		if (ret && errno != EPERM && errno != EAGAIN) {
			int errsv = errno;

			lc_free(ptr);
			return -errsv;
		}
	}

	mem = (struct lc_mem_def *)ptr;
	mem->size = full_size;
	mem->fd = -1;
	*memptr = ((uint8_t *)mem) + LC_MEM_DEF_ALIGNED_OFFSET;

	return 0;
}

LC_INTERFACE_FUNCTION(
int, lc_alloc_aligned, void **memptr, size_t alignment, size_t size)
{
	return alloc_aligned_secure_internal(memptr, alignment, size, 0);
}

LC_INTERFACE_FUNCTION(
int, lc_alloc_aligned_secure, void **memptr, size_t alignment, size_t size)
{
	struct lc_mem_def *mem = NULL;
	size_t full_size = LC_MEM_DEF_ALIGNED_OFFSET + size;
	int ret, fd;

	(void)alignment;

	if (!lc_alloc_have_memfd_secret)
		return alloc_aligned_secure_internal(memptr, alignment, size,
						     1);

	fd = (int)syscall(SYS_memfd_secret, O_CLOEXEC);
	if (fd == -1) {
		ret = -errno;
		if (ret == -ENOSYS) {
			lc_alloc_have_memfd_secret = 0;
			return alloc_aligned_secure_internal(memptr, alignment,
							     size, 1);
		}
		goto err;
	}

	if (ftruncate(fd, (off_t)full_size) == -1) {
		ret = -errno;
		goto err;
	}

	/* Memory is aligned on page boundary */
	mem = mmap(NULL, full_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		ret = -errno;
		goto err;
	}

	mem->fd = fd;
	mem->size = full_size;
	*memptr = ((uint8_t *)mem) + LC_MEM_DEF_ALIGNED_OFFSET;

	return 0;

err:
	if (mem)
		munmap(mem, size);
	if (fd != -1)
		close(fd);

	return ret;
}

LC_INTERFACE_FUNCTION(
int, lc_alloc_high_aligned, void **memptr, size_t alignment, size_t size)
{
	return lc_alloc_aligned(memptr, alignment, size);
}

static void lc_free_internal(void *ptr, int secure)
{
	struct lc_mem_def *mem;
	size_t size;
	int fd;

	if (!ptr)
		return;

	/* Alignment is guaranteed due to mmap */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	mem = (struct lc_mem_def *)
	       (((uint8_t *)ptr) - LC_MEM_DEF_ALIGNED_OFFSET);
#pragma GCC diagnostic pop

	size = mem->size;
	fd = mem->fd;

	if (secure)
		lc_memset_secure(mem, 0, size);

	if (lc_alloc_have_memfd_secret) {
		munmap(mem, size);
		if (fd != -1)
			close(fd);
	} else {
		free(mem);
	}
}

LC_INTERFACE_FUNCTION(
void, lc_free, void *ptr)
{
	lc_free_internal(ptr, 0);
}

LC_INTERFACE_FUNCTION(
void, lc_free_high_aligned, void *ptr, size_t size)
{
	(void)size;
	lc_free(ptr);
}
