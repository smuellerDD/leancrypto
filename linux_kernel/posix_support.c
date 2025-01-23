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

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/log2.h>

#include "ext_headers.h"
#include "lc_memory_support.h"

const int errno = 0;

int lc_alloc_aligned(void **memptr, size_t alignment, size_t size)
{
	void *mem;

	/* kmalloc is guaranteed to be aligned to power of 2 */
	if (ARCH_KMALLOC_MINALIGN < alignment) {
		if (size < alignment)
			size = alignment;
		mem = kmalloc(__roundup_pow_of_two(size), GFP_KERNEL);
	} else {
		mem = kmalloc(size, GFP_KERNEL);
	}

	if (!mem)
		return -ENOMEM;

	*memptr = mem;

	memset(*memptr, 0, size);

	return 0;
}
EXPORT_SYMBOL(lc_alloc_aligned);

void lc_free(void *ptr)
{
	kfree(ptr);
}
EXPORT_SYMBOL(lc_free);

int lc_alloc_high_aligned(void **memptr, size_t alignment, size_t size)
{
	struct page *pages =
		alloc_pages(GFP_KERNEL, get_order((unsigned long)size));

	if (!pages)
		return -ENOMEM;

	*memptr = page_address(pages);

	memset(*memptr, 0, size);

	return 0;
}
EXPORT_SYMBOL(lc_alloc_high_aligned);

void lc_free_high_aligned(void *ptr, size_t size)
{
	__free_pages(virt_to_page(ptr), get_order((unsigned long)size));
}
EXPORT_SYMBOL(lc_free_high_aligned);

int lc_alloc_aligned_secure(void **memptr, size_t alignment, size_t size)
{
	return lc_alloc_aligned(memptr, alignment, size);
}
EXPORT_SYMBOL(lc_alloc_aligned_secure);
