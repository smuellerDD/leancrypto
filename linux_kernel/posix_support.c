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

#include "posix_support.h"

const int errno = 0;

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *mem = kmalloc(size, GFP_KERNEL);

	WARN_ON(alignment > ARCH_KMALLOC_MINALIGN);
	if (!mem)
		return -ENOMEM;

	*memptr = mem;
	return 0;
#if 0
	void *aligned, *nonaligned = kmalloc(size + alignment, GFP_KERNEL);

	if (!nonaligned)
		return -ENOMEM;

	aligned = PTR_ALIGN(nonaligned, alignment + 1);

	*memptr = aligned;

	return 0;
#endif
}
EXPORT_SYMBOL(posix_memalign);
