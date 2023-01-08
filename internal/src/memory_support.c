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

#include "lc_memory_support.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(
int, lc_alloc_aligned, void **memptr, size_t alignment, size_t size)
{
	int ret = posix_memalign(memptr, alignment, size);

	if (ret)
		return ret;

	return 0;
}

LC_INTERFACE_FUNCTION(
int, lc_alloc_high_aligned, void **memptr, size_t alignment, size_t size)
{
	return lc_alloc_aligned(memptr, alignment, size);
}

LC_INTERFACE_FUNCTION(
void, lc_free, void *ptr)
{
	if (!ptr)
		return;
	free(ptr);
}

LC_INTERFACE_FUNCTION(
void, lc_free_high_aligned, void *ptr, size_t size)
{
	(void)size;
	lc_free(ptr);
}
