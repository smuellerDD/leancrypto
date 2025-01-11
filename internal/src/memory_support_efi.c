/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#define LC_EFI_PAGESIZE 4096

/*
 * Implementation follows guidance outlined at
 * https://tianocore-docs.github.io/edk2-UefiDriverWritersGuide/draft/5_uefi_services/51_services_that_uefi_drivers_commonly_use/511_memory_allocation_services.html
 */

LC_INTERFACE_FUNCTION(int, lc_alloc_aligned, void **memptr, size_t alignment,
		      size_t size)
{
	if (alignment > 8)
		return lc_alloc_high_aligned(memptr, alignment, size);

	*memptr = AllocatePool(size);

	if (!*memptr)
		return -ENOMEM;

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_alloc_aligned_secure, void **memptr,
		      size_t alignment, size_t size)
{
	return lc_alloc_aligned(memptr, alignment, size);
}

LC_INTERFACE_FUNCTION(int, lc_alloc_high_aligned, void **memptr,
		      size_t alignment, size_t size)
{
	EFI_PHYSICAL_ADDRESS PhysicalBuffer = 0;
	EFI_STATUS efi_status;
	size_t pages = (size + LC_EFI_PAGESIZE - 1) / LC_EFI_PAGESIZE;

	if (alignment > LC_EFI_PAGESIZE)
		return -ENOMEM;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	efi_status =
		uefi_call_wrapper(BS->AllocatePages, 4, AllocateAnyPages,
				  EfiBootServicesData, pages, &PhysicalBuffer);
#pragma GCC diagnostic pop
	if (EFI_ERROR(efi_status))
		return -ENOMEM;

	*memptr = (VOID *)(UINTN)PhysicalBuffer;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_free, void *ptr)
{
	if (!ptr)
		return;
	FreePool(ptr);
}

LC_INTERFACE_FUNCTION(void, lc_free_high_aligned, void *ptr, size_t size)
{
	EFI_STATUS efi_status;
	EFI_PHYSICAL_ADDRESS PhysicalBuffer;
	size_t pages = (size + LC_EFI_PAGESIZE - 1) / LC_EFI_PAGESIZE;

	if (!ptr)
		return;

	PhysicalBuffer = (UINTN)ptr;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	efi_status = uefi_call_wrapper(BS->FreePages, 2, PhysicalBuffer, pages);
#pragma GCC diagnostic pop

	(void)efi_status;
}
