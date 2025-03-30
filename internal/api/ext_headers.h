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

#ifndef EXT_HEADERS_H
#define EXT_HEADERS_H

/******************************************************************************
 * Generic Definitions
 ******************************************************************************/
#define LC_PURE __attribute__((pure))

/**
 * @brief Return the size of a member variable of a data structure
 *
 * @param [in] struct data structure containing the member variable
 * @param [in] member member variable name whose size shall be obtained
 *
 * @return size of the variable
 */
#define lc_member_size(struct, member) (sizeof(((struct *)0)->member))

#ifdef LINUX_KERNEL
/******************************************************************************
 * Linux Kernel
 ******************************************************************************/

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>

/* POSIX Support */
unsigned long getauxval(unsigned long type);

static inline int mlock(const void *ptr, size_t len)
{
	(void)ptr;
	(void)len;
	return 0;
}

extern const int errno;

static inline pid_t getpid(void)
{
	return 0;
}

#define restrict

#define printf printk

#ifndef assert
#define assert(x) WARN_ON(!(x))
#endif

#define PRIu64 "lu"

#define LC_DEFINE_CONSTRUCTOR(_func) void _func(void)
#define LC_DEFINE_DESTRUCTOR(_func) void _func(void)

#define SYSV_ABI

typedef s64 time64_t;

static inline int lc_get_time(time64_t *time_since_epoch)
{
	if (!time_since_epoch)
		return -EINVAL;

	*time_since_epoch = (time64_t)(jiffies / HZ);

	return 0;
}

#define LC_FIPS_RODATA_SECTION

#elif (defined(LC_EFI_ENVIRONMENT))
/******************************************************************************
 * UEFI support
 ******************************************************************************/

/* POSIX Support */
#include <efi/efi.h>
#include <efi/efilib.h>

#include "errno_private.h"

#define LC_DEFINE_CONSTRUCTOR(_func)                                           \
	void __attribute__((constructor)) _func(void)
#define LC_DEFINE_DESTRUCTOR(_func) void __attribute__((destructor)) _func(void)

#if !defined __ILP32__
#define __WORDSIZE 64
#else
#define __WORDSIZE 32
#endif

typedef int pid_t;
typedef long time_t;
typedef long long time64_t;

#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif

#if __WORDSIZE == 64

typedef unsigned long uintptr_t;

#ifndef _SIZE_T
typedef unsigned long size_t;
#define _SIZE_T
#endif

#ifndef _SSIZE_T
typedef long ssize_t;
#define _SSIZE_T
#endif

#elif __WORDSIZE == 32

#ifndef _UINTPTR_T
typedef unsigned int uintptr_t;
#define _UINTPTR_T
#endif

#error
#ifndef _SIZE_T
typedef unsigned int size_t;
#define _SIZE_T
#endif

#ifndef _SSIZE_T
typedef int ssize_t;
#define _SSIZE_T
#endif

#endif

#include "lc_memcpy_secure.h"

void *memset(void *d, int c, unsigned long long n);

static inline int mlock(const void *ptr, size_t len)
{
	(void)ptr;
	(void)len;
	return 0;
}

static inline pid_t getpid(void)
{
	return 0;
}

static inline int snprintf(char *restrict str, size_t size,
			   const char *restrict format, ...)
{
	(void)format;
	if (size) {
		memset(str, 0, size);
		return (int)size - 1;
	}
	return 0;
}

static inline void *memcpy(void *d, const void *s, size_t n)
{
	return lc_memcpy_secure(d, n, s, n);
}

static inline size_t strlen(const char *str)
{
	size_t len = 0;

	while (*str != '\0') {
		str++;
		len++;
	}

	return len;
}

static inline int lc_get_time(time64_t *time_since_epoch)
{
	if (!time_since_epoch)
		return -EINVAL;

	*time_since_epoch = -1;

	return -EOPNOTSUPP;
}

#define SYSV_ABI __attribute__((sysv_abi))

/*
 * See https://gcc.gnu.org/onlinedocs/gcc/Statement-Attributes.html#Statement-Attributes
 */
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough                                                            \
	do {                                                                   \
	} while (0)
#endif

#ifndef assert
#define assert(x)                                                              \
	if (x) {                                                               \
		Exit(EFI_ABORTED, 0, NULL);                                    \
	}
#endif

#ifndef INT_MAX
#define INT_MAX 2147483647
#endif

#define stdout NULL

#define printf(...) Print(L##__VA_ARGS__)

#undef errno
#define errno errno_private
static const int errno_private = 0;

#define LC_FIPS_RODATA_SECTION

#elif (defined(__CYGWIN__) || defined(_WIN32))
/******************************************************************************
 * Windows
 ******************************************************************************/

#ifndef MB_LEN_MAX
#define MB_LEN_MAX 16
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)

#define LC_DEFINE_CONSTRUCTOR(_func)                                           \
	void __attribute__((constructor)) _func(void)
#define LC_DEFINE_DESTRUCTOR(_func) void __attribute__((destructor)) _func(void)

#else

#error "Constructor / destructor not defined for compiler"

#endif

/*
 * Replace GCC-specific alternative keywords
 * see https://gcc.gnu.org/onlinedocs/gcc/Alternate-Keywords.html
 */
#ifndef __GNUC__
#define __asm__ asm
#define __volatile__ volatile
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static inline int mlock(const void *ptr, size_t len)
{
	(void)ptr;
	(void)len;
	return 0;
}

#define SYSV_ABI __attribute__((sysv_abi))

/*
 * See https://gcc.gnu.org/onlinedocs/gcc/Statement-Attributes.html#Statement-Attributes
 */
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough                                                            \
	do {                                                                   \
	} while (0)
#endif

typedef int64_t time64_t;

static inline int lc_get_time(time64_t *time_since_epoch)
{
	struct timespec tp = { 0 };

	if (!time_since_epoch)
		return -EINVAL;

	if (clock_gettime(CLOCK_REALTIME, &tp) == 0) {
		*time_since_epoch = tp.tv_sec;
		return 0;
	}

	*time_since_epoch = (time64_t)-1;
	return -errno;
}

#define LC_FIPS_RODATA_SECTION

#else /* LINUX_KERNEL */
/******************************************************************************
 * POSIX
 ******************************************************************************/

#ifndef MB_LEN_MAX
#define MB_LEN_MAX 16
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)

#define LC_DEFINE_CONSTRUCTOR(_func)                                           \
	void __attribute__((constructor)) _func(void)
#define LC_DEFINE_DESTRUCTOR(_func) void __attribute__((destructor)) _func(void)

#else

#error "Constructor / destructor not defined for compiler"

#endif

/*
 * Replace GCC-specific alternative keywords
 * see https://gcc.gnu.org/onlinedocs/gcc/Alternate-Keywords.html
 */
#ifndef __GNUC__
#define __asm__ asm
#define __volatile__ volatile
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SYSV_ABI

/*
 * See https://gcc.gnu.org/onlinedocs/gcc/Statement-Attributes.html#Statement-Attributes
 */
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough                                                            \
	do {                                                                   \
	} while (0)
#endif

typedef int64_t time64_t;

static inline int lc_get_time(time64_t *time_since_epoch)
{
	struct timespec tp = { 0 };

	if (!time_since_epoch)
		return -EINVAL;

	if (clock_gettime(CLOCK_REALTIME, &tp) == 0) {
		*time_since_epoch = tp.tv_sec;
		return 0;
	}

	*time_since_epoch = (time64_t)-1;
	return -errno;
}

/*
 * FIPS 140 integrity check cannot check the .rodata section. Thus move all
 * relevant data to teh fips_rodata section.
 */
#if defined __ELF__
#define LC_FIPS_RODATA_SECTION_NAME_START __start_fips_rodata
#define LC_FIPS_RODATA_SECTION_NAME_STOP __stop_fips_rodata
#define LC_FIPS_RODATA_SECTION_NAME "fips_rodata"
#define LC_FIPS_RODATA_SECTION                                                 \
	__attribute__((section(LC_FIPS_RODATA_SECTION_NAME)))
#else
#define LC_FIPS_RODATA_SECTION
#endif

#endif /* LINUX_KERNEL */

/******************************************************************************
 * Generic Definitions after all includes are present
 ******************************************************************************/

#ifndef ENOPKG
#define ENOPKG 254 /* Package not installed */
#endif
#ifndef EKEYREJECTED
#define EKEYREJECTED 253 /* Key was rejected by service */
#endif
#ifndef ENOKEY
#define ENOKEY 252 /* Key not found */
#endif

#endif /* EXT_HEADERS_H */
