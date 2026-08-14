/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <linux/timekeeping.h>
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
#define UINT64_C U64_C
#define UINT32_MAX U32_MAX

#ifndef assert
#define assert(x) WARN_ON(!(x))
#endif

#define PRIu64 "lu"

#define LC_DEFINE_CONSTRUCTOR(_func) void _func(void)
#define LC_DEFINE_DESTRUCTOR(_func) void _func(void)

#define SYSV_ABI

typedef s64 time64_t;

#define LC_FIPS_RODATA_SECTION

#elif (defined(LC_EFI_ENVIRONMENT))
/******************************************************************************
 * UEFI support
 ******************************************************************************/

/* POSIX Support */
#include <efi/efi.h>
#include <efi/efilib.h>

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

#ifndef memset
void *memset(void *d, int c, unsigned long long n);
#endif

#ifndef snprintf
#define lc_snprintf_compile
int snprintf(char *restrict str, size_t size, const char *restrict format, ...);
#endif

#ifndef memcpy
#define memcpy lc_memcpy
#define lc_memcpy_compile
void *lc_memcpy(void *d, const void *s, size_t n);
#endif

#ifndef strlen
#define lc_strlen_compile
size_t strlen(const char *str);
#endif

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

#ifndef UINT32_MAX
#define UINT32_MAX (4294967295U)
#endif

#ifndef ULONG_MAX
#define ULONG_MAX (__LONG_MAX__ * 2UL + 1UL)
#endif

#define stdout NULL

#define printf(...) Print(L##__VA_ARGS__)

#undef errno
#define errno errno_private
static const int errno_private = 0;

#define LC_FIPS_RODATA_SECTION

#define noinline __attribute__((__noinline__))

#elif (defined(__CYGWIN__) || defined(_WIN32))
/******************************************************************************
 * Windows
 ******************************************************************************/

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

#ifndef MB_LEN_MAX
#define MB_LEN_MAX 16
#endif

#ifdef __GNUC__

/* ....... MinGW ....... */

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)

#define LC_DEFINE_CONSTRUCTOR(_func)                                           \
	void __attribute__((constructor)) _func(void)
#define LC_DEFINE_DESTRUCTOR(_func) void __attribute__((destructor)) _func(void)

#include <memoryapi.h>
#include <unistd.h>

typedef int64_t time64_t;

#else /* __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7) */

#error "Constructor / destructor not defined for compiler"

#endif /* __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7) */

#elif defined(_MSC_VER)

/* ....... MSVC including optionally clang ....... */

#define LC_DEFINE_CONSTRUCTOR(_func)                                           \
	static void _func(void);                                               \
	__declspec(allocate(".CRT$XCU")) void (*_func##_ptr)(void) = _func;

#define LC_DEFINE_DESTRUCTOR(_func)                                            \
	static void _func(void);                                               \
	static void _func##_dtor(void)                                         \
	{                                                                      \
		atexit(_func);                                                 \
	}                                                                      \
	__declspec(allocate(".CRT$XCU")) void (*_func##_dtor##_ptr)(void) =    \
		_func##_dtor;

#include <io.h>
#include <windows.h>

typedef int64_t time64_t;
typedef int pid_t;

#ifndef _SSIZE_T
typedef long ssize_t;
#define _SSIZE_T
#endif

pid_t getpid(void);
#define strtok_r strtok_s
#define localtime_r(timep, result) localtime_s((result), (time_t)(timep))
#define write _write
#define read _read
#define close _close
#define open lc_open
int lc_open(const char *path, int flags, int mode);
#define fopen lc_fopen
FILE *fopen(const char *path, const char *mode);

#else /* __GNUC__ */

/* ....... Other unknown build environments ....... */

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

#ifdef __CYGWIN__
#include <sys/mman.h>
#else /* __CYGWIN__ */
int mlock(const void *ptr, size_t len);
int munlock(const void *ptr, size_t len);
#endif /* __CYGWIN__ */

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

#define LC_FIPS_RODATA_SECTION

#define noinline __attribute__((__noinline__))

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

#if defined(__linux__)
#include <sched.h>
#endif

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

/*
 * FIPS 140 integrity check cannot check the .rodata section. Thus move all
 * relevant data to teh fips_rodata section.
 */
#if (defined(__ELF__) && defined(LC_FIPS140_INTEGRITY_CHECKER))
#define LC_FIPS_RODATA_SECTION_NAME_START lc_fips_start_rodata
#define LC_FIPS_RODATA_SECTION_NAME_STOP lc_fips_end_rodata
#define LC_FIPS_RODATA_SECTION_NAME ".lc_fips_rodata"
#define LC_FIPS_RODATA_SECTION                                                 \
	__attribute__((section(LC_FIPS_RODATA_SECTION_NAME)))
#else
#define LC_FIPS_RODATA_SECTION
#endif

#define noinline __attribute__((__noinline__))

#endif /* LINUX_KERNEL */

/******************************************************************************
 * Generic Definitions after all includes are present
 ******************************************************************************/

#ifndef LC_EFI_ENVIRONMENT
#ifndef ENOPKG
#define ENOPKG 254 /* Package not installed */
#endif
#ifndef EKEYREJECTED
#define EKEYREJECTED 253 /* Key was rejected by service */
#endif
#ifndef ENOKEY
#define ENOKEY 252 /* Key not found */
#endif
#ifndef ENODATA
#define ENODATA 251 /* Data not provided */
#endif
#endif /* LC_EFI_ENVIRONMENT */

int lc_get_cpu(unsigned int *cpu);
int lc_get_time(time64_t *time_since_epoch, time64_t *n_sec);

#endif /* EXT_HEADERS_H */
