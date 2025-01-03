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
	(void)time_since_epoch;
	return -EOPNOTSUPP;
}

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

#define _POSIX_C_SOURCE 200112L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
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
	if (!time_since_epoch)
		return -EINVAL;

	*time_since_epoch = time(NULL);

	if (*time_since_epoch == (time_t)-1)
		return -errno;

	return 0;
}

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
	if (!time_since_epoch)
		return -EINVAL;

	*time_since_epoch = time(NULL);

	if (*time_since_epoch == (time_t)-1)
		return -errno;

	return 0;
}

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
