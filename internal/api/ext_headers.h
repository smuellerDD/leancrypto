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

#ifndef EXT_HEADERS_H
#define EXT_HEADERS_H

#ifdef LINUX_KERNEL

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

#define printf printk
#define assert(x) WARN_ON(!x)

#define LC_DEFINE_CONSTRUCTOR(_func) void _func(void)
#define LC_DEFINE_DESTRUCTOR(_func) void _func(void)

#else /* LINUX_KERNEL */

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

#endif /* LINUX_KERNEL */

#endif /* EXT_HEADERS_H */
