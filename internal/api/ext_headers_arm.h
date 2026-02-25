/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef EXT_HEADERS_ARM_H
#define EXT_HEADERS_ARM_H

#ifdef LINUX_KERNEL

#include <asm/neon.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
#include <asm/simd.h>

#define LC_NEON_ENABLE                                                         \
	scoped_ksimd()                                                         \
	{
#define LC_NEON_DISABLE }

#else

#define LC_NEON_ENABLE kernel_neon_begin()
#define LC_NEON_DISABLE kernel_neon_end()

#endif

#define UINT64_C U64_C

#else /* LINUX_KERNEL */

#define LC_NEON_ENABLE
#define LC_NEON_DISABLE

#if (defined(__APPLE__))
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#endif /* LINUX_KERNEL */

#endif /* EXT_HEADERS_ARM_H */
