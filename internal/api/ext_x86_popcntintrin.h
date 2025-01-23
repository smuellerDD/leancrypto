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
/*
 * This code is derived in parts from GCC (GPLv3) and the LLVM project (Apache
 * License v2.0).
 *
 * The only reason why this code is duplicated is the fact that the compiler
 * code cannot be included into kernel code code as is. Thus, the functions
 * used by leancrypto are extracted - I wished this would not have been
 * necessary.
 */

#ifndef EXT_X86_POPCNTINTRIN_H
#define EXT_X86_POPCNTINTRIN_H

/* Define the default attributes for the functions in this file. */
#ifdef __clang__
#define __DEFAULT_FN_ATTRS                                                     \
	__attribute__((__always_inline__, __nodebug__, __target__("popcnt")))

#if defined(__cplusplus) && (__cplusplus >= 201103L)
#define __DEFAULT_FN_ATTRS_CONSTEXPR __DEFAULT_FN_ATTRS constexpr
#else
#define __DEFAULT_FN_ATTRS_CONSTEXPR __DEFAULT_FN_ATTRS
#endif

#else

#ifndef __POPCNT__
#pragma GCC push_options
#pragma GCC target("popcnt")
#define __DISABLE_POPCNT__
#endif /* __POPCNT__ */

#define __DEFAULT_FN_ATTRS                                                     \
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
#define __DEFAULT_FN_ATTRS_CONSTEXPR __DEFAULT_FN_ATTRS

#endif

static __inline__ int __DEFAULT_FN_ATTRS_CONSTEXPR
_mm_popcnt_u32(unsigned int __A)
{
	return __builtin_popcount(__A);
}

#undef __DEFAULT_FN_ATTRS
#undef __DEFAULT_FN_ATTRS_CONSTEXPR

#endif /* EXT_X86_POPCNTINTRIN_H */
