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
/*
 * This code is derived in parts from GCC (GPLv3) and the LLVM project (Apache
 * License v2.0).
 *
 * The only reason why this code is duplicated is the fact that the compiler
 * code cannot be included into kernel code code as is. Thus, the functions
 * used by leancrypto are extracted - I wished this would not have been
 * necessary.
 */

#ifndef EXT_X86_BMI2INTRIN_H
#define EXT_X86_BMI2INTRIN_H

/* Define the default attributes for the functions in this file. */
#ifdef __clang__
#define __DEFAULT_FN_ATTRS                                                     \
	__attribute__((__always_inline__, __nodebug__, __target__("bmi2")))

static __inline__ unsigned int __DEFAULT_FN_ATTRS _pext_u32(unsigned int __X,
							    unsigned int __Y)
{
	return __builtin_ia32_pext_si(__X, __Y);
}

#else

#ifndef __BMI2__
#pragma GCC push_options
#pragma GCC target("bmi2")
#define __DISABLE_BMI2__
#endif /* __BMI2__ */

extern __inline unsigned int
	__attribute__((__gnu_inline__, __always_inline__, __artificial__))
	_pext_u32(unsigned int __X, unsigned int __Y)
{
	return __builtin_ia32_pext_si(__X, __Y);
}
#endif

#undef __DEFAULT_FN_ATTRS

#endif /* EXT_X86_BMI2INTRIN_H */
