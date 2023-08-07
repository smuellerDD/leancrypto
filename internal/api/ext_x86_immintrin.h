/*
 * Copyright (C) 2022, Stephan Mueller "ext_x2023_smueller@chronox.de"
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

#ifndef EXT_X86_IMMINTRIN_H
#define EXT_X86_IMMINTRIN_H

#if !(defined(_MSC_VER) || defined(__SCE__)) || defined(__SSE2__)
#include "ext_x86_emmintrin.h"
#endif

#if !(defined(_MSC_VER) || defined(__SCE__)) || defined(__SSE3__)
#include "ext_x86_pmmintrin.h"
#endif

#if !(defined(_MSC_VER) || defined(__SCE__)) || defined(__SSSE3__)
#include "ext_x86_tmmintrin.h"
#endif

#if !(defined(_MSC_VER) || defined(__SCE__)) ||                                \
	(defined(__SSE4_2__) || defined(__SSE4_1__))
#include "ext_x86_smmintrin.h"
#endif

#if !(defined(_MSC_VER) || defined(__SCE__)) || defined(__AVX__)
#include "ext_x86_avxintrin.h"
#endif

#if !(defined(_MSC_VER) || defined(__SCE__)) || defined(__AVX2__)
#include "ext_x86_avx2intrin.h"
#endif

#if !(defined(_MSC_VER) || defined(__SCE__)) || defined(__BMI2__)
#include "ext_x86_bmi2intrin.h"
#endif

#if !(defined(_MSC_VER) || defined(__SCE__)) || defined(__POPCNT__)
#include "ext_x86_popcntintrin.h"
#endif

#endif /* EXT_X86_IMMINTRIN_H */
