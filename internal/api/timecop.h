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
/*
 * This code is derived from
 * https://www.post-apocalyptic-crypto.org/timecop/#source-code
 *
 * The license is: this code is released into the public domain
 */

#ifndef TIMECOP_H
#define TIMECOP_H

#if defined __has_include
#if __has_include(<valgrind/memcheck.h>)
#define LC_HAS_TIMECOP
#endif
#endif

#if defined(LC_USE_TIMECOP) && !defined(LC_HAS_TIMECOP)
#error "Compilation with TIMECOP requested, but valgrind's memcheck.h missing."
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_USE_TIMECOP

/*
 * This code requires header files from valgrind. They can be installed with
 * packages like valgrind-client-headers.
 */
#include <valgrind/memcheck.h>


/**
 * Poisons a memory region of len bytes, starting at addr, indicating that
 * execution time must not depend on the content of this memory region.
 * Use this function to mark any memory regions containing secret data.
 */
#define poison(addr, len) VALGRIND_MAKE_MEM_UNDEFINED(addr, len)

/**
 * Use this function to indicate that the specified memory region does no longer
 * contain data that must not affect execution time.
 */
#define unpoison(addr, len) VALGRIND_MAKE_MEM_DEFINED(addr, len)

/**
 * Checks whether the memory region of len bytes, starting at addr,
 * contains any poisoned bits.
 * Returns 0 if the code is running natively, rather than within valgrind.
 * If valgrind is running, it returns the first address containing poisoned
 * data, or 0 if there is no poisoned data in the specified memory region.
 * You can use RUNNING_ON_VALGRIND from valgrind.h to check whether the code
 * is being executed within valgrind.
 */
#define is_poisoned(addr, len) VALGRIND_CHECK_MEM_IS_DEFINED(addr, len)

#else /* LC_USE_TIMECOP */

#define poison(addr, len)
#define unpoison(addr, len)
#define is_poisoned(addr, len)

#endif /* LC_USE_TIMECOP */

#ifdef __cplusplus
}
#endif

#endif /* TIMECOP_H */
