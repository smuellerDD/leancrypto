/* Conversion functions from LE to BE and vice versa
 *
 * Copyright (C) 2015 - 2024, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file
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

#ifndef CONV_BE_LE_H
#define CONV_BE_LE_H

#include "ext_headers.h"
#include "rotate.h"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(CONVERSION_TEST) && (defined(__gcc__) || defined(__clang__))
#define __HAVE_BUILTIN_BSWAP16__
#define __HAVE_BUILTIN_BSWAP32__
#define __HAVE_BUILTIN_BSWAP64__
#endif

/* Byte swap for 16-bit, 32-bit and 64-bit integers. */
#ifndef __HAVE_BUILTIN_BSWAP16__
static inline uint16_t _lc_bswap16(uint16_t x)
{
	return (uint16_t)((rol16(x, 8) & 0x00ff) | (ror16(x, 8) & 0xff00));
}
#define _lc_swap16(x) _lc_bswap16((uint16_t)(x))
#else
#define _lc_swap16(x) (uint16_t)__builtin_bswap16((uint16_t)(x))
#endif

#if !defined(__HAVE_BUILTIN_BSWAP32__) || !defined(__HAVE_BUILTIN_BSWAP64__)
static inline uint32_t _lc_bswap32(uint32_t x)
{
	return ((rol32(x, 8) & 0x00ff00ffL) | (ror32(x, 8) & 0xff00ff00L));
}
#define _lc_swap32(x) _lc_bswap32((uint32_t)(x))
#else
#define _lc_swap32(x) (uint32_t)__builtin_bswap32((uint32_t)(x))
#endif

#ifndef __HAVE_BUILTIN_BSWAP64__
static inline uint64_t _lc_bswap64(uint64_t x)
{
	return ((uint64_t)_lc_bswap32((uint32_t)x) << 32) |
	       (_lc_bswap32((uint32_t)(x >> 32)));
}
#define _lc_swap64(x) _lc_bswap64((uint64_t)(x))
#else
#define _lc_swap64(x) (uint64_t)__builtin_bswap64((uint64_t)(x))
#endif

/* Endian dependent byte swap operations.  */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

static inline uint16_t le_bswap16(uint16_t x)
{
	return _lc_swap16(x);
}

static inline uint16_t be_bswap16(uint16_t x)
{
	return x;
}

static inline uint32_t le_bswap32(uint32_t x)
{
	return _lc_swap32(x);
}

static inline uint32_t be_bswap32(uint32_t x)
{
	return x;
}

static inline uint64_t le_bswap64(uint64_t x)
{
	return _lc_swap64(x);
}

static inline uint64_t be_bswap64(uint64_t x)
{
	return x;
}

#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

static inline uint16_t le_bswap16(uint16_t x)
{
	return x;
}

static inline uint16_t be_bswap16(uint16_t x)
{
	return _lc_swap16(x);
}

static inline uint32_t le_bswap32(uint32_t x)
{
	return x;
}

static inline uint32_t be_bswap32(uint32_t x)
{
	return _lc_swap32(x);
}

static inline uint64_t le_bswap64(uint64_t x)
{
	return x;
}

static inline uint64_t be_bswap64(uint64_t x)
{
	return _lc_swap64(x);
}

#else
#error "Endianess not defined"
#endif

#ifdef __cplusplus
}
#endif

#endif /* CONV_BE_LE_H */
