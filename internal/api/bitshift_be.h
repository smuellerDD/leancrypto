/*
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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

#ifndef BITSHIFT_BE_H
#define BITSHIFT_BE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Conversion of Big-Endian representations in byte streams  - the data
 * representation in the integer values is the host representation.
 */
static inline uint32_t ptr_to_be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8  | (uint32_t)p[3];
}

static inline uint64_t ptr_to_be64(const uint8_t *p)
{
	return (uint64_t)ptr_to_be32(p) << 32 | (uint64_t)ptr_to_be32(p + 4);
}

static inline void be32_to_ptr(uint8_t *p, const uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)(value);
}

static inline void be64_to_ptr(uint8_t *p, const uint64_t value)
{
	be32_to_ptr(p,     (uint32_t)(value >> 32));
	be32_to_ptr(p + 4, (uint32_t)(value));
}

#ifdef __cplusplus
}
#endif

#endif /* BITSHIFT_BE_H */
