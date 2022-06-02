/* Conversion of a pointer value to an integer
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef BITSHIFT_H
#define BITSHIFT_H

#include "bitshift_le.h"
#include "bitshift_be.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__

static inline uint64_t ptr_to_64(const uint8_t *p)
{
	return ptr_to_be64(p);
}

static inline uint32_t ptr_to_32(const uint8_t *p)
{
	return ptr_to_be32(p);
}

#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

static inline uint64_t ptr_to_64(const uint8_t *p)
{
	return ptr_to_le64(p);
}

static inline uint32_t ptr_to_32(const uint8_t *p)
{
	return ptr_to_le32(p);
}

#else
# error "Endianess not defined"
#endif

#ifdef __cplusplus
}
#endif

#endif /* BITSHIFT_H */
