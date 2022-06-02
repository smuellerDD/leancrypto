/* Rotate left / right functions
 *
 * Copyright (C) 2015 - 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef ROTATE_H
#define ROTATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Rotate 16 bit unsigned integer X by N bits left/right
 */
static inline uint16_t rol16(uint16_t x, uint8_t n)
{
	return (uint16_t)( (x << (n&(16-1))) | (x >> ((16-n)&(16-1))) );
}

static inline uint16_t ror16(uint16_t x, uint8_t n)
{
	return (uint16_t)( (x >> (n&(16-1))) | (x << ((16-n)&(16-1))) );
}

/*
 * Rotate 16 bit unsigned integer X by N bits left/right
 */
static inline uint32_t rol32(uint32_t x, uint8_t n)
{
	return ( (x << (n&(32-1))) | (x >> ((32-n)&(32-1))) );
}

static inline uint32_t ror32(uint32_t x, uint8_t n)
{
	return ( (x >> (n&(32-1))) | (x << ((32-n)&(32-1))) );
}

#ifdef __cplusplus
}
#endif

#endif /* ROTATE_H */
