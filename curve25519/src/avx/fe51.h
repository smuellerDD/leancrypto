/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/jedisct1/libsodium.git
 *
 * That code is released under ISC License
 *
 * Copyright (c) 2013-2023 - 2024
 * Frank Denis <j at pureftpd dot org>
 */

#ifndef FE51_H
#define FE51_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
   This file is adapted from amd64-51/fe25519.h:
   'fe25519' is renamed as 'fe51';
   All the redundant functions are removed;
   New function fe51_nsquare is introduced.
*/

typedef struct {
	uint64_t v[5];
} fe51;

extern void curve25519_fe51_pack_avx(unsigned char *, const fe51 *);
extern void curve25519_fe51_mul_avx(fe51 *, const fe51 *, const fe51 *);
extern void curve25519_fe51_nsquare_avx(fe51 *, const fe51 *, int);
extern void curve25519_fe51_invert_avx(fe51 *, const fe51 *);

#ifdef __cplusplus
}
#endif

#endif /* FE51_H */
