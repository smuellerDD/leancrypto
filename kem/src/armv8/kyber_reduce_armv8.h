/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/psanal2018/kyber-arm64
 *
 * That code is released under MIT license.
 */

#ifndef KYBER_REDUCE_ARMV8_H
#define KYBER_REDUCE_ARMV8_H

#include "lc_kyber.h"

#ifdef __cplusplus
extern "C"
{
#endif

//#define MONT 2285 // 2^16 mod q
//#define QINV 62209 // q^-1 mod 2^16

void kyber_tomont_armv8(int16_t* a);

void kyber_barret_red_armv8(int16_t* a);

// Combination of add/sub and reduce
void kyber_sub_reduce_armv8(int16_t* r, const int16_t* a, const int16_t* b);
void kyber_add_reduce_armv8(int16_t* r, const int16_t* a, const int16_t* b);
void kyber_add_add_reduce_armv8(int16_t* r, const int16_t* a,
				const int16_t* b, const int16_t* c);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_REDUCE_ARMV8_H */
