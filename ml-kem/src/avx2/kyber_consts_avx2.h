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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_CONSTS_AVX2_H
#define KYBER_CONSTS_AVX2_H

#ifdef __cplusplus
extern "C" {
#endif

#define _16XQ 0
#define _16XQINV 16
#define _16XV 32
#define _16XFLO 48
#define _16XFHI 64
#define _16XMONTSQLO 80
#define _16XMONTSQHI 96
#define _16XMASK 112
#define _REVIDXB 128
#define _REVIDXD 144
#define _ZETAS_EXP 160
#define _16XSHIFT 624

#ifndef __ASSEMBLER__
#include "alignment_x86.h"
typedef BUF_ALIGNED_INT16_M256I(640) kyber_qdata_t;
extern const kyber_qdata_t kyber_qdata;
#endif

#ifdef __cplusplus
}
#endif

#endif /* KYBER_CONSTS_AVX2_H */
