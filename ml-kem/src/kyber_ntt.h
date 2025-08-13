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

#ifndef KYBER_NTT_H
#define KYBER_NTT_H

#include "ext_headers_internal.h"
#include "kyber_type.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const int16_t kyber_zetas[128];

/**
 * @brief ntt - Inplace number-theoretic transform (NTT) in Rq.
 *		input is in standard order, output is in bitreversed order
 *
 * @param [in,out] poly pointer to input/output vector of elements of Zq
 */
void kyber_ntt(int16_t poly[LC_KYBER_N]);

/**
 * @brief invntt_tomont - Inplace inverse number-theoretic transform in Rq and
 *			  multiplication by Montgomery factor 2^16.
 *			  Input is in bitreversed order, output is in standard
 *			  order
 *
 * @param poly pointer to input/output vector of elements of Zq
 */
void kyber_invntt(int16_t poly[LC_KYBER_N]);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_NTT_H */
