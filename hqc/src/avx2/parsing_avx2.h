/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * https://pqc-hqc.org/
 *
 * The code is referenced as Public Domain
 */
/**
 * @file parsing.h
 * @brief Header file for parsing.c
 */

#ifndef PARSING_AVX2_H
#define PARSING_AVX2_H

#include "ext_headers_x86.h"
#include "hqc_type.h"
#include "hqc_internal_avx2.h"

#ifdef __cplusplus
extern "C" {
#endif

void hqc_secret_key_from_string_avx2(__m256i *y256, uint8_t *sigma, uint8_t *pk,
				     const uint8_t *sk,
				     struct vect_set_random_fixed_weight_ws *ws);

#ifdef __cplusplus
}
#endif

#endif /* PARSING_AVX2_H */
