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
 * https://github.com/PQClean/PQClean/
 *
 * The code is referenced as Public Domain
 */
/**
 * @file parsing.h
 * @brief Header file for parsing.c
 */

#ifndef PARSING_H
#define PARSING_H

#include "hqc_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void load8_arr(uint64_t *out64, size_t outlen, const uint8_t *in8,
	       size_t inlen);

void store8_arr(uint8_t *out8, size_t outlen, const uint64_t *in64,
		size_t inlen);

void hqc_secret_key_to_string(uint8_t *sk, const uint8_t *sk_seed,
			      const uint8_t *sigma, const uint8_t *pk);

void hqc_secret_key_from_string(uint64_t *y, uint8_t *sigma, uint8_t *pk,
				const uint8_t *sk,
				struct vect_set_random_fixed_weight_ws *ws);

void hqc_public_key_to_string(uint8_t *pk, const uint8_t *pk_seed,
			      const uint64_t *s);

void hqc_public_key_from_string(uint64_t *h, uint64_t *s, const uint8_t *pk,
				struct vect_set_random_ws *ws);

void hqc_ciphertext_to_string(uint8_t *ct, const uint64_t *u, const uint64_t *v,
			      const uint8_t *salt);

void hqc_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *salt,
				const uint8_t *ct);

#ifdef __cplusplus
}
#endif

#endif /* PARSING_H */
