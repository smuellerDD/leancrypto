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
 * @file vector.h
 * @brief Header file for vector.c
 */

#ifndef VECTOR_H
#define VECTOR_H

#include "hqc_type.h"
#include "shake_prng.h"

#ifdef __cplusplus
extern "C" {
#endif

void vect_set_random_fixed_weight(struct lc_hash_ctx *shake256, uint64_t *v,
				  uint16_t weight);

void vect_set_random(struct lc_hash_ctx *shake256, uint64_t *v);

void vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, size_t size);

uint8_t vect_compare(const uint8_t *v1, const uint8_t *v2, size_t size);

void vect_resize(uint64_t *o, uint32_t size_o, const uint64_t *v,
		 uint32_t size_v);

#ifdef __cplusplus
}
#endif

#endif /* VECTOR_H */
