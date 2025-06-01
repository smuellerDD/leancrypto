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
 * @file reed_solomon.h
 * @brief Header file of reed_solomon.c
 */

#ifndef REED_SOLOMON_AVX2_H
#define REED_SOLOMON_AVX2_H

#include "hqc_internal_avx2.h"
#include "hqc_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void reed_solomon_encode_avx2(uint64_t *cdw, const uint64_t *msg);
void reed_solomon_decode_avx2(uint64_t *msg, uint64_t *cdw,
			      struct reed_solomon_decode_ws *ws);

#ifdef __cplusplus
}
#endif

#endif /* REED_SOLOMON_AVX2_H */
