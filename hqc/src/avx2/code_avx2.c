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
 * @file code.c
 * @brief Implementation of concatenated code
 */

#include "code_avx2.h"
#include "reed_muller_avx2.h"
#include "reed_solomon_avx2.h"

/**
 *
 * @brief Encoding the message m to a code word em using the concatenated code
 *
 * First we encode the message using the Reed-Solomon code, then with the
 * duplicated Reed-Muller code we obtain a concatenated code word.
 *
 * @param[out] em Pointer to an array that is the tensor code word
 * @param[in] m Pointer to an array that is the message
 */
void code_encode_avx2(uint64_t *em, const uint64_t *m)
{
	uint64_t tmp[LC_HQC_VEC_N1_SIZE_64] = { 0 };

	reed_solomon_encode_avx2(tmp, m);
	reed_muller_encode_avx2(em, tmp);
}

/**
 * @brief Decoding the code word em to a message m using the concatenated code
 *
 * @param[out] m Pointer to an array that is the message
 * @param[in] em Pointer to an array that is the code word
 */
void code_decode_avx2(uint64_t *m, const uint64_t *em,
		      struct reed_decode_ws *ws)
{
	memset(&ws->u.reed_muller_decode_ws, 0,
	       sizeof(ws->u.reed_muller_decode_ws));
	reed_muller_decode_avx2(ws->code_decode_tmp, em,
				&ws->u.reed_muller_decode_ws);

	memset(&ws->u.reed_solomon_decode_ws, 0,
	       sizeof(ws->u.reed_solomon_decode_ws));
	reed_solomon_decode_avx2(m, ws->code_decode_tmp,
				 &ws->u.reed_solomon_decode_ws);
}
