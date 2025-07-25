/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/PQClean/PQClean
 *
 * This file was originally licensed
 * under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.html)
 * at https://github.com/GMUCERG/PQC_NEON/blob/main/neon/kyber or
 * public domain at https://github.com/cothan/kyber/blob/master/neon
 *
 * We choose
 * CC0 1.0 Universal or the following MIT License for this file.
 *
 * MIT License
 *
 * Copyright (c) 2023 - 2025: Hanno Becker, Vincent Hwang, Matthias J. Kannwischer, Bo-Yin Yang, and Shang-Yi Yang
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "cpufeatures.h"
#include "ext_headers_arm.h"
#include "shake_2x_armv8.h"
#include "visibility.h"

// Define NEON operation
// c = load(ptr)
#define vload(ptr) vld1q_u64(ptr);
// ptr <= c;
#define vstore(ptr, c) vst1q_u64(ptr, c);
// c = a ^ b
#define vxor(c, a, b) c = veorq_u64(a, b);
// Rotate by n bit ((a << offset) ^ (a >> (64-offset)))
#define vROL(out, a, offset)                                                   \
	(out) = vshlq_n_u64(a, offset);                                        \
	(out) = vsriq_n_u64(out, a, 64 - (offset));
// Xor chain: out = a ^ b ^ c ^ d ^ e
#define vXOR4(out, a, b, c, d, e)                                              \
	(out) = veorq_u64(a, b);                                               \
	(out) = veorq_u64(out, c);                                             \
	(out) = veorq_u64(out, d);                                             \
	(out) = veorq_u64(out, e);
// Not And c = ~a & b
// #define vbic(c, a, b) c = vbicq_u64(b, a);
// Xor Not And: out = a ^ ( (~b) & c)
#define vXNA(out, a, b, c)                                                     \
	(out) = vbicq_u64(c, b);                                               \
	(out) = veorq_u64(out, a);
// Rotate by 1 bit, then XOR: a ^ ROL(b): SHA1 instruction, not support
#define vrxor(c, a, b) c = vrax1q_u64(a, b);
// End Define

/* Keccak round constants */
const uint64_t neon_KeccakF_RoundConstants[NROUNDS] = {
	(uint64_t)0x0000000000000001ULL, (uint64_t)0x0000000000008082ULL,
	(uint64_t)0x800000000000808aULL, (uint64_t)0x8000000080008000ULL,
	(uint64_t)0x000000000000808bULL, (uint64_t)0x0000000080000001ULL,
	(uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008009ULL,
	(uint64_t)0x000000000000008aULL, (uint64_t)0x0000000000000088ULL,
	(uint64_t)0x0000000080008009ULL, (uint64_t)0x000000008000000aULL,
	(uint64_t)0x000000008000808bULL, (uint64_t)0x800000000000008bULL,
	(uint64_t)0x8000000000008089ULL, (uint64_t)0x8000000000008003ULL,
	(uint64_t)0x8000000000008002ULL, (uint64_t)0x8000000000000080ULL,
	(uint64_t)0x000000000000800aULL, (uint64_t)0x800000008000000aULL,
	(uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008080ULL,
	(uint64_t)0x0000000080000001ULL, (uint64_t)0x8000000080008008ULL
};

void KeccakF1600_StatePermutex2(v128 state[25])
{
	enum lc_cpu_features feat = lc_cpu_feature_available();

	if (feat & LC_CPU_FEATURE_ARM_SHA3) {
		keccak_f1600x2_armce((uint64_t *)state,
				     neon_KeccakF_RoundConstants);
		return;
	}

	v128 Aba, Abe, Abi, Abo, Abu;
	v128 Aga, Age, Agi, Ago, Agu;
	v128 Aka, Ake, Aki, Ako, Aku;
	v128 Ama, Ame, Ami, Amo, Amu;
	v128 Asa, Ase, Asi, Aso, Asu;
	v128 BCa, BCe, BCi, BCo, BCu; // tmp
	v128 Da, De, Di, Do, Du; // D
	v128 Eba, Ebe, Ebi, Ebo, Ebu;
	v128 Ega, Ege, Egi, Ego, Egu;
	v128 Eka, Eke, Eki, Eko, Eku;
	v128 Ema, Eme, Emi, Emo, Emu;
	v128 Esa, Ese, Esi, Eso, Esu;

	//copyFromState(A, state)
	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	for (int round = 0; round < NROUNDS; round += 2) {
		//    prepareTheta
		vXOR4(BCa, Aba, Aga, Aka, Ama, Asa);
		vXOR4(BCe, Abe, Age, Ake, Ame, Ase);
		vXOR4(BCi, Abi, Agi, Aki, Ami, Asi);
		vXOR4(BCo, Abo, Ago, Ako, Amo, Aso);
		vXOR4(BCu, Abu, Agu, Aku, Amu, Asu);

		//thetaRhoPiChiIotaPrepareTheta(round  , A, E)
		vROL(Da, BCe, 1);
		vxor(Da, BCu, Da);
		vROL(De, BCi, 1);
		vxor(De, BCa, De);
		vROL(Di, BCo, 1);
		vxor(Di, BCe, Di);
		vROL(Do, BCu, 1);
		vxor(Do, BCi, Do);
		vROL(Du, BCa, 1);
		vxor(Du, BCo, Du);

		vxor(Aba, Aba, Da);
		vxor(Age, Age, De);
		vROL(BCe, Age, 44);
		vxor(Aki, Aki, Di);
		vROL(BCi, Aki, 43);
		vxor(Amo, Amo, Do);
		vROL(BCo, Amo, 21);
		vxor(Asu, Asu, Du);
		vROL(BCu, Asu, 14);
		vXNA(Eba, Aba, BCe, BCi);
		vxor(Eba, Eba, vdupq_n_u64(neon_KeccakF_RoundConstants[round]));
		vXNA(Ebe, BCe, BCi, BCo);
		vXNA(Ebi, BCi, BCo, BCu);
		vXNA(Ebo, BCo, BCu, Aba);
		vXNA(Ebu, BCu, Aba, BCe);

		vxor(Abo, Abo, Do);
		vROL(BCa, Abo, 28);
		vxor(Agu, Agu, Du);
		vROL(BCe, Agu, 20);
		vxor(Aka, Aka, Da);
		vROL(BCi, Aka, 3);
		vxor(Ame, Ame, De);
		vROL(BCo, Ame, 45);
		vxor(Asi, Asi, Di);
		vROL(BCu, Asi, 61);
		vXNA(Ega, BCa, BCe, BCi);
		vXNA(Ege, BCe, BCi, BCo);
		vXNA(Egi, BCi, BCo, BCu);
		vXNA(Ego, BCo, BCu, BCa);
		vXNA(Egu, BCu, BCa, BCe);

		vxor(Abe, Abe, De);
		vROL(BCa, Abe, 1);
		vxor(Agi, Agi, Di);
		vROL(BCe, Agi, 6);
		vxor(Ako, Ako, Do);
		vROL(BCi, Ako, 25);
		vxor(Amu, Amu, Du);
		vROL(BCo, Amu, 8);
		vxor(Asa, Asa, Da);
		vROL(BCu, Asa, 18);
		vXNA(Eka, BCa, BCe, BCi);
		vXNA(Eke, BCe, BCi, BCo);
		vXNA(Eki, BCi, BCo, BCu);
		vXNA(Eko, BCo, BCu, BCa);
		vXNA(Eku, BCu, BCa, BCe);

		vxor(Abu, Abu, Du);
		vROL(BCa, Abu, 27);
		vxor(Aga, Aga, Da);
		vROL(BCe, Aga, 36);
		vxor(Ake, Ake, De);
		vROL(BCi, Ake, 10);
		vxor(Ami, Ami, Di);
		vROL(BCo, Ami, 15);
		vxor(Aso, Aso, Do);
		vROL(BCu, Aso, 56);
		vXNA(Ema, BCa, BCe, BCi);
		vXNA(Eme, BCe, BCi, BCo);
		vXNA(Emi, BCi, BCo, BCu);
		vXNA(Emo, BCo, BCu, BCa);
		vXNA(Emu, BCu, BCa, BCe);

		vxor(Abi, Abi, Di);
		vROL(BCa, Abi, 62);
		vxor(Ago, Ago, Do);
		vROL(BCe, Ago, 55);
		vxor(Aku, Aku, Du);
		vROL(BCi, Aku, 39);
		vxor(Ama, Ama, Da);
		vROL(BCo, Ama, 41);
		vxor(Ase, Ase, De);
		vROL(BCu, Ase, 2);
		vXNA(Esa, BCa, BCe, BCi);
		vXNA(Ese, BCe, BCi, BCo);
		vXNA(Esi, BCi, BCo, BCu);
		vXNA(Eso, BCo, BCu, BCa);
		vXNA(Esu, BCu, BCa, BCe);

		// Next Round

		//    prepareTheta
		vXOR4(BCa, Eba, Ega, Eka, Ema, Esa);
		vXOR4(BCe, Ebe, Ege, Eke, Eme, Ese);
		vXOR4(BCi, Ebi, Egi, Eki, Emi, Esi);
		vXOR4(BCo, Ebo, Ego, Eko, Emo, Eso);
		vXOR4(BCu, Ebu, Egu, Eku, Emu, Esu);

		//thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
		vROL(Da, BCe, 1);
		vxor(Da, BCu, Da);
		vROL(De, BCi, 1);
		vxor(De, BCa, De);
		vROL(Di, BCo, 1);
		vxor(Di, BCe, Di);
		vROL(Do, BCu, 1);
		vxor(Do, BCi, Do);
		vROL(Du, BCa, 1);
		vxor(Du, BCo, Du);

		vxor(Eba, Eba, Da);
		vxor(Ege, Ege, De);
		vROL(BCe, Ege, 44);
		vxor(Eki, Eki, Di);
		vROL(BCi, Eki, 43);
		vxor(Emo, Emo, Do);
		vROL(BCo, Emo, 21);
		vxor(Esu, Esu, Du);
		vROL(BCu, Esu, 14);
		vXNA(Aba, Eba, BCe, BCi);
		vxor(Aba, Aba,
		     vdupq_n_u64(neon_KeccakF_RoundConstants[round + 1]));
		vXNA(Abe, BCe, BCi, BCo);
		vXNA(Abi, BCi, BCo, BCu);
		vXNA(Abo, BCo, BCu, Eba);
		vXNA(Abu, BCu, Eba, BCe);

		vxor(Ebo, Ebo, Do);
		vROL(BCa, Ebo, 28);
		vxor(Egu, Egu, Du);
		vROL(BCe, Egu, 20);
		vxor(Eka, Eka, Da);
		vROL(BCi, Eka, 3);
		vxor(Eme, Eme, De);
		vROL(BCo, Eme, 45);
		vxor(Esi, Esi, Di);
		vROL(BCu, Esi, 61);
		vXNA(Aga, BCa, BCe, BCi);
		vXNA(Age, BCe, BCi, BCo);
		vXNA(Agi, BCi, BCo, BCu);
		vXNA(Ago, BCo, BCu, BCa);
		vXNA(Agu, BCu, BCa, BCe);

		vxor(Ebe, Ebe, De);
		vROL(BCa, Ebe, 1);
		vxor(Egi, Egi, Di);
		vROL(BCe, Egi, 6);
		vxor(Eko, Eko, Do);
		vROL(BCi, Eko, 25);
		vxor(Emu, Emu, Du);
		vROL(BCo, Emu, 8);
		vxor(Esa, Esa, Da);
		vROL(BCu, Esa, 18);
		vXNA(Aka, BCa, BCe, BCi);
		vXNA(Ake, BCe, BCi, BCo);
		vXNA(Aki, BCi, BCo, BCu);
		vXNA(Ako, BCo, BCu, BCa);
		vXNA(Aku, BCu, BCa, BCe);

		vxor(Ebu, Ebu, Du);
		vROL(BCa, Ebu, 27);
		vxor(Ega, Ega, Da);
		vROL(BCe, Ega, 36);
		vxor(Eke, Eke, De);
		vROL(BCi, Eke, 10);
		vxor(Emi, Emi, Di);
		vROL(BCo, Emi, 15);
		vxor(Eso, Eso, Do);
		vROL(BCu, Eso, 56);
		vXNA(Ama, BCa, BCe, BCi);
		vXNA(Ame, BCe, BCi, BCo);
		vXNA(Ami, BCi, BCo, BCu);
		vXNA(Amo, BCo, BCu, BCa);
		vXNA(Amu, BCu, BCa, BCe);

		vxor(Ebi, Ebi, Di);
		vROL(BCa, Ebi, 62);
		vxor(Ego, Ego, Do);
		vROL(BCe, Ego, 55);
		vxor(Eku, Eku, Du);
		vROL(BCi, Eku, 39);
		vxor(Ema, Ema, Da);
		vROL(BCo, Ema, 41);
		vxor(Ese, Ese, De);
		vROL(BCu, Ese, 2);
		vXNA(Asa, BCa, BCe, BCi);
		vXNA(Ase, BCe, BCi, BCo);
		vXNA(Asi, BCi, BCo, BCu);
		vXNA(Aso, BCo, BCu, BCa);
		vXNA(Asu, BCu, BCa, BCe);
	}

	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

/*************************************************
* Name:        keccakx2_absorb
*
* Description: Absorb step of Keccak;
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*              - const uint8_t *m: pointer to input to be absorbed into s
*              - size_t mlen: length of input in bytes
*              - uint8_t p: domain-separation byte for different
*                           Keccak-derived functions
**************************************************/
static void keccakx2_absorb(v128 s[25], unsigned int r, const uint8_t *in0,
			    const uint8_t *in1, size_t inlen, uint8_t p)
{
	size_t i, pos = 0;

	// Declare SIMD registers
	v128 tmp, mask;
	uint64x1_t a, b;
	uint64x2_t a1, b1, atmp1, btmp1;
	uint64x2x2_t a2, b2, atmp2, btmp2;
	// End

	for (i = 0; i < 25; ++i) {
		s[i] = vdupq_n_u64(0);
	}

	// Load in0[i] to register, then in1[i] to register, exchange them
	while (inlen >= r) {
		for (i = 0; i < r / 8 - 1; i += 4) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			a2 = vld1q_u64_x2((uint64_t *)&in0[pos]);
			b2 = vld1q_u64_x2((uint64_t *)&in1[pos]);
#pragma GCC diagnostic pop
			// BD = zip1(AB and CD)
			atmp2.val[0] = vzip1q_u64(a2.val[0], b2.val[0]);
			atmp2.val[1] = vzip1q_u64(a2.val[1], b2.val[1]);
			// AC = zip2(AB and CD)
			btmp2.val[0] = vzip2q_u64(a2.val[0], b2.val[0]);
			btmp2.val[1] = vzip2q_u64(a2.val[1], b2.val[1]);

			vxor(s[i + 0], s[i + 0], atmp2.val[0]);
			vxor(s[i + 1], s[i + 1], btmp2.val[0]);
			vxor(s[i + 2], s[i + 2], atmp2.val[1]);
			vxor(s[i + 3], s[i + 3], btmp2.val[1]);

			pos += 8 * 2 * 2;
		}
		// Last iteration
		i = r / 8 - 1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		a = vld1_u64((uint64_t *)&in0[pos]);
		b = vld1_u64((uint64_t *)&in1[pos]);
#pragma GCC diagnostic pop
		tmp = vcombine_u64(a, b);
		vxor(s[i], s[i], tmp);
		pos += 8;

		KeccakF1600_StatePermutex2(s);
		inlen -= r;
	}

	i = 0;
	while (inlen >= 16) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		a1 = vld1q_u64((uint64_t *)&in0[pos]);
		b1 = vld1q_u64((uint64_t *)&in1[pos]);
#pragma GCC diagnostic pop
		// BD = zip1(AB and CD)
		atmp1 = vzip1q_u64(a1, b1);
		// AC = zip2(AB and CD)
		btmp1 = vzip2q_u64(a1, b1);

		vxor(s[i + 0], s[i + 0], atmp1);
		vxor(s[i + 1], s[i + 1], btmp1);

		i += 2;
		pos += 8 * 2;
		inlen -= 8 * 2;
	}

	if (inlen >= 8) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		a = vld1_u64((uint64_t *)&in0[pos]);
		b = vld1_u64((uint64_t *)&in1[pos]);
#pragma GCC diagnostic pop
		tmp = vcombine_u64(a, b);
		vxor(s[i], s[i], tmp);

		i++;
		pos += 8;
		inlen -= 8;
	}

	if (inlen) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		a = vld1_u64((uint64_t *)&in0[pos]);
		b = vld1_u64((uint64_t *)&in1[pos]);
#pragma GCC diagnostic pop
		tmp = vcombine_u64(a, b);
		mask = vdupq_n_u64((1ULL << (8 * inlen)) - 1);
		tmp = vandq_u64(tmp, mask);
		vxor(s[i], s[i], tmp);
	}

	tmp = vdupq_n_u64((uint64_t)p << (8 * inlen));
	vxor(s[i], s[i], tmp);

	mask = vdupq_n_u64(1ULL << 63);
	vxor(s[r / 8 - 1], s[r / 8 - 1], mask);
}

/**
 * @brief keccak_squeezeblocks - Keccak squeeze operation
 *
 * queeze step of Keccak. Squeezes full blocks of r bytes each. Modifies the
 * state. Can be called multiple times to keep squeezing, i.e., is incremental.
 *
 * @param [out] out0 pointer to output blocks
 * @param [in] nblocks number of blocks to be squeezed (written to h)
 * @param [in] r rate in bytes (e.g., 168 for SHAKE128)
 * @param [in] s pointer to input/output Keccak state
 */
static void keccakx2_squeezeblocks(uint8_t *out0, uint8_t *out1, size_t nblocks,
				   unsigned int r, v128 s[25])
{
	unsigned int i;

	uint64x1_t a, b;
	uint64x2x2_t a2, b2;

	while (nblocks > 0) {
		KeccakF1600_StatePermutex2(s);

		for (i = 0; i < r / 8 - 1; i += 4) {
			a2.val[0] = vuzp1q_u64(s[i], s[i + 1]);
			b2.val[0] = vuzp2q_u64(s[i], s[i + 1]);
			a2.val[1] = vuzp1q_u64(s[i + 2], s[i + 3]);
			b2.val[1] = vuzp2q_u64(s[i + 2], s[i + 3]);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			vst1q_u64_x2((uint64_t *)out0, a2);
			vst1q_u64_x2((uint64_t *)out1, b2);
#pragma GCC diagnostic pop

			out0 += 32;
			out1 += 32;
		}

		i = r / 8 - 1;
		// Last iteration
		a = vget_low_u64(s[i]);
		b = vget_high_u64(s[i]);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		vst1_u64((uint64_t *)out0, a);
		vst1_u64((uint64_t *)out1, b);
#pragma GCC diagnostic pop

		out0 += 8;
		out1 += 8;

		--nblocks;
	}
}

/**
 * @brief shake128x2_armv8_absorb - Keccak 128 2 lane absorb
 *
 * Absorb step of the SHAKE128 XOF. non-incremental, starts by zeroeing the
 * state.
 *
 * @param [in] state pointer to (uninitialized) output Keccak state
 * @param [in] in0 pointer to input to be absorbed into the state
 * @param [in] in1 pointer to input to be absorbed into the state
 * @param [in] inlen length of input in bytes
 */
void shake128x2_armv8_absorb(keccakx2_state *state, const uint8_t *in0,
			     const uint8_t *in1, size_t inlen)
{
	LC_NEON_ENABLE;
	keccakx2_absorb(state->s, SHAKE128_RATE, in0, in1, inlen, 0x1F);
	LC_NEON_DISABLE;
}

/**
 * @brief shake128x2_armv8_squeezeblocks - Keccak 128 2 lane squeeze
 *
 * Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes
 * each. Modifies the state. Can be called multiple times to keep squeezing,
 * i.e., is incremental.
 *
 * @param [out] out0 pointer to output blocks
 * @param [in] nblocks number of blocks to be squeezed (written to output)
 * @param [in] state pointer to input/output Keccak state
 */
void shake128x2_armv8_squeezeblocks(uint8_t *out0, uint8_t *out1,
				    size_t nblocks, keccakx2_state *state)
{
	LC_NEON_ENABLE;
	keccakx2_squeezeblocks(out0, out1, nblocks, SHAKE128_RATE, state->s);
	LC_NEON_DISABLE;
}

/**
 * @brief shake256x2_armv8_absorb - Keccak 256 2 lane absorb
 *
 * Absorb step of the SHAKE128 XOF. non-incremental, starts by zeroeing the
 * state.
 *
 * @param [in] state pointer to (uninitialized) output Keccak state
 * @param [in] in0 pointer to input to be absorbed into the state
 * @param [in] in1 pointer to input to be absorbed into the state
 * @param [in] inlen length of input in bytes
 */
void shake256x2_armv8_absorb(keccakx2_state *state, const uint8_t *in0,
			     const uint8_t *in1, size_t inlen)
{
	LC_NEON_ENABLE;
	keccakx2_absorb(state->s, SHAKE256_RATE, in0, in1, inlen, 0x1F);
	LC_NEON_DISABLE;
}

/**
 * @brief shake256_armv8_squeezeblocks- Keccak 256 2 lane squeeze
 *
 * Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes
 * each. Modifies the state. Can be called multiple times to keep squeezing,
 * i.e., is incremental.
 *
 * @param [out] out0 pointer to output blocks
 * @param [in] nblocks number of blocks to be squeezed (written to output)
 * @param [in] state pointer to input/output Keccak state
 */
void shake256x2_armv8_squeezeblocks(uint8_t *out0, uint8_t *out1,
				    size_t nblocks, keccakx2_state *state)
{
	LC_NEON_ENABLE;
	keccakx2_squeezeblocks(out0, out1, nblocks, SHAKE256_RATE, state->s);
	LC_NEON_DISABLE;
}

/**
 * @brief shake128x2_armv8 - SHAKE128 2 lane
 *
 * SHAKE128 XOF with non-incremental API
 *
 * @param [out] out pointer to output
 * @param [in] outlen requested output length in bytes
 * @param [in] in0 pointer to input
 * @param [in] in1 pointer to input
 * @param [in] inlen length of input in bytes
 */
LC_INTERFACE_FUNCTION(void, shake128x2_armv8, uint8_t *out0, uint8_t *out1,
		      size_t outlen, const uint8_t *in0, const uint8_t *in1,
		      size_t inlen)
{
	unsigned int i;
	size_t nblocks = outlen / SHAKE128_RATE;
	uint8_t t[2][SHAKE128_RATE];
	keccakx2_state state;

	shake128x2_armv8_absorb(&state, in0, in1, inlen);
	shake128x2_armv8_squeezeblocks(out0, out1, nblocks, &state);

	out0 += nblocks * SHAKE128_RATE;
	out1 += nblocks * SHAKE128_RATE;
	outlen -= nblocks * SHAKE128_RATE;

	if (outlen) {
		shake128x2_armv8_squeezeblocks(t[0], t[1], 1, &state);
		for (i = 0; i < outlen; ++i) {
			out0[i] = t[0][i];
			out1[i] = t[1][i];
		}
	}
}

/**
 * @brief shake256x2_armv8 - SHAKE256 2 lane
 *
 * SHAKE256 XOF with non-incremental API
 *
 * @param [out] out pointer to output
 * @param [in] outlen requested output length in bytes
 * @param [in] in0 pointer to input
 * @param [in] in1 pointer to input
 * @param [in] inlen length of input in bytes
 */
LC_INTERFACE_FUNCTION(void, shake256x2_armv8, uint8_t *out0, uint8_t *out1,
		      size_t outlen, const uint8_t *in0, const uint8_t *in1,
		      size_t inlen)
{
	unsigned int i;
	size_t nblocks = outlen / SHAKE256_RATE;
	uint8_t t[2][SHAKE256_RATE];
	keccakx2_state state;

	shake256x2_armv8_absorb(&state, in0, in1, inlen);
	shake256x2_armv8_squeezeblocks(out0, out1, nblocks, &state);

	out0 += nblocks * SHAKE256_RATE;
	out1 += nblocks * SHAKE256_RATE;
	outlen -= nblocks * SHAKE256_RATE;

	if (outlen) {
		shake256x2_armv8_squeezeblocks(t[0], t[1], 1, &state);
		for (i = 0; i < outlen; ++i) {
			out0[i] = t[0][i];
			out1[i] = t[1][i];
		}
	}
}
