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
 *
 * This code is derived from the file
 * https: *github.com/AsmOptC-RiscV/Assembly-Optimized-C-RiscV/Keccak/Permutation/keccakf1600_asm.S
 * which is subject to the following license:
 *
 * MIT License
 *
 * Copyright (c) 2020 Assembly-Optimized-C-RiscV
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "keccakf1600.h"

#define Aba0 0
#define Aba1 1
#define Abe0 2
#define Abe1 3
#define Abi0 4
#define Abi1 5
#define Abo0 6
#define Abo1 7
#define Abu0 8
#define Abu1 9
#define Aga0 10
#define Aga1 11
#define Age0 12
#define Age1 13
#define Agi0 14
#define Agi1 15
#define Ago0 16
#define Ago1 17
#define Agu0 18
#define Agu1 19
#define Aka0 20
#define Aka1 21
#define Ake0 22
#define Ake1 23
#define Aki0 24
#define Aki1 25
#define Ako0 26
#define Ako1 27
#define Aku0 28
#define Aku1 29
#define Ama0 30
#define Ama1 31
#define Ame0 32
#define Ame1 33
#define Ami0 34
#define Ami1 35
#define Amo0 36
#define Amo1 37
#define Amu0 38
#define Amu1 39
#define Asa0 40
#define Asa1 41
#define Ase0 42
#define Ase1 43
#define Asi0 44
#define Asi1 45
#define Aso0 46
#define Aso1 47
#define Asu0 48
#define Asu1 49

uint32_t keccakf1600_rc[] = {
	0x00000001, 0x00000000, 0x00000000, 0x00000089, 0x00000000, 0x8000008b,
	0x00000000, 0x80008080, 0x00000001, 0x0000008b, 0x00000001, 0x00008000,
	0x00000001, 0x80008088, 0x00000001, 0x80000082, 0x00000000, 0x0000000b,
	0x00000000, 0x0000000a, 0x00000001, 0x00008082, 0x00000000, 0x00008003,
	0x00000001, 0x0000808b, 0x00000001, 0x8000000b, 0x00000001, 0x8000008a,
	0x00000001, 0x80000081, 0x00000000, 0x80000081, 0x00000000, 0x80000008,
	0x00000000, 0x00000083, 0x00000000, 0x80008003, 0x00000001, 0x80008088,
	0x00000000, 0x80000088, 0x00000001, 0x00008000, 0x00000000, 0x80008082
};

inline static void __attribute__((always_inline))
xor5(uint32_t *dst, const int b, const int g, const int k, const int m,
     const int s, uint32_t *lanes, uint32_t *tmp)
{
	*dst = lanes[b];
	*tmp = *dst ^ lanes[g];
	*dst = *tmp;
	*tmp = *dst ^ lanes[k];
	*dst = *tmp;
	*tmp = *dst ^ lanes[m];
	*dst = *tmp;
	*tmp = *dst ^ lanes[s];
	*dst = *tmp;
}

inline static void __attribute__((always_inline))
ror(uint32_t *dst, const int dist, uint32_t *tmp)
{
	*tmp = *dst >> dist;
	*dst = *dst << (32 - dist);
	*dst = *dst ^ *tmp;
}

inline static void __attribute__((always_inline))
xorrol(uint32_t *dst, const uint32_t *aa, const uint32_t *bb)
{
	*dst = (*bb << 1) ^ (*bb >> 31) ^ *aa;
}

inline static void __attribute__((always_inline))
xorand(const int dst, const uint32_t *aa, const uint32_t *bb,
       const uint32_t *cc, uint32_t *lanes, uint32_t *tmp)
{
	*tmp = *bb & *cc;
	*tmp = *tmp ^ *aa;
	lanes[dst] = *tmp;
}

inline static void __attribute__((always_inline))
xornotand(const int dst, const uint32_t *aa, const uint32_t *bb,
	  const uint32_t *cc, uint32_t *lanes, uint32_t *tmp)
{
	*tmp = ~*bb;
	*tmp = *tmp & *cc;
	*tmp = *tmp ^ *aa;
	lanes[dst] = *tmp;
}

inline static void __attribute__((always_inline))
notxorand(const int dst, const uint32_t *aa, const uint32_t *bb,
	  const uint32_t *cc, uint32_t *lanes, uint32_t *tmp0, uint32_t *tmp1)
{
	*tmp0 = ~*aa;
	*tmp1 = *bb & *cc;
	*tmp0 = *tmp0 ^ *tmp1;
	lanes[dst] = *tmp0;
}

inline static void __attribute__((always_inline))
xoror(const int dst, const uint32_t *aa, const uint32_t *bb, const uint32_t *cc,
      uint32_t *lanes, uint32_t *tmp)
{
	*tmp = *bb | *cc;
	*tmp = *tmp ^ *aa;
	lanes[dst] = *tmp;
}

inline static void __attribute__((always_inline))
xornotor(const int dst, const uint32_t *aa, const uint32_t *bb,
	 const uint32_t *cc, uint32_t *lanes, uint32_t *tmp)
{
	*tmp = ~*bb;
	*tmp = *tmp | *cc;
	*tmp = *tmp ^ *aa;
	lanes[dst] = *tmp;
}

inline static void __attribute__((always_inline))
notxoror(const int dst, const uint32_t *aa, const uint32_t *bb,
	 const uint32_t *cc, uint32_t *lanes, uint32_t *tmp0, uint32_t *tmp1)
{
	*tmp0 = ~*aa;
	*tmp1 = *bb | *cc;
	*tmp0 = *tmp0 ^ *tmp1;
	lanes[dst] = *tmp0;
}

inline static void __attribute__((always_inline))
thetarhopifinal(const int aA1, const uint32_t *aDax, const int aA2,
		const uint32_t *aDex, const int rot2, const int aA3,
		const uint32_t *aDix, const int rot3, const int aA4,
		const uint32_t *aDox, const int rot4, const int aA5,
		const uint32_t *aDux, const int rot5, uint32_t *lanes,
		uint32_t *a2, uint32_t *a3, uint32_t *a4, uint32_t *a5,
		uint32_t *a6, uint32_t *tmp)
{
	*a2 = lanes[aA1] ^ *aDax;
	*a3 = lanes[aA2] ^ *aDex;
	*a4 = lanes[aA3] ^ *aDix;
	*a5 = lanes[aA4] ^ *aDox;
	*a6 = lanes[aA5] ^ *aDux;
	ror(a3, (32 - rot2), tmp);
	ror(a4, (32 - rot3), tmp);
	ror(a5, (32 - rot4), tmp);
	ror(a6, (32 - rot5), tmp);
}

inline static void __attribute__((always_inline))
thetarhopi(uint32_t *aB1, const int aA1, const uint32_t *aDax, const int rot1,
	   uint32_t *aB2, const int aA2, const uint32_t *aDex, const int rot2,
	   uint32_t *aB3, const int aA3, const uint32_t *aDix, const int rot3,
	   uint32_t *aB4, const int aA4, const uint32_t *aDox, const int rot4,
	   uint32_t *aB5, const int aA5, const uint32_t *aDux, const int rot5,
	   const uint32_t *lanes, uint32_t *tmp)
{
	*aB1 = lanes[aA1] ^ *aDax;
	*aB2 = lanes[aA2] ^ *aDex;
	*aB3 = lanes[aA3] ^ *aDix;
	*aB4 = lanes[aA4] ^ *aDox;
	*aB5 = lanes[aA5] ^ *aDux;
	ror(aB1, (32 - rot1), tmp);
	if (rot2 > 0) {
		ror(aB2, (32 - rot2), tmp);
	}
	ror(aB3, (32 - rot3), tmp);
	ror(aB4, (32 - rot4), tmp);
	ror(aB5, (32 - rot5), tmp);
}

inline static void __attribute__((always_inline))
chipattern0(const int aA1, const int aA2, const int aA3, const int aA4,
	    const int aA5, const uint32_t *a2, const uint32_t *a3,
	    const uint32_t *a4, const uint32_t *a5, const uint32_t *a6,
	    uint32_t *lanes, uint32_t *tmp)
{
	xoror(aA1, a2, a3, a4, lanes, tmp);
	xorand(aA2, a3, a4, a5, lanes, tmp);
	xornotor(aA3, a4, a6, a5, lanes, tmp);
	xoror(aA4, a5, a6, a2, lanes, tmp);
	xorand(aA5, a6, a2, a3, lanes, tmp);
}

inline static void __attribute__((always_inline))
chipattern1(const int aA1, const int aA2, const int aA3, const int aA4,
	    const int aA5, const uint32_t *a2, const uint32_t *a3,
	    const uint32_t *a4, const uint32_t *a5, const uint32_t *a6,
	    uint32_t *lanes, uint32_t *tmp, uint32_t *tmp2)
{
	xoror(aA1, a2, a3, a4, lanes, tmp);
	xorand(aA2, a3, a4, a5, lanes, tmp);
	xornotand(aA3, a4, a5, a6, lanes, tmp);
	notxoror(aA4, a5, a6, a2, lanes, tmp, tmp2);
	xorand(aA5, a6, a2, a3, lanes, tmp);
}

inline static void __attribute__((always_inline))
chipattern2(const int aA1, const int aA2, const int aA3, const int aA4,
	    const int aA5, const uint32_t *a2, const uint32_t *a3,
	    const uint32_t *a4, const uint32_t *a5, const uint32_t *a6,
	    uint32_t *lanes, uint32_t *tmp, uint32_t *tmp2)
{
	xorand(aA1, a2, a3, a4, lanes, tmp);
	xoror(aA2, a3, a4, a5, lanes, tmp);
	xornotor(aA3, a4, a5, a6, lanes, tmp);
	notxorand(aA4, a5, a6, a2, lanes, tmp, tmp2);
	xoror(aA5, a6, a2, a3, lanes, tmp);
}

inline static void __attribute__((always_inline))
chipattern3(const int aA1, const int aA2, const int aA3, const int aA4,
	    const int aA5, const uint32_t *a2, const uint32_t *a3,
	    const uint32_t *a4, const uint32_t *a5, const uint32_t *a6,
	    uint32_t *lanes, uint32_t *tmp, uint32_t *tmp2)
{
	xornotand(aA1, a2, a3, a4, lanes, tmp);
	notxoror(aA2, a3, a4, a5, lanes, tmp, tmp2);
	xorand(aA3, a4, a5, a6, lanes, tmp);
	xoror(aA4, a5, a6, a2, lanes, tmp);
	xorand(aA5, a6, a2, a3, lanes, tmp);
}

inline static void __attribute__((always_inline))
chiiota(const int aA1, const int aA2, const int aA3, const int aA4,
	const int aA5, const int offset, uint32_t *a2, const uint32_t *a3,
	uint32_t *a4, const uint32_t *a5, const uint32_t *a6, uint32_t *lanes,
	uint32_t *rc, uint32_t *tmp)
{
	xornotor(aA2, a3, a4, a5, lanes, tmp);
	xorand(aA3, a4, a5, a6, lanes, tmp);
	xoror(aA4, a5, a6, a2, lanes, tmp);
	xorand(aA5, a6, a2, a3, lanes, tmp);
	*a4 = *a4 | *a3;
	uint32_t t6 = rc[offset];
	*a2 = *a2 ^ *a4;
	*a2 = *a2 ^ t6;
	lanes[aA1] = *a2;
}

inline static void __attribute__((always_inline))
round0(uint32_t *lanes, uint32_t *rc, uint32_t *a2, uint32_t *a3, uint32_t *a4,
       uint32_t *a5, uint32_t *a6, uint32_t *a7, uint32_t *s0, uint32_t *s1,
       uint32_t *s2, uint32_t *s4, uint32_t *t0, uint32_t *t1, uint32_t *t2,
       uint32_t *t3, uint32_t *t4, uint32_t *t5, uint32_t *t6)
{
	;
	xor5(a2, Abu0, Agu0, Aku0, Amu0, Asu0, lanes, t1);
	xor5(a6, Abe1, Age1, Ake1, Ame1, Ase1, lanes, t1);
	xorrol(s0, a2, a6);
	xor5(a5, Abu1, Agu1, Aku1, Amu1, Asu1, lanes, t1);
	xor5(t5, Abe0, Age0, Ake0, Ame0, Ase0, lanes, t1);
	*t0 = *a5 ^ *t5;

	xor5(a4, Abi0, Agi0, Aki0, Ami0, Asi0, lanes, t1);
	xorrol(s4, a4, a5);
	xor5(a3, Abi1, Agi1, Aki1, Ami1, Asi1, lanes, t1);
	*s1 = *a2 ^ *a3;

	xor5(a2, Aba0, Aga0, Aka0, Ama0, Asa0, lanes, t1);
	xorrol(t2, a2, a3);
	xor5(a5, Aba1, Aga1, Aka1, Ama1, Asa1, lanes, t1);
	*t3 = *a5 ^ *a4;

	xor5(a3, Abo1, Ago1, Ako1, Amo1, Aso1, lanes, t1);
	xorrol(a7, t5, a3);
	xor5(a4, Abo0, Ago0, Ako0, Amo0, Aso0, lanes, t1);
	*s2 = *a6 ^ *a4;

	xorrol(t4, a4, a5);
	*t5 = *a3 ^ *a2;

	// used for masks: r2,r8,r9,r10,r11,r12,lr,mDa0,mDo1,mDi0,mDa1,mDo0
	//           = >  a7,t0,t1, t2, t3, t4,t5,  s0,  s1,  s2,  s3,  s4
	thetarhopi(a4, Aka1, t0, 2, a5, Ame1, t3, 23, a6, Asi1, s2, 31, a2,
		   Abo0, s4, 14, a3, Agu0, t4, 10, lanes, t1);
	chipattern0(Aka1, Ame1, Asi1, Abo0, Agu0, a2, a3, a4, a5, a6, lanes,
		    t1);
	thetarhopi(a6, Asa1, t0, 9, a2, Abe0, t2, 0, a3, Agi1, s2, 3, a4, Ako0,
		   s4, 12, a5, Amu1, t5, 4, lanes, t1);
	chipattern1(Asa1, Abe0, Agi1, Ako0, Amu1, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a3, Aga0, s0, 18, a4, Ake0, t2, 5, a5, Ami1, s2, 8, a6, Aso0,
		   s4, 28, a2, Abu1, t5, 14, lanes, t1);
	chipattern2(Aga0, Ake0, Ami1, Aso0, Abu1, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a5, Ama0, s0, 20, a6, Ase1, t3, 1, a2, Abi1, s2, 31, a3,
		   Ago0, s4, 27, a4, Aku0, t4, 19, lanes, t1);
	chipattern3(Ama0, Ase1, Abi1, Ago0, Aku0, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopifinal(Aba0, s0, Age0, t2, 22, Aki1, s2, 22, Amo1, s1, 11,
			Asu0, t4, 7, lanes, a2, a3, a4, a5, a6, t1);
	chiiota(Aba0, Age0, Aki1, Amo1, Asu0, 0, a2, a3, a4, a5, a6, lanes, rc,
		t1);

	thetarhopi(a4, Aka0, s0, 1, a5, Ame0, t2, 22, a6, Asi0, a7, 30, a2,
		   Abo1, s1, 14, a3, Agu1, t5, 10, lanes, t1);
	chipattern0(Aka0, Ame0, Asi0, Abo1, Agu1, a2, a3, a4, a5, a6, lanes,
		    t1);
	thetarhopi(a6, Asa0, s0, 9, a2, Abe1, t3, 1, a3, Agi0, a7, 3, a4, Ako1,
		   s1, 13, a5, Amu0, t4, 4, lanes, t1);
	chipattern1(Asa0, Abe1, Agi0, Ako1, Amu0, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a3, Aga1, t0, 18, a4, Ake1, t3, 5, a5, Ami0, a7, 7, a6, Aso1,
		   s1, 28, a2, Abu0, t4, 13, lanes, t1);
	chipattern2(Aga1, Ake1, Ami0, Aso1, Abu0, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a5, Ama1, t0, 21, a6, Ase0, t2, 1, a2, Abi0, a7, 31, a3,
		   Ago1, s1, 28, a4, Aku1, t5, 20, lanes, t1);
	chipattern3(Ama1, Ase0, Abi0, Ago1, Aku1, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopifinal(Aba1, t0, Age1, t3, 22, Aki0, a7, 21, Amo0, s4, 10,
			Asu1, t5, 7, lanes, a2, a3, a4, a5, a6, t1);
	chiiota(Aba1, Age1, Aki0, Amo0, Asu1, 1, a2, a3, a4, a5, a6, lanes, rc,
		t1);
}

inline static void __attribute__((always_inline))
round1(uint32_t *lanes, uint32_t *rc, uint32_t *a2, uint32_t *a3, uint32_t *a4,
       uint32_t *a5, uint32_t *a6, uint32_t *a7, uint32_t *s0, uint32_t *s1,
       uint32_t *s2, uint32_t *s4, uint32_t *t0, uint32_t *t1, uint32_t *t2,
       uint32_t *t3, uint32_t *t4, uint32_t *t5, uint32_t *t6)
{
	xor5(a2, Asu0, Agu0, Amu0, Abu1, Aku1, lanes, t1);
	xor5(a6, Age1, Ame0, Abe0, Ake1, Ase1, lanes, t1);
	xorrol(s0, a2, a6);
	xor5(a5, Asu1, Agu1, Amu1, Abu0, Aku0, lanes, t1);
	xor5(t5, Age0, Ame1, Abe1, Ake0, Ase0, lanes, t1);
	*t0 = *a5 ^ *t5;

	xor5(a4, Aki1, Asi1, Agi0, Ami1, Abi0, lanes, t1);
	xorrol(s4, a4, a5);
	xor5(a3, Aki0, Asi0, Agi1, Ami0, Abi1, lanes, t1);
	*s1 = *a2 ^ *a3;

	xor5(a2, Aba0, Aka1, Asa0, Aga0, Ama1, lanes, t1);
	xorrol(t2, a2, a3);
	xor5(a5, Aba1, Aka0, Asa1, Aga1, Ama0, lanes, t1);
	*t3 = *a5 ^ *a4;

	xor5(a3, Amo0, Abo1, Ako0, Aso1, Ago0, lanes, t1);
	xorrol(a7, t5, a3);
	xor5(a4, Amo1, Abo0, Ako1, Aso0, Ago1, lanes, t1);
	*s2 = *a6 ^ *a4;

	xorrol(t4, a4, a5);
	*t5 = *a3 ^ *a2;

	// used for masks: r2,r8,r9,r10,r11,r12,lr,mDa0,mDo1,mDi0,mDa1,mDo0
	//           = >  a7,t0,t1, t2, t3, t4,t5,  s0,  s1,  s2,  s3,  s4
	thetarhopi(a4, Asa1, t0, 2, a5, Ake1, t3, 23, a6, Abi1, s2, 31, a2,
		   Amo1, s4, 14, a3, Agu0, t4, 10, lanes, t1);
	chipattern0(Asa1, Ake1, Abi1, Amo1, Agu0, a2, a3, a4, a5, a6, lanes,
		    t1);
	thetarhopi(a6, Ama0, t0, 9, a2, Age0, t2, 0, a3, Asi0, s2, 3, a4, Ako1,
		   s4, 12, a5, Abu0, t5, 4, lanes, t1);
	chipattern1(Ama0, Age0, Asi0, Ako1, Abu0, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a3, Aka1, s0, 18, a4, Abe1, t2, 5, a5, Ami0, s2, 8, a6, Ago1,
		   s4, 28, a2, Asu1, t5, 14, lanes, t1);
	chipattern2(Aka1, Abe1, Ami0, Ago1, Asu1, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a5, Aga0, s0, 20, a6, Ase1, t3, 1, a2, Aki0, s2, 31, a3,
		   Abo0, s4, 27, a4, Amu0, t4, 19, lanes, t1);
	chipattern3(Aga0, Ase1, Aki0, Abo0, Amu0, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopifinal(Aba0, s0, Ame1, t2, 22, Agi1, s2, 22, Aso1, s1, 11,
			Aku1, t4, 7, lanes, a2, a3, a4, a5, a6, t1);
	chiiota(Aba0, Ame1, Agi1, Aso1, Aku1, 2, a2, a3, a4, a5, a6, lanes, rc,
		t1);

	thetarhopi(a4, Asa0, s0, 1, a5, Ake0, t2, 22, a6, Abi0, a7, 30, a2,
		   Amo0, s1, 14, a3, Agu1, t5, 10, lanes, t1);
	chipattern0(Asa0, Ake0, Abi0, Amo0, Agu1, a2, a3, a4, a5, a6, lanes,
		    t1);
	thetarhopi(a6, Ama1, s0, 9, a2, Age1, t3, 1, a3, Asi1, a7, 3, a4, Ako0,
		   s1, 13, a5, Abu1, t4, 4, lanes, t1);
	chipattern1(Ama1, Age1, Asi1, Ako0, Abu1, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a3, Aka0, t0, 18, a4, Abe0, t3, 5, a5, Ami1, a7, 7, a6, Ago0,
		   s1, 28, a2, Asu0, t4, 13, lanes, t1);
	chipattern2(Aka0, Abe0, Ami1, Ago0, Asu0, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a5, Aga1, t0, 21, a6, Ase0, t2, 1, a2, Aki1, a7, 31, a3,
		   Abo1, s1, 28, a4, Amu1, t5, 20, lanes, t1);
	chipattern3(Aga1, Ase0, Aki1, Abo1, Amu1, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopifinal(Aba1, t0, Ame0, t3, 22, Agi0, a7, 21, Aso0, s4, 10,
			Aku0, t5, 7, lanes, a2, a3, a4, a5, a6, t1);
	chiiota(Aba1, Ame0, Agi0, Aso0, Aku0, 3, a2, a3, a4, a5, a6, lanes, rc,
		t1);
}

inline static void __attribute__((always_inline)) round2(uint32_t *lanes,
							 uint32_t *rc, reg *p)
{
	xor5(&p->a2, Aku1, Agu0, Abu1, Asu1, Amu1, lanes, &p->t1);
	xor5(&p->a6, Ame0, Ake0, Age0, Abe0, Ase1, lanes, &p->t1);
	xorrol(&p->s0, &p->a2, &p->a6);
	xor5(&p->a5, Aku0, Agu1, Abu0, Asu0, Amu0, lanes, &p->t1);
	xor5(&p->t5, Ame1, Ake1, Age1, Abe1, Ase0, lanes, &p->t1);
	p->t0 = p->a5 ^ p->t5;

	xor5(&p->a4, Agi1, Abi1, Asi1, Ami0, Aki1, lanes, &p->t1);
	xorrol(&p->s4, &p->a4, &p->a5);
	xor5(&p->a3, Agi0, Abi0, Asi0, Ami1, Aki0, lanes, &p->t1);
	p->s1 = p->a2 ^ p->a3;

	xor5(&p->a2, Aba0, Asa1, Ama1, Aka1, Aga1, lanes, &p->t1);
	xorrol(&p->t2, &p->a2, &p->a3);
	xor5(&p->a5, Aba1, Asa0, Ama0, Aka0, Aga0, lanes, &p->t1);
	p->t3 = p->a5 ^ p->a4;

	xor5(&p->a3, Aso0, Amo0, Ako1, Ago0, Abo0, lanes, &p->t1);
	xorrol(&p->a7, &p->t5, &p->a3);
	xor5(&p->a4, Aso1, Amo1, Ako0, Ago1, Abo1, lanes, &p->t1);
	p->s2 = p->a6 ^ p->a4;

	xorrol(&p->t4, &p->a4, &p->a5);
	p->t5 = p->a3 ^ p->a2;

	// used for masks: r2,r8,r9,r10,r11,r12,lr,mDa0,mDo1,mDi0,mDa1,mDo0
	//           = >  a7,t0,t1, t2, t3, t4, t5,  s0,  s1,  s2,  s3,  s4
	thetarhopi(&p->a4, Ama0, &p->t0, 2, &p->a5, Abe0, &p->t3, 23, &p->a6,
		   Aki0, &p->s2, 31, &p->a2, Aso1, &p->s4, 14, &p->a3, Agu0,
		   &p->t4, 10, lanes, &p->t1);
	chipattern0(Ama0, Abe0, Aki0, Aso1, Agu0, &p->a2, &p->a3, &p->a4,
		    &p->a5, &p->a6, lanes, &p->t1);
	thetarhopi(&p->a6, Aga0, &p->t0, 9, &p->a2, Ame1, &p->t2, 0, &p->a3,
		   Abi0, &p->s2, 3, &p->a4, Ako0, &p->s4, 12, &p->a5, Asu0,
		   &p->t5, 4, lanes, &p->t1);
	chipattern1(Aga0, Ame1, Abi0, Ako0, Asu0, &p->a2, &p->a3, &p->a4,
		    &p->a5, &p->a6, lanes, &p->t1, &p->t6);
	thetarhopi(&p->a3, Asa1, &p->s0, 18, &p->a4, Age1, &p->t2, 5, &p->a5,
		   Ami1, &p->s2, 8, &p->a6, Abo1, &p->s4, 28, &p->a2, Aku0,
		   &p->t5, 14, lanes, &p->t1);
	chipattern2(Asa1, Age1, Ami1, Abo1, Aku0, &p->a2, &p->a3, &p->a4,
		    &p->a5, &p->a6, lanes, &p->t1, &p->t6);
	thetarhopi(&p->a5, Aka1, &p->s0, 20, &p->a6, Ase1, &p->t3, 1, &p->a2,
		   Agi0, &p->s2, 31, &p->a3, Amo1, &p->s4, 27, &p->a4, Abu1,
		   &p->t4, 19, lanes, &p->t1);
	chipattern3(Aka1, Ase1, Agi0, Amo1, Abu1, &p->a2, &p->a3, &p->a4,
		    &p->a5, &p->a6, lanes, &p->t1, &p->t6);
	thetarhopifinal(Aba0, &p->s0, Ake1, &p->t2, 22, Asi0, &p->s2, 22, Ago0,
			&p->s1, 11, Amu1, &p->t4, 7, lanes, &p->a2, &p->a3,
			&p->a4, &p->a5, &p->a6, &p->t1);
	chiiota(Aba0, Ake1, Asi0, Ago0, Amu1, 4, &p->a2, &p->a3, &p->a4, &p->a5,
		&p->a6, lanes, rc, &p->t1);

	thetarhopi(&p->a4, Ama1, &p->s0, 1, &p->a5, Abe1, &p->t2, 22, &p->a6,
		   Aki1, &p->a7, 30, &p->a2, Aso0, &p->s1, 14, &p->a3, Agu1,
		   &p->t5, 10, lanes, &p->t1);
	chipattern0(Ama1, Abe1, Aki1, Aso0, Agu1, &p->a2, &p->a3, &p->a4,
		    &p->a5, &p->a6, lanes, &p->t1);
	thetarhopi(&p->a6, Aga1, &p->s0, 9, &p->a2, Ame0, &p->t3, 1, &p->a3,
		   Abi1, &p->a7, 3, &p->a4, Ako1, &p->s1, 13, &p->a5, Asu1,
		   &p->t4, 4, lanes, &p->t1);
	chipattern1(Aga1, Ame0, Abi1, Ako1, Asu1, &p->a2, &p->a3, &p->a4,
		    &p->a5, &p->a6, lanes, &p->t1, &p->t6);
	thetarhopi(&p->a3, Asa0, &p->t0, 18, &p->a4, Age0, &p->t3, 5, &p->a5,
		   Ami0, &p->a7, 7, &p->a6, Abo0, &p->s1, 28, &p->a2, Aku1,
		   &p->t4, 13, lanes, &p->t1);
	chipattern2(Asa0, Age0, Ami0, Abo0, Aku1, &p->a2, &p->a3, &p->a4,
		    &p->a5, &p->a6, lanes, &p->t1, &p->t6);
	thetarhopi(&p->a5, Aka0, &p->t0, 21, &p->a6, Ase0, &p->t2, 1, &p->a2,
		   Agi1, &p->a7, 31, &p->a3, Amo0, &p->s1, 28, &p->a4, Abu0,
		   &p->t5, 20, lanes, &p->t1);
	chipattern3(Aka0, Ase0, Agi1, Amo0, Abu0, &p->a2, &p->a3, &p->a4,
		    &p->a5, &p->a6, lanes, &p->t1, &p->t6);
	thetarhopifinal(Aba1, &p->t0, Ake0, &p->t3, 22, Asi1, &p->a7, 21, Ago1,
			&p->s4, 10, Amu0, &p->t5, 7, lanes, &p->a2, &p->a3,
			&p->a4, &p->a5, &p->a6, &p->t1);
	chiiota(Aba1, Ake0, Asi1, Ago1, Amu0, 5, &p->a2, &p->a3, &p->a4, &p->a5,
		&p->a6, lanes, rc, &p->t1);
}

inline static void __attribute__((always_inline))
round3(uint32_t *lanes, uint32_t *rc, uint32_t *a2, uint32_t *a3, uint32_t *a4,
       uint32_t *a5, uint32_t *a6, uint32_t *a7, uint32_t *s0, uint32_t *s1,
       uint32_t *s2, uint32_t *s4, uint32_t *t0, uint32_t *t1, uint32_t *t2,
       uint32_t *t3, uint32_t *t4, uint32_t *t5, uint32_t *t6)
{
	xor5(a2, Amu1, Agu0, Asu1, Aku0, Abu0, lanes, t1);
	xor5(a6, Ake0, Abe1, Ame1, Age0, Ase1, lanes, t1);
	xorrol(s0, a2, a6);
	xor5(a5, Amu0, Agu1, Asu0, Aku1, Abu1, lanes, t1);
	xor5(t5, Ake1, Abe0, Ame0, Age1, Ase0, lanes, t1);
	*t0 = *a5 ^ *t5;

	xor5(a4, Asi0, Aki0, Abi1, Ami1, Agi1, lanes, t1);
	xorrol(s4, a4, a5);
	xor5(a3, Asi1, Aki1, Abi0, Ami0, Agi0, lanes, t1);
	*s1 = *a2 ^ *a3;

	xor5(a2, Aba0, Ama0, Aga1, Asa1, Aka0, lanes, t1);
	xorrol(t2, a2, a3);
	xor5(a5, Aba1, Ama1, Aga0, Asa0, Aka1, lanes, t1);
	*t3 = *a5 ^ *a4;

	xor5(a3, Ago1, Aso0, Ako0, Abo0, Amo1, lanes, t1);
	xorrol(a7, t5, a3);
	xor5(a4, Ago0, Aso1, Ako1, Abo1, Amo0, lanes, t1);
	*s2 = *a6 ^ *a4;

	xorrol(t4, a4, a5);
	*t5 = *a3 ^ *a2;

	// used for masks: r2,r8,r9,r10,r11,r12,lr,mDa0,mDo1,mDi0,mDa1,mDo0
	//           = >  a7,t0,t1, t2, t3, t4,t5,  s0,  s1,  s2,  s3,  s4
	thetarhopi(a4, Aga0, t0, 2, a5, Age0, t3, 23, a6, Agi0, s2, 31, a2,
		   Ago0, s4, 14, a3, Agu0, t4, 10, lanes, t1);
	chipattern0(Aga0, Age0, Agi0, Ago0, Agu0, a2, a3, a4, a5, a6, lanes,
		    t1);
	thetarhopi(a6, Aka1, t0, 9, a2, Ake1, t2, 0, a3, Aki1, s2, 3, a4, Ako1,
		   s4, 12, a5, Aku1, t5, 4, lanes, t1);
	chipattern1(Aka1, Ake1, Aki1, Ako1, Aku1, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a3, Ama0, s0, 18, a4, Ame0, t2, 5, a5, Ami0, s2, 8, a6, Amo0,
		   s4, 28, a2, Amu0, t5, 14, lanes, t1);
	chipattern2(Ama0, Ame0, Ami0, Amo0, Amu0, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a5, Asa1, s0, 20, a6, Ase1, t3, 1, a2, Asi1, s2, 31, a3,
		   Aso1, s4, 27, a4, Asu1, t4, 19, lanes, t1);
	chipattern3(Asa1, Ase1, Asi1, Aso1, Asu1, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopifinal(Aba0, s0, Abe0, t2, 22, Abi0, s2, 22, Abo0, s1, 11,
			Abu0, t4, 7, lanes, a2, a3, a4, a5, a6, t1);
	chiiota(Aba0, Abe0, Abi0, Abo0, Abu0, 6, a2, a3, a4, a5, a6, lanes, rc,
		t1);

	thetarhopi(a4, Aga1, s0, 1, a5, Age1, t2, 22, a6, Agi1, a7, 30, a2,
		   Ago1, s1, 14, a3, Agu1, t5, 10, lanes, t1);
	chipattern0(Aga1, Age1, Agi1, Ago1, Agu1, a2, a3, a4, a5, a6, lanes,
		    t1);
	thetarhopi(a6, Aka0, s0, 9, a2, Ake0, t3, 1, a3, Aki0, a7, 3, a4, Ako0,
		   s1, 13, a5, Aku0, t4, 4, lanes, t1);
	chipattern1(Aka0, Ake0, Aki0, Ako0, Aku0, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a3, Ama1, t0, 18, a4, Ame1, t3, 5, a5, Ami1, a7, 7, a6, Amo1,
		   s1, 28, a2, Amu1, t4, 13, lanes, t1);
	chipattern2(Ama1, Ame1, Ami1, Amo1, Amu1, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopi(a5, Asa0, t0, 21, a6, Ase0, t2, 1, a2, Asi0, a7, 31, a3,
		   Aso0, s1, 28, a4, Asu0, t5, 20, lanes, t1);
	chipattern3(Asa0, Ase0, Asi0, Aso0, Asu0, a2, a3, a4, a5, a6, lanes, t1,
		    t6);
	thetarhopifinal(Aba1, t0, Abe1, t3, 22, Abi1, a7, 21, Abo1, s4, 10,
			Abu1, t5, 7, lanes, a2, a3, a4, a5, a6, t1);
	chiiota(Aba1, Abe1, Abi1, Abo1, Abu1, 7, a2, a3, a4, a5, a6, lanes, rc,
		t1);
}

inline static void __attribute__((always_inline))
invert(const int dst, uint32_t *lanes, uint32_t *t6)
{
	*t6 = lanes[dst];
	*t6 = ~*t6;
	lanes[dst] = *t6;
}

inline static void __attribute__((always_inline))
complementlanes(uint32_t *lanes, uint32_t *t6)
{
	invert(Abe0, lanes, t6);
	invert(Abe1, lanes, t6);
	invert(Abi0, lanes, t6);
	invert(Abi1, lanes, t6);
	invert(Ago0, lanes, t6);
	invert(Ago1, lanes, t6);
	invert(Aki0, lanes, t6);
	invert(Aki1, lanes, t6);
	invert(Ami0, lanes, t6);
	invert(Ami1, lanes, t6);
	invert(Asa0, lanes, t6);
	invert(Asa1, lanes, t6);
}

void lc_keccakf1600_riscv(uint32_t *lanes)
{
	uint32_t *rc = keccakf1600_rc;
	reg p;
	complementlanes(lanes, &p.t6);

	// With this loop it still fits in 16 KiB instruction cache
	int s3 = 6;
	do {
		round0(lanes, rc, &p.a2, &p.a3, &p.a4, &p.a5, &p.a6, &p.a7,
		       &p.s0, &p.s1, &p.s2, &p.s4, &p.t0, &p.t1, &p.t2, &p.t3,
		       &p.t4, &p.t5, &p.t6);
		round1(lanes, rc, &p.a2, &p.a3, &p.a4, &p.a5, &p.a6, &p.a7,
		       &p.s0, &p.s1, &p.s2, &p.s4, &p.t0, &p.t1, &p.t2, &p.t3,
		       &p.t4, &p.t5, &p.t6);
		round2(lanes, rc, &p);
		round3(lanes, rc, &p.a2, &p.a3, &p.a4, &p.a5, &p.a6, &p.a7,
		       &p.s0, &p.s1, &p.s2, &p.s4, &p.t0, &p.t1, &p.t2, &p.t3,
		       &p.t4, &p.t5, &p.t6);
		rc += 8;
		s3--;
	} while (s3 > 0);

	// - for some reason using a struct here makes us gain 72 cycles: 13366
	// cycles. WTF
	// - if the struct is used in EVERY round functions, we are at 13408 cycles.
	// - if no struct is used we are at 13408 cycles
	// - if the increment of rc is + 32 instead of +8 we are at 13406 cycles

	complementlanes(lanes, &p.t6);
}
