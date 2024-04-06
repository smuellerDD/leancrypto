/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/ascon/ascon-c/crypto_aead/ascon128v12/neon/permutations.h
 * which is subject to the following license:
 *
 * CC0 1.0 Universal
 */

#ifndef PERMUTATIONS_H_
#define PERMUTATIONS_H_

#include "ext_headers.h"
#include "lc_ascon_hash.h"
#include "round.h"

const uint64_t C[12] = {
	0xffffffffffffff0full, 0xffffffffffffff1eull, 0xffffffffffffff2dull,
	0xffffffffffffff3cull, 0xffffffffffffff4bull, 0xffffffffffffff5aull,
	0xffffffffffffff69ull, 0xffffffffffffff78ull, 0xffffffffffffff87ull,
	0xffffffffffffff96ull, 0xffffffffffffffa5ull, 0xffffffffffffffb4ull,
};

#define P12ROUNDS(s)                                                           \
	ROUND(0)                                                               \
	ROUND(8)                                                               \
	ROUND(16)                                                              \
	ROUND(24)                                                              \
	ROUND(32)                                                              \
	ROUND(40)                                                              \
	ROUND(48)                                                              \
	ROUND(56)                                                              \
	ROUND(64)                                                              \
	ROUND(72)                                                              \
	ROUND(80)                                                              \
	ROUND(88)

#define P8ROUNDS(s)                                                            \
	ROUND(32)                                                              \
	ROUND(40)                                                              \
	ROUND(48)                                                              \
	ROUND(56)                                                              \
	ROUND(64)                                                              \
	ROUND(72)                                                              \
	ROUND(80)                                                              \
	ROUND(88)

#define P6ROUNDS(s)                                                            \
	ROUND(48)                                                              \
	ROUND(56)                                                              \
	ROUND(64)                                                              \
	ROUND(72)                                                              \
	ROUND(80)                                                              \
	ROUND(88)

/* clang-format off */
static inline void
ascon_permutation_12_arm_neon(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	__asm__ __volatile__(
		".fpu neon \n\t"
		"vldm %[s], {d0-d4} \n\t"
		"vmvn d2, d2 \n\t" P12ROUNDS(s)
		"vmvn d2, d2 \n\t"
		"vstm %[s], {d0-d4} \n\t"
		::[s] "r"(s), [C] "r"(C)
		: "d0", "d1", "d2", "d3", "d4", "d10", "d11",
		"d12", "d13", "d14", "d20", "d21", "d22", "d23",
		"d24", "d31", "memory");
}

static inline void
ascon_permutation_8_arm_neon(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	__asm__ __volatile__(
		".fpu neon \n\t"
		"vldm %[s], {d0-d4} \n\t"
		"vmvn d2, d2 \n\t" P8ROUNDS(s)
		"vmvn d2, d2 \n\t"
		"vstm %[s], {d0-d4} \n\t"
		::[s] "r"(s), [C] "r"(C)
		: "d0", "d1", "d2", "d3", "d4", "d10", "d11",
		"d12", "d13", "d14", "d20", "d21", "d22", "d23",
		"d24", "d31", "memory");
}

static inline void
ascon_permutation_6_arm_neon(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	__asm__ __volatile__(
		".fpu neon \n\t"
		"vldm %[s], {d0-d4} \n\t"
		"vmvn d2, d2 \n\t" P6ROUNDS(s)
		"vmvn d2, d2 \n\t"
		"vstm %[s], {d0-d4} \n\t"
		::[s] "r"(s), [C] "r"(C)
		: "d0", "d1", "d2", "d3", "d4", "d10", "d11",
		"d12", "d13", "d14", "d20", "d21", "d22", "d23",
		"d24", "d31", "memory");
}
/* clang-format on */

#endif /* PERMUTATIONS_H_ */
