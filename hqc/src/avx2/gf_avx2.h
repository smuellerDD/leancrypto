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
 * @file gf.h
 * @brief Header file of gf.c
 */

#ifndef GF_AVX2_H
#define GF_AVX2_H

#include "ext_headers_x86.h"
#include "hqc_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _mm256_set_m128i(v0, v1)                                               \
	_mm256_insertf128_si256(_mm256_castsi128_si256(v1), (v0), 1)

/**
 * Powers of the root alpha of 1 + x^2 + x^3 + x^4 + x^8.
 * The last two elements are needed by the gf_mul function
 * (for example if both elements to multiply are zero).
 */
static const uint16_t gf_exp[258] = {
	1,   2,	  4,   8,   16,	 32,  64,  128, 29,  58,  116, 232, 205, 135,
	19,  38,  76,  152, 45,	 90,  180, 117, 234, 201, 143, 3,   6,	 12,
	24,  48,  96,  192, 157, 39,  78,  156, 37,  74,  148, 53,  106, 212,
	181, 119, 238, 193, 159, 35,  70,  140, 5,   10,  20,  40,  80,	 160,
	93,  186, 105, 210, 185, 111, 222, 161, 95,  190, 97,  194, 153, 47,
	94,  188, 101, 202, 137, 15,  30,  60,	120, 240, 253, 231, 211, 187,
	107, 214, 177, 127, 254, 225, 223, 163, 91,  182, 113, 226, 217, 175,
	67,  134, 17,  34,  68,	 136, 13,  26,	52,  104, 208, 189, 103, 206,
	129, 31,  62,  124, 248, 237, 199, 147, 59,  118, 236, 197, 151, 51,
	102, 204, 133, 23,  46,	 92,  184, 109, 218, 169, 79,  158, 33,	 66,
	132, 21,  42,  84,  168, 77,  154, 41,	82,  164, 85,  170, 73,	 146,
	57,  114, 228, 213, 183, 115, 230, 209, 191, 99,  198, 145, 63,	 126,
	252, 229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75,  150, 49,
	98,  196, 149, 55,  110, 220, 165, 87,	174, 65,  130, 25,  50,	 100,
	200, 141, 7,   14,  28,	 56,  112, 224, 221, 167, 83,  166, 81,	 162,
	89,  178, 121, 242, 249, 239, 195, 155, 43,  86,  172, 69,  138, 9,
	18,  36,  72,  144, 61,	 122, 244, 245, 247, 243, 251, 235, 203, 139,
	11,  22,  44,  88,  176, 125, 250, 233, 207, 131, 27,  54,  108, 216,
	173, 71,  142, 1,   2,	 4
};

/**
 * Logarithm of elements of GF(2^8) to the base alpha (root of 1 + x^2 + x^3 + x^4 + x^8).
 * The logarithm of 0 is set to 256 by convention.
 */
static const uint16_t gf_log[256] = {
	0,   0,	  1,   25,  2,	 50,  26,  198, 3,   223, 51,  238, 27,	 104,
	199, 75,  4,   100, 224, 14,  52,  141, 239, 129, 28,  193, 105, 248,
	200, 8,	  76,  113, 5,	 138, 101, 47,	225, 36,  15,  33,  53,	 147,
	142, 218, 240, 18,  130, 69,  29,  181, 194, 125, 106, 39,  249, 185,
	201, 154, 9,   120, 77,	 228, 114, 166, 6,   191, 139, 98,  102, 221,
	48,  253, 226, 152, 37,	 179, 16,  145, 34,  136, 54,  208, 148, 206,
	143, 150, 219, 189, 241, 210, 19,  92,	131, 56,  70,  64,  30,	 66,
	182, 163, 195, 72,  126, 110, 107, 58,	40,  84,  250, 133, 186, 61,
	202, 94,  155, 159, 10,	 21,  121, 43,	78,  212, 229, 172, 115, 243,
	167, 87,  7,   112, 192, 247, 140, 128, 99,  13,  103, 74,  222, 237,
	49,  197, 254, 24,  227, 165, 153, 119, 38,  184, 180, 124, 17,	 68,
	146, 217, 35,  32,  137, 46,  55,  63,	209, 91,  149, 188, 207, 205,
	144, 135, 151, 178, 220, 252, 190, 97,	242, 86,  211, 171, 20,	 42,
	93,  158, 132, 60,  57,	 83,  71,  109, 65,  162, 31,  45,  67,	 216,
	183, 123, 164, 118, 196, 23,  73,  236, 127, 12,  111, 246, 108, 161,
	59,  82,  41,  157, 85,	 170, 251, 96,	134, 177, 187, 204, 62,	 90,
	203, 89,  95,  176, 156, 169, 160, 81,	11,  245, 22,  235, 122, 117,
	44,  215, 79,  174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234,
	168, 80,  88,  175
};

/** 
 * Masks needed for the computation of 16 mult in GF(2^M)
 */
static const __m256i mr0 = { 0x0100010001000100UL, 0x0100010001000100UL,
			     0x0100010001000100UL, 0x0100010001000100UL };
static const __m256i lastMask = { 0x00ff00ff00ff00ffUL, 0x00ff00ff00ff00ffUL,
				  0x00ff00ff00ff00ffUL, 0x00ff00ff00ff00ffUL };
static const __m128i maskl = { 0x0000ffff0000ffffUL, 0x0000ffff0000ffffUL };

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
static const __m128i maskh = { 0xffff0000ffff0000UL, 0xffff0000ffff0000UL };
static const __m128i indexh = { 0xffffffffffffffffUL, 0x0d0c090805040100UL };
static const __m128i indexl = { 0x0d0c090805040100UL, 0xffffffffffffffffUL };
#pragma GCC diagnostic pop

static const __m128i middlemaskl = { 0x000000000000ffffUL,
				     0x000000000000ffffUL };
static const __m128i middlemaskh = { 0x0000ffff00000000UL,
				     0x0000ffff00000000UL };

/** 
 * x^i modulo x^8+x^4+x^3+x^2+1 duplicate 4 times to fit a 256-bit register
 */
static const __m256i red[7] = {
	{ 0x001d001d001d001dUL, 0x001d001d001d001dUL, 0x001d001d001d001dUL,
	  0x001d001d001d001dUL },
	{ 0x003a003a003a003aUL, 0x003a003a003a003aUL, 0x003a003a003a003aUL,
	  0x003a003a003a003aUL },
	{ 0x0074007400740074UL, 0x0074007400740074UL, 0x0074007400740074UL,
	  0x0074007400740074UL },
	{ 0x00e800e800e800e8UL, 0x00e800e800e800e8UL, 0x00e800e800e800e8UL,
	  0x00e800e800e800e8UL },
	{ 0x00cd00cd00cd00cdUL, 0x00cd00cd00cd00cdUL, 0x00cd00cd00cd00cdUL,
	  0x00cd00cd00cd00cdUL },
	{ 0x0087008700870087UL, 0x0087008700870087UL, 0x0087008700870087UL,
	  0x0087008700870087UL },
	{ 0x0013001300130013UL, 0x0013001300130013UL, 0x0013001300130013UL,
	  0x0013001300130013UL },

};

void gf_generate_avx2(uint16_t *exp, uint16_t *log, const int16_t m);

uint16_t gf_mul_avx2(uint16_t a, uint16_t b);
__m256i gf_mul_vect_avx2(__m256i a, __m256i b);
uint16_t gf_square_avx2(uint16_t a);
uint16_t gf_inverse_avx2(uint16_t a);
uint16_t gf_mod_avx2(uint16_t i);

#ifdef __cplusplus
}
#endif

#endif /* GF_H */
