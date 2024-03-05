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
 */

#include "kyber_armv7.h"
#include "kyber_ntt.h"
#include "lc_kyber.h"

const int16_t zetas_armv7[64] = {
	2226, 430,  555,  843,	2078, 871,  1550, 105,	422,  587,  177,
	3094, 3038, 2869, 1574, 1653, 3083, 778,  1159, 3182, 2552, 1483,
	2727, 1119, 1739, 644,	2457, 349,  418,  329,	3173, 3254, 817,
	1097, 603,  610,  1322, 2044, 1864, 384,  2114, 3193, 1218, 1994,
	2455, 220,  2142, 1670, 2144, 1799, 2051, 794,	1819, 2475, 2459,
	478,  3221, 3021, 996,	991,  958,  1869, 1522, 1628
};

static const int16_t kyber_zetas_asm[128] = {
	// 7 & 6 & 5 layers
	2571,
	2970,
	1812,
	1493,
	1422,
	287,
	202,
	// 1st loop of 4 & 3 & 2 layers
	3158,
	573,
	2004,
	1223,
	652,
	2777,
	1015,
	// 2nd loop of 4 & 3 & 2 layers
	622,
	264,
	383,
	2036,
	1491,
	3047,
	1785,
	// 3rd loop of 4 & 3 & 2 layers
	1577,
	2500,
	1458,
	516,
	3321,
	3009,
	2663,
	// 4th loop of 4 & 3 & 2 layers
	182,
	1727,
	3199,
	1711,
	2167,
	126,
	1469,
	// 5th loop of 4 & 3 & 2 layers
	962,
	2648,
	1017,
	2476,
	3239,
	3058,
	830,
	// 6th loop of 4 & 3 & 2 layers
	2127,
	732,
	608,
	107,
	1908,
	3082,
	2378,
	// 7th loop of 4 & 3 & 2 layers
	1855,
	1787,
	411,
	2931,
	961,
	1821,
	2604,
	// 8th loop of 4 & 3 & 2 layers
	1468,
	3124,
	1758,
	448,
	2264,
	677,
	2054,
	// 1 layer
	2226,
	430,
	555,
	843,
	2078,
	871,
	1550,
	105,
	422,
	587,
	177,
	3094,
	3038,
	2869,
	1574,
	1653,
	3083,
	778,
	1159,
	3182,
	2552,
	1483,
	2727,
	1119,
	1739,
	644,
	2457,
	349,
	418,
	329,
	3173,
	3254,
	817,
	1097,
	603,
	610,
	1322,
	2044,
	1864,
	384,
	2114,
	3193,
	1218,
	1994,
	2455,
	220,
	2142,
	1670,
	2144,
	1799,
	2051,
	794,
	1819,
	2475,
	2459,
	478,
	3221,
	3021,
	996,
	991,
	958,
	1869,
	1522,
	1628,
};

static const int16_t kyber_zetas_inv_asm[128] = {
	// 1 layer
	1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510,
	2535, 1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215,
	2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911,
	2980, 872, 2685, 1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676,
	1755, 460, 291, 235, 3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486,
	2774, 2899, 1103,
	// 1st loop of 2 & 3 & 4 layers
	1275, 2652, 1065, 2881, 1571, 205, 1861,
	// 2nd loop of 2 & 3 & 4 layers
	725, 1508, 2368, 398, 2918, 1542, 1474,
	// 3rd loop of 2 & 3 & 4 layers
	951, 247, 1421, 3222, 2721, 2597, 1202,
	// 4th loop of 2 & 3 & 4 layers
	2499, 271, 90, 853, 2312, 681, 2367,
	// 5th loop of 2 & 3 & 4 layers
	1860, 3203, 1162, 1618, 130, 1602, 3147,
	// 6th loop of 2 & 3 & 4 layers
	666, 320, 8, 2813, 1871, 829, 1752,
	// 7th loop of 2 & 3 & 4 layers
	1544, 282, 1838, 1293, 2946, 3065, 2707,
	// 8th loop of 2 & 3 & 4 layers
	2314, 552, 2677, 2106, 1325, 2756, 171,
	// 5 & 6 & 7 layers
	3127, 3042, 1907, 1836, 1517, 359, 1932,
	// 128^-1 * 2^32
	1441
};

void kyber_ntt(int16_t r[LC_KYBER_N])
{
	kyber_ntt_armv7(r, kyber_zetas_asm);
}

void kyber_invntt(int16_t r[LC_KYBER_N])
{
	kyber_invntt_armv7(r, kyber_zetas_inv_asm);
}
