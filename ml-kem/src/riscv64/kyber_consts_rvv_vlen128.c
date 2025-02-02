/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * This file is derived from https://github.com/Ji-Peng/PQRV which uses the
 * following license.
 *
 * The MIT license, the text of which is below, applies to PQRV in general.
 *
 * Copyright (c) 2024 - 2025 Jipeng Zhang (jp-zhang@outlook.com)
 * SPDX-License-Identifier: MIT
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

#include "ntt_rvv_vlen128.h"

#define I16(l, h) (h << 8) | l

// clang-format off
const int16_t kyber_qdata_rvv_vlen128[] __attribute__((aligned(16))) = {
#define _MASK_45674567
    4,           5,           6,           7,           4,
    5,           6,           7,
#define _MASK_01230123
    0,           1,           2,           3,           0,
    1,           2,           3,
#define _MASK_01014545
    0,           1,           0,           1,           4,
    5,           4,           5,
#define _MASK_23236767
    2,           3,           2,           3,           6,
    7,           6,           7,
#define _MASK_10325476
    1,           0,           3,           2,           5,
    4,           7,           6,
#define _REJ_UNIFORM_IDX8
    I16(0, 1),   I16(1, 2),   I16(3, 4),   I16(4, 5),   I16(6, 7),
    I16(7, 8),   I16(9, 10),  I16(10, 11),
#define _REJ_UNIFORM_MASK_01
    0,           1,           0,           1,           0,
    1,           0,           1,
#define _CBD2_MASK_E8_01
    I16(0, 1),   I16(0, 1),   I16(0, 1),   I16(0, 1),   I16(0, 1),
    I16(0, 1),   I16(0, 1),   I16(0, 1),
#define _CBD2_IDX8_LOW
    I16(0, 0),   I16(1, 1),   I16(2, 2),   I16(3, 3),   I16(4, 4),
    I16(5, 5),   I16(6, 6),   I16(7, 7),
#define _CBD2_IDX8_HIGH
    I16(8, 8),   I16(9, 9),   I16(10, 10), I16(11, 11), I16(12, 12),
    I16(13, 13), I16(14, 14), I16(15, 15),
#define _CBD3_MASK_E8_0122
    I16(0, 1),   I16(2, 2),   I16(3, 4),   I16(5, 5),   I16(6, 7),
    I16(8, 8),   I16(9, 10),  I16(11, 11),
#define _CBD3_IDX16_HIGH
    4,           5,           4,           5,           6,
    7,           6,           7,
#define _CBD3_MASK_E16_1100
    1,           1,           0,           0,           1,
    1,           0,           0,
#define _CBD3_IDX16_LOW
    0,           1,           0,           1,           2,
    3,           2,           3,
#define _ZETAS_EXP
    31498,       -758,
#define _ZETAS_EXP_1TO6_P0_L1
    14745,       -359,
#define _ZETAS_EXP_1TO6_P0_L2
    13525,       1493,        -12402,      1422,
#define _ZETAS_EXP_1TO6_P0_L3
    -20907,      -20907,      27758,       27758,       -3799,
    -3799,       -15690,      -15690,      -171,        -171,
    622,         622,         1577,        1577,        182,
    182,
#define _ZETAS_EXP_1TO6_P0_L4
    -5827,       17363,       -26360,      -29057,      5571,
    -1102,       21438,       -26242,      573,         -1325,
    264,         383,         -829,        1458,        -1602,
    -130,
#define _ZETAS_EXP_1TO6_P0_L5
    -5689,       1496,        -23565,      20710,       -12796,
    16064,       9134,        -25986,      1223,        -552,
    -1293,       -282,        516,         -320,        -1618,
    126,         -6516,       30967,       20179,       25080,
    26616,       -12442,      -650,        27837,       652,
    1015,        1491,        -1544,       -8,          -666,
    -1162,       1469,
#define _ZETAS_EXP_1TO6_P0_L6
    -1103,       -1251,       422,         -291,        -246,
    -777,        -1590,       418,         430,         871,
    587,         -460,        778,         1483,        644,
    329,         555,         1550,        177,         1574,
    1159,        -602,        -872,        -156,        843,
    105,         -235,        1653,        -147,        1119,
    349,         -75,
#define _ZETAS_EXP_1TO6_P1_L1
    787,         -1517,
#define _ZETAS_EXP_1TO6_P1_L2
    28191,       287,         -16694,      202,         0,
    0,
#define _ZETAS_EXP_1TO6_P1_L3
    10690,       10690,       1358,        1358,        -11202,
    -11202,      31164,       31164,       962,         962,
    -1202,       -1202,       -1474,       -1474,       1468,
    1468,
#define _ZETAS_EXP_1TO6_P1_L4
    -28073,      24313,       -10532,      8800,        18426,
    8859,        26675,       -16163,      -681,        1017,
    732,         608,         -1542,       411,         -205,
    -1571,
#define _ZETAS_EXP_1TO6_P1_L5
    19883,       -15887,      -28309,      -30199,      13426,
    -29156,      16832,       -24155,      -853,        -271,
    107,         -247,        -398,        -1508,       448,
    677,         -28250,      -8898,       9075,        18249,
    14017,       -12757,      4311,        -17915,      -90,
    830,         -1421,       -951,        961,         -725,
    -1065,       -1275,
#define _ZETAS_EXP_1TO6_P1_L6
    817,         1322,        -1215,       -874,        -1185,
    -1510,       -108,        958,         1097,        -1285,
    -136,        220,         -1530,       -854,        -308,
    -1460,       603,         -1465,       1218,        -1187,
    -1278,       -870,        996,         1522,        610,
    384,         -1335,       -1659,       794,         478,
    991,         1628,
#define _ZETAS_BASEMUL
    -1103,       -1251,       422,         -291,        -246,
    -777,        -1590,       418,         1103,        1251,
    -422,        291,         246,         777,         1590,
    -418,        430,         871,         587,         -460,
    778,         1483,        644,         329,         -430,
    -871,        -587,        460,         -778,        -1483,
    -644,        -329,        555,         1550,        177,
    1574,        1159,        -602,        -872,        -156,
    -555,        -1550,       -177,        -1574,       -1159,
    602,         872,         156,         843,         105,
    -235,        1653,        -147,        1119,        349,
    -75,         -843,        -105,        235,         -1653,
    147,         -1119,       -349,        75,          817,
    1322,        -1215,       -874,        -1185,       -1510,
    -108,        958,         -817,        -1322,       1215,
    874,         1185,        1510,        108,         -958,
    1097,        -1285,       -136,        220,         -1530,
    -854,        -308,        -1460,       -1097,       1285,
    136,         -220,        1530,        854,         308,
    1460,        603,         -1465,       1218,        -1187,
    -1278,       -870,        996,         1522,        -603,
    1465,        -1218,       1187,        1278,        870,
    -996,        -1522,       610,         384,         -1335,
    -1659,       794,         478,         991,         1628,
    -610,        -384,        1335,        1659,        -794,
    -478,        -991,        -1628,
#define _ZETA_EXP_INTT_0TO5_P0_L0
    -1628,       -991,        -478,        -794,        1659,
    1335,        -384,        -610,        -1522,       -996,
    870,         1278,        1187,        -1218,       1465,
    -603,        1460,        308,         854,         1530,
    -220,        136,         1285,        -1097,       -958,
    108,         1510,        1185,        874,         1215,
    -1322,       -817,
#define _ZETA_EXP_INTT_0TO5_P0_L1
    17915,       -4311,       12757,       -14017,      -18249,
    -9075,       8898,        28250,       1275,        1065,
    725,         -961,        951,         1421,        -830,
    90,          24155,       -16832,      29156,       -13426,
    30199,       28309,       15887,       -19883,      -677,
    -448,        1508,        398,         247,         -107,
    271,         853,
#define _ZETA_EXP_INTT_0TO5_P0_L2
    16163,       -26675,      -8859,       -18426,      -8800,
    10532,       -24313,      28073,       1571,        205,
    -411,        1542,        -608,        -732,        -1017,
    681,
#define _ZETA_EXP_INTT_0TO5_P0_L3
    -31164,      -31164,      11202,       11202,       -1358,
    -1358,       -10690,      -10690,      -1468,       -1468,
    1474,        1474,        1202,        1202,        -962,
    -962,
#define _ZETA_EXP_INTT_0TO5_P0_L4
    16694,       16694,       16694,       16694,       -28191,
    -28191,      -28191,      -28191,      -202,        -202,
    -202,        -202,        -287,        -287,        -287,
    -287,
#define _ZETA_EXP_INTT_0TO5_P0_L5
    -787,        1517,        0,           0,           0,
    0,           0,           0,
#define _ZETA_EXP_INTT_0TO5_P1_L0
    75,          -349,        -1119,       147,         -1653,
    235,         -105,        -843,        156,         872,
    602,         -1159,       -1574,       -177,        -1550,
    -555,        -329,        -644,        -1483,       -778,
    460,         -587,        -871,        -430,        -418,
    1590,        777,         246,         291,         -422,
    1251,        1103,
#define _ZETA_EXP_INTT_0TO5_P1_L1
    -27837,      650,         12442,       -26616,      -25080,
    -20179,      -30967,      6516,        -1469,       1162,
    666,         8,           1544,        -1491,       -1015,
    -652,        25986,       -9134,       -16064,      12796,
    -20710,      23565,       -1496,       5689,        -126,
    1618,        320,         -516,        282,         1293,
    552,         -1223,
#define _ZETA_EXP_INTT_0TO5_P1_L2
    26242,       -21438,      1102,        -5571,       29057,
    26360,       -17363,      5827,        130,         1602,
    -1458,       829,         -383,        -264,        1325,
    -573,
#define _ZETA_EXP_INTT_0TO5_P1_L3
    15690,       15690,       3799,        3799,        -27758,
    -27758,      20907,       20907,       -182,        -182,
    -1577,       -1577,       -622,        -622,        171,
    171,
#define _ZETA_EXP_INTT_0TO5_P1_L4
    12402,       12402,       12402,       12402,       -13525,
    -13525,      -13525,      -13525,      -1422,       -1422,
    -1422,       -1422,       -1493,       -1493,       -1493,
    -1493,
#define _ZETA_EXP_INTT_0TO5_P1_L5
    -14745,      359,
#define _ZETA_EXP_INTT_L6
    -31498,      758,
};

// clang-format on
