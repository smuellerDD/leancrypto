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

#ifndef KYBER_CONSTS_RVV_VLEN128_H
#define KYBER_CONSTS_RVV_VLEN128_H

#define _MASK_45674567 0
#define _MASK_01230123 8
#define _MASK_01014545 16
#define _MASK_23236767 24
#define _MASK_10325476 32
#define _REJ_UNIFORM_IDX8 40
#define _REJ_UNIFORM_MASK_01 48
#define _CBD2_MASK_E8_01 56
#define _CBD2_IDX8_LOW 64
#define _CBD2_IDX8_HIGH 72
#define _CBD3_MASK_E8_0122 80
#define _CBD3_IDX16_HIGH 88
#define _CBD3_MASK_E16_1100 96
#define _CBD3_IDX16_LOW 104
#define _ZETAS_EXP 112
#define _ZETAS_EXP_1TO6_P0_L1 114
#define _ZETAS_EXP_1TO6_P0_L2 116
#define _ZETAS_EXP_1TO6_P0_L3 120
#define _ZETAS_EXP_1TO6_P0_L4 136
#define _ZETAS_EXP_1TO6_P0_L5 152
#define _ZETAS_EXP_1TO6_P0_L6 184
#define _ZETAS_EXP_1TO6_P1_L1 216
#define _ZETAS_EXP_1TO6_P1_L2 218
#define _ZETAS_EXP_1TO6_P1_L3 224
#define _ZETAS_EXP_1TO6_P1_L4 240
#define _ZETAS_EXP_1TO6_P1_L5 256
#define _ZETAS_EXP_1TO6_P1_L6 288
#define _ZETAS_BASEMUL 320
#define _ZETA_EXP_INTT_0TO5_P0_L0 448
#define _ZETA_EXP_INTT_0TO5_P0_L1 480
#define _ZETA_EXP_INTT_0TO5_P0_L2 512
#define _ZETA_EXP_INTT_0TO5_P0_L3 528
#define _ZETA_EXP_INTT_0TO5_P0_L4 544
#define _ZETA_EXP_INTT_0TO5_P0_L5 560
#define _ZETA_EXP_INTT_0TO5_P1_L0 568
#define _ZETA_EXP_INTT_0TO5_P1_L1 600
#define _ZETA_EXP_INTT_0TO5_P1_L2 632
#define _ZETA_EXP_INTT_0TO5_P1_L3 648
#define _ZETA_EXP_INTT_0TO5_P1_L4 664
#define _ZETA_EXP_INTT_0TO5_P1_L5 680
#define _ZETA_EXP_INTT_L6 682

#endif /* KYBER_CONSTS_RVV_VLEN128_H */
