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

#ifndef KYBER_CONSTS_RVV_VLEN256_H
#define KYBER_CONSTS_RVV_VLEN256_H

#define _MASK_0_7x2 0
#define _MASK_8_15x2 16
#define _MASK_0_3x2_8_11x2 32
#define _MASK_4_7x2_12_15x2 48
#define _MASK_01014545 64
#define _MASK_23236767 80
#define _MASK_10325476 96
#define _REJ_UNIFORM_IDX8 112
#define _REJ_UNIFORM_MASK_01 128
#define _CBD2_MASK_E8_01 144
#define _CBD2_IDX8_LOW 160
#define _CBD2_IDX8_HIGH 176
#define _CBD3_MASK_E8_0122 192
#define _CBD3_MASK_E16_1100 208
#define _CBD3_IDX16_LOW 224
#define _CBD3_IDX16_HIGH 240
#define _ZETAS_EXP_L0 256
#define _ZETAS_EXP_L1 258
#define _ZETAS_EXP_L2 262
#define _ZETAS_EXP_L3 272
#define _ZETAS_EXP_L4 336
#define _ZETAS_EXP_L5 400
#define _ZETAS_EXP_L6 464
#define _ZETAS_BASEMUL 592
#define _ZETA_EXP_INTT_L0 720
#define _ZETA_EXP_INTT_L1 848
#define _ZETA_EXP_INTT_L2 912
#define _ZETA_EXP_INTT_L3 976
#define _ZETA_EXP_INTT_L4 1040
#define _ZETA_EXP_INTT_L5 1104
#define _ZETA_EXP_INTT_L6 1108

#endif /* KYBER_CONSTS_RVV_VLEN256_H */
