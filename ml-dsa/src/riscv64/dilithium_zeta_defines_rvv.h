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

#ifndef DILITHIUM_ZETA_DEFINES_RVV_H
#define DILITHIUM_ZETA_DEFINES_RVV_H

#define _ZETA_EXP_0TO3_L0 (0 * 2)
#define _ZETA_EXP_0TO3_L1 (_ZETA_EXP_0TO3_L0 + 1 * 2)
#define _ZETA_EXP_0TO3_L2 (_ZETA_EXP_0TO3_L1 + 2 * 2)
#define _ZETA_EXP_0TO3_L3 (_ZETA_EXP_0TO3_L2 + 4 * 2)
#define _ZETA_EXP_4TO7_P0_L4 (_ZETA_EXP_0TO3_L3 + 8 * 2)
#define _ZETA_EXP_4TO7_P0_L5 (_ZETA_EXP_4TO7_P0_L4 + 4 * 2)
#define _ZETA_EXP_4TO7_P0_L6 (_ZETA_EXP_4TO7_P0_L5 + 8 * 2)
#define _ZETA_EXP_4TO7_P0_L7 (_ZETA_EXP_4TO7_P0_L6 + 16 * 2 * 2)
#define _ZETA_EXP_4TO7_P1_L4 (_ZETA_EXP_4TO7_P0_L7 + 32 * 2)
#define _ZETA_EXP_4TO7_P1_L5 (_ZETA_EXP_4TO7_P1_L4 + 4 * 2)
#define _ZETA_EXP_4TO7_P1_L6 (_ZETA_EXP_4TO7_P1_L5 + 8 * 2)
#define _ZETA_EXP_4TO7_P1_L7 (_ZETA_EXP_4TO7_P1_L6 + 16 * 2 * 2)
#define _ZETA_EXP_4TO7_P2_L4 (_ZETA_EXP_4TO7_P1_L7 + 32 * 2)
#define _ZETA_EXP_4TO7_P2_L5 (_ZETA_EXP_4TO7_P2_L4 + 4 * 2)
#define _ZETA_EXP_4TO7_P2_L6 (_ZETA_EXP_4TO7_P2_L5 + 8 * 2)
#define _ZETA_EXP_4TO7_P2_L7 (_ZETA_EXP_4TO7_P2_L6 + 16 * 2 * 2)
#define _ZETA_EXP_4TO7_P3_L4 (_ZETA_EXP_4TO7_P2_L7 + 32 * 2)
#define _ZETA_EXP_4TO7_P3_L5 (_ZETA_EXP_4TO7_P3_L4 + 4 * 2)
#define _ZETA_EXP_4TO7_P3_L6 (_ZETA_EXP_4TO7_P3_L5 + 8 * 2)
#define _ZETA_EXP_4TO7_P3_L7 (_ZETA_EXP_4TO7_P3_L6 + 16 * 2 * 2)
#define _MASK_1100 (_ZETA_EXP_4TO7_P3_L7 + 32 * 2)
#define _MASK_1010 (_MASK_1100 + 4)
#define _MASK_0101 (_MASK_1010 + 4)
#define _MASK_2323 (_MASK_0101 + 4)
#define _MASK_1032 (_MASK_2323 + 4)
#define _ZETA_EXP_INTT_0TO3_P0_L0 (_MASK_1032 + 4)
#define _ZETA_EXP_INTT_0TO3_P0_L1 (_ZETA_EXP_INTT_0TO3_P0_L0 + 32 * 2)
#define _ZETA_EXP_INTT_0TO3_P0_L2 (_ZETA_EXP_INTT_0TO3_P0_L1 + 16 * 2 * 2)
#define _ZETA_EXP_INTT_0TO3_P0_L3 (_ZETA_EXP_INTT_0TO3_P0_L2 + 8 * 2)
#define _ZETA_EXP_INTT_0TO3_P1_L0 (_ZETA_EXP_INTT_0TO3_P0_L3 + 4 * 2)
#define _ZETA_EXP_INTT_0TO3_P1_L1 (_ZETA_EXP_INTT_0TO3_P1_L0 + 32 * 2)
#define _ZETA_EXP_INTT_0TO3_P1_L2 (_ZETA_EXP_INTT_0TO3_P1_L1 + 16 * 2 * 2)
#define _ZETA_EXP_INTT_0TO3_P1_L3 (_ZETA_EXP_INTT_0TO3_P1_L2 + 8 * 2)
#define _ZETA_EXP_INTT_0TO3_P2_L0 (_ZETA_EXP_INTT_0TO3_P1_L3 + 4 * 2)
#define _ZETA_EXP_INTT_0TO3_P2_L1 (_ZETA_EXP_INTT_0TO3_P2_L0 + 32 * 2)
#define _ZETA_EXP_INTT_0TO3_P2_L2 (_ZETA_EXP_INTT_0TO3_P2_L1 + 16 * 2 * 2)
#define _ZETA_EXP_INTT_0TO3_P2_L3 (_ZETA_EXP_INTT_0TO3_P2_L2 + 8 * 2)
#define _ZETA_EXP_INTT_0TO3_P3_L0 (_ZETA_EXP_INTT_0TO3_P2_L3 + 4 * 2)
#define _ZETA_EXP_INTT_0TO3_P3_L1 (_ZETA_EXP_INTT_0TO3_P3_L0 + 32 * 2)
#define _ZETA_EXP_INTT_0TO3_P3_L2 (_ZETA_EXP_INTT_0TO3_P3_L1 + 16 * 2 * 2)
#define _ZETA_EXP_INTT_0TO3_P3_L3 (_ZETA_EXP_INTT_0TO3_P3_L2 + 8 * 2)
#define _ZETA_EXP_INTT_4TO7_L4 (_ZETA_EXP_INTT_0TO3_P3_L3 + 4 * 2)
#define _ZETA_EXP_INTT_4TO7_L5 (_ZETA_EXP_INTT_4TO7_L4 + 8 * 2)
#define _ZETA_EXP_INTT_4TO7_L6 (_ZETA_EXP_INTT_4TO7_L5 + 4 * 2)
#define _ZETA_EXP_INTT_4TO7_L7 (_ZETA_EXP_INTT_4TO7_L6 + 2 * 2)

#endif /* DILITHIUM_ZETA_DEFINES_RVV_H */
