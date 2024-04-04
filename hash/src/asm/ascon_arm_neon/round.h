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
 * https://github.com/ascon/ascon-c/crypto_aead/ascon128v12/neon/round.h
 * which is subject to the following license:
 *
 * CC0 1.0 Universal
 */

#ifndef ROUND_H_
#define ROUND_H_

#define ROUND(OFFSET) /* clang-format off */ \
  "vldr.64 d31, [%[C], #" #OFFSET "] \n\t" /* clang-format on */ \
  "veor.64 d0, d0, d4 \n\t"         \
  "veor.64 d4, d4, d3 \n\t"         \
  "veor.64 d2, d2, d31 \n\t"        \
  "vbic.64 d13, d0, d4 \n\t"        \
  "vbic.64 d12, d4, d3 \n\t"        \
  "veor.64 d2, d2, d1 \n\t"         \
  "vbic.64 d14, d1, d0 \n\t"        \
  "vbic.64 d11, d3, d2 \n\t"        \
  "vbic.64 d10, d2, d1 \n\t"        \
  "veor.64 q0, q0, q5 \n\t"         \
  "veor.64 q1, q1, q6 \n\t"         \
  "veor.64 d4, d4, d14 \n\t"        \
  "veor.64 d1, d1, d0 \n\t"         \
  "veor.64 d3, d3, d2 \n\t"         \
  "veor.64 d0, d0, d4 \n\t"         \
  "vsri.64 d14, d4, #7 \n\t"     \
  "vsri.64 d24, d4, #41 \n\t"    \
  "vsri.64 d11, d1, #39 \n\t"    \
  "vsri.64 d21, d1, #61 \n\t"    \
  "vsri.64 d10, d0, #19 \n\t"    \
  "vsri.64 d20, d0, #28 \n\t"    \
  "vsri.64 d12, d2, #1 \n\t"     \
  "vsri.64 d22, d2, #6 \n\t"     \
  "vsri.64 d13, d3, #10 \n\t"    \
  "vsri.64 d23, d3, #17 \n\t"    \
  "vsli.64 d10, d0, #45 \n\t"    \
  "vsli.64 d20, d0, #36 \n\t"    \
  "vsli.64 d11, d1, #25 \n\t"    \
  "vsli.64 d21, d1, #3 \n\t"     \
  "vsli.64 d12, d2, #63 \n\t"    \
  "vsli.64 d22, d2, #58 \n\t"    \
  "vsli.64 d13, d3, #54 \n\t"    \
  "vsli.64 d23, d3, #47 \n\t"    \
  "vsli.64 d14, d4, #57 \n\t"    \
  "vsli.64 d24, d4, #23 \n\t"    \
  "veor.64 q5, q5, q0 \n\t"         \
  "veor.64 q6, q6, q1 \n\t"         \
  "veor.64 d14, d14, d4 \n\t"       \
  "veor.64 q0, q5, q10 \n\t"        \
  "veor.64 d4, d14, d24 \n\t"       \
  "veor.64 q1, q6, q11 \n\t"

#endif /* ROUND_H_ */
