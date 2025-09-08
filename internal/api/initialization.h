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

#ifndef INITIALIZATION_H
#define INITIALIZATION_H

#include "visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

/* First prio is to ensure the algorithm selectors are run */
#define LC_INIT_PRIO_ALGO (1)
/* Second prio is to make the library available */
#define LC_INIT_PRIO_LIBRARY (2)
/* Last prio is to run the FIPS integrity test */
#define LC_INIT_PRIO_FIPS (3)

void ascon_fastest_impl(void);
void sha256_fastest_impl(void);
void sha512_fastest_impl(void);
void sha3_fastest_impl(void);
void aes_fastest_impl(void);
void kyber_riscv_rvv_selector(void);
void secure_execution_linux(void);
void chacha20_fastest_impl(void);
void lc_activate_library(void);

#ifdef __cplusplus
}
#endif

#endif /* INITIALIZATION_H */
